package server

import (
	"context"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.amzn.com/eks/eks-pod-identity-agent/configuration"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/middleware/logger"
	ratelimiter "go.amzn.com/eks/eks-pod-identity-agent/internal/middleware/rate_limiter"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/handlers"
)

type (
	// RegisterFunc function that is invoked by handlers to register their
	// endpoints
	RegisterFunc = func(pattern string, handlerFunc http.HandlerFunc)

	// HandlerConfigurer must be implemented by handlers that want to
	// register their handler in the server
	HandlerConfigurer interface {
		ConfigureHandler(register RegisterFunc)
	}

	// Server that will be initialized in ListenUntilContextCancelled
	Server struct {
		// Configurer is responsible for configuring the Server's mux, injecting
		// its own handlers
		configurer HandlerConfigurer
		// server contains the HTTP server that will listen to requests
		server *http.Server
		mux    *http.ServeMux
	}
)

const (
	defaultRequestTimeout = 30 * time.Second
	maxTerminationWait    = defaultRequestTimeout + 5*time.Second
)

func newBaseServer(addr string) *Server {
	mux := http.NewServeMux()
	return &Server{
		mux: mux,
		server: &http.Server{
			Addr:         addr,
			Handler:      mux,
			ReadTimeout:  defaultRequestTimeout,
			WriteTimeout: defaultRequestTimeout,
		},
	}
}

func NewProbeServer(addr string, hosts []string, port uint16) *Server {
	srv := newBaseServer(addr)
	srv.configurer = handlers.NewProbeHandler(hosts, port)
	return srv
}

func NewEksCredentialServer(addr string, opts handlers.EksCredentialHandlerOpts) *Server {
	srv := newBaseServer(addr)
	srv.configurer = handlers.NewEksCredentialHandler(opts)
	return srv
}

func NewMetricsServer(addr string, hosts []string, port uint16) *Server {
	srv := newBaseServer(addr)
	srv.configurer = handlers.NewProbeHandler(hosts, port)
	srv.mux.Handle("/metrics", promhttp.Handler())
	return srv
}

func (p *Server) ListenUntilContextCancelled(ctx context.Context) {
	log := logger.FromContext(ctx)
	p.configureHandler()

	// Run the server in a goroutine
	go func() {
		log.Info("Starting server...")
		if err := p.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Unable to start server: %v", err)
		}
		log.Debug("Server has stopped listening")
	}()

	// Block until a signal is received
	select {
	case <-ctx.Done():
	}

	log.Info("Shutting down server...")

	// Create a context with a timeout for the graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), maxTerminationWait)
	defer cancel()

	// Shutdown the server and wait for existing connections to be closed
	if err := p.server.Shutdown(ctx); err != nil {
		log.Fatalf("Server shutdown error: %v", err)
	}

	log.Info("Server gracefully stopped")
}

type interceptor = func(http.HandlerFunc) http.HandlerFunc

func (p *Server) configureHandler() {
	p.configurer.ConfigureHandler(func(pattern string, handler http.HandlerFunc) {
		//rate limit the EksCredentialsRequest request
		rateLimiter := ratelimiter.NewRateLimiter(configuration.RequestRate)

		// order here matters
		interceptors := []interceptor{
			// add logger so it can be used downstream
			logger.InjectLogger,
			// add rate limite to requests
			func(h http.HandlerFunc) http.HandlerFunc { return ratelimiter.RateLimitMiddleware(rateLimiter, h) },
		}

		for _, intercept := range interceptors {
			handler = intercept(handler)
		}

		// add the handler to the server mux
		p.mux.Handle(pattern, handler)
	})

}

func (p *Server) Addr() string {
	return p.server.Addr
}
