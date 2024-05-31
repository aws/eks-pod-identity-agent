package handlers

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"go.amzn.com/eks/eks-pod-identity-agent/internal/middleware/logger"
)

const defaultProbeTimeout = 10 * time.Second

type ProbeHandler interface {
	ConfigureHandler(register func(pattern string, handlerFunc http.HandlerFunc))
	HandleProbe(resp http.ResponseWriter, request *http.Request)
}

type probeHandler struct {
	addrs        []string
	client       http.Client
	probeTimeout time.Duration
}

func NewProbeHandler(hostToProbe []string, port uint16) ProbeHandler {
	addrs := make([]string, len(hostToProbe))
	for i, host := range hostToProbe {
		addrs[i] = fmt.Sprintf("%s:%d", host, port)
	}
	return &probeHandler{
		addrs:        addrs,
		probeTimeout: defaultProbeTimeout,
	}
}

func (p *probeHandler) ConfigureHandler(register func(pattern string, handlerFunc http.HandlerFunc)) {
	register("/readyz", p.HandleProbe)
	register("/healthz", p.HandleProbe)
}

func (p *probeHandler) HandleProbe(resp http.ResponseWriter, request *http.Request) {
	ctx, cancel := context.WithTimeout(request.Context(), p.probeTimeout)
	log := logger.FromContext(ctx)
	defer cancel()

	err := p.probeAddrs(ctx)

	if err == nil {
		resp.WriteHeader(http.StatusOK)
	} else if errors.Is(err, context.DeadlineExceeded) {
		resp.WriteHeader(http.StatusRequestTimeout)
	} else {
		resp.WriteHeader(http.StatusInternalServerError)
		log.Errorf("InternalServerError: %v", err)
		_, _ = resp.Write([]byte("Internal Server Error occurred"))
	}
}

func (p *probeHandler) probeAddrs(ctx context.Context) (ret error) {
	log := logger.FromContext(ctx)
	log.Tracef("Starting probe")

	ret = nil
	failProbeFunc := func(cause error) {
		log.Warnf("Failed probe: %v", cause)
		ret = cause
	}

	for _, addr := range p.addrs {
		req, err := http.NewRequestWithContext(ctx, "", "http://"+addr, nil)
		if err != nil {
			failProbeFunc(err)
			return
		}

		res, err := p.client.Do(req)
		if err != nil {
			failProbeFunc(err)
			return
		}

		// we expect a 404
		if res.StatusCode != http.StatusNotFound {
			failProbeFunc(fmt.Errorf("unexpected status code recieved, expected %d, got %d", http.StatusNotFound, res.StatusCode))
			return
		}
	}
	return
}
