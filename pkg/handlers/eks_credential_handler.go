package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/cloud/eksauth"
	imdscloud "go.amzn.com/eks/eks-pod-identity-agent/internal/cloud/imds"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/credcache"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/credsretriever"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/middleware/logger"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/validation"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/credentials"

	"go.amzn.com/eks/eks-pod-identity-agent/pkg/errors"
)

type EksCredentialHandler struct {
	// ClusterName is the EKS cluster name where the agent runs
	ClusterName string
	// RequestValidator does basic validations for parameters that we are
	// going to send to EKS Auth. Note that these validations are very
	// rough and will never be as thorough as the ones done in the server
	RequestValidator validation.RequestValidator
	// CredentialRetriever will call EksAuthService to retrieve credentials
	CredentialRetriever credentials.CredentialRetriever
}

type EksCredentialHandlerOpts struct {
	Cfg                aws.Config
	ClusterName        string
	CredentialRenewal  time.Duration
	MaxCacheSize       int
	RefreshQPS         int
	EndpointOverridden bool
	EnableIMDS         bool
}

var (
	promHttpStatus = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "pod_identity_http_response",
		Help: "Pod Identity http response code",
	}, []string{"code"})
)

// NewEksCredentialHandler builds the handler over NewCredentialManager(ctx, opts).Retriever.
func NewEksCredentialHandler(ctx context.Context, opts EksCredentialHandlerOpts) *EksCredentialHandler {
	return &EksCredentialHandler{
		RequestValidator:    validation.DefaultCredentialValidator{},
		ClusterName:         opts.ClusterName,
		CredentialRetriever: NewCredentialManager(ctx, opts).Retriever,
	}
}

// CredentialManager holds what serves pod credentials: the retriever the
// handler serves from, the cache under it and the EKS Auth client. A caller other
// than the handler uses the cache and EKS Auth directly rather than through the
// handler's retriever.
type CredentialManager struct {
	// Retriever is what the handler serves from: the cache's retriever over the
	// delegates, or the delegates alone when caching is off.
	Retriever credentials.CredentialRetriever
	// Cache stores credentials by pod UID. Nil when
	// --max-credential-retention-before-renewal or --max-cache-size is zero.
	Cache *credcache.Cache
	// EKSAuth is the EKS Auth client, the authoritative delegate.
	EKSAuth credentials.CredentialRetriever
}

// NewCredentialManager builds the EKS Auth client, the [imds, eksauth] chain when
// opts.EnableIMDS is set and IMDS answers, and, unless CredentialRenewal or
// MaxCacheSize is zero, the cache and its retriever with a token validator.
func NewCredentialManager(ctx context.Context, opts EksCredentialHandlerOpts) CredentialManager {
	ctx = logger.ContextWithField(ctx, "cluster-name", opts.ClusterName)
	log := logger.FromContext(ctx)
	credentialsRetriever := eksauth.NewService(context.Background(), opts.Cfg)

	var authSvc credentials.CredentialRetriever = credentialsRetriever

	// IMDS credential discovery is feature-flagged, default disabled
	if opts.EnableIMDS {
		// Check if IMDS is present on the node
		if imdscloud.ProbeIMDS(ctx, opts.Cfg) {
			// If so, configure the agent's credential delegates to be a chain of [imds, eksAuth]
			log.Info("IMDS available: using [imds, eksauth] chained retriever")
			imdsSvc := imdscloud.NewService(ctx, opts.Cfg)
			credentialsRetriever = credsretriever.NewChainedRetriever(imdsSvc, credentialsRetriever)
		} else {
			log.Info("IMDS not available on node: using eksauth-only retriever")
		}
	}

	tv, err := validation.NewTokenValidator(ctx)
	if err != nil {
		log.Infof("failed to initialize token validator: %v", err)
	}
	if tv != nil {
		tv.EndpointOverridden = opts.EndpointOverridden
	}

	return newCredentialManager(opts, credcache.Opts{}, credentialsRetriever, authSvc, tv)
}

// newCredentialManager is NewCredentialManager over delegates it's given: general
// serves the handler without a cache and refreshes the cache, and authSvc serves
// misses. cacheOpts carries the cache options only tests set.
func newCredentialManager(opts EksCredentialHandlerOpts, cacheOpts credcache.Opts,
	general, authSvc credentials.CredentialRetriever, tv *validation.TokenValidator) CredentialManager {
	manager := CredentialManager{Retriever: general, EKSAuth: authSvc}
	if opts.CredentialRenewal == 0 || opts.MaxCacheSize == 0 {
		return manager
	}
	cacheOpts.Delegate = general
	cacheOpts.RenewalTtl = opts.CredentialRenewal
	cacheOpts.MaxSize = opts.MaxCacheSize
	cacheOpts.RefreshQPS = opts.RefreshQPS
	manager.Cache = credcache.New(cacheOpts)
	retrieverOpts := credsretriever.CachedCredentialRetrieverOpts{
		Cache:                 manager.Cache,
		Delegate:              general,
		AuthoritativeDelegate: authSvc,
	}
	if tv != nil {
		retrieverOpts.TokenValidator = tv
	}
	manager.Retriever = credsretriever.NewCachedCredentialRetriever(retrieverOpts)
	return manager
}

func (h *EksCredentialHandler) ConfigureHandler(register func(pattern string, handlerFunc http.HandlerFunc)) {
	register("/v1/credentials", h.HandleRequest)
}

func (h *EksCredentialHandler) HandleRequest(resp http.ResponseWriter, req *http.Request) {
	ctx := logger.ContextWithField(req.Context(), "cluster-name", h.ClusterName)
	log := logger.FromContext(ctx)

	log.Infof("handling new request request from %s", req.RemoteAddr)

	eksCredentialsRequest := &credentials.EksCredentialsRequest{
		ClusterName:         h.ClusterName,
		ServiceAccountToken: req.Header.Get("Authorization"),
		RequestTargetHost:   req.Host,
	}

	creds, err := h.GetEksCredentials(ctx, eksCredentialsRequest)
	if err != nil {
		msg, code := errors.HandleCredentialFetchingError(ctx, err)
		promHttpStatus.WithLabelValues(strconv.Itoa(code)).Inc()
		http.Error(resp, msg, code)
		return
	}

	jsonOutput, err := json.Marshal(creds)
	if err != nil {
		promHttpStatus.WithLabelValues(strconv.Itoa(http.StatusInternalServerError)).Inc()
		http.Error(resp, "Unable to serialize credentials", http.StatusInternalServerError)
		return
	}

	// send the response
	resp.Header().Add("Content-Type", "application/json")
	promHttpStatus.WithLabelValues("200").Inc()
	_, err = resp.Write(jsonOutput)
	if err != nil {
		log.Errorf("failed to write response: %v", err)
	}
}

func (h *EksCredentialHandler) GetEksCredentials(ctx context.Context, request *credentials.EksCredentialsRequest) (*credentials.EksCredentialsResponse, error) {
	// validate request
	err := h.RequestValidator.ValidateEksCredentialRequest(ctx, request)
	if err != nil {
		return nil, err
	}
	// call EKS Auth
	iamCredentials, _, err := h.CredentialRetriever.GetIamCredentials(ctx, request)
	return iamCredentials, err
}
