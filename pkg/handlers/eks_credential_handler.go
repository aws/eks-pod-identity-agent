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
	Cfg               aws.Config
	ClusterName       string
	CredentialRenewal time.Duration
	MaxCacheSize      int
	RefreshQPS        int
}

var (
	promHttpStatus = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "pod_identity_http_response",
		Help: "Pod Identity http response code",
	}, []string{"code"})
)

func NewEksCredentialHandler(opts EksCredentialHandlerOpts) *EksCredentialHandler {
	credentialsRetriever := eksauth.NewService(opts.Cfg)
	if opts.CredentialRenewal != 0 && opts.MaxCacheSize != 0 {
		credentialsRetriever = credsretriever.NewCachedCredentialRetriever(credsretriever.CachedCredentialRetrieverOpts{
			Delegate:              credentialsRetriever,
			CredentialsRenewalTtl: opts.CredentialRenewal,
			MaxCacheSize:          opts.MaxCacheSize,
			RefreshQPS:            opts.RefreshQPS,
		})
	}

	return &EksCredentialHandler{
		RequestValidator:    validation.DefaultCredentialValidator{},
		ClusterName:         opts.ClusterName,
		CredentialRetriever: credentialsRetriever,
	}
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
