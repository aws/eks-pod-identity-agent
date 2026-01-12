package validation

import (
	"context"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"go.amzn.com/eks/eks-pod-identity-agent/configuration"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/middleware/logger"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/credentials"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/errors"
	"net"
)

// A RequestValidator validates the requests that are expected by the agent
type RequestValidator interface {
	ValidateEksCredentialRequest(ctx context.Context, credsRequest *credentials.EksCredentialsRequest) error
}

type DefaultCredentialValidator struct {
	// TargetHosts indicates which IP address we expect the call to come from
	// If not specified, we will use configuration.DefaultIpv4TargetHost and
	// configuration.DefaultIpv6TargetHost
	TargetHosts []string
}

var (
	jwtParser               = jwt.NewParser()
	jwtValidator            = jwt.NewValidator()
	defaultValidTargetHosts = []string{
		configuration.DefaultIpv4TargetHost,
		configuration.DefaultIpv6TargetHost,
	}
)

// ValidateEksCredentialRequest is called to validate whether a request from the user is valid or not
func (cv DefaultCredentialValidator) ValidateEksCredentialRequest(ctx context.Context, credsRequest *credentials.EksCredentialsRequest) error {
	log := logger.FromContext(ctx)

	log.Debugf("validating call to requested target host %s", credsRequest.RequestTargetHost)
	err := cv.validateRequestTargetHost(ctx, credsRequest.RequestTargetHost)
	if err != nil {
		return err
	}

	err = cv.validateToken(credsRequest)
	if err != nil {
		return err
	}

	log.Debug("validation passed")
	return nil
}

// validateToken checks if the JWT token is parseable
func (cv DefaultCredentialValidator) validateToken(credsRequest *credentials.EksCredentialsRequest) error {
	// just verify the token is parseable, we will detect if it's valid or not on the service
	if credsRequest.ServiceAccountToken == "" {
		return errors.NewRequestValidationError("Service account token cannot be empty")
	}
	parsedToken, _, err := jwtParser.ParseUnverified(credsRequest.ServiceAccountToken, &jwt.RegisteredClaims{})
	if err != nil {
		return errors.NewRequestValidationError(fmt.Sprintf("Service account token cannot be parsed: %v", err))
	}

	err = jwtValidator.Validate(parsedToken.Claims)
	if err != nil {
		return errors.NewRequestValidationError(fmt.Sprintf("Service account token failed basic claim validations: %v", err))
	}
	return nil
}

// validateRequestTargetHost checks whether the request address matches the
// assign bind address for the agent
func (cv DefaultCredentialValidator) validateRequestTargetHost(ctx context.Context, requestTargetHost string) error {
	// sometimes the port is included in the requestTargetHost, (eg when the port we are listening on
	// is not HTTP's default 80)
	log := logger.FromContext(ctx).WithField("target-host", requestTargetHost)
	if host, port, err := net.SplitHostPort(requestTargetHost); err == nil {
		log.WithFields(map[string]interface{}{
			"host": host,
			"port": port,
		}).Tracef("Parsing request target host as host-port addr")
		requestTargetHost = host
	}

	// sometimes IPv6 host is expressed as "[fe00::]" so we want to drop the brackets
	if len(requestTargetHost) > 1 && requestTargetHost[0] == '[' && requestTargetHost[len(requestTargetHost)-1] == ']' {
		requestTargetHost = requestTargetHost[1 : len(requestTargetHost)-1]
	}

	// if all else fails we may have some custom target host that we don't know how to parse, eg localhost or some
	// dns address that might fail validation. Unit tests bind use localhost so we will leave this as is.
	log.Trace("Interpreting request target host without port")

	desiredTargetHosts := defaultValidTargetHosts
	if cv.TargetHosts != nil {
		desiredTargetHosts = cv.TargetHosts
	}

	for _, desiredTargetHost := range desiredTargetHosts {
		if desiredTargetHost == requestTargetHost {
			return nil
		}
	}

	return errors.NewAccessDeniedError(
		fmt.Sprintf(
			"Called agent through invalid address, please use either %s address not %s", desiredTargetHosts, requestTargetHost))
}
