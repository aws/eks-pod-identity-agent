package validation

import (
	"context"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	"go.amzn.com/eks/eks-pod-identity-agent/configuration"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/test"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/credentials"
)

func TestValidateEksCredentialRequest(t *testing.T) {
	const (
		someValidClusterName = "some-cluster-name"
	)

	var (
		someValidSrcAddr        = configuration.DefaultIpv4TargetHost
		someValidSrc6Addr       = configuration.DefaultIpv6TargetHost
		someValidSrc6WithBraces = "[" + configuration.DefaultIpv6TargetHost + "]"
		someValidSrc6WithPort   = "[" + configuration.DefaultIpv6TargetHost + "]:4213"
	)

	testCases := []struct {
		name       string
		eksRequest credentials.EksCredentialsRequest
		wantErr    bool
	}{
		{
			name: "passes on valid request",
			eksRequest: credentials.EksCredentialsRequest{
				ServiceAccountToken: test.CreateToken(t, test.TokenConfig{Expiry: time.Now().Add(1 * time.Hour), Iat: time.Now(), Nbf: time.Now()}),
				ClusterName:       someValidClusterName,
				RequestTargetHost: someValidSrcAddr,
			},
		},
		{
			name: "passes on valid request IPv6 no braces",
			eksRequest: credentials.EksCredentialsRequest{
				ServiceAccountToken: test.CreateToken(t, test.TokenConfig{Expiry: time.Now().Add(1 * time.Hour), Iat: time.Now(), Nbf: time.Now()}),
				ClusterName:       someValidClusterName,
				RequestTargetHost: someValidSrc6Addr,
			},
		},
		{
			name: "passes on valid request IPv6 with braces",
			eksRequest: credentials.EksCredentialsRequest{
				ServiceAccountToken: test.CreateToken(t, test.TokenConfig{Expiry: time.Now().Add(1 * time.Hour), Iat: time.Now(), Nbf: time.Now()}),
				ClusterName:       someValidClusterName,
				RequestTargetHost: someValidSrc6WithBraces,
			},
		},
		{
			name: "passes on valid request IPv6 with port",
			eksRequest: credentials.EksCredentialsRequest{
				ServiceAccountToken: test.CreateToken(t, test.TokenConfig{Expiry: time.Now().Add(1 * time.Hour), Iat: time.Now(), Nbf: time.Now()}),
				ClusterName:       someValidClusterName,
				RequestTargetHost: someValidSrc6WithPort,
			},
		},
		{
			name: "no SA token passed",
			eksRequest: credentials.EksCredentialsRequest{
				ServiceAccountToken: "",
				ClusterName:         someValidClusterName,
				RequestTargetHost:   someValidSrcAddr,
			},
			wantErr: true,
		},
		{
			name: "no src add passed",
			eksRequest: credentials.EksCredentialsRequest{
				ServiceAccountToken: test.CreateToken(t, test.TokenConfig{Expiry: time.Now().Add(1 * time.Hour), Iat: time.Now(), Nbf: time.Now()}),
				ClusterName:       someValidClusterName,
				RequestTargetHost: "124.3.1.2",
			},
			wantErr: true,
		},
		{
			name: "expired token",
			eksRequest: credentials.EksCredentialsRequest{
				ServiceAccountToken: test.CreateToken(t, test.TokenConfig{Expiry: time.Now(), Iat: time.Now(), Nbf: time.Now()}),
				ClusterName:       someValidClusterName,
				RequestTargetHost: someValidSrcAddr,
			},
			wantErr: true,
		},
		{
			name: "token nbf in future",
			eksRequest: credentials.EksCredentialsRequest{
				ServiceAccountToken: test.CreateToken(t, test.TokenConfig{Expiry: time.Now().Add(1 * time.Hour), Iat: time.Now(), Nbf: time.Now().Add(1 * time.Hour)}),
				ClusterName:       someValidClusterName,
				RequestTargetHost: someValidSrcAddr,
			},
			wantErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// setup
			g := NewWithT(t)

			// trigger
			err := DefaultCredentialValidator{}.ValidateEksCredentialRequest(context.Background(), &tc.eksRequest)

			// validate
			if tc.wantErr {
				g.Expect(err).To(HaveOccurred())
			} else {
				g.Expect(err).To(Not(HaveOccurred()))
			}
		})
	}
}
