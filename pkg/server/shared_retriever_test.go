package server

import (
	"context"
	"testing"

	. "github.com/onsi/gomega"
	"go.uber.org/mock/gomock"

	"go.amzn.com/eks/eks-pod-identity-agent/internal/cloud/eksauth"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/handlers"
)

// TestNewEksCredentialServer_ServesFromTheGivenRetriever proves every server
// built with opts.CredentialRetriever set serves from that one instance, which
// is how cmd shares one credential cache across bind hosts.
func TestNewEksCredentialServer_ServesFromTheGivenRetriever(t *testing.T) {
	g := NewWithT(t)
	shared := eksauth.NewMockIface(gomock.NewController(t))
	opts := handlers.EksCredentialHandlerOpts{ClusterName: "cluster-a", CredentialRetriever: shared}

	for _, addr := range []string{"169.254.170.23:80", "[fd00:ec2::23]:80"} {
		handler, ok := NewEksCredentialServer(context.Background(), addr, opts).configurer.(*handlers.EksCredentialHandler)
		g.Expect(ok).To(BeTrue())
		g.Expect(handler.CredentialRetriever).To(BeIdenticalTo(shared), "server %s", addr)
		g.Expect(handler.ClusterName).To(Equal("cluster-a"))
	}
}
