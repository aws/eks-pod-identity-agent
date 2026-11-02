package grpcserver

import (
	secretv3 "github.com/envoyproxy/go-control-plane/envoy/service/secret/v3"
	"github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"google.golang.org/grpc"
)

// RegisterStubServices registers both services the workload identity socket serves
// with handlers that answer every method with Unimplemented, for tests of the server
// itself. They are the real service descriptors, so a client gets a structured
// Unimplemented rather than an unknown-service error.
func RegisterStubServices(registrar grpc.ServiceRegistrar) {
	workload.RegisterSpiffeWorkloadAPIServer(registrar, stubWorkloadAPI{})
	RegisterStubSDS(registrar)
}

// RegisterStubSDS registers the Envoy SDS stub alone, which is what the wiring site
// registers beside the real Workload API handler until the SDS handler lands.
func RegisterStubSDS(registrar grpc.ServiceRegistrar) {
	secretv3.RegisterSecretDiscoveryServiceServer(registrar, stubSDS{})
}

// stubWorkloadAPI answers every SPIFFE Workload API method with Unimplemented. The
// embedded struct supplies all of them, and it is embedded by value because the
// generated registration rejects a nil pointer embed.
type stubWorkloadAPI struct {
	workload.UnimplementedSpiffeWorkloadAPIServer
}

// stubSDS answers every Envoy SDS method with Unimplemented.
type stubSDS struct {
	secretv3.UnimplementedSecretDiscoveryServiceServer
}
