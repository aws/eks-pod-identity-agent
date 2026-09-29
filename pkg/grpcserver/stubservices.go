package grpcserver

import (
	secretv3 "github.com/envoyproxy/go-control-plane/envoy/service/secret/v3"
	"github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"google.golang.org/grpc"
)

// RegisterStubServices registers the SPIFFE Workload API and Envoy SDS services
// with handlers that answer every method Unimplemented. The wiring site passes it
// as Opts.Register until the real handlers land. Using the real descriptors means
// a client is told a method is not implemented, not that the service is unknown.
func RegisterStubServices(registrar grpc.ServiceRegistrar) {
	workload.RegisterSpiffeWorkloadAPIServer(registrar, stubWorkloadAPI{})
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
