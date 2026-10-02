package grpcserver

import (
	secretv3 "github.com/envoyproxy/go-control-plane/envoy/service/secret/v3"
	"github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"google.golang.org/grpc"
)

// RegisterStubServices registers the two services the workload identity socket will
// serve, with handlers that answer every method with Unimplemented.
//
// It is what the wiring site passes as Opts.Register until the real handlers land.
// The SPIFFE Workload API handlers and the Envoy SDS handler replace one stub each,
// at this call site, and nothing else about the server changes.
//
// Registering the real service descriptors rather than something invented is
// deliberate, for two reasons. It makes the socket's surface what it is going to be,
// so a client that connects gets a structured Unimplemented for a method the agent
// does not serve yet instead of an unknown-service error for one it will. And it
// links the upstream descriptors into the binary, so the size recorded for this task
// is the size the proto swap will be measured against; a stub that avoided them
// would understate the cost by the whole of the dependency the swap exists to
// remove.
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
