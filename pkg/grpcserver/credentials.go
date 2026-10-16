package grpcserver

import (
	"context"
	"errors"
	"net"
	"sync"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"

	"go.amzn.com/eks/eks-pod-identity-agent/internal/middleware/logger"
)

// authType is the label AuthInfo.AuthType reports. Nothing negotiates it and
// nothing matches on it; gRPC only prints it, in peer.Peer and in channelz.
const authType = "eks-workload-identity-uds"

// errClientHandshake is what ClientHandshake returns. These credentials are
// server-side only, so a client reaching them is a wiring bug rather than a
// fallback.
var errClientHandshake = errors.New("grpcserver: connection credentials are server-side only")

// AuthInfo carries the connection's pinned Peer from the handshake to the
// handler. gRPC copies it onto every RPC's peer.Peer.
type AuthInfo struct {
	credentials.CommonAuthInfo
	// Peer is the process that connected, pinned at the handshake.
	Peer *Peer
}

// AuthType implements credentials.AuthInfo.
//
// The value receiver matters to callers. ServerHandshake returns an AuthInfo
// value, so a consumer asserts peer.AuthInfo.(AuthInfo); the pointer form
// compiles and fails at runtime on every RPC, with nothing to catch it at build
// time. Do not change what ServerHandshake returns without changing every
// assertion.
func (AuthInfo) AuthType() string { return authType }

// peerCredentials is a credentials.TransportCredentials with no cryptography.
// Its handshake pins the process that connected, and refuses a connection it
// cannot pin, so every RPC this server runs has a Peer. This is SPIRE's
// peertracker shape, done in the handshake rather than in Accept so a slow
// /proc never stalls the accept loop.
type peerCredentials struct {
	method pinMethod
}

var _ credentials.TransportCredentials = peerCredentials{}

// NewPeerCredentials returns transport credentials that pin each accepted
// connection's peer, reachable from a handler through PeerFromContext, with the
// strongest tier this kernel offers.
func NewPeerCredentials() credentials.TransportCredentials {
	return peerCredentials{method: probePinMethod()}
}

// warnPIDZero makes the first peer_pid_zero refusal a warning: it means the agent
// runs without hostPID, a deployment bug no client can fix.
var warnPIDZero sync.Once

// ServerHandshake pins conn's peer, or counts and logs why it could not and
// refuses, which makes gRPC close the socket.
func (c peerCredentials) ServerHandshake(conn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	peer, err := peerFromConn(conn, c.method)
	countPin(err)
	if err != nil {
		log := logger.FromContext(context.Background())
		if errors.Is(err, errPeerPIDZero) {
			warnPIDZero.Do(func() { log.Warnf("Refusing workload identity connections: %v; is hostPID set?", err) })
		}
		log.Debugf("Refusing a workload identity connection: %v", err)
		return nil, nil, err
	}
	return &pinnedConn{Conn: conn, peer: peer}, AuthInfo{
		CommonAuthInfo: credentials.CommonAuthInfo{SecurityLevel: credentials.PrivacyAndIntegrity},
		Peer:           peer,
	}, nil
}

// ClientHandshake always fails. These credentials capture an accepted connection
// on the server; there is no client half.
func (peerCredentials) ClientHandshake(_ context.Context, _ string, conn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	_ = conn.Close()
	return nil, nil, errClientHandshake
}

// Info reports the protocol label gRPC surfaces through channelz. The remaining
// ProtocolInfo fields are TLS-specific or deprecated and stay empty.
func (peerCredentials) Info() credentials.ProtocolInfo {
	return credentials.ProtocolInfo{SecurityProtocol: authType}
}

// Clone returns the receiver. The type is an empty struct with no configuration
// to copy.
func (c peerCredentials) Clone() credentials.TransportCredentials { return c }

// OverrideServerName is a no-op. gRPC documents the method as deprecated, and a
// Unix socket has no server name to override.
func (peerCredentials) OverrideServerName(string) error { return nil }

// AuthInfoFromContext returns the AuthInfo gRPC recorded for the connection this
// RPC arrived on, or false on a server built without NewPeerCredentials.
func AuthInfoFromContext(ctx context.Context) (AuthInfo, bool) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return AuthInfo{}, false
	}
	info, ok := p.AuthInfo.(AuthInfo)
	return info, ok
}

// PeerFromContext returns the pinned Peer of the connection this RPC arrived
// on. It works in unary and stream handlers alike. False means the caller
// cannot be identified and has to be refused.
func PeerFromContext(ctx context.Context) (*Peer, bool) {
	info, ok := AuthInfoFromContext(ctx)
	if !ok || info.Peer == nil {
		return nil, false
	}
	return info.Peer, true
}
