package grpcserver

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	"go.amzn.com/eks/eks-pod-identity-agent/internal/attestation"
	wierrors "go.amzn.com/eks/eks-pod-identity-agent/pkg/errors"
)

// deadPin stands in for a connector that has exited.
type deadPin struct{}

func (deadPin) recheck() error { return errors.New("connector exited") }
func (deadPin) close() error   { return nil }

// togglePods is a pod store a test can empty and refill.
type togglePods struct {
	mu  sync.Mutex
	pod *attestation.PodInfo
}

func (s *togglePods) PodByUID(string) (*attestation.PodInfo, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pod, s.pod != nil
}

func (s *togglePods) set(p *attestation.PodInfo) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pod = p
}

// oneCgroup resolves every PID to the test pod.
type oneCgroup struct{}

func (oneCgroup) PodUIDForPID(int) (string, error) { return "uid-1", nil }

var e2ePod = &attestation.PodInfo{UID: "uid-1", Name: "web", Namespace: "a", ServiceAccount: "sa", NodeName: "node-a"}

// e2eServer runs grpcserver.New with the real attestor: a stream that attests at
// open and then stays open, and a unary that attests. Each reports its Peer.
func e2eServer(t *testing.T, pods *togglePods) (*grpc.ClientConn, chan *Peer, chan *Peer) {
	att := attestation.New("node-a", pods, oneCgroup{})
	streamPeers, unaryPeers := make(chan *Peer, 4), make(chan *Peer, 4)
	attest := func(ctx context.Context, out chan *Peer) error {
		p, ok := PeerFromContext(ctx)
		if !ok {
			return status.Error(codes.Internal, "no peer")
		}
		if _, err := att.Attest(ctx, p); err != nil {
			if wi, ok := wierrors.AsWorkloadIdentityError(err); ok {
				return status.Error(codes.PermissionDenied, wi.Message())
			}
			return status.Error(codes.Internal, err.Error())
		}
		out <- p
		return nil
	}
	stub := &stubService{
		unary: func(ctx context.Context) error { return attest(ctx, unaryPeers) },
		stream: func(ss grpc.ServerStream) error {
			if err := attest(ss.Context(), streamPeers); err != nil {
				return err
			}
			<-ss.Context().Done()
			return nil
		},
	}
	path := tempSocketPath(t)
	serve(t, newStubServer(t, stub, Opts{SocketPath: path}))
	return dial(t, path), streamPeers, unaryPeers
}

func recvErr(stream grpc.ClientStream) <-chan error {
	ch := make(chan error, 1)
	go func() { ch <- stream.RecvMsg(new(emptypb.Empty)) }()
	return ch
}

// TestDeadPin_EndsTheOpenStreamAndTheClientRepins: the RPC that finds the pin dead
// is refused and closes the connection, which ends the stream open on it; the
// client redials and is pinned afresh.
func TestDeadPin_EndsTheOpenStreamAndTheClientRepins(t *testing.T) {
	g := NewWithT(t)
	conn, streamPeers, unaryPeers := e2eServer(t, &togglePods{pod: e2ePod})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	stream, err := openStream(withHeader(ctx), conn)
	g.Expect(err).ToNot(HaveOccurred())
	var first *Peer
	g.Eventually(streamPeers).Should(Receive(&first))
	ended := recvErr(stream)

	func() {
		first.mu.Lock()
		defer first.mu.Unlock()
		_ = first.pin.close()
		first.pin = deadPin{}
	}()

	g.Expect(callUnary(withHeader(ctx), conn)).ToNot(Succeed(), "the RPC that saw the dead pin is refused")
	var streamErr error
	g.Eventually(ended, 5*time.Second).Should(Receive(&streamErr), "the stream on the dead connection must end")
	g.Expect(status.Code(streamErr)).To(Equal(codes.Unavailable))

	g.Eventually(func() error { return callUnary(withHeader(ctx), conn) }).WithContext(ctx).Should(Succeed())
	var second *Peer
	g.Eventually(unaryPeers).Should(Receive(&second))
	g.Expect(second).ToNot(BeIdenticalTo(first), "the client redialled and was pinned afresh")
}

// TestLivePin_RefusalKeepsTheConnection: a pod-store miss with a live pin is a
// plain refusal. The stream stays open and the next RPC uses the same pin.
func TestLivePin_RefusalKeepsTheConnection(t *testing.T) {
	g := NewWithT(t)
	pods := &togglePods{pod: e2ePod}
	conn, streamPeers, unaryPeers := e2eServer(t, pods)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	stream, err := openStream(withHeader(ctx), conn)
	g.Expect(err).ToNot(HaveOccurred())
	var first *Peer
	g.Eventually(streamPeers).Should(Receive(&first))
	ended := recvErr(stream)

	pods.set(nil)
	err = callUnary(withHeader(ctx), conn)
	g.Expect(status.Code(err)).To(Equal(codes.PermissionDenied))
	g.Expect(status.Convert(err).Message()).To(Equal("attestation refused"), "the reason stays out of the reply")
	g.Consistently(ended, 500*time.Millisecond).ShouldNot(Receive(), "a refusal with a live pin leaves the stream open")

	pods.set(e2ePod)
	g.Expect(callUnary(withHeader(ctx), conn)).To(Succeed())
	var again *Peer
	g.Eventually(unaryPeers).Should(Receive(&again))
	g.Expect(again).To(BeIdenticalTo(first), "same connection, same pin")
}
