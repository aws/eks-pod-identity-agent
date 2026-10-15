package workloadapi

import (
	"context"
	stderrors "errors"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	wierrors "go.amzn.com/eks/eks-pod-identity-agent/pkg/errors"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/handlers"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity/fake"
)

// This file drives every error the handler can be handed, the whole taxonomy and
// the errors outside it, through every place each RPC can be handed one, and
// checks the code the caller sees and how the RPC metrics count the call. The
// metrics are process-wide, so every metric assertion is a delta, and none of
// these tests run in parallel.

const (
	// errsSpiffeIDA is the SPIFFE ID the harness's svidA carries.
	errsSpiffeIDA = "spiffe://" + testTrustDomain + "/ns/ns/sa/sa-a"
	// errsAudience is the audience the unary calls ask for.
	errsAudience = "spiffe://" + testTrustDomain + "/audience"
	// errsWait bounds every wait for something the handler is expected to do.
	errsWait = 5 * time.Second
	// errsQuiet is how long a blocked stream must stay silent.
	errsQuiet = 50 * time.Millisecond
)

// errsCase is one error a tier or the attestor can return, with the code the
// caller should see and the error label the RPC metrics should count it under.
type errsCase struct {
	name  string
	err   error
	code  codes.Code
	label string
}

// errsCases is the whole taxonomy, an error nobody classified, which has to
// answer Internal and count as unknown, and the bare context errors a tier might
// return while the caller is still there, which are unexpected in the same way.
func errsCases() []errsCase {
	var cases []errsCase
	for _, member := range wierrors.WorkloadIdentityTaxonomy() {
		cases = append(cases, errsCase{
			name:  member.MetricLabel(),
			err:   member,
			code:  handlers.StatusCode(member),
			label: member.MetricLabel(),
		})
	}
	return append(cases,
		errsCase{name: "unclassified", err: stderrors.New("something nobody classified"), code: codes.Internal, label: wierrors.MetricLabelUnknown},
		errsCase{name: "tier deadline", err: context.DeadlineExceeded, code: codes.Internal, label: wierrors.MetricLabelUnknown},
		errsCase{name: "tier cancelled", err: context.Canceled, code: codes.Internal, label: wierrors.MetricLabelUnknown},
	)
}

// errsPath is one place an RPC can be handed an error. inject makes it return err
// and runs before the harness serves; calls counts how often it has been tried,
// which tells a blocked stream that is retrying from one that has stopped.
type errsPath struct {
	name   string
	inject func(h *harness, err error)
	calls  func(h *harness) int
}

var (
	errsAttestPath = errsPath{
		name: "attest",
		inject: func(h *harness, err error) {
			h.attestor.Func = func(context.Context, workloadidentity.Peer) (*workloadidentity.Workload, error) { return nil, err }
		},
		calls: func(h *harness) int { return h.attestor.Calls() },
	}
	errsSubscribePath = errsPath{
		name: "subscribe",
		inject: func(h *harness, err error) {
			h.subs.Func = func(context.Context, fake.SubscriptionKind, *workloadidentity.Workload) (<-chan struct{}, func(), error) {
				return nil, nil, err
			}
		},
		calls: func(h *harness) int { return h.subs.SubscribeCalls() },
	}
	errsLeasePath = errsPath{
		name:   "lease",
		inject: func(h *harness, err error) { h.bundles.LeaseErr = err },
		calls:  func(h *harness) int { return h.bundles.LeaseCalls() },
	}
	errsX509BundlesPath = errsPath{
		name:   "x509 bundles",
		inject: func(h *harness, err error) { h.bundles.X509Err = err },
		calls:  func(h *harness) int { return h.bundles.X509BundlesCalls() },
	}
)

// errsRecv is one Recv on a stream: a response, or the error that ended it.
type errsRecv struct {
	msg proto.Message
	err error
}

// errsStream is one streaming RPC and every place it can be handed an error.
type errsStream struct {
	rpc   string
	open  func(ctx context.Context, h *harness) (func() (proto.Message, error), error)
	paths []errsPath
}

func errsStreams() []errsStream {
	return []errsStream{
		{
			rpc:  workloadidentity.RPCFetchX509SVID,
			open: errsOpenX509SVID,
			paths: []errsPath{
				errsAttestPath, errsSubscribePath, errsLeasePath,
				{
					name:   "x509 svids",
					inject: func(h *harness, err error) { h.certs.Err = err },
					calls:  func(h *harness) int { return h.certs.Calls() },
				},
				{
					name:   "own trust domain",
					inject: func(h *harness, err error) { h.bundles.OwnTrustDomainErr = err },
					calls:  func(h *harness) int { return h.bundles.OwnTrustDomainCalls() },
				},
				errsX509BundlesPath,
			},
		},
		{
			rpc:   workloadidentity.RPCFetchX509Bundles,
			open:  errsOpenX509Bundles,
			paths: []errsPath{errsAttestPath, errsSubscribePath, errsLeasePath, errsX509BundlesPath},
		},
		{
			rpc:  workloadidentity.RPCFetchJWTBundles,
			open: errsOpenJWTBundles,
			paths: []errsPath{
				errsAttestPath, errsSubscribePath, errsLeasePath,
				{
					name:   "jwt bundles",
					inject: func(h *harness, err error) { h.bundles.JWTErr = err },
					calls:  func(h *harness) int { return h.bundles.JWTBundlesCalls() },
				},
			},
		},
	}
}

func errsOpenX509SVID(ctx context.Context, h *harness) (func() (proto.Message, error), error) {
	stream, err := h.client.FetchX509SVID(ctx, &workload.X509SVIDRequest{})
	if err != nil {
		return nil, err
	}
	return func() (proto.Message, error) { return stream.Recv() }, nil
}

func errsOpenX509Bundles(ctx context.Context, h *harness) (func() (proto.Message, error), error) {
	stream, err := h.client.FetchX509Bundles(ctx, &workload.X509BundlesRequest{})
	if err != nil {
		return nil, err
	}
	return func() (proto.Message, error) { return stream.Recv() }, nil
}

func errsOpenJWTBundles(ctx context.Context, h *harness) (func() (proto.Message, error), error) {
	stream, err := h.client.FetchJWTBundles(ctx, &workload.JWTBundlesRequest{})
	if err != nil {
		return nil, err
	}
	return func() (proto.Message, error) { return stream.Recv() }, nil
}

// errsReceive receives on a stream until it ends, so a test can wait on a
// response, an error, or neither. The goroutine exits with the stream, which
// every test ends by cancelling its ctx.
func errsReceive(recv func() (proto.Message, error)) <-chan errsRecv {
	received := make(chan errsRecv, 64)
	go func() {
		for {
			msg, err := recv()
			received <- errsRecv{msg: msg, err: err}
			if err != nil {
				return
			}
		}
	}()
	return received
}

// errsUnary is one unary RPC and every place it can be handed an error.
type errsUnary struct {
	rpc   string
	call  func(ctx context.Context, h *harness) error
	paths []errsPath
}

func errsUnaries() []errsUnary {
	return []errsUnary{
		{
			rpc:  workloadidentity.RPCFetchJWTSVID,
			call: errsCallFetchJWTSVID,
			paths: []errsPath{
				errsAttestPath,
				{
					name:   "jwt svids",
					inject: func(h *harness, err error) { h.tokens.Err = err },
					calls:  func(h *harness) int { return h.tokens.Calls() },
				},
			},
		},
		{
			rpc:  workloadidentity.RPCValidateJWTSVID,
			call: errsCallValidateJWTSVID,
			paths: []errsPath{
				errsAttestPath,
				{
					name:   "jwt source",
					inject: func(h *harness, err error) { h.bundles.JWTSourceErr = err },
					calls:  func(h *harness) int { return h.bundles.JWTSourceCalls() },
				},
			},
		},
	}
}

func errsCallFetchJWTSVID(ctx context.Context, h *harness) error {
	_, err := h.client.FetchJWTSVID(ctx, &workload.JWTSVIDRequest{Audience: []string{errsAudience}})
	return err
}

// errsCallValidateJWTSVID presents a token the harness's JWT authority signed,
// so only the injected error can make it fail.
func errsCallValidateJWTSVID(ctx context.Context, h *harness) error {
	token := h.jwt.sign(h.t, errsSpiffeIDA, []string{errsAudience}, time.Now().Add(time.Hour))
	_, err := h.client.ValidateJWTSVID(ctx, &workload.ValidateJWTSVIDRequest{Audience: errsAudience, Svid: token})
	return err
}

// errsSeries is one MetricRPCTotal series of an RPC.
type errsSeries struct {
	outcome string
	label   string
}

// errsSnapshot is both RPC metrics of one RPC: the count per outcome and error
// label, and the duration sample count per outcome.
type errsSnapshot struct {
	totals    map[errsSeries]float64
	durations map[string]uint64
}

// errsRPCMetrics reads both RPC metrics for rpc from the default registry, where
// promauto registered them.
func errsRPCMetrics(g Gomega, rpc string) errsSnapshot {
	families, err := prometheus.DefaultGatherer.Gather()
	g.Expect(err).ToNot(HaveOccurred())

	snap := errsNothing()
	for _, family := range families {
		for _, metric := range family.GetMetric() {
			labels := map[string]string{}
			for _, pair := range metric.GetLabel() {
				labels[pair.GetName()] = pair.GetValue()
			}
			if labels[workloadidentity.LabelRPC] != rpc {
				continue
			}
			switch family.GetName() {
			case workloadidentity.MetricRPCTotal:
				series := errsSeries{outcome: labels[workloadidentity.LabelOutcome], label: labels[workloadidentity.LabelError]}
				snap.totals[series] = metric.GetCounter().GetValue()
			case workloadidentity.MetricRPCDuration:
				snap.durations[labels[workloadidentity.LabelOutcome]] = metric.GetHistogram().GetSampleCount()
			}
		}
	}
	return snap
}

// since is what was counted between before and s, leaving out the series that
// did not move, so a test compares against exactly what one call should add.
func (s errsSnapshot) since(before errsSnapshot) errsSnapshot {
	delta := errsNothing()
	for series, value := range s.totals {
		if moved := value - before.totals[series]; moved != 0 {
			delta.totals[series] = moved
		}
	}
	for outcome, count := range s.durations {
		if moved := count - before.durations[outcome]; moved != 0 {
			delta.durations[outcome] = moved
		}
	}
	return delta
}

// errsNothing is the delta of an RPC nothing has counted yet.
func errsNothing() errsSnapshot {
	return errsSnapshot{totals: map[errsSeries]float64{}, durations: map[string]uint64{}}
}

// errsCounted is the delta of one answered RPC: one count under outcome and
// label, and one duration sample under outcome.
func errsCounted(outcome, label string) errsSnapshot {
	return errsSnapshot{
		totals:    map[errsSeries]float64{{outcome: outcome, label: label}: 1},
		durations: map[string]uint64{outcome: 1},
	}
}

// TestErrorMapping_UnaryAnswersMappedCodeOnEveryPath drives the whole table
// through every step of both unary RPCs. A unary call has nothing to wait on, so
// a retryable error answers too, with its own code, and each call counts once
// under its error label, unknown for the error nobody classified.
func TestErrorMapping_UnaryAnswersMappedCodeOnEveryPath(t *testing.T) {
	for _, unary := range errsUnaries() {
		for _, path := range unary.paths {
			for _, tc := range errsCases() {
				t.Run(unary.rpc+"/"+path.name+"/"+tc.name, func(t *testing.T) {
					g := NewWithT(t)
					h := newHarness(t, func(h *harness) { path.inject(h, tc.err) })
					before := errsRPCMetrics(g, unary.rpc)

					err := unary.call(h.ctxFor(podA), h)

					g.Expect(err).To(HaveOccurred())
					g.Expect(status.Code(err)).To(Equal(tc.code), "%v", err)
					g.Expect(path.calls(h)).To(BeNumerically(">=", 1), "the injected step was never reached")
					g.Expect(errsRPCMetrics(g, unary.rpc).since(before)).To(Equal(errsCounted(workloadidentity.OutcomeFailure, tc.label)))
				})
			}
		}
	}
}

// TestErrorMapping_StreamsEndOrBlockOnEveryPath drives the whole table through
// every step of all three streams. A non-retryable error ends the stream with its
// mapped code and counts once. A retryable one is the blocking rule: the stream
// keeps retrying and sends nothing, neither a response nor an error, and is not
// counted when the client gives up, since it never answered.
func TestErrorMapping_StreamsEndOrBlockOnEveryPath(t *testing.T) {
	for _, stream := range errsStreams() {
		for _, path := range stream.paths {
			for _, tc := range errsCases() {
				t.Run(stream.rpc+"/"+path.name+"/"+tc.name, func(t *testing.T) {
					h := newHarness(t, func(h *harness) { path.inject(h, tc.err) })
					if wierrors.IsRetryable(tc.err) {
						errsExpectBlocked(t, h, stream, path, tc)
						return
					}
					errsExpectEnded(t, h, stream, tc)
				})
			}
		}
	}
}

// errsExpectEnded opens the stream and expects it to end, before any response,
// with tc's code. The handler counts the call before it returns the status, so
// the count is already there when the client sees the error.
func errsExpectEnded(t *testing.T, h *harness, stream errsStream, tc errsCase) {
	t.Helper()
	g := NewWithT(t)
	before := errsRPCMetrics(g, stream.rpc)

	ctx, cancel := context.WithCancel(h.ctxFor(podA))
	defer cancel()
	recv, err := stream.open(ctx, h)
	g.Expect(err).ToNot(HaveOccurred())
	received := errsReceive(recv)

	var got errsRecv
	g.Eventually(received, errsWait, time.Millisecond).Should(Receive(&got))
	g.Expect(got.err).To(HaveOccurred(), "the stream sent a response instead of ending")
	g.Expect(status.Code(got.err)).To(Equal(tc.code), "%v", got.err)
	g.Expect(errsRPCMetrics(g, stream.rpc).since(before)).To(Equal(errsCounted(workloadidentity.OutcomeFailure, tc.label)))
}

// errsExpectBlocked opens the stream, waits until the failing step has been
// retried a few times, and expects the stream to have sent nothing and counted
// nothing. Then it disconnects and expects it still to have counted nothing.
func errsExpectBlocked(t *testing.T, h *harness, stream errsStream, path errsPath, tc errsCase) {
	t.Helper()
	g := NewWithT(t)
	before := errsRPCMetrics(g, stream.rpc)

	ctx, cancel := context.WithCancel(h.ctxFor(podA))
	defer cancel()
	recv, err := stream.open(ctx, h)
	g.Expect(err).ToNot(HaveOccurred())
	received := errsReceive(recv)

	g.Eventually(func() int { return path.calls(h) }, errsWait, time.Millisecond).Should(BeNumerically(">=", 3),
		"the stream is not retrying its %s step", path.name)
	g.Consistently(received, errsQuiet).ShouldNot(Receive(), "a stream blocked on a retryable error answered")
	g.Expect(errsRPCMetrics(g, stream.rpc).since(before)).To(Equal(errsNothing()),
		"a blocked stream was counted before it answered or ended")

	cancel()
	var got errsRecv
	g.Eventually(received, errsWait, time.Millisecond).Should(Receive(&got))
	g.Expect(status.Code(got.err)).To(Equal(codes.Canceled), "%v", got.err)
	// The client reports Canceled without waiting for the server, so wait for the
	// handler itself to return before asserting it counted nothing.
	g.Eventually(h.streamsEnded, errsWait, time.Millisecond).Should(BeEquivalentTo(1))
	g.Expect(errsRPCMetrics(g, stream.rpc).since(before)).To(Equal(errsNothing()),
		"a stream whose client left before it answered was counted")
}

// TestErrorMapping_AttestationNamingNoWorkloadIsUnattestable pins that an attestor
// answering with neither a workload nor an error is refused as unattestable on
// every RPC, rather than reaching a tier with a nil workload.
func TestErrorMapping_AttestationNamingNoWorkloadIsUnattestable(t *testing.T) {
	noWorkload := func(h *harness) {
		h.attestor.Func = func(context.Context, workloadidentity.Peer) (*workloadidentity.Workload, error) { return nil, nil }
	}
	tc := errsCase{
		err:   wierrors.ErrUnattestable,
		code:  codes.PermissionDenied,
		label: wierrors.ErrUnattestable.MetricLabel(),
	}

	for _, unary := range errsUnaries() {
		t.Run(unary.rpc, func(t *testing.T) {
			g := NewWithT(t)
			h := newHarness(t, noWorkload)
			before := errsRPCMetrics(g, unary.rpc)

			err := unary.call(h.ctxFor(podA), h)

			g.Expect(status.Code(err)).To(Equal(tc.code), "%v", err)
			g.Expect(errsRPCMetrics(g, unary.rpc).since(before)).To(Equal(errsCounted(workloadidentity.OutcomeFailure, tc.label)))
		})
	}
	for _, stream := range errsStreams() {
		t.Run(stream.rpc, func(t *testing.T) {
			h := newHarness(t, noWorkload)
			errsExpectEnded(t, h, stream, tc)
			NewWithT(t).Expect(h.bundles.WorkloadRequests()).To(BeEmpty())
		})
	}
}

// TestErrorMapping_HandlerRefusalsOfTheRequest covers the errors the handler
// raises itself, before any tier runs or after one answers. Each is a taxonomy
// member, so each is counted under its own label rather than as none or unknown.
func TestErrorMapping_HandlerRefusalsOfTheRequest(t *testing.T) {
	for _, tc := range []struct {
		name  string
		rpc   string
		call  func(ctx context.Context, h *harness) error
		code  codes.Code
		label string
	}{
		{
			name: "no audience", rpc: workloadidentity.RPCFetchJWTSVID,
			call: func(ctx context.Context, h *harness) error {
				_, err := h.client.FetchJWTSVID(ctx, &workload.JWTSVIDRequest{})
				return err
			},
			code: codes.InvalidArgument, label: wierrors.ErrInvalidAudience.MetricLabel(),
		},
		{
			name: "an empty audience", rpc: workloadidentity.RPCFetchJWTSVID,
			call: func(ctx context.Context, h *harness) error {
				_, err := h.client.FetchJWTSVID(ctx, &workload.JWTSVIDRequest{Audience: []string{errsAudience, ""}})
				return err
			},
			code: codes.InvalidArgument, label: wierrors.ErrInvalidAudience.MetricLabel(),
		},
		{
			name: "an invalid SPIFFE ID", rpc: workloadidentity.RPCFetchJWTSVID,
			call: func(ctx context.Context, h *harness) error {
				_, err := h.client.FetchJWTSVID(ctx, &workload.JWTSVIDRequest{Audience: []string{errsAudience}, SpiffeId: "not a SPIFFE ID"})
				return err
			},
			code: codes.InvalidArgument, label: wierrors.ErrInvalidRequest.MetricLabel(),
		},
		{
			name: "a SPIFFE ID the caller does not hold", rpc: workloadidentity.RPCFetchJWTSVID,
			call: func(ctx context.Context, h *harness) error {
				h.tokens.SetResult([]*jwtsvid.SVID{h.jwt.svid(h.t, errsSpiffeIDA, errsAudience)}, nil)
				_, err := h.client.FetchJWTSVID(ctx, &workload.JWTSVIDRequest{
					Audience: []string{errsAudience},
					SpiffeId: "spiffe://" + testTrustDomain + "/someone/else",
				})
				return err
			},
			code: codes.PermissionDenied, label: wierrors.ErrNoIdentity.MetricLabel(),
		},
		{
			name: "no audience", rpc: workloadidentity.RPCValidateJWTSVID,
			call: func(ctx context.Context, h *harness) error {
				_, err := h.client.ValidateJWTSVID(ctx, &workload.ValidateJWTSVIDRequest{Svid: "a.b.c"})
				return err
			},
			code: codes.InvalidArgument, label: wierrors.ErrInvalidAudience.MetricLabel(),
		},
		{
			name: "no token", rpc: workloadidentity.RPCValidateJWTSVID,
			call: func(ctx context.Context, h *harness) error {
				_, err := h.client.ValidateJWTSVID(ctx, &workload.ValidateJWTSVIDRequest{Audience: errsAudience})
				return err
			},
			code: codes.InvalidArgument, label: wierrors.ErrInvalidRequest.MetricLabel(),
		},
	} {
		t.Run(tc.rpc+"/"+tc.name, func(t *testing.T) {
			g := NewWithT(t)
			h := newHarness(t)
			before := errsRPCMetrics(g, tc.rpc)

			err := tc.call(h.ctxFor(podA), h)

			g.Expect(status.Code(err)).To(Equal(tc.code), "%v", err)
			g.Expect(errsRPCMetrics(g, tc.rpc).since(before)).To(Equal(errsCounted(workloadidentity.OutcomeFailure, tc.label)))
		})
	}
}

// TestRPCMetrics_UnaryCountsSuccessUnderItsConstant pins the rpc label of the
// unary RPCs to the constants T9's metrics use, with error none on a success.
func TestRPCMetrics_UnaryCountsSuccessUnderItsConstant(t *testing.T) {
	t.Run(workloadidentity.RPCFetchJWTSVID, func(t *testing.T) {
		g := NewWithT(t)
		h := newHarness(t, func(h *harness) {
			h.tokens.Result = []*jwtsvid.SVID{h.jwt.svid(t, errsSpiffeIDA, errsAudience)}
		})
		before := errsRPCMetrics(g, workloadidentity.RPCFetchJWTSVID)

		g.Expect(errsCallFetchJWTSVID(h.ctxFor(podA), h)).To(Succeed())

		g.Expect(errsRPCMetrics(g, workloadidentity.RPCFetchJWTSVID).since(before)).
			To(Equal(errsCounted(workloadidentity.OutcomeSuccess, wierrors.MetricLabelNone)))
	})

	t.Run(workloadidentity.RPCValidateJWTSVID, func(t *testing.T) {
		g := NewWithT(t)
		h := newHarness(t)
		before := errsRPCMetrics(g, workloadidentity.RPCValidateJWTSVID)

		g.Expect(errsCallValidateJWTSVID(h.ctxFor(podA), h)).To(Succeed())

		g.Expect(errsRPCMetrics(g, workloadidentity.RPCValidateJWTSVID).since(before)).
			To(Equal(errsCounted(workloadidentity.OutcomeSuccess, wierrors.MetricLabelNone)))
	})
}

// TestRPCMetrics_RejectedTokenIsLabelledInvalidToken pins that a token failing
// validation is a failure under its own label, invalid_token, not unknown: nothing
// unexpected happened, and a bad token is told apart from a malformed request.
func TestRPCMetrics_RejectedTokenIsLabelledInvalidToken(t *testing.T) {
	for _, tc := range []struct {
		name  string
		token func(h *harness) string
	}{
		{"signed by a key the bundle does not hold", func(h *harness) string {
			stranger := newTestJWTAuthority(h.t, testTrustDomain, jwtKeyID)
			return stranger.sign(h.t, errsSpiffeIDA, []string{errsAudience}, time.Now().Add(time.Hour))
		}},
		{"under a key ID the bundle does not name", func(h *harness) string {
			stranger := newTestJWTAuthority(h.t, testTrustDomain, "unknown-key")
			return stranger.sign(h.t, errsSpiffeIDA, []string{errsAudience}, time.Now().Add(time.Hour))
		}},
		{"for another audience", func(h *harness) string {
			return h.jwt.sign(h.t, errsSpiffeIDA, []string{"spiffe://" + testTrustDomain + "/other"}, time.Now().Add(time.Hour))
		}},
		{"expired", func(h *harness) string {
			return h.jwt.sign(h.t, errsSpiffeIDA, []string{errsAudience}, time.Now().Add(-time.Hour))
		}},
		{"not a JWT", func(*harness) string { return "not-a-jwt" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)
			h := newHarness(t)
			before := errsRPCMetrics(g, workloadidentity.RPCValidateJWTSVID)

			_, err := h.client.ValidateJWTSVID(h.ctxFor(podA), &workload.ValidateJWTSVIDRequest{Audience: errsAudience, Svid: tc.token(h)})

			g.Expect(status.Code(err)).To(Equal(codes.InvalidArgument), "%v", err)
			g.Expect(errsRPCMetrics(g, workloadidentity.RPCValidateJWTSVID).since(before)).
				To(Equal(errsCounted(workloadidentity.OutcomeFailure, wierrors.ErrInvalidToken.MetricLabel())))
		})
	}
}

// errsLiveStream is a stream that answers, with a way to change what it serves
// and a way to make its next read fail, each followed by the notification that
// wakes it.
type errsLiveStream struct {
	rpc    string
	open   func(ctx context.Context, h *harness) (func() (proto.Message, error), error)
	change func(h *harness)
	fail   func(h *harness, err error)
}

func errsLiveStreams() []errsLiveStream {
	failX509 := func(h *harness, err error) {
		h.bundles.SetX509Bundles(nil, err)
		h.subs.NotifyCertBundles(providerA)
	}
	return []errsLiveStream{
		{
			rpc:  workloadidentity.RPCFetchX509SVID,
			open: errsOpenX509SVID,
			change: func(h *harness) {
				h.certs.SetResult([]*x509svid.SVID{h.pki.issue(h.t, errsSpiffeIDA)}, nil)
				h.subs.NotifyWorkload(podA.PodUID)
			},
			fail: failX509,
		},
		{
			rpc:  workloadidentity.RPCFetchX509Bundles,
			open: errsOpenX509Bundles,
			change: func(h *harness) {
				h.bundles.SetX509Bundles(x509Set(h.pki), nil)
				h.subs.NotifyCertBundles(providerA)
			},
			fail: failX509,
		},
		{
			rpc:  workloadidentity.RPCFetchJWTBundles,
			open: errsOpenJWTBundles,
			change: func(h *harness) {
				rolled := newTestJWTAuthority(h.t, testTrustDomain, "test-key-2")
				h.bundles.SetJWTBundles(map[string][]byte{testTrustDomain: rolled.jwks(h.t)}, nil)
				h.subs.NotifyJWTBundles(providerA)
			},
			fail: func(h *harness, err error) {
				h.bundles.SetJWTBundles(nil, err)
				h.subs.NotifyJWTBundles(providerA)
			},
		},
	}
}

// TestRPCMetrics_StreamCountsOnceAtFirstResponse pins that a stream is one answer
// on the RPC metrics, a success under its RPC constant at its first response,
// however many responses follow and however it ends after that: by the client
// leaving, or by a failure the caller is told about but the metrics are not.
func TestRPCMetrics_StreamCountsOnceAtFirstResponse(t *testing.T) {
	answered := errsCounted(workloadidentity.OutcomeSuccess, wierrors.MetricLabelNone)

	for _, stream := range errsLiveStreams() {
		t.Run(stream.rpc+"/ended by the client", func(t *testing.T) {
			g := NewWithT(t)
			h := newHarness(t)
			before := errsRPCMetrics(g, stream.rpc)

			ctx, cancel := context.WithCancel(h.ctxFor(podA))
			defer cancel()
			recv, err := stream.open(ctx, h)
			g.Expect(err).ToNot(HaveOccurred())
			received := errsReceive(recv)

			errsExpectResponse(g, received)
			g.Eventually(func(g Gomega) {
				g.Expect(errsRPCMetrics(g, stream.rpc).since(before)).To(Equal(answered))
			}, errsWait).Should(Succeed())

			stream.change(h)
			errsExpectResponse(g, received)

			cancel()
			var got errsRecv
			g.Eventually(received, errsWait).Should(Receive(&got))
			g.Expect(status.Code(got.err)).To(Equal(codes.Canceled), "%v", got.err)
			// The handler releases its subscription on its way out, after the last
			// point it could count, so once the release lands the count is final.
			g.Eventually(h.subs.CancelCalls, errsWait).Should(Equal(1))
			g.Expect(errsRPCMetrics(g, stream.rpc).since(before)).To(Equal(answered))
		})

		t.Run(stream.rpc+"/ended by a failure after answering", func(t *testing.T) {
			g := NewWithT(t)
			h := newHarness(t)
			before := errsRPCMetrics(g, stream.rpc)

			ctx, cancel := context.WithCancel(h.ctxFor(podA))
			defer cancel()
			recv, err := stream.open(ctx, h)
			g.Expect(err).ToNot(HaveOccurred())
			received := errsReceive(recv)

			errsExpectResponse(g, received)
			g.Eventually(func(g Gomega) {
				g.Expect(errsRPCMetrics(g, stream.rpc).since(before)).To(Equal(answered))
			}, errsWait).Should(Succeed())

			stream.fail(h, wierrors.ErrBundleRefused)
			var got errsRecv
			g.Eventually(received, errsWait).Should(Receive(&got))
			g.Expect(status.Code(got.err)).To(Equal(handlers.StatusCode(wierrors.ErrBundleRefused)), "%v", got.err)
			g.Expect(errsRPCMetrics(g, stream.rpc).since(before)).To(Equal(answered))
		})
	}
}

// errsExpectResponse waits for the stream's next response.
func errsExpectResponse(g Gomega, received <-chan errsRecv) {
	var got errsRecv
	g.Eventually(received, errsWait).Should(Receive(&got))
	g.Expect(got.err).ToNot(HaveOccurred())
	g.Expect(got.msg).ToNot(BeNil())
}
