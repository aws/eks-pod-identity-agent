package workloadapi

import (
	"context"
	"errors"
	"fmt"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"google.golang.org/protobuf/proto"

	wierrors "go.amzn.com/eks/eks-pod-identity-agent/pkg/errors"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity"
)

// This file translates what the tiers hold onto the Workload API's wire types.
// The wire keys trust material by the trust domain's SPIFFE ID, such as
// spiffe://example.org, and carries X.509 authorities as concatenated DER.

// buildX509SVIDResponse reads the caller's SVIDs and its provider's X.509
// authorities. Each SVID carries its own trust domain's bundle, and every other
// domain the provider names goes under federated_bundles.
func (h *Handler) buildX509SVIDResponse(ctx context.Context, caller *workloadidentity.Workload) (*workload.X509SVIDResponse, error) {
	svids, err := h.opts.Certs.X509SVIDs(ctx, caller)
	if err != nil {
		return nil, err
	}
	if len(svids) == 0 {
		return nil, wierrors.ErrNoIdentity.Wrapf(nil, "no identity issued")
	}
	own, err := h.opts.Bundles.OwnTrustDomain(ctx, caller)
	if err != nil {
		return nil, err
	}
	bundles, err := h.x509Bundles(ctx, caller)
	if err != nil {
		return nil, err
	}

	resp := &workload.X509SVIDResponse{FederatedBundles: map[string][]byte{}}
	for _, svid := range svids {
		wire, err := x509SVIDToWire(svid, bundles)
		if err != nil {
			return nil, err
		}
		resp.Svids = append(resp.Svids, wire)
	}
	for _, bundle := range bundles.Bundles() {
		if bundle.TrustDomain() != own {
			resp.FederatedBundles[bundle.TrustDomain().IDString()] = bundleDER(bundle)
		}
	}
	return resp, nil
}

// x509SVIDToWire marshals one SVID with its trust domain's bundle. The key leaves
// crypto.Signer form here, as the PKCS#8 DER the Workload API requires, and an
// error never carries it. A bundle missing the SVID's own domain is retryable, so
// the stream waits for one rather than serving an identity nothing can verify.
func x509SVIDToWire(svid *x509svid.SVID, bundles *x509bundle.Set) (*workload.X509SVID, error) {
	if svid == nil || svid.ID.IsZero() {
		return nil, errors.New("the cert tier returned an X.509-SVID with no SPIFFE ID")
	}
	bundle, ok := bundles.Get(svid.ID.TrustDomain())
	if !ok {
		return nil, wierrors.ErrBundleUnavailable.Wrapf(nil, "no X.509 authorities for the SVID's trust domain %q", svid.ID.TrustDomain().Name())
	}
	chain, key, err := svid.MarshalRaw()
	if err != nil {
		return nil, fmt.Errorf("marshalling %s: %w", svid.ID, err)
	}
	return &workload.X509SVID{
		SpiffeId:    svid.ID.String(),
		X509Svid:    chain,
		X509SvidKey: key,
		Bundle:      bundleDER(bundle),
		Hint:        svid.Hint,
	}, nil
}

// x509SVIDView is what the X.509 stream compares to dedupe: the response without
// its private keys. An identical leaf certifies an identical key, so the key adds
// nothing to the comparison, and leaving it out keeps the stream from holding a
// copy of it between sends.
func x509SVIDView(resp *workload.X509SVIDResponse) proto.Message {
	view := &workload.X509SVIDResponse{Crl: resp.GetCrl(), FederatedBundles: resp.GetFederatedBundles()}
	for _, svid := range resp.GetSvids() {
		view.Svids = append(view.Svids, &workload.X509SVID{
			SpiffeId: svid.GetSpiffeId(),
			X509Svid: svid.GetX509Svid(),
			Bundle:   svid.GetBundle(),
			Hint:     svid.GetHint(),
		})
	}
	return view
}

// buildX509BundlesResponse reads the caller's provider's X.509 authorities, every
// trust domain's as one concatenated DER bundle.
func (h *Handler) buildX509BundlesResponse(ctx context.Context, caller *workloadidentity.Workload) (*workload.X509BundlesResponse, error) {
	bundles, err := h.x509Bundles(ctx, caller)
	if err != nil {
		return nil, err
	}
	resp := &workload.X509BundlesResponse{Bundles: map[string][]byte{}}
	for _, bundle := range bundles.Bundles() {
		resp.Bundles[bundle.TrustDomain().IDString()] = bundleDER(bundle)
	}
	return resp, nil
}

// buildJWTBundlesResponse reads the caller's provider's JWT authorities, which the
// bundle tier already holds as the JWK Sets the RPC returns, keyed by trust domain
// name, as example.org, which the wire keys by SPIFFE ID.
func (h *Handler) buildJWTBundlesResponse(ctx context.Context, caller *workloadidentity.Workload) (*workload.JWTBundlesResponse, error) {
	bundles, err := h.opts.Bundles.JWTBundles(ctx, caller)
	if err != nil {
		return nil, err
	}
	resp := &workload.JWTBundlesResponse{Bundles: make(map[string][]byte, len(bundles))}
	for name, jwks := range bundles {
		td, err := spiffeid.TrustDomainFromString(name)
		if err != nil {
			return nil, fmt.Errorf("the bundle tier named an invalid trust domain %q: %w", name, err)
		}
		resp.Bundles[td.IDString()] = jwks
	}
	return resp, nil
}

// x509Bundles reads the caller's provider's X.509 authorities, reading a nil set
// as an empty one so a tier answering with neither a set nor an error cannot
// panic the stream.
func (h *Handler) x509Bundles(ctx context.Context, caller *workloadidentity.Workload) (*x509bundle.Set, error) {
	bundles, err := h.opts.Bundles.X509Bundles(ctx, caller)
	if err != nil {
		return nil, err
	}
	if bundles == nil {
		return x509bundle.NewSet(), nil
	}
	return bundles, nil
}

// bundleDER is a bundle's authorities as the one concatenated DER string the wire
// carries, which x509.ParseCertificates splits again. Bundle.Marshal is PEM.
func bundleDER(bundle *x509bundle.Bundle) []byte {
	var der []byte
	for _, authority := range bundle.X509Authorities() {
		der = append(der, authority.Raw...)
	}
	return der
}
