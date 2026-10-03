package handlers

import (
	stderrors "errors"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"

	"go.amzn.com/eks/eks-pod-identity-agent/pkg/workloadidentity"
)

// Flag names for the workload identity tunables. They are declared here, beside
// the struct the flags fill, so a validation error can name the flag an operator
// has to change and cannot drift from the name cmd registers.
const (
	FlagX509SVIDDuration    = "x509-svid-duration"
	FlagJWTSVIDDuration     = "jwt-svid-duration"
	FlagSVIDRenewalFraction = "svid-renewal-fraction"
	FlagSVIDRenewalJitter   = "svid-renewal-jitter"
	FlagSVIDKeyType         = "svid-key-type"
)

// WorkloadIdentityServerOpts carries configuration from the command line into
// the workload identity tiers, the way EksCredentialHandlerOpts does for the AWS
// credentials path. It is a parallel struct rather than a widening of that one
// because the two paths share almost no tunable: nothing on the credentials path
// has an SVID lifetime. MaxCacheSize is the exception, and it is deliberately
// the same flag on both paths rather than a second one.
//
// The socket path is deliberately absent. It is a contract with the Pod Identity
// webhook, so it is the constant configuration.WorkloadIdentitySocketPath rather
// than a field, and the wiring site passes it to the server the way an HTTP
// server is given its addr today.
type WorkloadIdentityServerOpts struct {
	// Cfg is the AWS configuration the STS and EKS Auth clients are built from.
	Cfg aws.Config
	// ClusterName is the EKS cluster the agent runs in.
	ClusterName string
	// MaxCacheSize bounds each per-pod cache, in entries. It is --max-cache-size,
	// the same value the AWS credentials cache is given, because both are sized
	// by the same thing: the number of pods that can run on this node. A node
	// budgeted for N credential entries is budgeted for N token entries.
	//
	// Zero disables caching on the credentials path. It cannot mean that here —
	// an uncached tier would mint per request — so the tiers reject it.
	MaxCacheSize int
	// X509SVIDDuration is the lifetime requested on every X.509-SVID issuance.
	// It is a ceiling and not a grant: STS issues the least of this and what its
	// own policy allows, and reports what it issued in the certificate, so the
	// renewal schedule is derived from the issued NotBefore and NotAfter rather
	// than from this value.
	X509SVIDDuration time.Duration
	// JWTSVIDDuration is the lifetime requested on every JWT-SVID issuance, with
	// the same ceiling-not-grant semantics as X509SVIDDuration. The renewal
	// schedule comes from the issued token's exp claim.
	JWTSVIDDuration time.Duration
	// SVIDRenewalFraction is the fraction of an SVID's issued lifetime at which
	// renewal starts. It is a fraction rather than a fixed offset because a
	// fixed offset breaks at the short end of the lifetime envelope: an offset
	// of one hour against a one hour credential means renewing before it is
	// usable.
	SVIDRenewalFraction float64
	// SVIDRenewalJitter spreads the renewal point, as a fraction of half the
	// issued lifetime. The renewal point is therefore drawn from
	//
	//	[fraction - jitter/2, fraction + jitter/2] of the issued lifetime
	//
	// An unjittered fraction synchronises every workload on the node onto the
	// same renewal instant, which puts every renewal on the node into one burst
	// against STS. Zero disables jitter, which is only useful in a test.
	SVIDRenewalJitter float64
	// SVIDKeyType is the kind of key pair generated for every X.509-SVID on this
	// node. It is one setting for the whole agent because the SPIFFE Workload API
	// gives a workload no way to ask for a particular kind, and SPIRE fixes it at
	// bootstrap for the same reason.
	//
	// Empty means workloadidentity.DefaultKeyType. JWT-SVIDs are unaffected: STS
	// signs those, so no key is generated here for them.
	SVIDKeyType workloadidentity.KeyType
}

// durationEnvelope is the range of requested lifetimes the issuing API accepts
// for one credential format.
//
// The agent checks a requested lifetime against its envelope once at startup
// rather than per issuance. An out-of-envelope value is rejected by STS at its
// request validation layer on every single issuance, so the agent would
// otherwise boot successfully and then fail every pod on the node with an error
// that names no flag.
type durationEnvelope struct {
	// flag names the flag the checked value came from.
	flag string
	// format names the credential format, for the error message.
	format string
	// min and max are inclusive.
	min time.Duration
	max time.Duration
	// source names where min and max come from, so the next person to touch
	// them knows what to re-read rather than adjusting a number that looks
	// wrong.
	source string
}

// validate reports whether d is inside the envelope.
func (e durationEnvelope) validate(d time.Duration) error {
	if d < e.min || d > e.max {
		return fmt.Errorf("--%s is %s: a requested %s lifetime has to be between %s and %s inclusive (%s)",
			e.flag, d, e.format, e.min, e.max, e.source)
	}
	return nil
}

// The two SVID lifetime envelopes, confirmed against the STS API model rather
// than inferred from the defaults.
//
// For X.509 the model and the architecture spec disagree at the top, and the
// envelope is the intersection, so a value that passes here is one both sources
// accept: the model caps MaxDurationSeconds at 43200 while the spec's prose says
// 24 hours.
//
// Both formats carry the same range. That is a decision recorded here rather
// than a coincidence: a JWT-SVID and an X.509-SVID are renewed by the same
// fraction-of-lifetime policy, so a narrower JWT range would put the two formats
// on different renewal cadences for no reason the agent can act on.
var (
	// x509SVIDDurationEnvelope bounds --x509-svid-duration.
	x509SVIDDurationEnvelope = durationEnvelope{
		flag:   FlagX509SVIDDuration,
		format: "X.509-SVID",
		min:    time.Hour,
		max:    12 * time.Hour,
		source: "sts:GetWorkloadIdentityCertificate MaxDurationSeconds accepts 3600 to 43200",
	}

	// jwtSVIDDurationEnvelope bounds --jwt-svid-duration.
	jwtSVIDDurationEnvelope = durationEnvelope{
		flag:   FlagJWTSVIDDuration,
		format: "JWT-SVID",
		min:    time.Hour,
		max:    12 * time.Hour,
		source: "a JWT-SVID lifetime is bounded to the same 1 to 12 hour range as an X.509-SVID",
	}
)

// X509SVIDDurationBounds reports the accepted range for --x509-svid-duration, so
// the flag's usage string can state the bound an operator has to satisfy without
// copying it out of the envelope.
func X509SVIDDurationBounds() (lower, upper time.Duration) {
	return x509SVIDDurationEnvelope.min, x509SVIDDurationEnvelope.max
}

// JWTSVIDDurationBounds reports the accepted range for --jwt-svid-duration.
func JWTSVIDDurationBounds() (lower, upper time.Duration) {
	return jwtSVIDDurationEnvelope.min, jwtSVIDDurationEnvelope.max
}

// maxSVIDRenewalJitter bounds --svid-renewal-jitter. Jitter is a fraction of
// half the issued lifetime, so half of it is the distance the renewal point
// moves. Above 0.5 that distance exceeds a quarter of the lifetime and, at the
// default fraction, can push a renewal past the point where the credential is
// closer to expiry than to issuance.
const maxSVIDRenewalJitter = 0.5

// Validate reports every problem with the configured values at once. It returns
// a joined error rather than the first failure, because an operator restarting
// the agent per rejected flag is the slowest way to learn what is wrong.
func (o WorkloadIdentityServerOpts) Validate() error {
	return stderrors.Join(
		x509SVIDDurationEnvelope.validate(o.X509SVIDDuration),
		jwtSVIDDurationEnvelope.validate(o.JWTSVIDDuration),
		validateSVIDRenewal(o.SVIDRenewalFraction, o.SVIDRenewalJitter),
		validateSVIDKeyType(o.SVIDKeyType),
	)
}

// validateSVIDKeyType accepts an empty value, which means the default, and otherwise
// checks the name against the kinds the agent can generate. Checked at startup so a
// mistyped flag stops the agent rather than failing every pod on the node.
func validateSVIDKeyType(k workloadidentity.KeyType) error {
	if k == "" {
		return nil
	}
	if err := k.Validate(); err != nil {
		return fmt.Errorf("--%s: %w", FlagSVIDKeyType, err)
	}
	return nil
}

// validateSVIDRenewal checks the renewal point stays strictly inside the issued
// lifetime, both for each value on its own and for the band the two describe
// together. The comparisons are written as negated ranges so a NaN, which
// compares false against everything, is rejected rather than accepted.
func validateSVIDRenewal(fraction, jitter float64) error {
	var errs []error

	fractionOk := fraction > 0 && fraction < 1
	if !fractionOk {
		errs = append(errs, fmt.Errorf("--%s is %v: it has to be greater than 0 and less than 1, since renewal happens after issuance and before expiry",
			FlagSVIDRenewalFraction, fraction))
	}

	jitterOk := jitter >= 0 && jitter <= maxSVIDRenewalJitter
	if !jitterOk {
		errs = append(errs, fmt.Errorf("--%s is %v: it has to be between 0 and %v inclusive, as a fraction of half the issued lifetime",
			FlagSVIDRenewalJitter, jitter, maxSVIDRenewalJitter))
	}

	// A fraction and a jitter that are each in range can still describe a band
	// reaching outside the credential's life, and the failure that produces is a
	// workload renewing before it holds a credential or after it has expired.
	if fractionOk && jitterOk {
		earliest := fraction - jitter/2
		latest := fraction + jitter/2
		if earliest <= 0 || latest >= 1 {
			errs = append(errs, fmt.Errorf("--%s of %v with --%s of %v renews between %v and %v of the issued lifetime: the whole band has to fall strictly inside it",
				FlagSVIDRenewalFraction, fraction, FlagSVIDRenewalJitter, jitter, earliest, latest))
		}
	}

	return stderrors.Join(errs...)
}
