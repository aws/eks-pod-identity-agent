// Package jwt provides per-pod, per-audience-set JWT-SVID issuance, caching, and renewal.
//
// Start with [New] for setup, then [Source.JWTSVIDs] for the application request
// path. All six implementation files share one [Source]; they are not separate
// services.
//
// # Reading order
//
//  1. token_source.go: New validates configuration, creates the cache, and
//     registers renewal and pod-deletion callbacks. JWTSVIDs normalizes the
//     requested audience set. forAudiences returns a fresh cached token or shares
//     issuance with concurrent requests for the same pod and audience set.
//  2. cache.go: checkPod and beginUse check local pod presence and track active
//     work against deletion. Invalidate evicts every audience set for a pod and
//     invalidates its in-flight work. reserveAudienceSet bounds per-pod cache
//     growth. store saves an owned audience snapshot and the token's deadlines.
//  3. issuance.go: issueAndStore reserves an audience set, calls issue, and rechecks
//     pod presence before storing. issue obtains the workload session, checks
//     presence again, and calls STS with those credentials. classify translates
//     STS failures; staleSession identifies rejected credentials to invalidate.
//  4. token.go: normalizeAudiences validates, copies, sorts, and deduplicates
//     audiences. parseIssuedToken produces a go-spiffe JWT-SVID, validates its
//     identity, complete audience set, algorithm, and time claims, checks that
//     its expiry matches the STS response, and extracts iat. This parses the trusted STS
//     response; relying parties still verify the signature against a JWT bundle.
//  5. renewal.go: renewalPoint calculates renewal from the actual issued lifetime
//     and configured fraction and jitter. renewalDelay keeps the cache timer's
//     delay positive. onRefresh checks pod presence and reuses issueAndStore for
//     rate-limited background renewal.
//  6. metrics.go: defaultSVIDMetrics initializes or reuses the shared collectors.
//     observeIssuance records issuance outcome and latency, and renewal counts
//     when the operation is a renewal.
//
// # Request flow
//
//	JWTSVIDs -> normalizeAudiences -> forAudiences
//	  fresh cached token -> return
//	  cache miss or renewal due -> issueAndStore
//	    issue -> Session -> GetWebIdentityToken -> parseIssuedToken
//	    store -> renewalPoint / renewalDelay
//	    observeIssuance -> return
//
// Background renewal enters through onRefresh. Pod deletion enters through
// [Source.Invalidate]. Requests made after deletion observed in the local pod
// cache are rejected, and late STS responses cannot restore that pod's entries.
// A failed renewal for a present pod can serve its previous token until expiry.
//
// # Audience sets
//
// One STS call issues one JWT covering the complete requested audience set.
// Returned SVIDs represent workload identities, not individual audiences.
// Reordered or duplicated audiences share a cache entry and singleflight key.
// Length-prefixed keys distinguish sets without reserving a delimiter character.
// Different sets never reuse a broader token. MaxAudienceSetsPerPod counts both
// cached and pending sets, bounding caller-controlled combinations. Reservations
// cover renewals too, so expiry during issuance cannot release a slot early.
// Foreground and background issuance share the per-key singleflight, so each
// reservation has one owner.
// Each request also respects STS's limit of 1-10 audiences and 1000 characters
// per audience.
// Token parsing compares the exact audience sets because go-spiffe's audience
// validation alone accepts any requested audience match.
//
// # Renewal jitter
//
// The private draw function supplies a random value for renewal scheduling.
// Production uses math/rand/v2.Float64; tests inject fixed values to assert exact
// renewal points. The selected fraction is fraction - jitter/2 + jitter*draw().
// A 60-minute lifetime with fraction 0.5 and jitter 0.1 therefore renews across
// 27-33 minutes. This randomness is not used to generate or sign tokens.
//
// Background renewals default to 20 per second with burst size one. Due entries
// wait for a permit in the current sweep rather than being skipped. Foreground
// issuance and background attempts each default to a 10-second timeout. Cache
// refresh callbacks remain sequential.
//
// # STS dependency
//
// [Issuer] contains only the STS operation this source uses. The existing STS
// service satisfies it directly, without an adapter or a separate client. This
// keeps the source's required operations and test doubles small; it does not
// remove its dependency on STS request and response types. The shared STS client
// still owns endpoint resolution, signing, query encoding, and HTTP transport.
//
// Issuance refusals are limited to the exceptions modeled on GetWebIdentityToken.
// Throttling uses the AWS SDK's classifier, not a local list of generic aliases.
// Other STS errors remain issuance failures with their original cause preserved;
// a generic validation error is not assumed to mean the audience is invalid.
//
// # Integration
//
// Startup must construct the source with the same node-scoped PodStore used for
// attestation and pass it to the Workload API handler. Current agent startup does
// not yet construct this source; package tests do not enable production wiring.
package jwt
