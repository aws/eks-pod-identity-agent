package workloadidentity

// Metric and label names for the workload identity path.
//
// These are declared here, ahead of any implementation, so that every tier emits
// consistently and no tier invents a second convention. This file holds names
// only: no collectors, no registration, no init. Each tier registers its own
// collectors against the names below.
//
// The existing agent metrics are pod_identity_cache_errors,
// pod_identity_cache_state, pod_identity_local_validation and
// pod_identity_http_response. The workload identity path uses the distinct
// prefix "workload_identity_" instead. It is a separate feature namespace and is
// deliberately not folded into pod_identity_, so that dashboards and alarms for
// the AWS credentials path and the SPIFFE path can be reasoned about apart.

// Metric names. Each comment names the task that owns the collector and the
// label set it registers with.
const (
	// MetricPeerPinTotal counts connections by whether the handshake pinned
	// their peer. T2: {outcome, reason}.
	MetricPeerPinTotal = "workload_identity_peer_pin_total"
	// MetricAttestationTotal counts attestation attempts. T3: {outcome, reason}.
	MetricAttestationTotal = "workload_identity_attestation_total"
	// MetricAttestationDuration observes attestation latency. T3: {outcome}.
	MetricAttestationDuration = "workload_identity_attestation_duration_seconds"
	// MetricTokenMintTotal counts ServiceAccount token mints. T4: {outcome, error}.
	MetricTokenMintTotal = "workload_identity_token_mint_total"
	// MetricTokenMintDuration observes token mint latency. T4: {outcome}.
	MetricTokenMintDuration = "workload_identity_token_mint_duration_seconds"
	// MetricSessionTotal counts AWS session exchanges. T5: {outcome, error}.
	MetricSessionTotal = "workload_identity_session_total"
	// MetricSessionDuration observes session exchange latency. T5: {outcome}.
	MetricSessionDuration = "workload_identity_session_duration_seconds"
	// MetricSvidIssuanceTotal counts SVID issuances. T7,T8: {format, outcome, error}.
	MetricSvidIssuanceTotal = "workload_identity_svid_issuance_total"
	// MetricSvidIssuanceDuration observes SVID issuance latency. T7,T8: {format, outcome}.
	MetricSvidIssuanceDuration = "workload_identity_svid_issuance_duration_seconds"
	// MetricSvidRenewalTotal counts SVID renewals. T7,T8: {format, outcome, error}.
	MetricSvidRenewalTotal = "workload_identity_svid_renewal_total"
	// MetricBundleFetchTotal counts trust bundle fetches. T6: {outcome, error}.
	MetricBundleFetchTotal = "workload_identity_bundle_fetch_total"
	// MetricBundleFetchDuration observes trust bundle fetch latency. T6: {outcome}.
	MetricBundleFetchDuration = "workload_identity_bundle_fetch_duration_seconds"
	// MetricBundleChangeTotal counts detected trust bundle changes. T6: no labels.
	MetricBundleChangeTotal = "workload_identity_bundle_change_total"
	// MetricSubscriptionsActive gauges open stream subscriptions. T9: {rpc}.
	MetricSubscriptionsActive = "workload_identity_subscriptions_active"
	// MetricNotificationTotal counts notifications delivered to streams. T9: {rpc, delivery}.
	//
	// The second label was {outcome} when this name was declared. It is
	// {delivery} instead because neither thing that can happen to a signal is a
	// failure: it either lands in an empty channel or coalesces into one already
	// pending, and both are the tier working as specified. Labelling a coalesced
	// signal "failure" would alarm on the mechanism that keeps a slow stream from
	// being handed a superseded credential.
	MetricNotificationTotal = "workload_identity_notification_total"
	// MetricCacheTotal counts cache lookups. All tiers: {tier, result}.
	MetricCacheTotal = "workload_identity_cache_total"
	// MetricCredentialSourceTotal counts the credential source a refresh was
	// routed to, by pod enrollment. T15: {source}.
	//
	// It is the observable for the HOSM/WISE overlap: an enrolled pod must never
	// refresh through IMDS, because the DR aggregator publishes undecorated
	// credentials for it there, and consuming one is a silent correctness break
	// rather than a latency regression. Only a refresh is counted, since a sync
	// is EKS Auth for every pod by construction.
	MetricCredentialSourceTotal = "workload_identity_credential_source_total"
	// MetricRPCTotal counts served RPCs. T10,T11: {rpc, outcome, error}.
	MetricRPCTotal = "workload_identity_rpc_total"
	// MetricRPCDuration observes served RPC latency. T10,T11: {rpc, outcome}.
	MetricRPCDuration = "workload_identity_rpc_duration_seconds"
	// MetricVolumeMountTotal counts CSI publishes and unpublishes of the socket
	// directory. T12: {operation, outcome}.
	MetricVolumeMountTotal = "workload_identity_volume_mount_total"
	// MetricRegistrationTotal counts what the kubelet decided about the CSI node
	// plugin. T12: {outcome}.
	//
	// Separate from the mount metric because a refusal is terminal rather than
	// retried: no publish follows it, so every enrolled pod on the node fails.
	MetricRegistrationTotal = "workload_identity_registration_total"
)

// Label names for the metrics above.
//
// Cardinality rule: no per-pod, per-namespace, or per-service-account label is
// permitted on any of these metrics. Label only on outcome, attestation failure
// reason, the taxonomy error label, credential format, RPC name, cache tier and
// cache result. A pod UID, pod name, namespace or ServiceAccount name as a label
// value grows the series count with cluster churn and is not admissible.
//
// The values for LabelError come from pkg/errors, where errors.MetricLabel
// defines the whole set: a taxonomy member's own MetricLabel, MetricLabelNone
// for a nil error so a success is readable on a metric that carries the label,
// and MetricLabelUnknown for a failure outside the taxonomy. They are
// deliberately not duplicated here, so this package does not import pkg/errors.
const (
	// LabelOutcome carries OutcomeSuccess or OutcomeFailure.
	LabelOutcome = "outcome"
	// LabelReason carries a refusal reason, one of the Reason values, on
	// MetricPeerPinTotal and MetricAttestationTotal, which use different subsets.
	LabelReason = "reason"
	// LabelError carries whatever errors.MetricLabel in pkg/errors returns for
	// the operation's error, which is one of a taxonomy member's label,
	// MetricLabelNone or MetricLabelUnknown.
	LabelError = "error"
	// LabelFormat carries the credential format, FormatX509SVID or FormatJWTSVID.
	LabelFormat = "format"
	// LabelRPC carries the name of the RPC being served, one of the RPC values.
	LabelRPC = "rpc"
	// LabelDelivery carries how a change notification reached a subscription,
	// one of the Delivery values. It is on MetricNotificationTotal only.
	LabelDelivery = "delivery"
	// LabelTier carries the cache tier, one of the CacheTier values.
	LabelTier = "tier"
	// LabelResult carries the cache lookup result, one of the CacheResult values.
	LabelResult = "result"
	// LabelSource carries the credential source a refresh was routed to, one of
	// the CredentialSource values. It is on MetricCredentialSourceTotal only.
	LabelSource = "source"
	// LabelOperation carries which half of a paired operation ran, one of the
	// Operation values. It is on MetricVolumeMountTotal only.
	LabelOperation = "operation"
)

// Values for LabelOutcome.
const (
	// OutcomeSuccess means the operation completed.
	OutcomeSuccess = "success"
	// OutcomeFailure means the operation returned an error.
	OutcomeFailure = "failure"
)

// Values for LabelFormat, the credential format an operation produced.
const (
	// FormatX509SVID is an X.509-SVID.
	FormatX509SVID = "x509_svid"
	// FormatJWTSVID is a JWT-SVID.
	FormatJWTSVID = "jwt_svid"
)

// Values for LabelRPC, one per RPC the workload identity socket serves.
//
// These are metric label values and not wire method names: the wire names are
// mixed case, such as FetchX509SVID, and a Prometheus label value is
// lower_snake_case. Code that needs the wire name reads it off the generated
// service descriptor instead.
//
// The two WIT RPCs on the Workload API interface have no value here, because the
// agent answers them Unimplemented and never subscribes or counts for them.
const (
	// RPCFetchX509SVID is the SPIFFE Workload API FetchX509SVID stream.
	RPCFetchX509SVID = "fetch_x509_svid"
	// RPCFetchX509Bundles is the SPIFFE Workload API FetchX509Bundles stream.
	RPCFetchX509Bundles = "fetch_x509_bundles"
	// RPCFetchJWTSVID is the unary SPIFFE Workload API FetchJWTSVID.
	RPCFetchJWTSVID = "fetch_jwt_svid"
	// RPCFetchJWTBundles is the SPIFFE Workload API FetchJWTBundles stream.
	RPCFetchJWTBundles = "fetch_jwt_bundles"
	// RPCValidateJWTSVID is the unary SPIFFE Workload API ValidateJWTSVID.
	RPCValidateJWTSVID = "validate_jwt_svid"
	// RPCStreamSecrets is the Envoy SDS StreamSecrets stream.
	RPCStreamSecrets = "stream_secrets"
	// RPCFetchSecrets is the unary Envoy SDS FetchSecrets. No sidecar calls it,
	// since Envoy subscribes over the stream, so expect tooling and probes here
	// rather than mesh traffic.
	RPCFetchSecrets = "fetch_secrets"
)

// Values for LabelDelivery, how one change notification reached a subscription.
//
// There is no value for a signal nobody read. A subscription that is released
// between a publish and a read is normal, and the notification tier cannot tell
// that case from one where the read is simply still to come.
const (
	// DeliverySignalled means the signal landed in an empty channel, so the
	// subscriber had nothing pending and will wake on it.
	DeliverySignalled = "signalled"
	// DeliveryCoalesced means a signal was already pending and unread, so this
	// one replaced it rather than queueing behind it. The subscriber wakes once
	// and reads the newest state. A sustained rate here is a slow stream, not an
	// error.
	DeliveryCoalesced = "coalesced"
)

// Values for LabelTier, naming which cache a lookup hit.
const (
	// CacheTierToken is the projected ServiceAccount token cache.
	CacheTierToken = "token"
	// CacheTierSession is the AWS session cache.
	CacheTierSession = "session"
	// CacheTierX509SVID is the X.509-SVID cache.
	CacheTierX509SVID = "x509_svid"
	// CacheTierJWTSVID is the JWT-SVID cache.
	CacheTierJWTSVID = "jwt_svid"
	// CacheTierBundle is the trust bundle cache.
	CacheTierBundle = "bundle"
)

// Values for LabelResult, the outcome of a cache lookup.
const (
	// CacheResultHit means a usable entry was served from cache.
	CacheResultHit = "hit"
	// CacheResultMiss means no entry was present.
	CacheResultMiss = "miss"
	// CacheResultExpired means an entry was present but past its usable life.
	CacheResultExpired = "expired"
	// CacheResultEvicted means an entry was removed to stay within bounds.
	CacheResultEvicted = "evicted"
)

// Values for LabelOperation, naming which half of a paired operation ran.
const (
	// OperationPublish is a NodePublishVolume, mounting the socket directory
	// into a pod.
	OperationPublish = "publish"
	// OperationUnpublish is a NodeUnpublishVolume, unmounting it again.
	OperationUnpublish = "unpublish"
)

// Values for LabelSource, naming where a refresh was routed.
//
// These name the route the enrollment decision picked, not the source that
// ultimately answered. A refresh routed to the chain may still be served by EKS
// Auth when IMDS holds nothing, and which arm of the chain won is already
// counted by pod_identity_chained_retriever_result. What is not observable
// anywhere else, and what this metric exists for, is how many refreshes skipped
// IMDS because the pod is enrolled.
const (
	// CredentialSourceEKSAuth means the pod is enrolled, so the refresh went
	// straight to EKS Auth and IMDS was not read.
	CredentialSourceEKSAuth = "eks_auth"
	// CredentialSourceIMDSFirst means the pod is not enrolled, so the refresh
	// went to the [IMDS, EKS Auth] chain and kept HOSM static stability.
	CredentialSourceIMDSFirst = "imds_first"
)

// Values for LabelReason. MetricPeerPinTotal (the handshake) carries
// not_unix_socket, peercred_failed, peer_pid_zero, peer_gone and
// liveness_recheck_failed; MetricAttestationTotal (each RPC) carries peer_gone,
// liveness_recheck_failed, the cgroup and pod reasons, and peercred_failed for a
// missing Peer.
const (
	// ReasonNotUnixSocket means the connection was not a Unix socket, so the
	// handshake refused it before any handler ran.
	ReasonNotUnixSocket = "not_unix_socket"
	// ReasonPeerCredFailed means reading the kernel's record of the peer
	// (SO_PEERCRED, SO_PEERPIDFD or /proc/<pid>) failed for a reason other than
	// the peer exiting, such as an LSM or hidepid denial.
	ReasonPeerCredFailed = "peercred_failed"
	// ReasonPeerPIDZero means SO_PEERCRED reported PID 0: the peer is in another
	// PID namespace, so the agent lacks hostPID. A deployment bug, alarmed on
	// MetricPeerPinTotal; it never reaches MetricAttestationTotal.
	ReasonPeerPIDZero = "peer_pid_zero"
	// ReasonPeerGone means the peer exited before the handshake pinned it, or
	// before an RPC resolved it.
	ReasonPeerGone = "peer_gone"
	// ReasonLivenessRecheckFailed means the pin failed its recheck: at the
	// handshake (a PID reused by another owner), or after an RPC's resolution.
	ReasonLivenessRecheckFailed = "liveness_recheck_failed"
	// ReasonCgroupNoPodUID means no pod UID could be extracted from the peer's
	// cgroup path.
	ReasonCgroupNoPodUID = "cgroup_no_pod_uid"
	// ReasonCgroupReadFailed means reading the live peer's /proc/<pid>/cgroup
	// failed (permission, I/O). A dead pin is counted as peer_gone or
	// liveness_recheck_failed instead, so this points at the node or the agent.
	ReasonCgroupReadFailed = "cgroup_read_failed"
	// ReasonPodNotInStore means the resolved pod UID is absent from the agent's
	// pod store.
	ReasonPodNotInStore = "pod_not_in_store"
	// ReasonPodNodeMismatch means the resolved pod is recorded as scheduled on a
	// different node than the one the agent runs on. This is a security-relevant
	// signal: a local caller should never resolve to a pod on another node.
	ReasonPodNodeMismatch = "pod_node_mismatch"
)

// MetricNames returns every workload identity metric name, in declaration
// order. It exists so dashboards, alarm generation and tests can enumerate the
// set without reflection.
func MetricNames() []string {
	return []string{
		MetricPeerPinTotal,
		MetricAttestationTotal,
		MetricAttestationDuration,
		MetricTokenMintTotal,
		MetricTokenMintDuration,
		MetricSessionTotal,
		MetricSessionDuration,
		MetricSvidIssuanceTotal,
		MetricSvidIssuanceDuration,
		MetricSvidRenewalTotal,
		MetricBundleFetchTotal,
		MetricBundleFetchDuration,
		MetricBundleChangeTotal,
		MetricSubscriptionsActive,
		MetricNotificationTotal,
		MetricCacheTotal,
		MetricCredentialSourceTotal,
		MetricRPCTotal,
		MetricRPCDuration,
		MetricVolumeMountTotal,
		MetricRegistrationTotal,
	}
}
