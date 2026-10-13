# EKS Pod Identity Agent

This chart installs the `eks-pod-identity-agent`.
This agent is required for EKS pods to get granular IAM permissions with EKS Pod Identity feature.

## Prerequisites

- Kubernetes v{?} running on AWS
- Helm v3

## Update below Env to your cluster and region in values.yaml

* `EKS_CLUSTER_NAME` 
* `AWS_REGION_NAME`

## Installing the Chart

```shell
git clone https://github.com/aws/eks-pod-identity-agent.git
cd eks-pod-identity-agent/
helm install eks-pod-identity-agent --namespace kube-system ./charts/eks-pod-identity-agent --values ./charts/eks-pod-identity-agent/values.yaml
```

To uninstall:

```shell
helm uninstall eks-pod-identity-agent --namespace kube-system
```

## Configuration

The following table lists the configurable parameters for this chart and their default values.

| Parameter                 | Description                                             | Default                  |
|---------------------------|---------------------------------------------------------|--------------------------|
| `affinity`                | Map of node/pod affinities                              | (see `values.yaml`)      |
| `agent.additionalArgs`    | Additional arguments to pass to the agent-container     | (see `values.yaml`)      |
| `csiDriver.resources`     | Resources for the CSI driver sidecar                    | `{}`                     |
| `env`                     | List of environment variables.                          | (see `values.yaml`)      |
| `fullnameOverride`        | Override the fullname of the chart                      | `eks-pod-identity-agent` |
| `image.pullPolicy`        | Container pull policy                                   | `Always`                 |
| `imagePullSecrets`        | Docker registry pull secret                             | `[]`                     |
| `init.additionalArgs`     | Additional arguments to pass to the init-container      | (see `values.yaml`)      |
| `init.create`             | Specifies whether init-container should be created      | `true`                   |
| `nameOverride`            | Override the name of the chart                          | `eks-pod-identity-agent` |
| `nodeSelector`            | Node labels for pod assignment                          | `{}`                     |
| `podAnnotations`          | annotations to add to each pod                          | `{}`                     |
| `priorityClassName`       | Name of the priorityClass                               | `system-node-critical`   |
| `resources`               | Resources for the agent container                       | `{}`                     |
| `tolerations`             | Optional deployment tolerations                         | `all`                    |
| `updateStrategy`          | Optional update strategy                                | `type: RollingUpdate`    |
| `workloadIdentity.enabled`| Serve workload identity (not usable yet; see below)     | `false`                  |

Specify each parameter using the `--set key=value[,key=value]` argument to `helm install` or provide a YAML file
containing the values for the above parameters.

## Workload identity

Off by default. `workloadIdentity.enabled: true` passes `--enable-workload-identity=true` to
the agent and adds everything below: the agent's socket directory, the CSI driver sidecar, the
`CSIDriver` object, and `hostPID: true`, which attestation needs to read a caller's PID.
Isolated regions never get any of it, whatever the value says. Turn it on only with an image
built with workload identity, which ships `/eks-pod-identity-csi-driver`. Images without it
(every release through v0.2.5) reject the flag and crash-loop.

Not usable yet. With it on, the agent builds its node client from
`/var/lib/kubelet/kubeconfig`, which this chart doesn't mount, so every agent pod exits at boot
and crash-loops, taking the Pod Identity credential endpoint on that node down with it. The
node credential comes in a later change. With it off, the rendered manifest has no workload
identity piece at all.

Pass the flag through this value, not `agent.additionalArgs`. That map renders a key and its
value as two arguments, and the agent reads a bare `--enable-workload-identity` as true and
ignores a separate `false`.

### CSI driver

The chart installs a cluster-scoped `CSIDriver` named `spiffe.csi.eks.amazonaws.com`, served by
the `eks-pod-identity-agent-csi-driver` sidecar of each agent pod. It publishes the workload
identity socket into pods the EKS Pod Identity webhook has enrolled. The sidecar runs
`/eks-pod-identity-csi-driver`, a separate binary in the agent's image.

**Why the object is required.** Kubernetes 1.33's `ServiceAccountNodeAudienceRestriction` only
lets a node identity mint a ServiceAccount token for an audience the target pod already
references — through a projected volume, or through the `tokenRequests` of a CSI driver one of
its volumes names. Enrolled pods carry a CSI volume naming this driver, so this one declaration
makes the agent's `TokenRequest` permissible fleet-wide with no change to any pod spec.

It's rendered only when workload identity is on. Turning workload identity off deletes it and
removes the sidecar, so first stop enrolling pods and roll the enrolled ones: a pod whose
volume names this driver can't unmount it once the driver is gone and stays `Terminating`.

The sidecar registers only once the agent's socket answers, so enrolled pods wait in
`ContainerCreating` rather than start with an empty socket directory. After registration an
agent restart is harmless: pods mount the socket directory, not the socket.

### Sidecar mounts and privilege

The agent binds its socket in `/var/run/secrets/pods.eks.amazonaws.com/workloadidentity`, a
`hostPath` both containers mount. On each publish the sidecar bind mounts that directory onto
the pod's volume target under `/var/lib/kubelet/pods`, read-only at every hop.

`/var/lib/kubelet/pods` is mounted `mountPropagation: Bidirectional` so the kubelet sees those
binds. Kubernetes allows Bidirectional only on a privileged container, so the sidecar is
`privileged: true` — and the agent container, which every pod on the node talks to, is not.

Each kubelet directory is mounted at its host path, because the kubelet opens the registered
plugin socket and the publish targets in the host mount namespace.

Two `hostPath` details are deliberate. The socket directory and the CSI plugin directories are
`DirectoryOrCreate` since nothing else creates them on a first boot, while `/var/lib/kubelet/pods`
is a strict `Directory` — its absence means the kubelet root is elsewhere and publishing there
would write where nothing reads. And the socket directory is a `hostPath` rather than an
`emptyDir` so it outlives the agent pod; an `emptyDir` restart would invalidate every bind mount
already published into running workloads.

### Updating the object

Re-applying on a later add-on update is a no-op. `attachRequired` and `volumeLifecycleModes` are
immutable after creation, so changing those two means deleting and recreating the object.
`podInfoOnMount`, `fsGroupPolicy` and `tokenRequests` can be changed in place.
