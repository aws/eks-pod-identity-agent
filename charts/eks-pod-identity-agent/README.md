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
| `csiDriver.additionalArgs`| Additional arguments to pass to the CSI driver sidecar  | (see `values.yaml`)      |
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

Specify each parameter using the `--set key=value[,key=value]` argument to `helm install` or provide a YAML file
containing the values for the above parameters.

## Workload identity CSI driver

The chart installs a cluster-scoped `CSIDriver` named `spiffe.csi.eks.amazonaws.com`, served by
the `eks-pod-identity-agent-csi-driver` sidecar of each agent pod. It publishes the workload
identity socket into pods the EKS Pod Identity webhook has enrolled. The sidecar runs
`/eks-pod-identity-csi-driver`, a separate binary in the agent's image; its CSI node service is
upstream [spiffe-csi](https://github.com/spiffe/spiffe-csi)'s, and it registers with the kubelet
itself instead of through `node-driver-registrar`.

The sidecar registers only once the agent's socket answers. Until then, and for good with
`--enable-workload-identity=false`, enrolled pods wait in `ContainerCreating` rather than start
with an empty socket directory. After registration an agent restart is harmless: the socket
directory, not the socket, is what each pod has mounted.

There is no values knob for it. This chart is what the EKS managed add-on installs, so it is
always the owner of the object, and a customer should not need a flag to get a working agent. On
a cluster not using workload identity the object is inert: only enrolled pods mount the driver,
so an unused declaration changes no pod. It is not rendered in isolated regions, where workload
identity is not enabled.

The object must exist before the agent can mint a token. Kubernetes 1.33's
`ServiceAccountNodeAudienceRestriction` only lets a node identity mint a ServiceAccount token for
an audience the target pod already references, either through a projected `serviceAccountToken`
volume or through the `tokenRequests` of a CSI driver the pod mounts. Enrolled pods mount this
driver, so this one declaration makes the agent's `TokenRequest` permissible fleet-wide with no
change to any pod spec. As a side effect, kubelet mints a token for that audience on every
publish and passes it in the volume context; the node service ignores it and the agent mints its
own, bound to the pod.

### Sidecar mounts and privilege

The agent binds its socket in `/var/run/secrets/pods.eks.amazonaws.com/workloadidentity`, a
`hostPath` both containers mount. On each publish the sidecar bind mounts that directory onto
the pod's volume target under `/var/lib/kubelet/pods`. The sidecar mounts the socket directory
read-only, so each bind is read-only on the host too, and the kubelet also mounts the volume
read-only into the pod because the webhook sets `csi.readOnly: true`.

The sidecar mounts `/var/lib/kubelet/pods` with `mountPropagation: Bidirectional`, so the
kubelet sees the bind mounts it makes in its own mount namespace. Kubernetes allows
Bidirectional only on a privileged container, so the sidecar is `privileged: true`. The agent
container, which every pod on the node talks to, is not.

Each kubelet directory is mounted at its host path. The kubelet opens the plugin socket the
sidecar reports at registration in the host mount namespace, and the publish targets it passes
are host paths the sidecar bind mounts onto in its own; `plugins_registry` follows the same
convention.

The `hostPath` types differ on purpose. The socket directory and the two CSI plugin directories
are `DirectoryOrCreate`, since on a first boot nothing else creates them. `/var/lib/kubelet/pods`
is a strict `Directory`: the kubelet creates it on any node that runs pods, so its absence means
the kubelet root is somewhere else and publishing there would write into a directory nothing
reads.

The socket directory is a `hostPath` rather than an `emptyDir` so that it outlives the agent pod.
An `emptyDir` is tied to the pod instance, and a restart would invalidate every bind mount
already published into running workloads.

### Updating the object

Re-applying the object on a later add-on update is a no-op. `attachRequired` and
`volumeLifecycleModes` are immutable after creation, so a future version wanting different
values for those two must delete and recreate the object. `podInfoOnMount`, `fsGroupPolicy` and
`tokenRequests` can be changed in place.
