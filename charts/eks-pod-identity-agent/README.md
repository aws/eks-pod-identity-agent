# EKS Pod Identity Agent

This chart installs the `eks-pod-identity-agent`.
This agent is required for EKS pods to get granular IAM permissions with EKS Pod Identity feature.

## Prerequisites

- Kubernetes v{?} running on AWS
- Helm v3

## Installing the Chart

First add the EKS repository to Helm:

```shell
helm repo add eks https://aws.github.io/eks-charts
```

To install the chart with the release name `eks-pod-identity-agent` and default configuration:

```shell
$ helm install eks-pod-identity-agent --namespace kube-system eks/eks-pod-identity-agent
```

To install manually, clone the repository to your local machine.
Then, use the helm install command to install the chart into your Kubernetes cluster:

```shell
$ helm install eks-pod-identity-agent --namespace kube-system ./charts/eks-pod-identity-agent
```

To uninstall:

```shell
$ helm uninstall eks-pod-identity-agent --namespace kube-system
```

## Configuration

The following table lists the configurable parameters for this chart and their default values.

| Parameter                 | Description                                             | Default                  |
|---------------------------|---------------------------------------------------------|--------------------------|
| `affinity`                | Map of node/pod affinities                              | (see `values.yaml`)      |
| `agent.additionalArgs`    | Additional arguments to pass to the agent-container     | (see `values.yaml`)      |
| `agent.command`           | Command to start the agent-container                    | (see `values.yaml`)      |
| `agent.livenessEndpoint`  | Liveness endpoint for the agent                         | `/healthz`               |
| `agent.probePort`         | Port for liveliness and readiness server                | `2703`                   |
| `agent.readinessEndpoint` | Readiness endpoint for the agent                        | `/readyz`                |
| `clusterName`             | Name of your cluster                                    | `nil`                    |
| `eksStageName`            | EKS Stage Name                                          | `nil`                    |
| `env`                     | List of environment variables.                          | (see `values.yaml`)      |
| `fullnameOverride`        | Override the fullname of the chart                      | `eks-pod-identity-agent` |
| `image.pullPolicy`        | Container pull policy                                   | `Always`                 |
| `image.containerRegistry` | Image registry to use                                   | `TBD`                    |
| `image.region`            | ECR repository region to use. Should match your cluster | `us-west-2`              |
| `image.tag`               | Image tag                                               | `TBD`                    |
| `image.override`          | A custom image to use                                   | `nil`                    |
| `imagePullSecrets`        | Docker registry pull secret                             | `[]`                     |
| `init.additionalArgs`     | Additional arguments to pass to the init-container      | (see `values.yaml`)      |
| `init.command`            | Command to start the init-container                     | (see `values.yaml`)      |
| `init.create`             | Specifies whether init-container should be created      | `true`                   |
| `nameOverride`            | Override the name of the chart                          | `eks-pod-identity-agent` |
| `nodeSelector`            | Node labels for pod assignment                          | `{}`                     |
| `podAnnotations`          | annotations to add to each pod                          | `{}`                     |
| `priorityClassName`       | Name of the priorityClass                               | `system-node-critical`   |
| `resources`               | Resources for containers in pod                         | `{}`                     |
| `tolerations`             | Optional deployment tolerations                         | `all`                    |
| `updateStrategy`          | Optional update strategy                                | `type: RollingUpdate`    |

Specify each parameter using the `--set key=value[,key=value]` argument to `helm install` or provide a YAML file
containing the values for the above parameters:

```shell
$ helm install eks-pod-identity-agent --namespace kube-system eks/eks-pod-identity-agent --values values.yaml
```

Manual install:

```shell
$ helm install eks-pod-identity-agent --namespace kube-system ./charts/eks-pod-identity-agent --values values.yaml
```

