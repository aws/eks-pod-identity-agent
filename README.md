# Amazon EKS Pod Identity agent
An agent required by the [EKS Pod Identity feature](https://aws.amazon.com/blogs/containers/amazon-eks-pod-identity-a-new-way-for-applications-on-eks-to-obtain-iam-credentials/).

## Amazon EKS Pod Identity agent
[EKS Pod Identity](https://aws.amazon.com/blogs/containers/amazon-eks-pod-identity-a-new-way-for-applications-on-eks-to-obtain-iam-credentials/) is a feature of Amazon EKS that simplifies the process for cluster administrators to configure Kubernetes applications with AWS IAM permissions. A prerequisite for using the Pod Identity feature is running the Pod Identity agent on the worker nodes. AWS recommends you install the [Pod Identity Agent as an EKS Add-on](https://docs.aws.amazon.com/eks/latest/userguide/pod-id-agent-setup.html). Alternatively, you can self manage the add-on using the open source code in this repo, bake the agent as part of the worker node AMI or use Helm to install the agent.

You can use AWS SDKs to receive temporary IAM permissions required to access various AWS services from your applications running on the EKS cluster. All AWS SDKs have a series of places (or sources) that they check in order to find valid credentials to use to make a request to an AWS service. After valid credentials are found, the search is stopped. This systematic search is called the default credential provider chain.  For more information about the Credential provider chain, refer to the [AWS SDKs and Tools Reference Guide](https://docs.aws.amazon.com/sdkref/latest/guide/standardized-credentials.html#credentialProviderChain).

EKS Pod Identity has been added to the Container credential provider, which is searched as a step in the default credential provider chain. If your workloads currently use credentials that are earlier in the chain, then those credentials will continue to be used even if you configure an EKS Pod Identity association for the same workload. This way, you can safely migrate from other types of credentials by creating the association first, before removing the old credentials.

The container credentials provider provides temporary credentials from an agent that runs on each worker node. In Amazon EKS, the agent is the EKS Pod Identity Agent and on Amazon Elastic Container Service (ECS) the agent is the amazon-ecs-agent. AWS SDKs use environment variables to locate the agent to connect to.

Visit [EKS user guide](https://docs.aws.amazon.com/eks/latest/userguide/pod-id-how-it-works.html)  to learn more about the Pod Identity feature.

## Building

* `make build`  builds the Linux binaries.
* `make dev`  runs pod identity agent locally.
* `test`, `test-verbose`, `format`,`lint` and `vet` provide ways to run the respective tests/tools and should be run before submitting a PR.
* `make docker` will build an image using `docker buildx`.
* `make push` gives an example push the image to an aws ecr.

## Installation

### Helm Install

Refer [README.md in `charts`](./charts/eks-pod-identity-agent/README.md) for Helm installation.

### Kubectl Install

Update below Env in hack/dev/ds.yaml:

* `EKS_CLUSTER_NAME`
* `AWS_REGION_NAME`

Run `kubectl apply -f hack/dev/ds.yaml`

## Dependency Management

This repository uses automated dependency management to keep dependencies secure and up-to-date.

### Automated Security Updates

- **Dependabot** runs daily scans to detect CVEs and security vulnerabilities in Go dependencies
- When a security issue is detected, Dependabot automatically creates a PR with the fix
- Go version updates are automatically synchronized across:
  - `go.mod` - Go module version
  - `.go-version` - Tooling version reference
  - `Dockerfile` - Builder image version

### How It Works

1. Dependabot scans dependencies daily against GitHub's Security Advisory Database (includes CVEs from NVD and other sources)
2. When an update is needed, Dependabot creates a PR updating `go.mod`
3. A GitHub Actions workflow automatically detects the change and updates `.go-version` and `Dockerfile` to match
4. All three files are kept in sync within the same PR

This ensures consistent Go versions across the project and rapid response to security vulnerabilities.

### Testing

See [TESTING.md](TESTING.md) for details on how the automated sync workflow was tested and validated.

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This project is licensed under the Apache-2.0 License.

