## eks-pod-identity-agent

In your code, you can use the AWS SDKs to access AWS services. You write code to create a client for an AWS service with an SDK, and by default the SDK searches in a chain of locations for AWS Identity and Access Management credentials to use. After valid credentials are found, the search is stopped. For more information about the default locations used, see the Credential provider chain in the AWS SDKs and Tools Reference Guide.

EKS Pod Identities have been added to the Container credential provider which is searched in a step in the default credential chain. If your workloads currently use credentials that are earlier in the chain of credentials, those credentials will continue to be used even if you configure an EKS Pod Identity association for the same workload. This way you can safely migrate from other types of credentials by creating the association first, before removing the old credentials.

The container credentials provider provides temporary credentials from an agent that runs on each node. In Amazon EKS, the agent is the Amazon EKS Pod Identity Agent and on Amazon Elastic Container Service the agent is the amazon-ecs-agent. The SDKs use environment variables to locate the agent to connect to.

In contrast, IAM roles for service accounts provides a web identity token that the AWS SDK must exchange with AWS Security Token Service by using AssumeRoleWithWebIdentity.

checking [EKS Pod Identity](https://docs.aws.amazon.com/eks/latest/userguide/pod-id-how-it-works.html) for more information.

## Building

* `make build`  builds the Linux binaries.
* `make dev`  runs pod identity agent locally.
* `test`, `test-verbose`, `format`,`lint` and `vet` provide ways to run the respective tests/tools and should be run before submitting a PR.
* `make docker` will build an image using `docker buildx`.
* `make push` gives an example push the image to an aws ecr.

## Installation

checking README.md in `charts` for Helm installation.

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This project is licensed under the Apache-2.0 License.

