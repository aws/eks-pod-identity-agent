

ARG BUILDER=public.ecr.aws/eks-distro-build-tooling/golang:1.23.6

FROM --platform=$BUILDPLATFORM ${BUILDER} as builder
WORKDIR /workspace
COPY . .
ARG TARGETOS TARGETARCH
RUN GOOS=$TARGETOS GOARCH=$TARGETARCH make build

FROM --platform=$TARGETPLATFORM public.ecr.aws/eks-distro/kubernetes/go-runner:v0.18.0-eks-1-32-latest as go-runner
FROM --platform=$TARGETPLATFORM public.ecr.aws/eks-distro-build-tooling/eks-distro-minimal-base:latest-al23

ARG TARGETOS TARGETARCH
COPY --from=go-runner /go-runner /go-runner
COPY --from=builder /workspace/_output/${TARGETARCH}/bin/eks-pod-identity-agent /eks-pod-identity-agent
