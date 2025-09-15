ROOT_DIR_RELATIVE := .
include $(ROOT_DIR_RELATIVE)/common.mk

VERSION_FILE=version.txt

# GIT_VERSION includes the latest git tag and is unique and not semver
GIT_VERSION := $(shell git describe --tags --always)
# GIT_VERSION_SHORT is only the latest git tag, not unique, semver
GIT_VERSION_SHORT := $(shell git describe --tags --abbrev=0 --always)
GIT_COMMIT_ID := $(shell git show -s --format=%H)
GOOS?=$(shell go env GOOS)
GOARCH?=$(shell go env GOARCH)
OUTPUT := _output/$(GOARCH)
BINARY := $(OUTPUT)/bin/eks-pod-identity-agent

# Directories
TOOLS_DIR := hack/tools
TOOLS_BIN_DIR := $(TOOLS_DIR)/bin

# Binaries
MOCKGEN := $(TOOLS_BIN_DIR)/mockgen
HELM := $(TOOLS_BIN_DIR)/helm
HELM_VERSION := v3.16.1

$(TOOLS_BIN_DIR):
	mkdir -p $(TOOLS_BIN_DIR)

$(HELM): $(TOOLS_BIN_DIR)
	@echo "Installing Helm $(HELM_VERSION)"
	curl -sSL https://get.helm.sh/helm-$(HELM_VERSION)-$(GOOS)-$(GOARCH).tar.gz | tar -xzv -C $(TOOLS_BIN_DIR) --strip-components=1 $(GOOS)-$(GOARCH)/helm

# Generic make
REGISTRY_ID?=$(shell aws sts get-caller-identity | jq -r '.Account')
IMAGE_NAME?=eks/eks-pod-identity-agent
REGION?=us-west-2
IMAGE?=$(REGISTRY_ID).dkr.ecr.$(REGION).amazonaws.com/$(IMAGE_NAME)
TAG?=0.1.0


.PHONY: docker
docker:
	@echo 'Building image $(IMAGE)...'
	docker buildx build --platform=linux/amd64 --progress plain --output=type=docker -t $(IMAGE):$(TAG) .

.PHONY: push
push: docker
	eval $$(aws ecr get-login --registry-ids $(REGISTRY_ID) --no-include-email)
	docker push $(IMAGE):$(TAG)

.PHONY: build
build:
	@echo "Building eks-pod-identity-agent for $(shell go env GOOS)/$(GOARCH)"
	cp $(VERSION_FILE) configuration
	GOOS=$(GOOS) GOARCH=$(GOARCH) CGO_ENABLED=0 go build \
		-ldflags "-X 'k8s.io/component-base/version.gitVersion=$(GIT_VERSION_SHORT)' \
		-X 'k8s.io/component-base/version.gitCommit=$(GIT_COMMIT_ID)' \
		-X 'k8s.io/component-base/version/verflag.programName=eks-pod-identity-agent' " \
		-o $(BINARY) .

# Run the agent locally
.PHONY: dev
dev: export BINARY := $(BINARY)
dev: build
	./hack/run-bin.sh

.PHONY: clean
clean:
	rm -rf "$(shell pwd)/$(OUTPUT)"

.PHONY: test
test: generate-mocks
	go test -race -cover -covermode=atomic ./...

# test-verbose also prints output for tests that didn't fail
# and sets the verbosity to 5
.PHONY: test-verbose
test-verbose: generate-mocks
	go test -v -race -cover -covermode=atomic ./... -test.v

.PHONY: generate-mocks
generate-mocks: $(MOCKGEN)
	PATH="$(PATH):$(shell pwd)/hack/scripts" go generate ./...

.PHONY: format
format:
	gofmt -w ./

.PHONY: vet
vet:
	go vet -json ./...

.PHONY: lint
lint:
	if ! command -v golangci-lint 2> /dev/null; then \
		curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(shell go env GOPATH)/bin v1.52.1; \
	fi
	golangci-lint run ./...

.PHONY: helm-verify
helm-verify: $(HELM)
	$(HELM) lint charts/eks-pod-identity-agent
	hack/scripts/helmverify.sh $(HELM)
