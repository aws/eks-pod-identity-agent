
# Use GOPROXY environment variable if set
GOPROXY := $(shell go env GOPROXY)
ifeq ($(GOPROXY),)
# We could use proxy.go but we have to rely on a direct connection
# due to internal Amazon limitations (eg running it within the corp net
# sends requests to the sinkhole so running go build would fail)
GOPROXY := direct
endif
export GOPROXY

TOOLS_DIR := $(ROOT_DIR_RELATIVE)/hack/tools
TOOLS_DIR_DEPS := $(TOOLS_DIR)/go.sum $(TOOLS_DIR)/go.mod $(TOOLS_DIR)/Makefile
TOOLS_BIN_DIR := $(TOOLS_DIR)/bin


$(TOOLS_BIN_DIR)/%: $(TOOLS_DIR_DEPS)
	make -C $(TOOLS_DIR) $(subst $(TOOLS_DIR)/,,$@)


help:  ## Display this help
ifeq ($(OS),Windows_NT)
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make <target>\n"} /^[a-zA-Z_-]+:.*?##/ { printf "  %-40s %s\n", $$1, $$2 } /^##@/ { printf "\n%s\n", substr($$0, 5) } ' $(MAKEFILE_LIST)
else
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-40s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)
endif