
ROOT_DIR_RELATIVE := ../..
include $(ROOT_DIR_RELATIVE)/common.mk

UNAME := $(shell uname -s)

# Directories.
BIN_DIR := bin

$(BIN_DIR):
	mkdir -p $@

MOCKGEN := $(BIN_DIR)/mockgen
$(MOCKGEN): $(BIN_DIR) go.mod go.sum # Build mockgen from tools folder.
	go build -tags=tools -o $@ go.uber.org/mock/mockgen


.PHONY: clean
clean: ## Remove all tools
	rm -rf bin
	rm -rf share