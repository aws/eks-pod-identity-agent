#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

set -x

if [[ -z "${BINARY}" ]]; then
    echo "BINARY must be set"
    exit 1
fi

# TODO: setup proper args
${BINARY} \
    server -c test -p 14215
