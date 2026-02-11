# Testing Documentation: Automated Go Version Sync

## Overview
This document describes the testing performed to validate the automated Go version synchronization workflow.

## What Was Tested

### 1. Workflow YAML Syntax
**Test**: Validated YAML syntax using Python's YAML parser
```bash
python3 -c "import yaml; yaml.safe_load(open('.github/workflows/sync-go-version.yml'))"
```
**Result**: ✓ Valid YAML syntax

### 2. Go Version Extraction from go.mod
**Test**: Verified the script correctly extracts the Go version
```bash
grep '^go ' go.mod | awk '{print $2}'
```
**Result**: Successfully extracted `1.25.6`

### 3. .go-version File Update
**Test**: Simulated writing extracted version to .go-version
```bash
GO_VERSION=$(grep '^go ' go.mod | awk '{print $2}')
echo "$GO_VERSION" > /tmp/test-go-version
```
**Result**: ✓ File correctly written with version `1.25.6`

### 4. Dockerfile Update
**Test**: Verified sed command correctly updates Dockerfile
```bash
sed -i "s/golang:[0-9.]\+/golang:1.26.0/" Dockerfile
```
**Result**: ✓ Successfully updated from `golang:1.25.6` to `golang:1.26.0`

### 5. End-to-End Workflow Simulation
**Test**: Simulated complete workflow with version change
```bash
GO_VERSION="1.26.0"
echo "$GO_VERSION" > .go-version
sed -i "s/golang:[0-9.]\+/golang:$GO_VERSION/" Dockerfile
```
**Result**: ✓ Both files synchronized to `1.26.0`

## Workflow Behavior

### Trigger Conditions
- Runs on: Pull requests that modify `go.mod`
- Only executes if: PR author is `dependabot[bot]`

### Actions Performed
1. Checks out the PR branch
2. Extracts Go version from `go.mod`
3. Updates `.go-version` with extracted version
4. Updates `Dockerfile` golang base image version
5. Commits and pushes changes to the same PR

## Manual Testing Steps

To manually test this workflow:

1. Create a test branch:
   ```bash
   git checkout -b test/go-version-sync
   ```

2. Modify go.mod to simulate a version bump:
   ```bash
   sed -i 's/^go .*/go 1.26.0/' go.mod
   ```

3. Run the sync commands locally:
   ```bash
   GO_VERSION=$(grep '^go ' go.mod | awk '{print $2}')
   echo "$GO_VERSION" > .go-version
   sed -i "s/golang:[0-9.]\+/golang:$GO_VERSION/" Dockerfile
   ```

4. Verify all three files match:
   ```bash
   echo "go.mod: $(grep '^go ' go.mod | awk '{print $2}')"
   echo ".go-version: $(cat .go-version)"
   echo "Dockerfile: $(grep 'ARG BUILDER' Dockerfile | sed 's/.*golang:\([0-9.]*\).*/\1/')"
   ```

## Expected Behavior in Production

When Dependabot creates a PR updating Go dependencies:
1. Dependabot updates `go.mod` with new Go version
2. GitHub Actions workflow triggers automatically
3. Workflow updates `.go-version` and `Dockerfile`
4. Changes are committed to the Dependabot PR
5. PR now contains all three files synchronized

## Limitations

- Workflow only runs on Dependabot PRs (by design)
- Requires `contents: write` permission
- Uses `GITHUB_TOKEN` which has limited scope in forked PRs
