package test

import "go.amzn.com/eks/eks-pod-identity-agent/internal/middleware/logger"

// This package should be included whenever you write a test. It will initialize the
// logger and configure it for your test.
func init() {
	logger.Initialize("trace")
}
