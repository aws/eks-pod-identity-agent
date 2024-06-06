package ratelimiter

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	. "github.com/onsi/gomega"

	_ "go.amzn.com/eks/eks-pod-identity-agent/internal/test"
	"golang.org/x/time/rate"
)

func TestRateLimitMiddleware(t *testing.T) {
	// Create a rate limiter with a limit of 2 requests per second with burst size equal to 2.
	limiter := rate.NewLimiter(2, 2)

	// Create a test HTTP server with the rate-limited handler
	handler := RateLimitMiddleware(limiter, testHandler)
	server := httptest.NewServer(handler)
	defer server.Close()

	makeRequest := func() error {
		resp, err := http.Get(server.URL)
		defer func() {
			_ = resp.Body.Close()
		}()
		if err != nil {
			t.Errorf("Request failed: %v", err)
			return err
		}

		if resp.StatusCode == http.StatusTooManyRequests {
			return fmt.Errorf("expected request to be allowed, got rate-limited (status: %d)", resp.StatusCode)
		}
		return nil
	}

	g := NewWithT(t)

	// Create three concurrent requests and send them to the server and expect only 2 of them to succeed.

	// errorCount keeps count of number of request failure
	errorCount := 0

	for i := 0; i < 3; i++ {
		err := makeRequest()
		if err != nil {
			errorCount++
		}
	}

	g.Expect(errorCount).To(Equal(1))
}

// testHandler is a mock handler for testing
func testHandler(w http.ResponseWriter, _ *http.Request) {
	// Mock response
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("Test response"))
}
