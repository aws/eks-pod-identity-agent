package ratelimiter

import (
	"net/http"

	"golang.org/x/time/rate"
)

func NewRateLimiter(requestsPerSecond rate.Limit) *rate.Limiter {
	// TODO: update it with right values after running tests
	// allow 'requestsPerSecond' per second with burst size of requestsPerSecond/2.
	return rate.NewLimiter(requestsPerSecond, int(requestsPerSecond/2))
}

// RateLimitMiddleware is a middleware function that enforces rate limiting
func RateLimitMiddleware(limiter *rate.Limiter, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Check if the request should be allowed or rate-limited
		if limiter.Allow() {
			// If allowed, call the next handler
			next(w, r)
		} else {
			// If rate-limited, return a 429 (Too Many Requests) status
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
		}
	}
}
