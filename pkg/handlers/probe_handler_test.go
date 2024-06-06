package handlers

import (
	"bytes"
	"net"
	"net/http"
	"testing"
	"time"

	. "github.com/onsi/gomega"
)

type fakeResponseWriter struct {
	bytes.Buffer
	responseCode int
	header       http.Header
}

func (f *fakeResponseWriter) Header() http.Header {
	return f.header
}

func (f *fakeResponseWriter) WriteHeader(statusCode int) {
	f.responseCode = statusCode
}

var _ http.ResponseWriter = &fakeResponseWriter{}

func TestProbeHandler_HandleProbe(t *testing.T) {
	createServer := func(g Gomega, handlerFn func(http.ResponseWriter)) (string, func() error) {
		// create listener
		ln, err := net.Listen("tcp", "127.0.0.1:")
		g.Expect(err).ToNot(HaveOccurred())

		mux := http.NewServeMux()
		mux.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
			handlerFn(writer)
		})

		server := &http.Server{
			Handler: mux,
		}
		// start server
		go func() {
			err := server.Serve(ln)
			g.Expect(err).To(MatchError(http.ErrServerClosed))
		}()
		return ln.Addr().String(), server.Close
	}

	createServers := func(g Gomega, nSuccess int, nErr int, fnErr func(http.ResponseWriter)) ([]string, func()) {
		nTotal := nSuccess + nErr
		addrs := make([]string, nTotal)
		closeFns := make([]func() error, nTotal)
		for i := 0; i < nSuccess; i++ {
			addrs[i], closeFns[i] = createServer(g, func(w http.ResponseWriter) {
				w.WriteHeader(http.StatusNotFound)
			})
		}
		for i := nSuccess; i < nTotal; i++ {
			addrs[i], closeFns[i] = createServer(g, fnErr)
		}
		return addrs, func() {
			for i := 0; i < nTotal; i++ {
				_ = closeFns[i]()
			}
		}
	}
	const probeTimeout = 1 * time.Second
	testCases := []struct {
		name                 string
		expectedResponseCode int
		expectedResponse     string
		numberOfEndpoints    int
		startServers         func(g Gomega) ([]string, func())
	}{
		{
			name:                 "returns success on a single endpoint",
			expectedResponseCode: 200,
			startServers: func(g Gomega) ([]string, func()) {
				return createServers(g, 1, 0, nil)
			},
		},
		{
			name:                 "returns success on two endpoints",
			expectedResponseCode: 200,
			startServers: func(g Gomega) ([]string, func()) {
				return createServers(g, 2, 0, nil)
			},
		},
		{
			name:                 "returns failure if either endpoint fails the health check",
			expectedResponseCode: 500,
			startServers: func(g Gomega) ([]string, func()) {
				return createServers(g, 1, 1, func(w http.ResponseWriter) {
					w.WriteHeader(500)
				})
			},
		},
		{
			name:                 "returns error on timeout",
			expectedResponseCode: 408,
			startServers: func(g Gomega) ([]string, func()) {
				return createServers(g, 0, 1, func(writer http.ResponseWriter) {
					time.Sleep(probeTimeout + 1*time.Second)
				})
			},
		},
		{
			name:                 "deadline is shared across probes",
			expectedResponseCode: 408,
			startServers: func(g Gomega) ([]string, func()) {
				return createServers(g, 0, 2, func(writer http.ResponseWriter) {
					time.Sleep(probeTimeout/2 + 100*time.Millisecond)
					writer.WriteHeader(http.StatusNotFound)
				})
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)
			addrs, closeFn := tc.startServers(g)
			defer closeFn()

			// setup
			handler := &probeHandler{
				addrs:        addrs,
				probeTimeout: probeTimeout,
			}

			// trigger
			resp := &fakeResponseWriter{}
			handler.HandleProbe(resp, &http.Request{})

			// validate
			g.Expect(string(resp.Bytes())).To(ContainSubstring(tc.expectedResponse))
			g.Expect(resp.responseCode).To(Equal(tc.expectedResponseCode))
		})
	}
}
