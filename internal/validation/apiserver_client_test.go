package validation

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/version"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	_ "go.amzn.com/eks/eks-pod-identity-agent/internal/test"
)

// newTestApiserverClient creates an apiserverClient backed by the given test server.
func newTestApiserverClient(srv *httptest.Server) *apiserverClient {
	clientset, err := kubernetes.NewForConfig(&rest.Config{
		Host:            srv.URL,
		TLSClientConfig: rest.TLSClientConfig{Insecure: true},
		QPS:             apiserverQPS,
		Burst:           apiserverQPS,
	})
	if err != nil {
		panic(err)
	}
	return &apiserverClient{clientset: clientset}
}

// versionedHandler wraps a JWKS handler with a /version endpoint that returns k8s 1.34.
func versionedHandler(jwksHandler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/version" {
			json.NewEncoder(w).Encode(version.Info{Major: "1", Minor: "34"})
			return
		}
		jwksHandler(w, r)
	}
}

func TestFetchPublicKeys(t *testing.T) {
	tests := []struct {
		name     string
		handler  http.HandlerFunc
		wantKeys int
		wantErr  bool
	}{
		{
			name: "0 keys",
			handler: func(w http.ResponseWriter, r *http.Request) {
				json.NewEncoder(w).Encode(JWKSet{})
			},
			wantKeys: 0,
		},
		{
			name: "1 key",
			handler: func(w http.ResponseWriter, r *http.Request) {
				json.NewEncoder(w).Encode(JWKSet{Keys: []JWK{{Kid: "k1"}}})
			},
			wantKeys: 1,
		},
		{
			name: "2 keys",
			handler: func(w http.ResponseWriter, r *http.Request) {
				json.NewEncoder(w).Encode(JWKSet{Keys: []JWK{{Kid: "k1"}, {Kid: "k2"}}})
			},
			wantKeys: 2,
		},
		{
			name: "malformed json",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte("not json"))
			},
			wantErr: true,
		},
		{
			name: "server error",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)
			srv := httptest.NewServer(versionedHandler(tc.handler))
			defer srv.Close()

			ac := newTestApiserverClient(srv)

			jwks, err := ac.fetchPublicKeys(context.Background())
			if tc.wantErr {
				g.Expect(err).To(HaveOccurred())
			} else {
				g.Expect(err).ToNot(HaveOccurred())
				g.Expect(jwks.Keys).To(HaveLen(tc.wantKeys))
			}
		})
	}
}

func TestCheckK8sVersion(t *testing.T) {
	tests := []struct {
		name    string
		handler http.HandlerFunc
		wantErr bool
	}{
		{
			name: "1.34 passes",
			handler: func(w http.ResponseWriter, r *http.Request) {
				json.NewEncoder(w).Encode(version.Info{Major: "1", Minor: "34"})
			},
		},
		{
			name: "1.35 passes",
			handler: func(w http.ResponseWriter, r *http.Request) {
				json.NewEncoder(w).Encode(version.Info{Major: "1", Minor: "35"})
			},
		},
		{
			name: "2.0 passes",
			handler: func(w http.ResponseWriter, r *http.Request) {
				json.NewEncoder(w).Encode(version.Info{Major: "2", Minor: "0"})
			},
		},
		{
			name: "1.33 fails",
			handler: func(w http.ResponseWriter, r *http.Request) {
				json.NewEncoder(w).Encode(version.Info{Major: "1", Minor: "33"})
			},
			wantErr: true,
		},
		{
			name: "1.0 fails",
			handler: func(w http.ResponseWriter, r *http.Request) {
				json.NewEncoder(w).Encode(version.Info{Major: "1", Minor: "0"})
			},
			wantErr: true,
		},
		{
			name: "server error",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			},
			wantErr: true,
		},
		{
			name: "1.34+ minor with plus suffix",
			handler: func(w http.ResponseWriter, r *http.Request) {
				json.NewEncoder(w).Encode(version.Info{Major: "1", Minor: "34+"})
			},
		},
		{
			name: "1+.34 major with plus suffix",
			handler: func(w http.ResponseWriter, r *http.Request) {
				json.NewEncoder(w).Encode(version.Info{Major: "1+", Minor: "34"})
			},
			wantErr: true,
		},
		{
			name: "empty major and minor",
			handler: func(w http.ResponseWriter, r *http.Request) {
				json.NewEncoder(w).Encode(version.Info{Major: "", Minor: ""})
			},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)
			srv := httptest.NewServer(tc.handler)
			defer srv.Close()

			ac := newTestApiserverClient(srv)

			err := ac.checkK8sVersion(context.Background())
			if tc.wantErr {
				g.Expect(err).To(HaveOccurred())
			} else {
				g.Expect(err).ToNot(HaveOccurred())
			}
		})
	}
}
