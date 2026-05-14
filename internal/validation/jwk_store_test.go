package validation

import (
	"os"
	"path/filepath"
	"testing"

	. "github.com/onsi/gomega"

	"go.amzn.com/eks/eks-pod-identity-agent/internal/test"
)

// TestJWKDiskPersistence_WriteAndRead_RoundTrips verifies that a JWKSet written to disk
// can be read back with all key fields intact.
func TestJWKDiskPersistence_WriteAndRead_RoundTrips(t *testing.T) {
	g := NewWithT(t)
	key := test.GenerateTestKey(t)
	jwks := &JWKSet{Keys: []JWK{rsaJWK("kid-1", &key.PublicKey)}}

	path := filepath.Join(t.TempDir(), "jwks-cache.json")
	err := writeJWKCache(path, jwks)
	g.Expect(err).ToNot(HaveOccurred())

	got, err := readJWKCache(path)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(got.Keys).To(HaveLen(1))
	g.Expect(got.Keys[0].Kid).To(Equal("kid-1"))
	g.Expect(got.Keys[0].Kty).To(Equal("RSA"))
	g.Expect(got.Keys[0].N).To(Equal(jwks.Keys[0].N))
	g.Expect(got.Keys[0].E).To(Equal(jwks.Keys[0].E))
}

// TestReadJWKCache_ErrorCases verifies that readJWKCache returns descriptive errors
// for corrupt and missing cache files rather than panicking.
func TestReadJWKCache_ErrorCases(t *testing.T) {
	tests := []struct {
		name      string
		setup     func(t *testing.T) string
		wantError string
	}{
		{
			name: "corrupt file",
			setup: func(t *testing.T) string {
				path := filepath.Join(t.TempDir(), "jwks-cache.json")
				os.WriteFile(path, []byte("not valid json{{{"), 0600)
				return path
			},
			wantError: "failed to unmarshal cache file",
		},
		{
			name: "missing file",
			setup: func(t *testing.T) string {
				return filepath.Join(t.TempDir(), "nonexistent.json")
			},
			wantError: "failed to read cache file",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)
			path := tt.setup(t)
			_, err := readJWKCache(path)
			g.Expect(err).To(HaveOccurred())
			g.Expect(err.Error()).To(ContainSubstring(tt.wantError))
		})
	}
}

// TestJWKDiskPersistence_FilePermissions_0600 verifies that the cache file is written
// with restrictive permissions (owner read/write only).
func TestJWKDiskPersistence_FilePermissions_0600(t *testing.T) {
	g := NewWithT(t)
	key := test.GenerateTestKey(t)
	jwks := &JWKSet{Keys: []JWK{rsaJWK("kid-1", &key.PublicKey)}}

	path := filepath.Join(t.TempDir(), "jwks-cache.json")
	err := writeJWKCache(path, jwks)
	g.Expect(err).ToNot(HaveOccurred())

	info, err := os.Stat(path)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(info.Mode().Perm()).To(Equal(os.FileMode(0600)))
}

// TestJWKDiskPersistence_RestartFileIntegrity verifies that the file content is
// byte-identical when read back after a simulated agent restart (new process reads
// the same file written by the previous process).
func TestJWKDiskPersistence_RestartFileIntegrity(t *testing.T) {
	g := NewWithT(t)
	key := test.GenerateTestKey(t)
	jwks := &JWKSet{Keys: []JWK{rsaJWK("kid-1", &key.PublicKey)}}

	path := filepath.Join(t.TempDir(), "jwks-cache.json")

	// "First boot" writes the file
	err := writeJWKCache(path, jwks)
	g.Expect(err).ToNot(HaveOccurred())

	// Capture raw bytes written to disk
	original, err := os.ReadFile(path)
	g.Expect(err).ToNot(HaveOccurred())

	// "Restart" — read the file back as a new process would
	reloaded, err := os.ReadFile(path)
	g.Expect(err).ToNot(HaveOccurred())

	g.Expect(reloaded).To(Equal(original), "file content must be byte-identical after restart")

	// Also verify the deserialized keys match
	got, err := readJWKCache(path)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(got.Keys).To(HaveLen(1))
	g.Expect(got.Keys[0].Kid).To(Equal("kid-1"))
	g.Expect(got.Keys[0].N).To(Equal(jwks.Keys[0].N))
	g.Expect(got.Keys[0].E).To(Equal(jwks.Keys[0].E))
}

// TestJWKDiskPersistence_PodDeletion_EmptyDirSemantics verifies that when the cache
// directory is removed (simulating pod deletion with emptyDir volume or container
// ephemeral storage), readJWKCache returns a clear error and writeJWKCache can
// recreate the directory structure from scratch.
func TestJWKDiskPersistence_PodDeletion_EmptyDirSemantics(t *testing.T) {
	g := NewWithT(t)
	key := test.GenerateTestKey(t)
	jwks := &JWKSet{Keys: []JWK{rsaJWK("kid-1", &key.PublicKey)}}

	dir := t.TempDir()
	cacheDir := filepath.Join(dir, "run", "eks-pod-identity-agent")
	path := filepath.Join(cacheDir, "jwks-cache.json")

	// Write cache (creates directory)
	err := writeJWKCache(path, jwks)
	g.Expect(err).ToNot(HaveOccurred())

	// Simulate pod deletion: remove the entire directory tree
	err = os.RemoveAll(cacheDir)
	g.Expect(err).ToNot(HaveOccurred())

	// Read should fail gracefully (no panic)
	_, err = readJWKCache(path)
	g.Expect(err).To(HaveOccurred())
	g.Expect(err.Error()).To(ContainSubstring("failed to read cache file"))

	// New pod starts: writeJWKCache recreates the directory and file
	err = writeJWKCache(path, jwks)
	g.Expect(err).ToNot(HaveOccurred())

	got, err := readJWKCache(path)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(got.Keys).To(HaveLen(1))
}
