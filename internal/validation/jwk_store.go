package validation

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

const defaultJWKCachePath = "/var/lib/eks-pod-identity-agent/jwks-cache.json"

// cacheDirPerm is the permission for the cache directory (owner rwx only).
const cacheDirPerm = os.FileMode(0700)

// writeJWKCache atomically writes a JWKSet to disk using a temp file + rename
// for crash safety. The parent directory is created if it doesn't exist.
func writeJWKCache(path string, jwks *JWKSet) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, cacheDirPerm); err != nil {
		return fmt.Errorf("failed to create cache directory: %w", err)
	}

	data, err := json.Marshal(jwks)
	if err != nil {
		return fmt.Errorf("failed to marshal JWKSet: %w", err)
	}

	// Create temp file in the same directory
	f, err := os.CreateTemp(dir, ".jwks-cache-*.tmp")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	defer f.Close() // safety net in case a panic skips the explicit closes below
	tmp := f.Name()

	// Write data to temp file; close + remove on failure to avoid fd/file leaks.
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("failed to write temp file: %w", err)
	}

	// Close before rename so data is fully flushed to disk.
	f.Close()

	// Atomic rename — readers see old or new file, never partial data.
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("failed to rename temp file: %w", err)
	}
	return nil
}

// readJWKCache reads and unmarshals a JWKSet from disk.
func readJWKCache(path string) (*JWKSet, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read cache file: %w", err)
	}

	var jwks JWKSet
	if err := json.Unmarshal(data, &jwks); err != nil {
		return nil, fmt.Errorf("failed to unmarshal cache file: %w", err)
	}
	return &jwks, nil
}
