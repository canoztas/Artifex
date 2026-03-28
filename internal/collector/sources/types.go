// Package sources provides individual evidence collection functions for Windows
// DFIR. Each source collects a specific category of forensic artifact using
// safe, read-only system commands.
package sources

import "os"

// CollectedFile describes a file that was copied during evidence collection.
type CollectedFile struct {
	// Path is the location of the collected copy (in the temp/evidence directory).
	Path string `json:"path"`
	// Source is the original location the file was copied from.
	Source string `json:"source"`
	// Type describes the artifact category (e.g. "evtx", "prefetch", "amcache").
	Type string `json:"type"`
}

// ReadFile reads an entire file into memory. This is used by the collector
// orchestrator to read collected temporary files before storing them in the
// evidence store.
func ReadFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}
