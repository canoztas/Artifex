// Package sources provides individual evidence collection functions for Windows
// DFIR. Each source collects a specific category of forensic artifact using
// safe, read-only system commands.
package sources

import (
	"io"
	"os"
	"time"
)

// SourceState captures lightweight file metadata for file-backed artifacts so
// repeated runs can skip unchanged sources before reading them again.
type SourceState struct {
	Size    int64     `json:"size"`
	ModTime time.Time `json:"mod_time"`
}

// CollectedFile describes a file-backed artifact discovered during evidence
// collection.
type CollectedFile struct {
	// Path is the readable path for the artifact bytes. This may be the original
	// source path or a temporary export path for generated artifacts.
	Path string `json:"path"`
	// Source is the logical original location of the artifact.
	Source string `json:"source"`
	// Type describes the artifact category (e.g. "evtx", "prefetch", "amcache").
	Type string `json:"type"`
	// State carries original file metadata when the source is a stable on-disk
	// file that can be skipped on subsequent runs if unchanged.
	State *SourceState `json:"state,omitempty"`
}

// CollectedFileFromPath creates a CollectedFile backed directly by an existing
// on-disk file and records its size and modtime for cache-friendly re-collection.
func CollectedFileFromPath(path, source, artifactType string) (CollectedFile, error) {
	info, err := os.Stat(path)
	if err != nil {
		return CollectedFile{}, err
	}
	return CollectedFile{
		Path:   path,
		Source: source,
		Type:   artifactType,
		State: &SourceState{
			Size:    info.Size(),
			ModTime: info.ModTime().UTC(),
		},
	}, nil
}

// ReadFile reads an artifact file into memory before storing it in the evidence
// store.
func ReadFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}

// copyFile copies a file from src to dst. It remains available for sources
// that need a temporary or shadow-copied export, such as locked registry hives.
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Close()
}
