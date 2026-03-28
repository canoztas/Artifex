package sources

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
)

const prefetchDir = `C:\Windows\Prefetch`

// CollectPrefetch copies all .pf files from the Windows Prefetch directory to
// a temporary evidence directory and returns the list of collected files.
func CollectPrefetch() ([]CollectedFile, error) {
	tmpDir, err := os.MkdirTemp("", "pickaxe-prefetch-*")
	if err != nil {
		return nil, fmt.Errorf("create temp dir: %w", err)
	}

	matches, err := filepath.Glob(filepath.Join(prefetchDir, "*.pf"))
	if err != nil {
		return nil, fmt.Errorf("glob prefetch: %w", err)
	}
	if len(matches) == 0 {
		log.Printf("[prefetch] no .pf files found in %s", prefetchDir)
		return nil, nil
	}

	var collected []CollectedFile
	for _, src := range matches {
		dst := filepath.Join(tmpDir, filepath.Base(src))
		if err := copyFile(src, dst); err != nil {
			log.Printf("[prefetch] failed to copy %s: %v", src, err)
			continue
		}
		collected = append(collected, CollectedFile{
			Path:   dst,
			Source: src,
			Type:   "prefetch",
		})
	}

	return collected, nil
}

// copyFile copies a single file from src to dst. It creates the destination
// file with the same permissions as the source.
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
