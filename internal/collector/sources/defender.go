package sources

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
)

const (
	defenderSupportDir = `C:\ProgramData\Microsoft\Windows Defender\Support`
	defenderHistoryDir = `C:\ProgramData\Microsoft\Windows Defender\Scans\History`
)

// CollectDefenderLogs copies Windows Defender MPLog files and scan history
// to a temporary evidence directory.
func CollectDefenderLogs() ([]CollectedFile, error) {
	tmpDir, err := os.MkdirTemp("", "pickaxe-defender-*")
	if err != nil {
		return nil, fmt.Errorf("create temp dir: %w", err)
	}

	var collected []CollectedFile

	// Collect MPLog files.
	mpLogs, err := filepath.Glob(filepath.Join(defenderSupportDir, "MPLog-*.log"))
	if err != nil {
		log.Printf("[defender] glob MPLog: %v", err)
	}
	for _, src := range mpLogs {
		dst := filepath.Join(tmpDir, filepath.Base(src))
		if err := copyFile(src, dst); err != nil {
			log.Printf("[defender] failed to copy %s: %v", src, err)
			continue
		}
		collected = append(collected, CollectedFile{
			Path:   dst,
			Source: src,
			Type:   "defender_mplog",
		})
	}

	// Collect scan history directory recursively.
	historyDst := filepath.Join(tmpDir, "History")
	if err := copyDirRecursive(defenderHistoryDir, historyDst); err != nil {
		log.Printf("[defender] failed to copy history: %v", err)
	} else {
		// Walk the copied history directory and record each file.
		_ = filepath.Walk(historyDst, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}
			// Compute the original source path.
			rel, _ := filepath.Rel(historyDst, path)
			origPath := filepath.Join(defenderHistoryDir, rel)
			collected = append(collected, CollectedFile{
				Path:   path,
				Source: origPath,
				Type:   "defender_history",
			})
			return nil
		})
	}

	if len(collected) == 0 {
		log.Printf("[defender] no Defender logs found")
	}

	return collected, nil
}

// copyDirRecursive copies a directory tree from src to dst.
func copyDirRecursive(src, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // skip inaccessible entries
		}

		rel, err := filepath.Rel(src, path)
		if err != nil {
			return nil
		}
		target := filepath.Join(dst, rel)

		if info.IsDir() {
			return os.MkdirAll(target, 0o755)
		}

		if err := copyFile(path, target); err != nil {
			log.Printf("[defender] copy %s: %v", path, err)
		}
		return nil
	})
}
