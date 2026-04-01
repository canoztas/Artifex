package sources

import (
	"log"
	"os"
	"path/filepath"
)

const (
	defenderSupportDir = `C:\ProgramData\Microsoft\Windows Defender\Support`
	defenderHistoryDir = `C:\ProgramData\Microsoft\Windows Defender\Scans\History`
)

// CollectDefenderLogs enumerates Windows Defender MPLog files and scan history
// directly from disk.
func CollectDefenderLogs() ([]CollectedFile, error) {
	var collected []CollectedFile

	// Collect MPLog files.
	mpLogs, err := filepath.Glob(filepath.Join(defenderSupportDir, "MPLog-*.log"))
	if err != nil {
		log.Printf("[defender] glob MPLog: %v", err)
	}
	for _, src := range mpLogs {
		collectedFile, err := CollectedFileFromPath(src, src, "defender_mplog")
		if err != nil {
			log.Printf("[defender] failed to stat %s: %v", src, err)
			continue
		}
		collected = append(collected, collectedFile)
	}

	// Collect scan history directory recursively.
	_ = filepath.Walk(defenderHistoryDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info == nil || info.IsDir() {
			return nil
		}

		collectedFile, statErr := CollectedFileFromPath(path, path, "defender_history")
		if statErr != nil {
			log.Printf("[defender] failed to stat %s: %v", path, statErr)
			return nil
		}

		collected = append(collected, collectedFile)
		return nil
	})

	if len(collected) == 0 {
		log.Printf("[defender] no Defender logs found")
	}

	return collected, nil
}
