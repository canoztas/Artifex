package sources

import (
	"log"
	"path/filepath"
)

const prefetchDir = `C:\Windows\Prefetch`

// CollectPrefetch enumerates all .pf files from the Windows Prefetch directory
// and returns them as directly readable sources.
func CollectPrefetch() ([]CollectedFile, error) {
	matches, err := filepath.Glob(filepath.Join(prefetchDir, "*.pf"))
	if err != nil {
		return nil, err
	}
	if len(matches) == 0 {
		log.Printf("[prefetch] no .pf files found in %s", prefetchDir)
		return nil, nil
	}

	var collected []CollectedFile
	for _, src := range matches {
		collectedFile, err := CollectedFileFromPath(src, src, "prefetch")
		if err != nil {
			log.Printf("[prefetch] failed to stat %s: %v", src, err)
			continue
		}
		collected = append(collected, collectedFile)
	}

	return collected, nil
}
