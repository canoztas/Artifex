package sources

import (
	"log"
	"os"
	"path/filepath"
	"strings"
)

// CollectShortcuts enumerates .lnk files from high-signal user and system
// locations such as Recent, Desktop, and Startup folders.
func CollectShortcuts() ([]CollectedFile, error) {
	roots := shortcutRoots()
	seen := make(map[string]struct{})
	var collected []CollectedFile

	for _, root := range roots {
		if root == "" {
			continue
		}

		info, err := os.Stat(root)
		if err != nil || !info.IsDir() {
			continue
		}

		_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if info.IsDir() || !strings.EqualFold(filepath.Ext(path), ".lnk") {
				return nil
			}
			if _, ok := seen[path]; ok {
				return nil
			}

			collectedFile, err := CollectedFileFromPath(path, path, "lnk")
			if err != nil {
				log.Printf("[lnk] failed to stat %s: %v", path, err)
				return nil
			}

			seen[path] = struct{}{}
			collected = append(collected, collectedFile)
			return nil
		})
	}

	if len(collected) == 0 {
		log.Printf("[lnk] no shortcut files found in monitored locations")
	}

	return collected, nil
}

func shortcutRoots() []string {
	roots := []string{
		`C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup`,
		`C:\Users\Public\Desktop`,
	}

	usersDir := `C:\Users`
	entries, err := os.ReadDir(usersDir)
	if err != nil {
		return roots
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		name := entry.Name()
		if strings.EqualFold(name, "Default") ||
			strings.EqualFold(name, "Default User") ||
			strings.EqualFold(name, "All Users") {
			continue
		}

		profile := filepath.Join(usersDir, name)
		roots = append(roots,
			filepath.Join(profile, `AppData\Roaming\Microsoft\Windows\Recent`),
			filepath.Join(profile, `Desktop`),
			filepath.Join(profile, `AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`),
		)
	}

	return roots
}
