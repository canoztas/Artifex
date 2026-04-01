package sources

import (
	"log"
	"os"
	"path/filepath"
	"strings"
)

// CollectJumpLists enumerates Windows Jump List containers from per-user
// Recent folders. Both automatic and custom destinations are collected.
func CollectJumpLists() ([]CollectedFile, error) {
	var collected []CollectedFile
	seen := make(map[string]struct{})

	for _, root := range jumpListRoots() {
		info, err := os.Stat(root)
		if err != nil || !info.IsDir() {
			continue
		}

		_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}

			ext := strings.ToLower(filepath.Ext(path))
			if ext != ".automaticdestinations-ms" && ext != ".customdestinations-ms" {
				return nil
			}
			if _, ok := seen[path]; ok {
				return nil
			}

			kind := "jumplist_custom"
			if ext == ".automaticdestinations-ms" {
				kind = "jumplist_automatic"
			}
			collectedFile, err := CollectedFileFromPath(path, path, kind)
			if err != nil {
				log.Printf("[jumplist] failed to stat %s: %v", path, err)
				return nil
			}

			seen[path] = struct{}{}
			collected = append(collected, collectedFile)
			return nil
		})
	}

	if len(collected) == 0 {
		log.Printf("[jumplist] no Jump List files found")
	}

	return collected, nil
}

func jumpListRoots() []string {
	var roots []string

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
			filepath.Join(profile, `AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations`),
			filepath.Join(profile, `AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations`),
		)
	}

	return roots
}
