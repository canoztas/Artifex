package sources

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/pickaxe/dfir/internal/models"
)

// maxHashFileSize is the size threshold below which we compute a SHA-256 hash
// for a collected file. Files above this size are too large to hash quickly
// during triage.
const maxHashFileSize = 10 * 1024 * 1024 // 10 MiB

const fileTimestampLayout = "2006-01-02T15:04:05Z"

// scanDirs returns the list of directories to scan for filesystem metadata.
func scanDirs() []string {
	dirs := []string{
		`C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup`,
		`C:\Windows\Temp`,
	}

	// Per-user startup folders and temp directories.
	userProfile := os.Getenv("USERPROFILE")
	if userProfile != "" {
		dirs = append(dirs,
			filepath.Join(userProfile, `AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`),
			os.Getenv("TEMP"),
		)
	}

	// Scan top level of common user profile roots for suspicious files.
	usersDir := `C:\Users`
	entries, err := os.ReadDir(usersDir)
	if err == nil {
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			name := e.Name()
			if strings.EqualFold(name, "Public") || strings.EqualFold(name, "Default") ||
				strings.EqualFold(name, "Default User") || strings.EqualFold(name, "All Users") {
				continue
			}
			dirs = append(dirs, filepath.Join(usersDir, name))
		}
	}

	return dirs
}

// CollectFileSystemMetadata scans forensically interesting directories and
// returns metadata for the files found. Directories are only scanned one
// level deep to keep the operation fast during triage.
func CollectFileSystemMetadata() ([]models.FileMetadata, error) {
	var results []models.FileMetadata

	for _, dir := range scanDirs() {
		if dir == "" {
			continue
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			log.Printf("[filesystem] cannot read %s: %v", dir, err)
			continue
		}

		for _, entry := range entries {
			fullPath := filepath.Join(dir, entry.Name())
			info, err := entry.Info()
			if err != nil {
				log.Printf("[filesystem] stat %s: %v", fullPath, err)
				continue
			}

			meta := models.FileMetadata{
				Path:        fullPath,
				Size:        info.Size(),
				Modified:    info.ModTime().UTC().Format(fileTimestampLayout),
				IsDirectory: info.IsDir(),
			}

			// Populate Created/Accessed timestamps using platform-specific
			// data when available; fall back to ModTime.
			populateTimestamps(&meta, info)

			// Hash small regular files.
			if !info.IsDir() && info.Size() > 0 && info.Size() <= maxHashFileSize {
				if h, err := hashFile(fullPath); err == nil {
					meta.SHA256 = h
				}
			}

			results = append(results, meta)
		}
	}

	return results, nil
}

// hashFile computes the SHA-256 digest of a file.
func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
