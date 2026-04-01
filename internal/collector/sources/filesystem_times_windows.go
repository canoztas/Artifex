//go:build windows

package sources

import (
	"os"
	"syscall"
	"time"

	"github.com/artifex/dfir/internal/models"
)

// populateTimestamps fills in Created and Accessed fields using the native
// Win32 file metadata already attached to os.FileInfo.
func populateTimestamps(meta *models.FileMetadata, info os.FileInfo) {
	meta.Modified = info.ModTime().UTC().Format(fileTimestampLayout)

	data, ok := info.Sys().(*syscall.Win32FileAttributeData)
	if !ok || data == nil {
		meta.Created = meta.Modified
		meta.Accessed = meta.Modified
		return
	}

	meta.Created = formatFiletime(data.CreationTime, meta.Modified)
	meta.Accessed = formatFiletime(data.LastAccessTime, meta.Modified)
}

func formatFiletime(ft syscall.Filetime, fallback string) string {
	ns := ft.Nanoseconds()
	if ns <= 0 {
		return fallback
	}
	return time.Unix(0, ns).UTC().Format(fileTimestampLayout)
}
