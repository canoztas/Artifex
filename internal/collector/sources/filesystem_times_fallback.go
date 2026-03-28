//go:build !windows

package sources

import (
	"os"

	"github.com/pickaxe/dfir/internal/models"
)

// populateTimestamps keeps non-Windows builds working with a reasonable
// fallback when creation and access timestamps are not available.
func populateTimestamps(meta *models.FileMetadata, info os.FileInfo) {
	meta.Modified = info.ModTime().UTC().Format(fileTimestampLayout)
	meta.Created = meta.Modified
	meta.Accessed = meta.Modified
}
