package sources

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// DefaultEVTXChannels lists the event log channels collected by default.
var DefaultEVTXChannels = []string{
	"System",
	"Security",
	"Application",
	"Microsoft-Windows-PowerShell/Operational",
	"Microsoft-Windows-TaskScheduler/Operational",
	"Microsoft-Windows-WMI-Activity/Operational",
	"Microsoft-Windows-Windows Defender/Operational",
	"Microsoft-Windows-Sysmon/Operational",
}

// CollectEVTX exports Windows Event Log channels to .evtx files using wevtutil.
// If channels is nil the DefaultEVTXChannels list is used. hoursBack controls
// how far back to query; 0 means no time filter.
func CollectEVTX(channels []string, hoursBack int) ([]CollectedFile, error) {
	if len(channels) == 0 {
		channels = DefaultEVTXChannels
	}

	tmpDir, err := os.MkdirTemp("", "artifex-evtx-*")
	if err != nil {
		return nil, fmt.Errorf("create temp dir: %w", err)
	}

	var collected []CollectedFile

	for _, ch := range channels {
		safeName := sanitizeChannelName(ch)
		outPath := filepath.Join(tmpDir, safeName+".evtx")

		args := buildWevtutilArgs(ch, outPath, hoursBack)
		if _, err := runCommand("wevtutil", args...); err != nil {
			log.Printf("[evtx] failed to export channel %s: %v", ch, err)
			continue
		}

		// Verify the file was actually created.
		if info, err := os.Stat(outPath); err == nil && info.Size() > 0 {
			collected = append(collected, CollectedFile{
				Path:   outPath,
				Source: ch,
				Type:   "evtx",
			})
		}
	}

	return collected, nil
}

// buildWevtutilArgs constructs the wevtutil epl argument list, optionally
// applying a time-based XPath filter.
func buildWevtutilArgs(channel, outPath string, hoursBack int) []string {
	if hoursBack <= 0 {
		return []string{"epl", channel, outPath}
	}

	// Build an XPath query that filters on TimeCreated.
	ms := int64(hoursBack) * int64(time.Hour/time.Millisecond)
	query := fmt.Sprintf(
		"*[System[TimeCreated[timediff(@SystemTime) <= %d]]]", ms,
	)
	return []string{"epl", channel, outPath, "/q:" + query}
}

// sanitizeChannelName replaces characters that are illegal in file names.
func sanitizeChannelName(ch string) string {
	r := strings.NewReplacer("/", "_", " ", "_", "\\", "_")
	return r.Replace(ch)
}
