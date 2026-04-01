package sources

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
)

const amcachePath = `C:\Windows\AppCompat\Programs\Amcache.hve`

// CollectAmCache copies the Amcache.hve hive file to a temporary directory.
// Because the file is typically locked by the system, we first attempt a
// direct copy and fall back to using a Volume Shadow Copy if that fails.
func CollectAmCache() ([]CollectedFile, error) {
	tmpDir, err := os.MkdirTemp("", "artifex-amcache-*")
	if err != nil {
		return nil, fmt.Errorf("create temp dir: %w", err)
	}

	dst := filepath.Join(tmpDir, "Amcache.hve")

	// Try a direct copy first.
	if err := copyFile(amcachePath, dst); err != nil {
		log.Printf("[amcache] direct copy failed (%v), trying shadow copy", err)

		// Fall back to Volume Shadow Copy via PowerShell.
		if err := shadowCopy(amcachePath, dst); err != nil {
			return nil, fmt.Errorf("amcache shadow copy: %w", err)
		}
	}

	// Verify the file was collected.
	info, err := os.Stat(dst)
	if err != nil || info.Size() == 0 {
		return nil, fmt.Errorf("amcache file not collected or empty")
	}

	return []CollectedFile{
		{
			Path:   dst,
			Source: amcachePath,
			Type:   "amcache",
		},
	}, nil
}

// shadowCopy uses PowerShell to create a VSS snapshot and copy a locked file.
// This requires administrator privileges.
func shadowCopy(src, dst string) error {
	// Use a PowerShell script that creates a shadow copy, copies the file,
	// and removes the shadow. This is a privileged operation.
	script := fmt.Sprintf(`
$shadow = (Get-WmiObject -List Win32_ShadowCopy).Create("C:\", "ClientAccessible")
$shadowID = $shadow.ShadowID
$shadowObj = Get-WmiObject Win32_ShadowCopy | Where-Object { $_.ID -eq $shadowID }
$device = $shadowObj.DeviceObject
$srcRel = "%s" -replace '^C:\\', ''
cmd /c mklink /d "$env:TEMP\ArtifexVSS" "$device\"
Copy-Item "$env:TEMP\ArtifexVSS\$srcRel" "%s" -Force
cmd /c rmdir "$env:TEMP\ArtifexVSS"
$shadowObj.Delete()
`, src, dst)

	_, err := runPowerShell(script)
	return err
}
