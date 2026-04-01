package sources

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
)

const shimcacheRegPath = `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache`

// CollectShimCache exports the AppCompatCache (ShimCache) registry value to a
// binary file. The ShimCache stores execution metadata and is a key forensic
// artifact.
func CollectShimCache() ([]CollectedFile, error) {
	tmpDir, err := os.MkdirTemp("", "artifex-shimcache-*")
	if err != nil {
		return nil, fmt.Errorf("create temp dir: %w", err)
	}

	outPath := filepath.Join(tmpDir, "AppCompatCache.reg")

	// Export the registry key to a .reg file using reg export.
	_, err = runCommand("reg", "export", shimcacheRegPath, outPath, "/y")
	if err != nil {
		// Fall back to reg save for the SYSTEM hive section.
		log.Printf("[shimcache] reg export failed (%v), trying reg query binary dump", err)
		return collectShimCacheViaPowerShell(tmpDir)
	}

	info, err := os.Stat(outPath)
	if err != nil || info.Size() == 0 {
		return nil, fmt.Errorf("shimcache export produced empty file")
	}

	return []CollectedFile{
		{
			Path:   outPath,
			Source: shimcacheRegPath,
			Type:   "shimcache",
		},
	}, nil
}

// collectShimCacheViaPowerShell reads the AppCompatCache binary value via
// PowerShell and writes the raw bytes to a file.
func collectShimCacheViaPowerShell(tmpDir string) ([]CollectedFile, error) {
	outPath := filepath.Join(tmpDir, "AppCompatCache.bin")

	script := fmt.Sprintf(`
$key = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache'
$val = (Get-ItemProperty -Path $key -Name AppCompatCache).AppCompatCache
[System.IO.File]::WriteAllBytes('%s', $val)
`, outPath)

	_, err := runPowerShell(script)
	if err != nil {
		return nil, fmt.Errorf("shimcache powershell: %w", err)
	}

	info, err := os.Stat(outPath)
	if err != nil || info.Size() == 0 {
		return nil, fmt.Errorf("shimcache binary dump produced empty file")
	}

	return []CollectedFile{
		{
			Path:   outPath,
			Source: shimcacheRegPath,
			Type:   "shimcache",
		},
	}, nil
}
