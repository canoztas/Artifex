package sources

import (
	"fmt"
	"log"
	"regexp"
	"strings"

	"github.com/artifex/dfir/internal/models"
)

// persistenceKeys lists the registry paths commonly used by persistence
// mechanisms. These are safe to read and are standard DFIR targets.
var persistenceKeys = []string{
	`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,
	`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`,
	`HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,
	`HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`,
	`HKLM\SYSTEM\CurrentControlSet\Services`,
	`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`,
	`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`,
	`HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`,
	`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run`,
	`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32`,
	`HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run`,
}

// CollectPersistenceKeys reads all allowlisted persistence registry keys and
// returns their values. Errors on individual keys are logged but do not cause
// the function to fail.
func CollectPersistenceKeys() ([]models.RegistryKeyValue, error) {
	var all []models.RegistryKeyValue
	for _, key := range persistenceKeys {
		vals, err := ReadRegistryKey(key)
		if err != nil {
			log.Printf("[registry] skipping %s: %v", key, err)
			continue
		}
		all = append(all, vals...)
	}
	return all, nil
}

// ReadRegistryKey reads all values under the given registry path using
// "reg query". The path should be in the form HKLM\... or HKCU\...
func ReadRegistryKey(path string) ([]models.RegistryKeyValue, error) {
	out, err := runCommand("reg", "query", path)
	if err != nil {
		return nil, fmt.Errorf("reg query %s: %w", path, err)
	}

	return parseRegOutput(path, out), nil
}

// SearchRegistry recursively searches for registry values matching a pattern
// under rootPath using "reg query /s /f".
func SearchRegistry(rootPath, pattern string) ([]models.RegistryKeyValue, error) {
	out, err := runCommand("reg", "query", rootPath, "/s", "/f", pattern)
	if err != nil {
		return nil, fmt.Errorf("reg query search %s: %w", rootPath, err)
	}

	return parseRegSearchOutput(out), nil
}

// regValuePattern matches lines like:
//
//	ValueName    REG_SZ    ValueData
var regValuePattern = regexp.MustCompile(
	`^\s{4}(\S+)\s+(REG_\w+)\s+(.*)$`,
)

// parseRegOutput parses "reg query" output into RegistryKeyValue slices.
func parseRegOutput(basePath string, output string) []models.RegistryKeyValue {
	var results []models.RegistryKeyValue
	currentKey := basePath

	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimRight(line, "\r")

		// A line starting with HKLM or HKCU is a key path header.
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "HKLM\\") || strings.HasPrefix(trimmed, "HKCU\\") ||
			strings.HasPrefix(trimmed, "HKU\\") || strings.HasPrefix(trimmed, "HKCR\\") {
			currentKey = trimmed
			continue
		}

		if m := regValuePattern.FindStringSubmatch(line); m != nil {
			results = append(results, models.RegistryKeyValue{
				Path: currentKey,
				Name: m[1],
				Type: m[2],
				Data: strings.TrimSpace(m[3]),
			})
		}
	}
	return results
}

// parseRegSearchOutput parses output from "reg query /s /f" into results.
func parseRegSearchOutput(output string) []models.RegistryKeyValue {
	var results []models.RegistryKeyValue
	currentKey := ""

	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimRight(line, "\r")
		trimmed := strings.TrimSpace(line)

		if strings.HasPrefix(trimmed, "HKLM\\") || strings.HasPrefix(trimmed, "HKCU\\") ||
			strings.HasPrefix(trimmed, "HKU\\") || strings.HasPrefix(trimmed, "HKCR\\") {
			currentKey = trimmed
			continue
		}

		if m := regValuePattern.FindStringSubmatch(line); m != nil {
			results = append(results, models.RegistryKeyValue{
				Path: currentKey,
				Name: m[1],
				Type: m[2],
				Data: strings.TrimSpace(m[3]),
			})
		}
	}
	return results
}
