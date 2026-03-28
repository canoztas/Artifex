package sources

import (
	"encoding/csv"
	"log"
	"strconv"
	"strings"

	"github.com/pickaxe/dfir/internal/models"
)

// CollectProcesses captures a snapshot of all running processes using
// PowerShell's Get-CimInstance Win32_Process. The output includes the process
// owner obtained via the GetOwner method.
func CollectProcesses() ([]models.ProcessInfo, error) {
	// PowerShell script that emits CSV with headers.
	// GetOwner() returns Domain and User; we concatenate them.
	script := `
$procs = Get-CimInstance Win32_Process
$results = foreach ($p in $procs) {
    try { $owner = Invoke-CimMethod -InputObject $p -MethodName GetOwner -ErrorAction SilentlyContinue } catch { $owner = $null }
    $user = ''
    if ($owner -and $owner.ReturnValue -eq 0) {
        $user = "$($owner.Domain)\$($owner.User)"
    }
    [PSCustomObject]@{
        PID         = $p.ProcessId
        PPID        = $p.ParentProcessId
        Name        = $p.Name
        ImagePath   = $p.ExecutablePath
        CommandLine = $p.CommandLine
        UserContext = $user
        StartTime   = if ($p.CreationDate) { $p.CreationDate.ToString('o') } else { '' }
        SessionID   = $p.SessionId
    }
}
$results | ConvertTo-Csv -NoTypeInformation
`

	out, err := runPowerShell(script)
	if err != nil {
		return nil, err
	}

	return parseProcessCSV(out)
}

// runPowerShell executes a PowerShell script and returns the combined output.
func runPowerShell(script string) (string, error) {
	return runCommand("powershell", "-NoProfile", "-NonInteractive",
		"-ExecutionPolicy", "Bypass", "-Command", script)
}

// parseProcessCSV parses CSV-formatted process output into ProcessInfo slices.
func parseProcessCSV(data string) ([]models.ProcessInfo, error) {
	reader := csv.NewReader(strings.NewReader(data))
	reader.LazyQuotes = true
	reader.TrimLeadingSpace = true

	records, err := reader.ReadAll()
	if err != nil {
		return nil, err
	}
	if len(records) < 2 {
		return nil, nil
	}

	// Build a header index map.
	headers := make(map[string]int, len(records[0]))
	for i, h := range records[0] {
		headers[strings.TrimSpace(h)] = i
	}

	var procs []models.ProcessInfo
	for _, row := range records[1:] {
		if len(row) < len(headers) {
			continue
		}
		p := models.ProcessInfo{
			PID:         safeAtoi(getCol(row, headers, "PID")),
			PPID:        safeAtoi(getCol(row, headers, "PPID")),
			Name:        getCol(row, headers, "Name"),
			ImagePath:   getCol(row, headers, "ImagePath"),
			CommandLine: getCol(row, headers, "CommandLine"),
			UserContext: getCol(row, headers, "UserContext"),
			StartTime:   getCol(row, headers, "StartTime"),
			SessionID:   safeAtoi(getCol(row, headers, "SessionID")),
		}
		procs = append(procs, p)
	}

	return procs, nil
}

// getCol retrieves a column value by header name, returning "" if not found.
func getCol(row []string, headers map[string]int, name string) string {
	idx, ok := headers[name]
	if !ok || idx >= len(row) {
		return ""
	}
	return strings.TrimSpace(row[idx])
}

// safeAtoi converts a string to int, logging and returning 0 on failure.
func safeAtoi(s string) int {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	v, err := strconv.Atoi(s)
	if err != nil {
		log.Printf("[processes] failed to parse int %q: %v", s, err)
		return 0
	}
	return v
}
