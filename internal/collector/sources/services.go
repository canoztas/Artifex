package sources

import (
	"encoding/csv"
	"strings"

	"github.com/pickaxe/dfir/internal/models"
)

// CollectServices captures a snapshot of all Windows services using
// PowerShell's Get-CimInstance Win32_Service.
func CollectServices() ([]models.ServiceInfo, error) {
	script := `
Get-CimInstance Win32_Service | Select-Object Name, DisplayName, PathName, StartMode, State, StartName |
    ConvertTo-Csv -NoTypeInformation
`
	out, err := runPowerShell(script)
	if err != nil {
		return nil, err
	}

	return parseServiceCSV(out)
}

// parseServiceCSV parses CSV service output into ServiceInfo slices.
func parseServiceCSV(data string) ([]models.ServiceInfo, error) {
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

	headers := make(map[string]int, len(records[0]))
	for i, h := range records[0] {
		headers[strings.TrimSpace(h)] = i
	}

	var services []models.ServiceInfo
	for _, row := range records[1:] {
		if len(row) < len(headers) {
			continue
		}
		s := models.ServiceInfo{
			Name:           getCol(row, headers, "Name"),
			DisplayName:    getCol(row, headers, "DisplayName"),
			BinaryPath:     getCol(row, headers, "PathName"),
			StartupType:    getCol(row, headers, "StartMode"),
			CurrentState:   getCol(row, headers, "State"),
			ServiceAccount: getCol(row, headers, "StartName"),
		}
		services = append(services, s)
	}

	return services, nil
}
