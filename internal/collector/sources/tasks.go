package sources

import (
	"encoding/csv"
	"strings"

	"github.com/artifex/dfir/internal/models"
)

// CollectScheduledTasks captures all scheduled tasks using schtasks.exe with
// verbose CSV output.
func CollectScheduledTasks() ([]models.ScheduledTaskInfo, error) {
	out, err := runCommand("schtasks", "/query", "/fo", "CSV", "/v")
	if err != nil {
		return nil, err
	}

	return parseTaskCSV(out)
}

// parseTaskCSV parses the verbose CSV output from schtasks /query.
func parseTaskCSV(data string) ([]models.ScheduledTaskInfo, error) {
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
		// schtasks headers may have surrounding quotes already stripped by
		// the csv reader, but we still trim whitespace.
		headers[strings.TrimSpace(h)] = i
	}

	var tasks []models.ScheduledTaskInfo
	for _, row := range records[1:] {
		if len(row) < len(headers) {
			continue
		}
		t := models.ScheduledTaskInfo{
			Name:        getCol(row, headers, "TaskName"),
			Path:        getCol(row, headers, "TaskName"), // schtasks includes path in TaskName
			Triggers:    getCol(row, headers, "Schedule Type"),
			Actions:     getCol(row, headers, "Task To Run"),
			RunAsUser:   getCol(row, headers, "Run As User"),
			LastRunTime: getCol(row, headers, "Last Run Time"),
			Status:      getCol(row, headers, "Status"),
		}

		// Derive a cleaner path vs name if possible.
		if idx := strings.LastIndex(t.Name, "\\"); idx >= 0 {
			t.Path = t.Name[:idx]
			t.Name = t.Name[idx+1:]
		}

		tasks = append(tasks, t)
	}

	return tasks, nil
}
