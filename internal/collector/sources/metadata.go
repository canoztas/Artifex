package sources

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/artifex/dfir/internal/models"
)

// CollectHostMetadata gathers host identification information using safe,
// read-only system commands and the Go standard library.
func CollectHostMetadata() (*models.HostMetadata, error) {
	meta := &models.HostMetadata{
		Architecture: runtime.GOARCH,
	}

	// Hostname via Go stdlib.
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}
	meta.Hostname = hostname

	// OS version, build, boot time, and domain from systeminfo.
	if out, err := runCommand("systeminfo"); err == nil {
		meta.OSVersion = extractField(out, "OS Name:")
		meta.OSBuild = extractField(out, "OS Version:")
		meta.BootTime = extractField(out, "System Boot Time:")
		meta.Domain = extractField(out, "Domain:")
		meta.Timezone = extractField(out, "Time Zone:")
	}

	// Machine SID via WMIC (read-only).
	if out, err := runCommand("wmic", "useraccount", "where",
		fmt.Sprintf("name='%s'", os.Getenv("USERNAME")), "get", "sid"); err == nil {
		meta.MachineSID = parseMachineSID(out)
	}

	// Local user list via net user.
	if out, err := runCommand("net", "user"); err == nil {
		meta.Users = parseUserList(out)
	}

	return meta, nil
}

// runCommand executes a command and returns its combined output as a string.
func runCommand(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("command %s failed: %w: %s", name, err, string(out))
	}
	return string(out), nil
}

// extractField finds a line starting with the given prefix in multi-line
// output and returns the trimmed value after the colon.
func extractField(output, prefix string) string {
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, prefix) {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1])
			}
		}
	}
	return ""
}

// parseMachineSID extracts the machine SID from WMIC output.
// The machine SID is the user SID with the final RID removed.
func parseMachineSID(output string) string {
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "S-") {
			// Strip the trailing RID to get the machine SID.
			idx := strings.LastIndex(line, "-")
			if idx > 0 {
				return line[:idx]
			}
			return line
		}
	}
	return ""
}

// parseUserList turns the raw output of "net user" into a JSON array string.
func parseUserList(output string) string {
	var users []string
	inList := false
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "---") {
			inList = true
			continue
		}
		if strings.HasPrefix(line, "The command completed") {
			break
		}
		if inList && line != "" {
			for _, u := range strings.Fields(line) {
				users = append(users, u)
			}
		}
	}
	if len(users) == 0 {
		return "[]"
	}
	// Build a simple JSON array.
	quoted := make([]string, len(users))
	for i, u := range users {
		quoted[i] = fmt.Sprintf("%q", u)
	}
	return "[" + strings.Join(quoted, ",") + "]"
}
