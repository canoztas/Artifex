package sources

import (
	"log"
	"strconv"
	"strings"

	"github.com/artifex/dfir/internal/models"
)

// CollectNetworkSnapshot captures network connections, DNS cache, ARP table,
// and routing table using PowerShell and built-in Windows commands.
func CollectNetworkSnapshot() (*models.NetworkSnapshot, error) {
	snap := &models.NetworkSnapshot{}

	// TCP connections.
	if conns, err := collectTCPConnections(); err != nil {
		log.Printf("[network] TCP connections: %v", err)
	} else {
		snap.Connections = append(snap.Connections, conns...)
	}

	// UDP endpoints.
	if conns, err := collectUDPEndpoints(); err != nil {
		log.Printf("[network] UDP endpoints: %v", err)
	} else {
		snap.Connections = append(snap.Connections, conns...)
	}

	// DNS cache.
	if cache, err := collectDNSCache(); err != nil {
		log.Printf("[network] DNS cache: %v", err)
	} else {
		snap.DNSCache = cache
	}

	// ARP table.
	if arp, err := collectARPTable(); err != nil {
		log.Printf("[network] ARP table: %v", err)
	} else {
		snap.ARPTable = arp
	}

	// Routing table.
	if routes, err := collectRoutes(); err != nil {
		log.Printf("[network] routes: %v", err)
	} else {
		snap.Routes = routes
	}

	return snap, nil
}

// collectTCPConnections uses PowerShell Get-NetTCPConnection.
func collectTCPConnections() ([]models.NetworkConnection, error) {
	script := `
Get-NetTCPConnection | ForEach-Object {
    $procName = ''
    try { $procName = (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Name } catch {}
    "$($_.LocalAddress)|$($_.LocalPort)|$($_.RemoteAddress)|$($_.RemotePort)|$($_.State)|$($_.OwningProcess)|$procName"
}
`
	out, err := runPowerShell(script)
	if err != nil {
		return nil, err
	}

	var conns []models.NetworkConnection
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "|", 7)
		if len(parts) < 7 {
			continue
		}
		conns = append(conns, models.NetworkConnection{
			Protocol:    "TCP",
			LocalAddr:   parts[0],
			LocalPort:   parsePort(parts[1]),
			RemoteAddr:  parts[2],
			RemotePort:  parsePort(parts[3]),
			State:       parts[4],
			PID:         parsePort(parts[5]),
			ProcessName: parts[6],
		})
	}
	return conns, nil
}

// collectUDPEndpoints uses PowerShell Get-NetUDPEndpoint.
func collectUDPEndpoints() ([]models.NetworkConnection, error) {
	script := `
Get-NetUDPEndpoint | ForEach-Object {
    $procName = ''
    try { $procName = (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Name } catch {}
    "$($_.LocalAddress)|$($_.LocalPort)|$($_.OwningProcess)|$procName"
}
`
	out, err := runPowerShell(script)
	if err != nil {
		return nil, err
	}

	var conns []models.NetworkConnection
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "|", 4)
		if len(parts) < 4 {
			continue
		}
		conns = append(conns, models.NetworkConnection{
			Protocol:    "UDP",
			LocalAddr:   parts[0],
			LocalPort:   parsePort(parts[1]),
			State:       "LISTENING",
			PID:         parsePort(parts[2]),
			ProcessName: parts[3],
		})
	}
	return conns, nil
}

// collectDNSCache uses PowerShell Get-DnsClientCache.
func collectDNSCache() ([]models.DNSCacheEntry, error) {
	script := `
Get-DnsClientCache | ForEach-Object {
    "$($_.Entry)|$($_.Type)|$($_.TimeToLive)|$($_.Data)"
}
`
	out, err := runPowerShell(script)
	if err != nil {
		return nil, err
	}

	var entries []models.DNSCacheEntry
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "|", 4)
		if len(parts) < 4 {
			continue
		}
		ttl, _ := strconv.Atoi(strings.TrimSpace(parts[2]))
		entries = append(entries, models.DNSCacheEntry{
			Name:   parts[0],
			Type:   parts[1],
			TTL:    ttl,
			Record: parts[3],
		})
	}
	return entries, nil
}

// collectARPTable uses arp -a and parses the output.
func collectARPTable() ([]models.ARPEntry, error) {
	out, err := runCommand("arp", "-a")
	if err != nil {
		return nil, err
	}

	var entries []models.ARPEntry
	currentIface := ""
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Interface:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				currentIface = parts[1]
			}
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 3 && isIPv4(fields[0]) {
			entries = append(entries, models.ARPEntry{
				Interface:  currentIface,
				IPAddress:  fields[0],
				MACAddress: fields[1],
				Type:       fields[2],
			})
		}
	}
	return entries, nil
}

// collectRoutes uses route print and parses the IPv4 section.
func collectRoutes() ([]models.RouteEntry, error) {
	out, err := runCommand("route", "print")
	if err != nil {
		return nil, err
	}

	var routes []models.RouteEntry
	inIPv4 := false
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "IPv4 Route Table") {
			inIPv4 = true
			continue
		}
		if strings.Contains(line, "IPv6 Route Table") {
			break
		}
		if !inIPv4 {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 5 && isIPv4(fields[0]) {
			metric, _ := strconv.Atoi(fields[4])
			routes = append(routes, models.RouteEntry{
				Destination: fields[0],
				Netmask:     fields[1],
				Gateway:     fields[2],
				Interface:   fields[3],
				Metric:      metric,
			})
		}
	}
	return routes, nil
}

// parsePort converts a string to an int, returning 0 on failure.
func parsePort(s string) int {
	s = strings.TrimSpace(s)
	v, _ := strconv.Atoi(s)
	return v
}

// isIPv4 is a quick heuristic check for IPv4-like strings.
func isIPv4(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if _, err := strconv.Atoi(p); err != nil {
			return false
		}
	}
	return true
}
