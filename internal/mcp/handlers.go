package mcp

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/pickaxe/dfir/internal/models"
)

// executeTool dispatches a named tool call to its handler. Every handler
// validates required parameters, enforces pagination limits, logs the call to
// the audit trail, and returns results as a ToolResult.
func (s *MCPServer) executeTool(ctx context.Context, name string, args map[string]interface{}) ToolResult {
	switch name {
	case "start_collection":
		return s.handleStartCollection(ctx, args)
	case "get_collection_status":
		return s.handleGetCollectionStatus(ctx, args)
	case "list_artifacts":
		return s.handleListArtifacts(ctx, args)
	case "read_artifact":
		return s.handleReadArtifact(ctx, args)
	case "list_event_sources":
		return s.handleListEventSources(ctx, args)
	case "search_events":
		return s.handleSearchEvents(ctx, args)
	case "get_event":
		return s.handleGetEvent(ctx, args)
	case "get_timeline":
		return s.handleGetTimeline(ctx, args)
	case "read_registry_keys":
		return s.handleReadRegistryKeys(ctx, args)
	case "search_registry":
		return s.handleSearchRegistry(ctx, args)
	case "yara_scan":
		return s.handleYaraScan(ctx, args)
	case "get_persistence_items":
		return s.handleGetPersistenceItems(ctx, args)
	case "get_execution_artifacts":
		return s.handleGetExecutionArtifacts(ctx, args)
	case "get_network_snapshot":
		return s.handleGetNetworkSnapshot(ctx, args)
	case "list_yara_rules":
		return s.handleListYaraRules(ctx, args)
	case "create_yara_rule":
		return s.handleCreateYaraRule(ctx, args)
	case "get_yara_results":
		return s.handleGetYaraResults(ctx, args)
	case "recommend_action":
		return s.handleRecommendAction(ctx, args)
	case "get_audit_log":
		return s.handleGetAuditLog(ctx, args)
	case "get_process_snapshot":
		return s.handleGetProcessSnapshot(ctx, args)
	default:
		return errorResult(fmt.Sprintf("unknown tool: %s", name))
	}
}

// ---------------------------------------------------------------------------
// Parameter extraction helpers
// ---------------------------------------------------------------------------

func requireString(args map[string]interface{}, key string) (string, error) {
	v, ok := args[key]
	if !ok {
		return "", fmt.Errorf("missing required parameter: %s", key)
	}
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("parameter %s must be a string", key)
	}
	if s == "" {
		return "", fmt.Errorf("parameter %s must not be empty", key)
	}
	return s, nil
}

func optionalString(args map[string]interface{}, key, defaultVal string) string {
	v, ok := args[key]
	if !ok {
		return defaultVal
	}
	s, ok := v.(string)
	if !ok || s == "" {
		return defaultVal
	}
	return s
}

func optionalInt(args map[string]interface{}, key string, defaultVal, minVal, maxVal int) int {
	v, ok := args[key]
	if !ok {
		return defaultVal
	}
	// JSON numbers unmarshal as float64.
	f, ok := v.(float64)
	if !ok {
		return defaultVal
	}
	n := int(f)
	if n < minVal {
		n = minVal
	}
	if n > maxVal {
		n = maxVal
	}
	return n
}

func requireInt(args map[string]interface{}, key string) (int, error) {
	v, ok := args[key]
	if !ok {
		return 0, fmt.Errorf("missing required parameter: %s", key)
	}
	f, ok := v.(float64)
	if !ok {
		return 0, fmt.Errorf("parameter %s must be a number", key)
	}
	return int(f), nil
}

func requireStringSlice(args map[string]interface{}, key string) ([]string, error) {
	v, ok := args[key]
	if !ok {
		return nil, fmt.Errorf("missing required parameter: %s", key)
	}
	raw, ok := v.([]interface{})
	if !ok {
		return nil, fmt.Errorf("parameter %s must be an array", key)
	}
	result := make([]string, 0, len(raw))
	for i, item := range raw {
		s, ok := item.(string)
		if !ok {
			return nil, fmt.Errorf("parameter %s[%d] must be a string", key, i)
		}
		result = append(result, s)
	}
	return result, nil
}

// clampLimit enforces pagination limits, returning a value between 1 and
// MaxPageSize.
func clampLimit(limit int) int {
	if limit < 1 {
		return 100
	}
	if limit > MaxPageSize {
		return MaxPageSize
	}
	return limit
}

// ---------------------------------------------------------------------------
// Tool 1: start_collection
// ---------------------------------------------------------------------------

func (s *MCPServer) handleStartCollection(ctx context.Context, args map[string]interface{}) ToolResult {
	caseID, err := requireString(args, "case_id")
	if err != nil {
		return errorResult(err.Error())
	}
	preset, err := requireString(args, "preset")
	if err != nil {
		return errorResult(err.Error())
	}
	if preset != "standard" && preset != "deep" {
		return errorResult("preset must be 'standard' or 'deep'")
	}
	timeRangeHours := optionalInt(args, "time_range_hours", 72, 1, 8760)

	// Build the collection config and POST to the collector API.
	collectionReq := models.CollectionConfig{
		CaseID:         caseID,
		Preset:         preset,
		TimeRangeHours: timeRangeHours,
	}
	body, err := json.Marshal(collectionReq)
	if err != nil {
		return errorResult(fmt.Sprintf("marshal collection request: %v", err))
	}

	url := fmt.Sprintf("%s/api/v1/collections", s.apiURL)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return errorResult(fmt.Sprintf("create HTTP request: %v", err))
	}
	httpReq.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: ToolCallTimeout}
	resp, err := client.Do(httpReq)
	if err != nil {
		return errorResult(fmt.Sprintf("collector API request failed: %v", err))
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return errorResult(fmt.Sprintf("collector API returned status %d", resp.StatusCode))
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return errorResult(fmt.Sprintf("decode collector response: %v", err))
	}

	// Audit log the collection start.
	_ = s.audit.Log(caseID, "agent", "start_collection", "start_collection",
		fmt.Sprintf("preset=%s time_range_hours=%d", preset, timeRangeHours))

	return textResult(result)
}

// ---------------------------------------------------------------------------
// Tool 2: get_collection_status
// ---------------------------------------------------------------------------

func (s *MCPServer) handleGetCollectionStatus(ctx context.Context, args map[string]interface{}) ToolResult {
	caseID, err := requireString(args, "case_id")
	if err != nil {
		return errorResult(err.Error())
	}
	jobID, err := requireString(args, "job_id")
	if err != nil {
		return errorResult(err.Error())
	}

	job, err := s.db.GetJob(jobID)
	if err != nil {
		return errorResult(fmt.Sprintf("get job: %v", err))
	}
	// Verify case scoping.
	if job.CaseID != caseID {
		return errorResult("job does not belong to the specified case")
	}

	_ = s.audit.Log(caseID, "agent", "get_collection_status", "get_collection_status",
		fmt.Sprintf("job_id=%s", jobID))

	return textResult(job)
}

// ---------------------------------------------------------------------------
// Tool 3: list_artifacts
// ---------------------------------------------------------------------------

func (s *MCPServer) handleListArtifacts(ctx context.Context, args map[string]interface{}) ToolResult {
	caseID, err := requireString(args, "case_id")
	if err != nil {
		return errorResult(err.Error())
	}
	limit := clampLimit(optionalInt(args, "limit", 100, 1, MaxPageSize))
	// The existing DB API uses offset-based pagination. We translate cursor
	// to offset: cursor is a string-encoded offset for simplicity.
	offset := optionalInt(args, "cursor", 0, 0, MaxRowsPerCall)

	artifacts, total, err := s.db.ListArtifacts(caseID, limit, offset)
	if err != nil {
		return errorResult(fmt.Sprintf("list artifacts: %v", err))
	}

	hasMore := offset+limit < total
	nextCursor := ""
	if hasMore {
		nextCursor = fmt.Sprintf("%d", offset+limit)
	}

	_ = s.audit.Log(caseID, "agent", "list_artifacts", "list_artifacts",
		fmt.Sprintf("limit=%d offset=%d returned=%d", limit, offset, len(artifacts)))

	return textResult(map[string]interface{}{
		"data":        artifacts,
		"next_cursor": nextCursor,
		"total":       total,
		"has_more":    hasMore,
	})
}

// ---------------------------------------------------------------------------
// Tool 4: read_artifact
// ---------------------------------------------------------------------------

func (s *MCPServer) handleReadArtifact(ctx context.Context, args map[string]interface{}) ToolResult {
	caseID, err := requireString(args, "case_id")
	if err != nil {
		return errorResult(err.Error())
	}
	artifactID, err := requireString(args, "artifact_id")
	if err != nil {
		return errorResult(err.Error())
	}
	offset := int64(optionalInt(args, "offset", 0, 0, 1<<30))
	length := int64(optionalInt(args, "length", 65536, 1, 1048576))

	// Look up the artifact to get its SHA-256 hash for the blob store.
	artifact, err := s.db.GetArtifact(artifactID)
	if err != nil {
		return errorResult(fmt.Sprintf("get artifact: %v", err))
	}
	if artifact.CaseID != caseID {
		return errorResult("artifact does not belong to the specified case")
	}

	chunk, err := s.store.RetrieveChunk(caseID, artifact.SHA256, offset, length)
	if err != nil {
		return errorResult(fmt.Sprintf("read artifact chunk: %v", err))
	}

	_ = s.audit.Log(caseID, "agent", "read_artifact", "read_artifact",
		fmt.Sprintf("artifact_id=%s offset=%d length=%d returned=%d", artifactID, offset, length, len(chunk)))

	return textResult(map[string]interface{}{
		"artifact_id": artifactID,
		"offset":      offset,
		"length":      len(chunk),
		"data":        base64.StdEncoding.EncodeToString(chunk),
		"encoding":    "base64",
	})
}

// ---------------------------------------------------------------------------
// Tool 5: list_event_sources
// ---------------------------------------------------------------------------

func (s *MCPServer) handleListEventSources(ctx context.Context, args map[string]interface{}) ToolResult {
	caseID, err := requireString(args, "case_id")
	if err != nil {
		return errorResult(err.Error())
	}

	// Query distinct sources directly via the DB connection.
	rows, err := s.db.Conn().QueryContext(ctx,
		`SELECT source, channel, COUNT(*) as event_count,
			MIN(timestamp) as earliest, MAX(timestamp) as latest
			FROM events WHERE case_id = ? GROUP BY source, channel ORDER BY source, channel`,
		caseID)
	if err != nil {
		return errorResult(fmt.Sprintf("list event sources: %v", err))
	}
	defer rows.Close()

	type eventSource struct {
		Source     string `json:"source"`
		Channel   string `json:"channel"`
		Count     int    `json:"event_count"`
		Earliest  string `json:"earliest"`
		Latest    string `json:"latest"`
	}
	var sources []eventSource
	for rows.Next() {
		var src eventSource
		if err := rows.Scan(&src.Source, &src.Channel, &src.Count, &src.Earliest, &src.Latest); err != nil {
			return errorResult(fmt.Sprintf("scan event source: %v", err))
		}
		sources = append(sources, src)
	}

	_ = s.audit.Log(caseID, "agent", "list_event_sources", "list_event_sources",
		fmt.Sprintf("returned=%d sources", len(sources)))

	return textResult(sources)
}

// ---------------------------------------------------------------------------
// Tool 6: search_events
// ---------------------------------------------------------------------------

func (s *MCPServer) handleSearchEvents(ctx context.Context, args map[string]interface{}) ToolResult {
	caseID, err := requireString(args, "case_id")
	if err != nil {
		return errorResult(err.Error())
	}
	query, err := requireString(args, "query")
	if err != nil {
		return errorResult(err.Error())
	}
	limit := clampLimit(optionalInt(args, "limit", 100, 1, MaxPageSize))
	offset := optionalInt(args, "cursor", 0, 0, MaxRowsPerCall)
	timeStart := optionalString(args, "time_start", "")
	timeEnd := optionalString(args, "time_end", "")

	// Build the query with optional time filtering.
	sqlQuery := `SELECT e.id, e.case_id, e.artifact_id, e.timestamp, e.source, e.event_id,
		e.level, e.channel, e.provider, e.computer, e.message
		FROM events e
		JOIN events_fts f ON e.id = f.rowid
		WHERE e.case_id = ? AND events_fts MATCH ?`
	sqlArgs := []interface{}{caseID, query}

	if timeStart != "" {
		sqlQuery += " AND e.timestamp >= ?"
		sqlArgs = append(sqlArgs, timeStart)
	}
	if timeEnd != "" {
		sqlQuery += " AND e.timestamp <= ?"
		sqlArgs = append(sqlArgs, timeEnd)
	}
	sqlQuery += " ORDER BY rank LIMIT ? OFFSET ?"
	sqlArgs = append(sqlArgs, limit+1, offset)

	rows, err := s.db.Conn().QueryContext(ctx, sqlQuery, sqlArgs...)
	if err != nil {
		return errorResult(fmt.Sprintf("search events: %v", err))
	}
	defer rows.Close()

	var events []models.Event
	for rows.Next() {
		var ev models.Event
		var ts string
		if err := rows.Scan(&ev.ID, &ev.CaseID, &ev.ArtifactID, &ts, &ev.Source,
			&ev.EventID, &ev.Level, &ev.Channel, &ev.Provider, &ev.Computer, &ev.Message); err != nil {
			return errorResult(fmt.Sprintf("scan event: %v", err))
		}
		ev.Timestamp, _ = time.Parse(time.RFC3339Nano, ts)
		events = append(events, ev)
	}

	hasMore := len(events) > limit
	if hasMore {
		events = events[:limit]
	}
	nextCursor := ""
	if hasMore {
		nextCursor = fmt.Sprintf("%d", offset+limit)
	}

	_ = s.audit.Log(caseID, "agent", "search_events", "search_events",
		fmt.Sprintf("query=%q limit=%d returned=%d", query, limit, len(events)))

	return textResult(map[string]interface{}{
		"data":        events,
		"next_cursor": nextCursor,
		"has_more":    hasMore,
	})
}

// ---------------------------------------------------------------------------
// Tool 7: get_event
// ---------------------------------------------------------------------------

func (s *MCPServer) handleGetEvent(ctx context.Context, args map[string]interface{}) ToolResult {
	caseID, err := requireString(args, "case_id")
	if err != nil {
		return errorResult(err.Error())
	}
	eventID, err := requireInt(args, "event_id")
	if err != nil {
		return errorResult(err.Error())
	}

	event, err := s.db.GetEvent(int64(eventID))
	if err != nil {
		return errorResult(fmt.Sprintf("get event: %v", err))
	}
	// Verify case scoping.
	if event.CaseID != caseID {
		return errorResult("event does not belong to the specified case")
	}

	_ = s.audit.Log(caseID, "agent", "get_event", "get_event",
		fmt.Sprintf("event_id=%d", eventID))

	return textResult(event)
}

// ---------------------------------------------------------------------------
// Tool 8: get_timeline
// ---------------------------------------------------------------------------

func (s *MCPServer) handleGetTimeline(ctx context.Context, args map[string]interface{}) ToolResult {
	caseID, err := requireString(args, "case_id")
	if err != nil {
		return errorResult(err.Error())
	}
	limit := clampLimit(optionalInt(args, "limit", 100, 1, MaxPageSize))
	offset := optionalInt(args, "cursor", 0, 0, MaxRowsPerCall)
	timeStart := optionalString(args, "time_start", "")
	timeEnd := optionalString(args, "time_end", "")

	sqlQuery := `SELECT id, case_id, artifact_id, timestamp, source, event_id, level,
		channel, provider, computer, message
		FROM events WHERE case_id = ?`
	sqlArgs := []interface{}{caseID}

	if timeStart != "" {
		sqlQuery += " AND timestamp >= ?"
		sqlArgs = append(sqlArgs, timeStart)
	}
	if timeEnd != "" {
		sqlQuery += " AND timestamp <= ?"
		sqlArgs = append(sqlArgs, timeEnd)
	}
	sqlQuery += " ORDER BY timestamp ASC, id ASC LIMIT ? OFFSET ?"
	sqlArgs = append(sqlArgs, limit+1, offset)

	rows, err := s.db.Conn().QueryContext(ctx, sqlQuery, sqlArgs...)
	if err != nil {
		return errorResult(fmt.Sprintf("get timeline: %v", err))
	}
	defer rows.Close()

	var events []models.Event
	for rows.Next() {
		var ev models.Event
		var ts string
		if err := rows.Scan(&ev.ID, &ev.CaseID, &ev.ArtifactID, &ts, &ev.Source,
			&ev.EventID, &ev.Level, &ev.Channel, &ev.Provider, &ev.Computer, &ev.Message); err != nil {
			return errorResult(fmt.Sprintf("scan timeline event: %v", err))
		}
		ev.Timestamp, _ = time.Parse(time.RFC3339Nano, ts)
		events = append(events, ev)
	}

	hasMore := len(events) > limit
	if hasMore {
		events = events[:limit]
	}
	nextCursor := ""
	if hasMore {
		nextCursor = fmt.Sprintf("%d", offset+limit)
	}

	_ = s.audit.Log(caseID, "agent", "get_timeline", "get_timeline",
		fmt.Sprintf("limit=%d returned=%d", limit, len(events)))

	return textResult(map[string]interface{}{
		"data":        events,
		"next_cursor": nextCursor,
		"has_more":    hasMore,
	})
}

// ---------------------------------------------------------------------------
// Tool 9: read_registry_keys
// ---------------------------------------------------------------------------

func (s *MCPServer) handleReadRegistryKeys(ctx context.Context, args map[string]interface{}) ToolResult {
	caseID, err := requireString(args, "case_id")
	if err != nil {
		return errorResult(err.Error())
	}
	path, err := requireString(args, "path")
	if err != nil {
		return errorResult(err.Error())
	}

	rows, err := s.db.Conn().QueryContext(ctx,
		`SELECT path, name, type, data, modified FROM registry_entries
		WHERE case_id = ? AND path = ? ORDER BY name ASC LIMIT ?`,
		caseID, path, MaxPageSize)
	if err != nil {
		return errorResult(fmt.Sprintf("read registry keys: %v", err))
	}
	defer rows.Close()

	var keys []models.RegistryKeyValue
	for rows.Next() {
		var k models.RegistryKeyValue
		if err := rows.Scan(&k.Path, &k.Name, &k.Type, &k.Data, &k.Modified); err != nil {
			return errorResult(fmt.Sprintf("scan registry key: %v", err))
		}
		keys = append(keys, k)
	}

	_ = s.audit.Log(caseID, "agent", "read_registry_keys", "read_registry_keys",
		fmt.Sprintf("path=%s returned=%d", path, len(keys)))

	return textResult(keys)
}

// ---------------------------------------------------------------------------
// Tool 10: search_registry
// ---------------------------------------------------------------------------

func (s *MCPServer) handleSearchRegistry(ctx context.Context, args map[string]interface{}) ToolResult {
	caseID, err := requireString(args, "case_id")
	if err != nil {
		return errorResult(err.Error())
	}
	rootPath, err := requireString(args, "root_path")
	if err != nil {
		return errorResult(err.Error())
	}
	pattern, err := requireString(args, "pattern")
	if err != nil {
		return errorResult(err.Error())
	}

	likePath := rootPath + "%"
	likePattern := "%" + pattern + "%"

	rows, err := s.db.Conn().QueryContext(ctx,
		`SELECT path, name, type, data, modified FROM registry_entries
		WHERE case_id = ? AND path LIKE ? AND (name LIKE ? OR data LIKE ?)
		ORDER BY path, name ASC LIMIT ?`,
		caseID, likePath, likePattern, likePattern, MaxPageSize)
	if err != nil {
		return errorResult(fmt.Sprintf("search registry: %v", err))
	}
	defer rows.Close()

	var keys []models.RegistryKeyValue
	for rows.Next() {
		var k models.RegistryKeyValue
		if err := rows.Scan(&k.Path, &k.Name, &k.Type, &k.Data, &k.Modified); err != nil {
			return errorResult(fmt.Sprintf("scan registry key: %v", err))
		}
		keys = append(keys, k)
	}

	_ = s.audit.Log(caseID, "agent", "search_registry", "search_registry",
		fmt.Sprintf("root_path=%s pattern=%s returned=%d", rootPath, pattern, len(keys)))

	return textResult(keys)
}

// ---------------------------------------------------------------------------
// Tool 11: yara_scan
// ---------------------------------------------------------------------------

func (s *MCPServer) handleYaraScan(ctx context.Context, args map[string]interface{}) ToolResult {
	caseID, err := requireString(args, "case_id")
	if err != nil {
		return errorResult(err.Error())
	}
	ruleID, err := requireString(args, "rule_id")
	if err != nil {
		return errorResult(err.Error())
	}
	artifactID, err := requireString(args, "artifact_id")
	if err != nil {
		return errorResult(err.Error())
	}

	// Verify the rule exists and belongs to the case.
	rule, err := s.db.GetRule(ruleID)
	if err != nil {
		return errorResult(fmt.Sprintf("get rule: %v", err))
	}
	if rule.CaseID != caseID {
		return errorResult("rule does not belong to the specified case")
	}

	// Verify the artifact exists and belongs to the case.
	artifact, err := s.db.GetArtifact(artifactID)
	if err != nil {
		return errorResult(fmt.Sprintf("get artifact: %v", err))
	}
	if artifact.CaseID != caseID {
		return errorResult("artifact does not belong to the specified case")
	}

	// POST scan job to the worker API.
	scanReq := map[string]string{
		"case_id":     caseID,
		"rule_id":     ruleID,
		"artifact_id": artifactID,
	}
	body, err := json.Marshal(scanReq)
	if err != nil {
		return errorResult(fmt.Sprintf("marshal scan request: %v", err))
	}

	url := fmt.Sprintf("%s/api/v1/yara/scan", s.apiURL)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return errorResult(fmt.Sprintf("create HTTP request: %v", err))
	}
	httpReq.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: ToolCallTimeout}
	resp, err := client.Do(httpReq)
	if err != nil {
		return errorResult(fmt.Sprintf("worker API request failed: %v", err))
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		return errorResult(fmt.Sprintf("worker API returned status %d", resp.StatusCode))
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return errorResult(fmt.Sprintf("decode worker response: %v", err))
	}

	_ = s.audit.Log(caseID, "agent", "yara_scan", "yara_scan",
		fmt.Sprintf("rule_id=%s artifact_id=%s", ruleID, artifactID))

	return textResult(result)
}

// ---------------------------------------------------------------------------
// Tool 12: get_persistence_items
// ---------------------------------------------------------------------------

func (s *MCPServer) handleGetPersistenceItems(ctx context.Context, args map[string]interface{}) ToolResult {
	caseID, err := requireString(args, "case_id")
	if err != nil {
		return errorResult(err.Error())
	}

	items, err := s.db.ListPersistenceItems(caseID)
	if err != nil {
		return errorResult(fmt.Sprintf("get persistence items: %v", err))
	}

	_ = s.audit.Log(caseID, "agent", "get_persistence_items", "get_persistence_items",
		fmt.Sprintf("returned=%d", len(items)))

	return textResult(items)
}

// ---------------------------------------------------------------------------
// Tool 13: get_execution_artifacts
// ---------------------------------------------------------------------------

func (s *MCPServer) handleGetExecutionArtifacts(ctx context.Context, args map[string]interface{}) ToolResult {
	caseID, err := requireString(args, "case_id")
	if err != nil {
		return errorResult(err.Error())
	}
	limit := clampLimit(optionalInt(args, "limit", 100, 1, MaxPageSize))
	offset := optionalInt(args, "cursor", 0, 0, MaxRowsPerCall)

	rows, err := s.db.Conn().QueryContext(ctx,
		`SELECT id, case_id, artifact_id, timestamp, source, event_id, level,
			channel, provider, computer, message
			FROM events WHERE case_id = ?
			AND source IN ('prefetch','shimcache','amcache','userassist','bam')
			ORDER BY timestamp ASC, id ASC LIMIT ? OFFSET ?`,
		caseID, limit+1, offset)
	if err != nil {
		return errorResult(fmt.Sprintf("get execution artifacts: %v", err))
	}
	defer rows.Close()

	var events []models.Event
	for rows.Next() {
		var ev models.Event
		var ts string
		if err := rows.Scan(&ev.ID, &ev.CaseID, &ev.ArtifactID, &ts, &ev.Source,
			&ev.EventID, &ev.Level, &ev.Channel, &ev.Provider, &ev.Computer, &ev.Message); err != nil {
			return errorResult(fmt.Sprintf("scan execution artifact: %v", err))
		}
		ev.Timestamp, _ = time.Parse(time.RFC3339Nano, ts)
		events = append(events, ev)
	}

	hasMore := len(events) > limit
	if hasMore {
		events = events[:limit]
	}
	nextCursor := ""
	if hasMore {
		nextCursor = fmt.Sprintf("%d", offset+limit)
	}

	_ = s.audit.Log(caseID, "agent", "get_execution_artifacts", "get_execution_artifacts",
		fmt.Sprintf("limit=%d returned=%d", limit, len(events)))

	return textResult(map[string]interface{}{
		"data":        events,
		"next_cursor": nextCursor,
		"has_more":    hasMore,
	})
}

// ---------------------------------------------------------------------------
// Tool 14: get_network_snapshot
// ---------------------------------------------------------------------------

func (s *MCPServer) handleGetNetworkSnapshot(ctx context.Context, args map[string]interface{}) ToolResult {
	caseID, err := requireString(args, "case_id")
	if err != nil {
		return errorResult(err.Error())
	}

	snapshot := models.NetworkSnapshot{}

	// Connections.
	connRows, err := s.db.Conn().QueryContext(ctx,
		`SELECT protocol, local_addr, local_port, remote_addr, remote_port, state, pid, process_name
		FROM network_connections WHERE case_id = ? LIMIT ?`, caseID, MaxRowsPerCall)
	if err != nil {
		return errorResult(fmt.Sprintf("get network connections: %v", err))
	}
	defer connRows.Close()
	for connRows.Next() {
		var c models.NetworkConnection
		if err := connRows.Scan(&c.Protocol, &c.LocalAddr, &c.LocalPort, &c.RemoteAddr,
			&c.RemotePort, &c.State, &c.PID, &c.ProcessName); err != nil {
			return errorResult(fmt.Sprintf("scan connection: %v", err))
		}
		snapshot.Connections = append(snapshot.Connections, c)
	}

	// DNS cache.
	dnsRows, err := s.db.Conn().QueryContext(ctx,
		`SELECT name, type, ttl, record FROM dns_cache WHERE case_id = ? LIMIT ?`, caseID, MaxRowsPerCall)
	if err != nil {
		return errorResult(fmt.Sprintf("get dns cache: %v", err))
	}
	defer dnsRows.Close()
	for dnsRows.Next() {
		var d models.DNSCacheEntry
		if err := dnsRows.Scan(&d.Name, &d.Type, &d.TTL, &d.Record); err != nil {
			return errorResult(fmt.Sprintf("scan dns entry: %v", err))
		}
		snapshot.DNSCache = append(snapshot.DNSCache, d)
	}

	// ARP table.
	arpRows, err := s.db.Conn().QueryContext(ctx,
		`SELECT interface, ip_address, mac_address, type FROM arp_entries WHERE case_id = ? LIMIT ?`, caseID, MaxRowsPerCall)
	if err != nil {
		return errorResult(fmt.Sprintf("get arp table: %v", err))
	}
	defer arpRows.Close()
	for arpRows.Next() {
		var a models.ARPEntry
		if err := arpRows.Scan(&a.Interface, &a.IPAddress, &a.MACAddress, &a.Type); err != nil {
			return errorResult(fmt.Sprintf("scan arp entry: %v", err))
		}
		snapshot.ARPTable = append(snapshot.ARPTable, a)
	}

	// Routes.
	routeRows, err := s.db.Conn().QueryContext(ctx,
		`SELECT destination, netmask, gateway, interface, metric FROM routes WHERE case_id = ? LIMIT ?`, caseID, MaxRowsPerCall)
	if err != nil {
		return errorResult(fmt.Sprintf("get routes: %v", err))
	}
	defer routeRows.Close()
	for routeRows.Next() {
		var r models.RouteEntry
		if err := routeRows.Scan(&r.Destination, &r.Netmask, &r.Gateway, &r.Interface, &r.Metric); err != nil {
			return errorResult(fmt.Sprintf("scan route: %v", err))
		}
		snapshot.Routes = append(snapshot.Routes, r)
	}

	_ = s.audit.Log(caseID, "agent", "get_network_snapshot", "get_network_snapshot",
		fmt.Sprintf("connections=%d dns=%d arp=%d routes=%d",
			len(snapshot.Connections), len(snapshot.DNSCache), len(snapshot.ARPTable), len(snapshot.Routes)))

	return textResult(snapshot)
}

// ---------------------------------------------------------------------------
// Tool 15: list_yara_rules
// ---------------------------------------------------------------------------

func (s *MCPServer) handleListYaraRules(ctx context.Context, args map[string]interface{}) ToolResult {
	caseID, err := requireString(args, "case_id")
	if err != nil {
		return errorResult(err.Error())
	}

	rules, err := s.db.ListRules(caseID)
	if err != nil {
		return errorResult(fmt.Sprintf("list yara rules: %v", err))
	}

	_ = s.audit.Log(caseID, "agent", "list_yara_rules", "list_yara_rules",
		fmt.Sprintf("returned=%d", len(rules)))

	return textResult(rules)
}

// ---------------------------------------------------------------------------
// Tool 16: create_yara_rule
// ---------------------------------------------------------------------------

func (s *MCPServer) handleCreateYaraRule(ctx context.Context, args map[string]interface{}) ToolResult {
	caseID, err := requireString(args, "case_id")
	if err != nil {
		return errorResult(err.Error())
	}
	name, err := requireString(args, "name")
	if err != nil {
		return errorResult(err.Error())
	}
	content, err := requireString(args, "content")
	if err != nil {
		return errorResult(err.Error())
	}

	rule := models.YaraRule{
		ID:        uuid.New().String(),
		CaseID:    caseID,
		Name:      name,
		Content:   content,
		CreatedAt: time.Now().UTC(),
		CreatedBy: "agent",
	}

	if err := s.db.CreateRule(rule); err != nil {
		return errorResult(fmt.Sprintf("create yara rule: %v", err))
	}

	_ = s.audit.Log(caseID, "agent", "create_yara_rule", "create_yara_rule",
		fmt.Sprintf("rule_id=%s name=%s", rule.ID, name))

	return textResult(rule)
}

// ---------------------------------------------------------------------------
// Tool 17: get_yara_results
// ---------------------------------------------------------------------------

func (s *MCPServer) handleGetYaraResults(ctx context.Context, args map[string]interface{}) ToolResult {
	caseID, err := requireString(args, "case_id")
	if err != nil {
		return errorResult(err.Error())
	}
	ruleID, err := requireString(args, "rule_id")
	if err != nil {
		return errorResult(err.Error())
	}

	results, err := s.db.ListResults(caseID, ruleID)
	if err != nil {
		return errorResult(fmt.Sprintf("get yara results: %v", err))
	}

	_ = s.audit.Log(caseID, "agent", "get_yara_results", "get_yara_results",
		fmt.Sprintf("rule_id=%s returned=%d", ruleID, len(results)))

	return textResult(results)
}

// ---------------------------------------------------------------------------
// Tool 18: recommend_action
// ---------------------------------------------------------------------------

func (s *MCPServer) handleRecommendAction(ctx context.Context, args map[string]interface{}) ToolResult {
	caseID, err := requireString(args, "case_id")
	if err != nil {
		return errorResult(err.Error())
	}
	actionType, err := requireString(args, "type")
	if err != nil {
		return errorResult(err.Error())
	}
	title, err := requireString(args, "title")
	if err != nil {
		return errorResult(err.Error())
	}
	rationale, err := requireString(args, "rationale")
	if err != nil {
		return errorResult(err.Error())
	}
	steps, err := requireStringSlice(args, "steps")
	if err != nil {
		return errorResult(err.Error())
	}

	// Validate action type.
	validTypes := map[string]bool{
		"isolate": true, "collect_additional": true, "remediate": true,
		"escalate": true, "monitor": true, "other": true,
	}
	if !validTypes[actionType] {
		return errorResult(fmt.Sprintf("invalid action type: %s", actionType))
	}

	// Serialize steps as JSON array.
	stepsJSON, err := json.Marshal(steps)
	if err != nil {
		return errorResult(fmt.Sprintf("marshal steps: %v", err))
	}

	proposal := models.ActionProposal{
		ID:        uuid.New().String(),
		CaseID:    caseID,
		Type:      actionType,
		Title:     title,
		Rationale: rationale,
		Steps:     string(stepsJSON),
		Status:    "pending",
		CreatedAt: time.Now().UTC(),
	}

	if err := s.db.CreateProposal(proposal); err != nil {
		return errorResult(fmt.Sprintf("create action proposal: %v", err))
	}

	_ = s.audit.Log(caseID, "agent", "recommend_action", "recommend_action",
		fmt.Sprintf("proposal_id=%s type=%s title=%s", proposal.ID, actionType, title))

	return textResult(proposal)
}

// ---------------------------------------------------------------------------
// Tool 19: get_audit_log
// ---------------------------------------------------------------------------

func (s *MCPServer) handleGetAuditLog(ctx context.Context, args map[string]interface{}) ToolResult {
	caseID, err := requireString(args, "case_id")
	if err != nil {
		return errorResult(err.Error())
	}
	limit := clampLimit(optionalInt(args, "limit", 100, 1, MaxPageSize))
	offset := optionalInt(args, "offset", 0, 0, MaxRowsPerCall)

	entries, err := s.audit.GetLog(caseID, limit, offset)
	if err != nil {
		return errorResult(fmt.Sprintf("get audit log: %v", err))
	}

	// Do not log audit log reads to the audit log to avoid recursive noise.

	return textResult(map[string]interface{}{
		"data":  entries,
		"count": len(entries),
	})
}

// ---------------------------------------------------------------------------
// Tool 20: get_process_snapshot
// ---------------------------------------------------------------------------

func (s *MCPServer) handleGetProcessSnapshot(ctx context.Context, args map[string]interface{}) ToolResult {
	caseID, err := requireString(args, "case_id")
	if err != nil {
		return errorResult(err.Error())
	}
	snapshotType, err := requireString(args, "type")
	if err != nil {
		return errorResult(err.Error())
	}

	var data interface{}

	switch snapshotType {
	case "processes":
		rows, qErr := s.db.Conn().QueryContext(ctx,
			`SELECT pid, ppid, name, image_path, command_line, user_context,
				start_time, session_id, integrity_level
				FROM processes WHERE case_id = ? ORDER BY pid ASC LIMIT ?`,
			caseID, MaxRowsPerCall)
		if qErr != nil {
			return errorResult(fmt.Sprintf("get processes: %v", qErr))
		}
		defer rows.Close()
		var procs []models.ProcessInfo
		for rows.Next() {
			var p models.ProcessInfo
			if err := rows.Scan(&p.PID, &p.PPID, &p.Name, &p.ImagePath, &p.CommandLine,
				&p.UserContext, &p.StartTime, &p.SessionID, &p.IntegrityLevel); err != nil {
				return errorResult(fmt.Sprintf("scan process: %v", err))
			}
			procs = append(procs, p)
		}
		data = procs

	case "services":
		rows, qErr := s.db.Conn().QueryContext(ctx,
			`SELECT name, display_name, binary_path, startup_type, current_state, service_account
				FROM services WHERE case_id = ? ORDER BY name ASC LIMIT ?`,
			caseID, MaxRowsPerCall)
		if qErr != nil {
			return errorResult(fmt.Sprintf("get services: %v", qErr))
		}
		defer rows.Close()
		var svcs []models.ServiceInfo
		for rows.Next() {
			var svc models.ServiceInfo
			if err := rows.Scan(&svc.Name, &svc.DisplayName, &svc.BinaryPath, &svc.StartupType,
				&svc.CurrentState, &svc.ServiceAccount); err != nil {
				return errorResult(fmt.Sprintf("scan service: %v", err))
			}
			svcs = append(svcs, svc)
		}
		data = svcs

	case "tasks":
		rows, qErr := s.db.Conn().QueryContext(ctx,
			`SELECT name, path, triggers, actions, run_as_user, last_run_time, status
				FROM scheduled_tasks WHERE case_id = ? ORDER BY name ASC LIMIT ?`,
			caseID, MaxRowsPerCall)
		if qErr != nil {
			return errorResult(fmt.Sprintf("get scheduled tasks: %v", qErr))
		}
		defer rows.Close()
		var tasks []models.ScheduledTaskInfo
		for rows.Next() {
			var t models.ScheduledTaskInfo
			if err := rows.Scan(&t.Name, &t.Path, &t.Triggers, &t.Actions, &t.RunAsUser,
				&t.LastRunTime, &t.Status); err != nil {
				return errorResult(fmt.Sprintf("scan task: %v", err))
			}
			tasks = append(tasks, t)
		}
		data = tasks

	default:
		return errorResult(fmt.Sprintf("type must be 'processes', 'services', or 'tasks'; got %q", snapshotType))
	}

	_ = s.audit.Log(caseID, "agent", "get_process_snapshot", "get_process_snapshot",
		fmt.Sprintf("type=%s", snapshotType))

	return textResult(map[string]interface{}{
		"type": snapshotType,
		"data": data,
	})
}
