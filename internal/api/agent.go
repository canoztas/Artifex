package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/artifex/dfir/internal/llm"
	"github.com/artifex/dfir/internal/models"
	"github.com/google/uuid"
)

const dfirSystemPrompt = `You are Artifex, an expert DFIR (Digital Forensics and Incident Response) analyst AI assistant.

You help investigators analyze Windows security incidents by examining collected evidence artifacts. You have access to tools that let you:
- Browse and search collected artifacts (event logs, registry keys, prefetch files, etc.)
- Search normalized events using full-text search
- View timeline of events chronologically
- Examine process, service, and network snapshots
- Identify persistence mechanisms
- Run YARA scans against evidence
- Recommend response actions (which require human approval)

IMPORTANT RESTRICTIONS:
- You are READ-ONLY. You cannot modify, delete, or execute anything on the target system.
- You can only recommend actions via the recommend_action tool. These create proposals that the investigator must approve.
- All your tool calls are logged in the audit trail.
- Be thorough but concise in your analysis.
- Always cite specific evidence (event IDs, timestamps, file paths, registry keys) to support your findings.
- Prioritize identifying indicators of compromise (IOCs), lateral movement, persistence mechanisms, and data exfiltration.
- When unsure, say so rather than speculating.`

// agentChatRequest is the JSON body for POST /api/cases/{caseId}/agent/chat
type agentChatRequest struct {
	Message string        `json:"message"`
	History []llm.Message `json:"history,omitempty"`
}

// agentChatResponse is the JSON response for the chat endpoint.
type agentChatResponse struct {
	Answer string          `json:"answer"`
	Steps  []llm.AgentStep `json:"steps"`
	Error  string          `json:"error,omitempty"`
}

// handleAgentChat processes a user message through the LLM agent loop.
func (s *Server) handleAgentChat(w http.ResponseWriter, r *http.Request) {
	caseID := r.PathValue("caseId")

	if s.llm == nil {
		errorResponse(w, http.StatusServiceUnavailable, "LLM provider not configured. Set provider and api_key in config.json.")
		return
	}

	var req agentChatRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errorResponse(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if strings.TrimSpace(req.Message) == "" {
		errorResponse(w, http.StatusBadRequest, "message is required")
		return
	}

	// Log the user message.
	s.audit.Log(caseID, "user", "agent_chat", "", fmt.Sprintf("user message: %.200s", req.Message))

	// Build the tool executor that calls our DB/store functions.
	executor := s.buildToolExecutor(caseID)

	// Build the available tools list.
	tools := s.buildAgentTools()

	// Add case context to the system prompt.
	caseInfo, _ := s.db.GetCase(caseID)
	systemPrompt := dfirSystemPrompt
	if caseInfo != nil {
		systemPrompt += fmt.Sprintf("\n\nCurrent case: %s (ID: %s)\nDescription: %s\nStatus: %s",
			caseInfo.Name, caseInfo.ID, caseInfo.Description, caseInfo.Status)
	}

	// Run the agent loop with a timeout.
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()

	result, err := llm.RunAgent(ctx, s.llm, systemPrompt, req.Message, req.History, tools, executor)
	if err != nil {
		s.audit.Log(caseID, "agent", "agent_error", "", err.Error())
		errorResponse(w, http.StatusInternalServerError, "agent error: "+err.Error())
		return
	}

	// Log the agent response.
	s.audit.Log(caseID, "agent", "agent_response", "", fmt.Sprintf("answer: %.200s (steps: %d)", result.Answer, len(result.Steps)))

	jsonResponse(w, http.StatusOK, agentChatResponse{
		Answer: result.Answer,
		Steps:  result.Steps,
		Error:  result.Error,
	})
}

// buildToolExecutor creates a function that executes tool calls against the DB and evidence store.
func (s *Server) buildToolExecutor(caseID string) llm.ToolExecutor {
	return func(ctx context.Context, name string, args map[string]interface{}) (string, error) {
		// Log every tool call for audit.
		argsJSON, _ := json.Marshal(args)
		s.audit.Log(caseID, "agent", "tool_call", name, string(argsJSON))

		switch name {
		case "list_artifacts":
			return s.toolListArtifacts(caseID, args)
		case "read_artifact":
			return s.toolReadArtifact(caseID, args)
		case "search_events":
			return s.toolSearchEvents(caseID, args)
		case "get_event":
			return s.toolGetEvent(caseID, args)
		case "get_timeline":
			return s.toolGetTimeline(caseID, args)
		case "get_persistence_items":
			return s.toolGetPersistence(caseID)
		case "get_network_snapshot":
			return s.toolGetNetworkSnapshot(caseID)
		case "get_process_snapshot":
			return s.toolGetProcessSnapshot(caseID)
		case "get_execution_artifacts":
			return s.toolGetExecutionArtifacts(caseID, args)
		case "get_recent_activity":
			return s.toolGetRecentActivity(caseID, args)
		case "read_registry_keys":
			return s.toolReadRegistry(caseID, args)
		case "search_registry":
			return s.toolSearchRegistry(caseID, args)
		case "list_yara_rules":
			return s.toolListYaraRules(caseID)
		case "create_yara_rule":
			return s.toolCreateYaraRule(caseID, args)
		case "get_yara_results":
			return s.toolGetYaraResults(caseID, args)
		case "recommend_action":
			return s.toolRecommendAction(caseID, args)
		case "get_audit_log":
			return s.toolGetAuditLog(caseID, args)
		case "get_collection_status":
			return s.toolGetCollectionStatus(caseID, args)
		default:
			return "", fmt.Errorf("unknown tool: %s", name)
		}
	}
}

// ---------------------------------------------------------------------------
// Tool implementations (all read-only except recommend_action and create_yara_rule)
// ---------------------------------------------------------------------------

func (s *Server) toolListArtifacts(caseID string, args map[string]interface{}) (string, error) {
	limit := getIntArg(args, "limit", 50)
	offset := getIntArg(args, "offset", 0)
	artifacts, total, err := s.db.ListArtifacts(caseID, limit, offset)
	if err != nil {
		return "", err
	}
	return marshalResult(map[string]interface{}{"artifacts": artifacts, "total": total})
}

func (s *Server) toolReadArtifact(caseID string, args map[string]interface{}) (string, error) {
	artifactID := getStringArg(args, "artifact_id")
	if artifactID == "" {
		return "", fmt.Errorf("artifact_id is required")
	}
	a, err := s.db.GetArtifact(artifactID)
	if err != nil {
		return "", err
	}
	if a.CaseID != caseID {
		return "", fmt.Errorf("artifact not found in this case")
	}

	offset := getInt64Arg(args, "offset", 0)
	length := getInt64Arg(args, "length", 10000) // default 10KB for text preview

	data, err := s.store.RetrieveChunk(a.CaseID, a.SHA256, offset, length)
	if err != nil {
		return "", err
	}

	return marshalResult(map[string]interface{}{
		"artifact": a,
		"content":  string(data),
		"offset":   offset,
		"length":   len(data),
	})
}

func (s *Server) toolSearchEvents(caseID string, args map[string]interface{}) (string, error) {
	query := getStringArg(args, "query")
	limit := getIntArg(args, "limit", 50)
	offset := getIntArg(args, "offset", 0)

	if query != "" {
		events, total, err := s.db.SearchEvents(caseID, query, "", "", limit, offset)
		if err != nil {
			return "", err
		}
		return marshalResult(map[string]interface{}{"events": events, "total": total})
	}

	events, total, err := s.db.GetEventsByTimeRange(caseID,
		time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC),
		time.Now().Add(24*time.Hour), limit, offset)
	if err != nil {
		return "", err
	}
	return marshalResult(map[string]interface{}{"events": events, "total": total})
}

func (s *Server) toolGetEvent(caseID string, args map[string]interface{}) (string, error) {
	eventID := getInt64Arg(args, "event_id", 0)
	if eventID == 0 {
		return "", fmt.Errorf("event_id is required")
	}
	event, err := s.db.GetEvent(eventID)
	if err != nil {
		return "", err
	}
	return marshalResult(event)
}

func (s *Server) toolGetTimeline(caseID string, args map[string]interface{}) (string, error) {
	limit := getIntArg(args, "limit", 100)
	offset := getIntArg(args, "offset", 0)

	start := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	end := time.Now().Add(24 * time.Hour)

	if s := getStringArg(args, "time_start"); s != "" {
		if t, err := time.Parse(time.RFC3339, s); err == nil {
			start = t
		}
	}
	if s := getStringArg(args, "time_end"); s != "" {
		if t, err := time.Parse(time.RFC3339, s); err == nil {
			end = t
		}
	}

	events, total, err := s.db.GetEventsByTimeRange(caseID, start, end, limit, offset)
	if err != nil {
		return "", err
	}
	return marshalResult(map[string]interface{}{"events": events, "total": total})
}

func (s *Server) toolGetPersistence(caseID string) (string, error) {
	items, err := s.db.ListPersistenceItems(caseID)
	if err != nil {
		return "", err
	}
	return marshalResult(items)
}

func (s *Server) toolGetNetworkSnapshot(caseID string) (string, error) {
	artifacts, _, _ := s.db.ListArtifacts(caseID, 100, 0)
	for _, a := range artifacts {
		if a.Type == "network_snapshot" {
			data, err := s.store.Retrieve(a.CaseID, a.SHA256)
			if err != nil {
				continue
			}
			return string(data), nil
		}
	}
	return `{"message": "no network snapshot collected yet"}`, nil
}

func (s *Server) toolGetProcessSnapshot(caseID string) (string, error) {
	artifacts, _, _ := s.db.ListArtifacts(caseID, 100, 0)
	for _, a := range artifacts {
		if a.Type == "process_snapshot" {
			data, err := s.store.Retrieve(a.CaseID, a.SHA256)
			if err != nil {
				continue
			}
			return string(data), nil
		}
	}
	return `{"message": "no process snapshot collected yet"}`, nil
}

func (s *Server) toolGetExecutionArtifacts(caseID string, args map[string]interface{}) (string, error) {
	if err := s.ensureCaseEventsIndexed(caseID); err != nil {
		if errors.Is(err, errWorkerUnavailable) {
			log.Printf("[api] execution artifact indexing skipped for case %s: %v", caseID, err)
		} else {
			return "", err
		}
	}

	limit := getIntArg(args, "limit", 100)
	if limit <= 0 {
		limit = 100
	}
	offset := getIntArg(args, "offset", 0)
	if offset < 0 {
		offset = 0
	}

	var total int
	if err := s.db.Conn().QueryRow(
		`SELECT COUNT(*) FROM events
		 WHERE case_id = ? AND source IN ('prefetch','shimcache','amcache','userassist','bam')`,
		caseID,
	).Scan(&total); err != nil {
		return "", err
	}

	rows, err := s.db.Conn().Query(
		`SELECT id, case_id, artifact_id, timestamp, source, event_id,
		 level, channel, provider, computer, message, raw_data
		 FROM events WHERE case_id = ?
		 AND source IN ('prefetch','shimcache','amcache','userassist','bam')
		 ORDER BY timestamp ASC, id ASC
		 LIMIT ? OFFSET ?`,
		caseID, limit, offset,
	)
	if err != nil {
		return "", err
	}
	defer rows.Close()

	var events []models.Event
	for rows.Next() {
		var event models.Event
		var ts string
		if err := rows.Scan(
			&event.ID, &event.CaseID, &event.ArtifactID, &ts, &event.Source, &event.EventID,
			&event.Level, &event.Channel, &event.Provider, &event.Computer, &event.Message, &event.RawData,
		); err != nil {
			return "", err
		}
		event.Timestamp, _ = time.Parse(time.RFC3339Nano, ts)
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return "", err
	}

	return marshalResult(map[string]interface{}{
		"events":      events,
		"total":       total,
		"has_more":    offset+len(events) < total,
		"next_offset": offset + len(events),
	})
}

func (s *Server) toolGetRecentActivity(caseID string, args map[string]interface{}) (string, error) {
	if err := s.ensureCaseEventsIndexed(caseID); err != nil {
		if errors.Is(err, errWorkerUnavailable) {
			log.Printf("[api] recent activity indexing skipped for case %s: %v", caseID, err)
		} else {
			return "", err
		}
	}

	kind := strings.ToLower(getStringArg(args, "kind"))
	if kind == "" {
		kind = "all"
	}

	var sourceClause string
	switch kind {
	case "all":
		sourceClause = "source IN ('lnk','lnk_recent','lnk_startup','lnk_desktop','jumplist','jumplist_automatic','jumplist_custom')"
	case "shortcut":
		sourceClause = "source IN ('lnk','lnk_recent','lnk_startup','lnk_desktop')"
	case "jumplist":
		sourceClause = "source IN ('jumplist','jumplist_automatic','jumplist_custom')"
	default:
		return "", fmt.Errorf("kind must be one of: all, shortcut, jumplist")
	}

	limit := getIntArg(args, "limit", 100)
	if limit <= 0 {
		limit = 100
	}
	offset := getIntArg(args, "offset", 0)
	if offset < 0 {
		offset = 0
	}

	rows, err := s.db.Conn().Query(
		fmt.Sprintf(`SELECT id, case_id, artifact_id, timestamp, source, event_id,
		 level, channel, provider, computer, message, raw_data
		 FROM events WHERE case_id = ? AND %s
		 ORDER BY timestamp ASC, id ASC
		 LIMIT ? OFFSET ?`, sourceClause),
		caseID, limit, offset,
	)
	if err != nil {
		return "", err
	}
	defer rows.Close()

	var results []map[string]interface{}
	for rows.Next() {
		var event models.Event
		var ts string
		if err := rows.Scan(
			&event.ID, &event.CaseID, &event.ArtifactID, &ts, &event.Source, &event.EventID,
			&event.Level, &event.Channel, &event.Provider, &event.Computer, &event.Message, &event.RawData,
		); err != nil {
			return "", err
		}
		event.Timestamp, _ = time.Parse(time.RFC3339Nano, ts)

		entry := map[string]interface{}{
			"id":          event.ID,
			"artifact_id": event.ArtifactID,
			"timestamp":   event.Timestamp,
			"source":      event.Source,
			"message":     event.Message,
		}
		if strings.TrimSpace(event.RawData) != "" {
			var details map[string]interface{}
			if err := json.Unmarshal([]byte(event.RawData), &details); err == nil {
				entry["details"] = details
			} else {
				entry["raw_data"] = event.RawData
			}
		}
		results = append(results, entry)
	}
	if err := rows.Err(); err != nil {
		return "", err
	}

	var total int
	if err := s.db.Conn().QueryRow(
		fmt.Sprintf(`SELECT COUNT(*) FROM events WHERE case_id = ? AND %s`, sourceClause),
		caseID,
	).Scan(&total); err != nil {
		return "", err
	}

	return marshalResult(map[string]interface{}{
		"events":      results,
		"total":       total,
		"has_more":    offset+len(results) < total,
		"next_offset": offset + len(results),
	})
}

func (s *Server) toolReadRegistry(caseID string, args map[string]interface{}) (string, error) {
	path := getStringArg(args, "path")
	if path == "" {
		return "", fmt.Errorf("path is required")
	}
	artifacts, _, _ := s.db.ListArtifacts(caseID, 100, 0)
	for _, a := range artifacts {
		if a.Type == "registry_persistence" {
			data, err := s.store.Retrieve(a.CaseID, a.SHA256)
			if err != nil {
				continue
			}
			var keys []models.RegistryKeyValue
			json.Unmarshal(data, &keys)
			var matching []models.RegistryKeyValue
			for _, k := range keys {
				if strings.Contains(strings.ToLower(k.Path), strings.ToLower(path)) {
					matching = append(matching, k)
				}
			}
			if len(matching) > 0 {
				return marshalResult(matching)
			}
		}
	}
	return `[]`, nil
}

func (s *Server) toolSearchRegistry(caseID string, args map[string]interface{}) (string, error) {
	pattern := getStringArg(args, "pattern")
	if pattern == "" {
		return "", fmt.Errorf("pattern is required")
	}
	query := strings.ToLower(pattern)
	var results []models.RegistryKeyValue
	artifacts, _, _ := s.db.ListArtifacts(caseID, 100, 0)
	for _, a := range artifacts {
		if a.Type == "registry_persistence" {
			data, err := s.store.Retrieve(a.CaseID, a.SHA256)
			if err != nil {
				continue
			}
			var keys []models.RegistryKeyValue
			json.Unmarshal(data, &keys)
			for _, k := range keys {
				if strings.Contains(strings.ToLower(k.Path), query) ||
					strings.Contains(strings.ToLower(k.Name), query) ||
					strings.Contains(strings.ToLower(k.Data), query) {
					results = append(results, k)
				}
			}
		}
	}
	return marshalResult(results)
}

func (s *Server) toolListYaraRules(caseID string) (string, error) {
	rules, err := s.db.ListRules(caseID)
	if err != nil {
		return "", err
	}
	return marshalResult(rules)
}

func (s *Server) toolCreateYaraRule(caseID string, args map[string]interface{}) (string, error) {
	name := getStringArg(args, "name")
	content := getStringArg(args, "content")
	if name == "" || content == "" {
		return "", fmt.Errorf("name and content are required")
	}
	rule, err := s.db.CreateYaraRuleByName(caseID, name, content, "agent")
	if err != nil {
		return "", err
	}
	return marshalResult(rule)
}

func (s *Server) toolGetYaraResults(caseID string, args map[string]interface{}) (string, error) {
	ruleID := getStringArg(args, "rule_id")
	results, err := s.db.ListResults(caseID, ruleID)
	if err != nil {
		return "", err
	}
	return marshalResult(results)
}

func (s *Server) toolRecommendAction(caseID string, args map[string]interface{}) (string, error) {
	actionType := getStringArg(args, "type")
	title := getStringArg(args, "title")
	rationale := getStringArg(args, "rationale")
	steps := getStringArg(args, "steps")
	if title == "" || actionType == "" {
		return "", fmt.Errorf("type and title are required")
	}

	proposal := models.ActionProposal{
		ID:        uuid.New().String(),
		CaseID:    caseID,
		Type:      actionType,
		Title:     title,
		Rationale: rationale,
		Steps:     steps,
		Status:    "pending",
		CreatedAt: time.Now().UTC(),
	}
	if err := s.db.CreateProposal(proposal); err != nil {
		return "", err
	}

	s.audit.Log(caseID, "agent", "recommend_action", "recommend_action",
		fmt.Sprintf("proposed: %s - %s", actionType, title))

	return marshalResult(map[string]interface{}{
		"status":   "created",
		"message":  "Action proposal created. The investigator must review and approve it before execution.",
		"proposal": proposal,
	})
}

func (s *Server) toolGetAuditLog(caseID string, args map[string]interface{}) (string, error) {
	limit := getIntArg(args, "limit", 50)
	offset := getIntArg(args, "offset", 0)
	entries, err := s.db.GetAuditLog(caseID, limit, offset)
	if err != nil {
		return "", err
	}
	return marshalResult(entries)
}

func (s *Server) toolGetCollectionStatus(caseID string, args map[string]interface{}) (string, error) {
	jobs, err := s.db.ListJobs(caseID)
	if err != nil {
		return "", err
	}
	return marshalResult(jobs)
}

// ---------------------------------------------------------------------------
// Tool definitions for the agent
// ---------------------------------------------------------------------------

func (s *Server) buildAgentTools() []llm.ToolDefinition {
	return []llm.ToolDefinition{
		{
			Name:        "list_artifacts",
			Description: "List all evidence artifacts collected for this case. Returns artifact metadata including type, source, hash, and timestamps.",
			Parameters: jsonSchema(map[string]propDef{
				"limit":  {Type: "integer", Desc: "Max results (default 50)"},
				"offset": {Type: "integer", Desc: "Pagination offset"},
			}, nil),
		},
		{
			Name:        "read_artifact",
			Description: "Read the content of a specific artifact. Returns raw data (text preview for large artifacts). Use this to examine event logs, registry data, process lists, etc.",
			Parameters: jsonSchema(map[string]propDef{
				"artifact_id": {Type: "string", Desc: "The artifact ID to read"},
				"offset":      {Type: "integer", Desc: "Byte offset for chunked reading"},
				"length":      {Type: "integer", Desc: "Number of bytes to read (default 10000)"},
			}, []string{"artifact_id"}),
		},
		{
			Name:        "search_events",
			Description: "Full-text search across all normalized events (EVTX logs, etc.). Use this to find specific event IDs, error messages, suspicious commands, user activity, etc.",
			Parameters: jsonSchema(map[string]propDef{
				"query":  {Type: "string", Desc: "Search query (full-text search)"},
				"limit":  {Type: "integer", Desc: "Max results (default 50)"},
				"offset": {Type: "integer", Desc: "Pagination offset"},
			}, []string{"query"}),
		},
		{
			Name:        "get_event",
			Description: "Retrieve a single event by its ID. Use this to get full details of a specific event.",
			Parameters: jsonSchema(map[string]propDef{
				"event_id": {Type: "integer", Desc: "The event ID"},
			}, []string{"event_id"}),
		},
		{
			Name:        "get_timeline",
			Description: "Get a chronological timeline of all events. Supports time range filtering. Use this to understand the sequence of events.",
			Parameters: jsonSchema(map[string]propDef{
				"limit":      {Type: "integer", Desc: "Max results (default 100)"},
				"offset":     {Type: "integer", Desc: "Pagination offset"},
				"time_start": {Type: "string", Desc: "Start time (RFC3339)"},
				"time_end":   {Type: "string", Desc: "End time (RFC3339)"},
			}, nil),
		},
		{
			Name:        "get_persistence_items",
			Description: "Get all identified persistence mechanisms (registry autoruns, scheduled tasks, services, startup folders). Critical for finding how an attacker maintains access.",
			Parameters:  jsonSchema(nil, nil),
		},
		{
			Name:        "get_network_snapshot",
			Description: "Get the network state at collection time: active connections, DNS cache, ARP table, routing table. Useful for identifying C2 connections and lateral movement.",
			Parameters:  jsonSchema(nil, nil),
		},
		{
			Name:        "get_process_snapshot",
			Description: "Get running processes at collection time with PID, PPID, command lines, user context, and integrity levels. Useful for identifying suspicious processes.",
			Parameters:  jsonSchema(nil, nil),
		},
		{
			Name:        "get_execution_artifacts",
			Description: "Get parsed execution evidence from Prefetch, AmCache, and ShimCache. Shows what programs have been executed on the system.",
			Parameters: jsonSchema(map[string]propDef{
				"limit":  {Type: "integer", Desc: "Max results"},
				"offset": {Type: "integer", Desc: "Pagination offset"},
			}, nil),
		},
		{
			Name:        "get_recent_activity",
			Description: "Get parsed recent-activity evidence from shortcut files and Jump Lists. Useful for identifying recently accessed files, launched applications, and startup shortcut behavior.",
			Parameters: jsonSchema(map[string]propDef{
				"kind":   {Type: "string", Desc: "Optional filter: all, shortcut, or jumplist"},
				"limit":  {Type: "integer", Desc: "Max results"},
				"offset": {Type: "integer", Desc: "Pagination offset"},
			}, nil),
		},
		{
			Name:        "read_registry_keys",
			Description: "Read values from specific registry paths collected during evidence acquisition. Searches within stored registry data.",
			Parameters: jsonSchema(map[string]propDef{
				"path": {Type: "string", Desc: "Registry path to search for (e.g., 'CurrentVersion\\Run')"},
			}, []string{"path"}),
		},
		{
			Name:        "search_registry",
			Description: "Search all collected registry data for values matching a pattern. Useful for finding malware entries, suspicious paths, etc.",
			Parameters: jsonSchema(map[string]propDef{
				"pattern": {Type: "string", Desc: "Search pattern to match against registry paths, names, and values"},
			}, []string{"pattern"}),
		},
		{
			Name:        "list_yara_rules",
			Description: "List all YARA rules available for this case.",
			Parameters:  jsonSchema(nil, nil),
		},
		{
			Name:        "create_yara_rule",
			Description: "Create a new YARA rule (stored only, not executed automatically). Useful for creating detection rules based on identified IOCs.",
			Parameters: jsonSchema(map[string]propDef{
				"name":    {Type: "string", Desc: "Rule name"},
				"content": {Type: "string", Desc: "YARA rule content"},
			}, []string{"name", "content"}),
		},
		{
			Name:        "get_yara_results",
			Description: "Get results from YARA scans that have been run.",
			Parameters: jsonSchema(map[string]propDef{
				"rule_id": {Type: "string", Desc: "Filter by specific rule ID (optional)"},
			}, nil),
		},
		{
			Name:        "recommend_action",
			Description: "Recommend a response action for the investigator to review and approve. This creates a proposal — it does NOT execute anything. Use this to suggest containment, eradication, or recovery steps.",
			Parameters: jsonSchema(map[string]propDef{
				"type":      {Type: "string", Desc: "Action type: containment, eradication, recovery, investigation"},
				"title":     {Type: "string", Desc: "Short action title"},
				"rationale": {Type: "string", Desc: "Why this action is recommended"},
				"steps":     {Type: "string", Desc: "JSON array of step descriptions"},
			}, []string{"type", "title", "rationale"}),
		},
		{
			Name:        "get_audit_log",
			Description: "Retrieve the audit log showing all actions taken in this case.",
			Parameters: jsonSchema(map[string]propDef{
				"limit":  {Type: "integer", Desc: "Max entries (default 50)"},
				"offset": {Type: "integer", Desc: "Pagination offset"},
			}, nil),
		},
		{
			Name:        "get_collection_status",
			Description: "Get the status of evidence collection jobs for this case.",
			Parameters:  jsonSchema(nil, nil),
		},
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

type propDef struct {
	Type string
	Desc string
}

func jsonSchema(props map[string]propDef, required []string) map[string]interface{} {
	schema := map[string]interface{}{
		"type": "object",
	}
	if len(props) > 0 {
		properties := make(map[string]interface{})
		for name, def := range props {
			properties[name] = map[string]interface{}{
				"type":        def.Type,
				"description": def.Desc,
			}
		}
		schema["properties"] = properties
	}
	if len(required) > 0 {
		schema["required"] = required
	}
	return schema
}

func getStringArg(args map[string]interface{}, key string) string {
	if v, ok := args[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func getIntArg(args map[string]interface{}, key string, defaultVal int) int {
	if v, ok := args[key]; ok {
		switch n := v.(type) {
		case float64:
			return int(n)
		case int:
			return n
		case json.Number:
			if i, err := n.Int64(); err == nil {
				return int(i)
			}
		}
	}
	return defaultVal
}

func getInt64Arg(args map[string]interface{}, key string, defaultVal int64) int64 {
	if v, ok := args[key]; ok {
		switch n := v.(type) {
		case float64:
			return int64(n)
		case int64:
			return n
		case json.Number:
			if i, err := n.Int64(); err == nil {
				return i
			}
		}
	}
	return defaultVal
}

func marshalResult(v interface{}) (string, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return string(data), nil
}
