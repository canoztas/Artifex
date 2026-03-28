package mcp

// AllTools returns the complete list of MCP tool definitions with their JSON
// Schema input specifications. Every tool is scoped to a case_id to prevent
// cross-case data access. Tools are read-only except for start_collection,
// create_yara_rule, yara_scan, and recommend_action which create records but
// never modify existing data or the underlying system.
func AllTools() []Tool {
	return []Tool{
		startCollectionTool(),
		getCollectionStatusTool(),
		listArtifactsTool(),
		readArtifactTool(),
		listEventSourcesTool(),
		searchEventsTool(),
		getEventTool(),
		getTimelineTool(),
		readRegistryKeysTool(),
		searchRegistryTool(),
		yaraScanTool(),
		getPersistenceItemsTool(),
		getExecutionArtifactsTool(),
		getNetworkSnapshotTool(),
		listYaraRulesTool(),
		createYaraRuleTool(),
		getYaraResultsTool(),
		recommendActionTool(),
		getAuditLogTool(),
		getProcessSnapshotTool(),
	}
}

// ---------------------------------------------------------------------------
// Tool 1: start_collection
// ---------------------------------------------------------------------------

func startCollectionTool() Tool {
	return Tool{
		Name:        "start_collection",
		Description: "Start an evidence collection job on the target host. Creates a new collection job with the specified preset and time range. The collection runs asynchronously; use get_collection_status to monitor progress.",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"case_id": map[string]interface{}{
					"type":        "string",
					"description": "The case ID to collect evidence for.",
				},
				"preset": map[string]interface{}{
					"type":        "string",
					"enum":        []string{"standard", "deep"},
					"description": "Collection preset. 'standard' collects common artifacts (event logs, prefetch, registry). 'deep' adds memory, full MFT, and volume shadow copies.",
				},
				"time_range_hours": map[string]interface{}{
					"type":        "integer",
					"minimum":     1,
					"maximum":     8760,
					"description": "How many hours back from now to collect time-scoped artifacts (e.g. event logs). Default: 72.",
				},
			},
			"required":             []string{"case_id", "preset"},
			"additionalProperties": false,
		},
	}
}

// ---------------------------------------------------------------------------
// Tool 2: get_collection_status
// ---------------------------------------------------------------------------

func getCollectionStatusTool() Tool {
	return Tool{
		Name:        "get_collection_status",
		Description: "Get the current status and progress of a collection job. Returns status (pending, running, completed, failed), progress percentage, and step-level details.",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"case_id": map[string]interface{}{
					"type":        "string",
					"description": "The case ID the job belongs to.",
				},
				"job_id": map[string]interface{}{
					"type":        "string",
					"description": "The collection job ID to check.",
				},
			},
			"required":             []string{"case_id", "job_id"},
			"additionalProperties": false,
		},
	}
}

// ---------------------------------------------------------------------------
// Tool 3: list_artifacts
// ---------------------------------------------------------------------------

func listArtifactsTool() Tool {
	return Tool{
		Name:        "list_artifacts",
		Description: "List collected evidence artifacts for a case. Returns artifact metadata including type, source, SHA-256 hash, and sizes. Supports pagination.",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"case_id": map[string]interface{}{
					"type":        "string",
					"description": "The case ID to list artifacts for.",
				},
				"cursor": map[string]interface{}{
					"type":        "string",
					"description": "Pagination cursor from a previous response. Omit for the first page.",
				},
				"limit": map[string]interface{}{
					"type":        "integer",
					"minimum":     1,
					"maximum":     MaxPageSize,
					"description": "Maximum number of artifacts to return. Default: 100.",
				},
			},
			"required":             []string{"case_id"},
			"additionalProperties": false,
		},
	}
}

// ---------------------------------------------------------------------------
// Tool 4: read_artifact
// ---------------------------------------------------------------------------

func readArtifactTool() Tool {
	return Tool{
		Name:        "read_artifact",
		Description: "Read a chunk of raw data from a collected artifact. The artifact is decompressed and the specified byte range is returned as base64-encoded text. Use offset and length for large artifacts.",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"case_id": map[string]interface{}{
					"type":        "string",
					"description": "The case ID the artifact belongs to.",
				},
				"artifact_id": map[string]interface{}{
					"type":        "string",
					"description": "The artifact ID to read.",
				},
				"offset": map[string]interface{}{
					"type":        "integer",
					"minimum":     0,
					"description": "Byte offset to start reading from. Default: 0.",
				},
				"length": map[string]interface{}{
					"type":        "integer",
					"minimum":     1,
					"maximum":     1048576,
					"description": "Number of bytes to read. Maximum 1MB (1048576). Default: 65536.",
				},
			},
			"required":             []string{"case_id", "artifact_id"},
			"additionalProperties": false,
		},
	}
}

// ---------------------------------------------------------------------------
// Tool 5: list_event_sources
// ---------------------------------------------------------------------------

func listEventSourcesTool() Tool {
	return Tool{
		Name:        "list_event_sources",
		Description: "List all parsed event sources for a case, grouped by source and channel. Returns event counts and time ranges for each source. Useful for understanding what data is available before searching.",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"case_id": map[string]interface{}{
					"type":        "string",
					"description": "The case ID to list event sources for.",
				},
			},
			"required":             []string{"case_id"},
			"additionalProperties": false,
		},
	}
}

// ---------------------------------------------------------------------------
// Tool 6: search_events
// ---------------------------------------------------------------------------

func searchEventsTool() Tool {
	return Tool{
		Name:        "search_events",
		Description: "Search parsed events using SQLite FTS5 full-text search. Supports boolean queries (AND, OR, NOT), phrase matching, and prefix matching. Results can be filtered by time range. Returns matching events with pagination.",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"case_id": map[string]interface{}{
					"type":        "string",
					"description": "The case ID to search within.",
				},
				"query": map[string]interface{}{
					"type":        "string",
					"description": "FTS5 search query. Supports AND, OR, NOT operators, quoted phrases, and prefix matching with *. Example: '\"powershell\" AND (\"encoded\" OR \"bypass\")'.",
				},
				"cursor": map[string]interface{}{
					"type":        "string",
					"description": "Pagination cursor from a previous response.",
				},
				"limit": map[string]interface{}{
					"type":        "integer",
					"minimum":     1,
					"maximum":     MaxPageSize,
					"description": "Maximum number of events to return. Default: 100.",
				},
				"time_start": map[string]interface{}{
					"type":        "string",
					"format":      "date-time",
					"description": "Filter events on or after this RFC 3339 timestamp.",
				},
				"time_end": map[string]interface{}{
					"type":        "string",
					"format":      "date-time",
					"description": "Filter events on or before this RFC 3339 timestamp.",
				},
			},
			"required":             []string{"case_id", "query"},
			"additionalProperties": false,
		},
	}
}

// ---------------------------------------------------------------------------
// Tool 7: get_event
// ---------------------------------------------------------------------------

func getEventTool() Tool {
	return Tool{
		Name:        "get_event",
		Description: "Get a single event by its ID, including the full raw_data field. Use this to inspect the complete details of an event found via search_events or get_timeline.",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"case_id": map[string]interface{}{
					"type":        "string",
					"description": "The case ID the event belongs to.",
				},
				"event_id": map[string]interface{}{
					"type":        "integer",
					"description": "The numeric event ID to retrieve.",
				},
			},
			"required":             []string{"case_id", "event_id"},
			"additionalProperties": false,
		},
	}
}

// ---------------------------------------------------------------------------
// Tool 8: get_timeline
// ---------------------------------------------------------------------------

func getTimelineTool() Tool {
	return Tool{
		Name:        "get_timeline",
		Description: "Get a chronological timeline of all events for a case. Events are sorted by timestamp. Supports time range filtering and pagination. Useful for building a sequence of events during an incident.",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"case_id": map[string]interface{}{
					"type":        "string",
					"description": "The case ID to get the timeline for.",
				},
				"cursor": map[string]interface{}{
					"type":        "string",
					"description": "Pagination cursor from a previous response.",
				},
				"limit": map[string]interface{}{
					"type":        "integer",
					"minimum":     1,
					"maximum":     MaxPageSize,
					"description": "Maximum number of timeline entries to return. Default: 100.",
				},
				"time_start": map[string]interface{}{
					"type":        "string",
					"format":      "date-time",
					"description": "Filter events on or after this RFC 3339 timestamp.",
				},
				"time_end": map[string]interface{}{
					"type":        "string",
					"format":      "date-time",
					"description": "Filter events on or before this RFC 3339 timestamp.",
				},
			},
			"required":             []string{"case_id"},
			"additionalProperties": false,
		},
	}
}

// ---------------------------------------------------------------------------
// Tool 9: read_registry_keys
// ---------------------------------------------------------------------------

func readRegistryKeysTool() Tool {
	return Tool{
		Name:        "read_registry_keys",
		Description: "Read collected registry values at a specific registry key path. Returns all values under the given key including name, type (REG_SZ, REG_DWORD, etc.), data, and last modified timestamp.",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"case_id": map[string]interface{}{
					"type":        "string",
					"description": "The case ID to read registry data from.",
				},
				"path": map[string]interface{}{
					"type":        "string",
					"description": "Full registry key path, e.g. 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run'.",
				},
			},
			"required":             []string{"case_id", "path"},
			"additionalProperties": false,
		},
	}
}

// ---------------------------------------------------------------------------
// Tool 10: search_registry
// ---------------------------------------------------------------------------

func searchRegistryTool() Tool {
	return Tool{
		Name:        "search_registry",
		Description: "Search collected registry entries by pattern within a root path. Matches against both value names and data. Limited to 1000 results.",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"case_id": map[string]interface{}{
					"type":        "string",
					"description": "The case ID to search registry data in.",
				},
				"root_path": map[string]interface{}{
					"type":        "string",
					"description": "Root registry path to search under, e.g. 'HKLM\\SOFTWARE'. All subkeys under this path are searched.",
				},
				"pattern": map[string]interface{}{
					"type":        "string",
					"description": "Search pattern to match against value names and data. Supports SQL LIKE wildcards internally.",
				},
			},
			"required":             []string{"case_id", "root_path", "pattern"},
			"additionalProperties": false,
		},
	}
}

// ---------------------------------------------------------------------------
// Tool 11: yara_scan
// ---------------------------------------------------------------------------

func yaraScanTool() Tool {
	return Tool{
		Name:        "yara_scan",
		Description: "Submit a YARA scan job against a specific evidence artifact. The scan runs asynchronously on the worker. Use get_yara_results to retrieve the findings once complete.",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"case_id": map[string]interface{}{
					"type":        "string",
					"description": "The case ID the scan belongs to.",
				},
				"rule_id": map[string]interface{}{
					"type":        "string",
					"description": "The ID of the YARA rule to scan with (must already exist via create_yara_rule or list_yara_rules).",
				},
				"artifact_id": map[string]interface{}{
					"type":        "string",
					"description": "The artifact ID to scan.",
				},
			},
			"required":             []string{"case_id", "rule_id", "artifact_id"},
			"additionalProperties": false,
		},
	}
}

// ---------------------------------------------------------------------------
// Tool 12: get_persistence_items
// ---------------------------------------------------------------------------

func getPersistenceItemsTool() Tool {
	return Tool{
		Name:        "get_persistence_items",
		Description: "Get all identified persistence mechanisms for a case. Returns registry run keys, services, scheduled tasks, startup folder entries, and other persistence vectors that have been parsed from collected evidence.",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"case_id": map[string]interface{}{
					"type":        "string",
					"description": "The case ID to get persistence items for.",
				},
			},
			"required":             []string{"case_id"},
			"additionalProperties": false,
		},
	}
}

// ---------------------------------------------------------------------------
// Tool 13: get_execution_artifacts
// ---------------------------------------------------------------------------

func getExecutionArtifactsTool() Tool {
	return Tool{
		Name:        "get_execution_artifacts",
		Description: "Get execution evidence for a case: prefetch entries, shimcache, amcache, userassist, and BAM (Background Activity Moderator) data. Useful for determining what programs have been run on the system.",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"case_id": map[string]interface{}{
					"type":        "string",
					"description": "The case ID to get execution artifacts for.",
				},
				"cursor": map[string]interface{}{
					"type":        "string",
					"description": "Pagination cursor from a previous response.",
				},
				"limit": map[string]interface{}{
					"type":        "integer",
					"minimum":     1,
					"maximum":     MaxPageSize,
					"description": "Maximum number of entries to return. Default: 100.",
				},
			},
			"required":             []string{"case_id"},
			"additionalProperties": false,
		},
	}
}

// ---------------------------------------------------------------------------
// Tool 14: get_network_snapshot
// ---------------------------------------------------------------------------

func getNetworkSnapshotTool() Tool {
	return Tool{
		Name:        "get_network_snapshot",
		Description: "Get the network state snapshot captured during evidence collection. Includes active connections (with PIDs and process names), DNS resolver cache, ARP table, and routing table.",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"case_id": map[string]interface{}{
					"type":        "string",
					"description": "The case ID to get the network snapshot for.",
				},
			},
			"required":             []string{"case_id"},
			"additionalProperties": false,
		},
	}
}

// ---------------------------------------------------------------------------
// Tool 15: list_yara_rules
// ---------------------------------------------------------------------------

func listYaraRulesTool() Tool {
	return Tool{
		Name:        "list_yara_rules",
		Description: "List all YARA rules defined for a case. Returns rule ID, name, content, and who created it.",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"case_id": map[string]interface{}{
					"type":        "string",
					"description": "The case ID to list YARA rules for.",
				},
			},
			"required":             []string{"case_id"},
			"additionalProperties": false,
		},
	}
}

// ---------------------------------------------------------------------------
// Tool 16: create_yara_rule
// ---------------------------------------------------------------------------

func createYaraRuleTool() Tool {
	return Tool{
		Name:        "create_yara_rule",
		Description: "Create and store a new YARA rule for a case. The rule is stored only and NOT executed until yara_scan is called. The rule content must be valid YARA syntax.",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"case_id": map[string]interface{}{
					"type":        "string",
					"description": "The case ID to create the rule for.",
				},
				"name": map[string]interface{}{
					"type":        "string",
					"description": "Human-readable name for the rule.",
				},
				"content": map[string]interface{}{
					"type":        "string",
					"description": "The YARA rule content in valid YARA syntax.",
				},
			},
			"required":             []string{"case_id", "name", "content"},
			"additionalProperties": false,
		},
	}
}

// ---------------------------------------------------------------------------
// Tool 17: get_yara_results
// ---------------------------------------------------------------------------

func getYaraResultsTool() Tool {
	return Tool{
		Name:        "get_yara_results",
		Description: "Get YARA scan results for a specific rule. Returns match details including which artifacts matched and the specific match offsets and strings.",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"case_id": map[string]interface{}{
					"type":        "string",
					"description": "The case ID the scan belongs to.",
				},
				"rule_id": map[string]interface{}{
					"type":        "string",
					"description": "The YARA rule ID to get results for.",
				},
			},
			"required":             []string{"case_id", "rule_id"},
			"additionalProperties": false,
		},
	}
}

// ---------------------------------------------------------------------------
// Tool 18: recommend_action
// ---------------------------------------------------------------------------

func recommendActionTool() Tool {
	return Tool{
		Name:        "recommend_action",
		Description: "Create an advisory action proposal for the human analyst to review. This does NOT execute any action. The proposal includes a type, title, rationale, and ordered steps. The analyst must approve and execute the action separately.",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"case_id": map[string]interface{}{
					"type":        "string",
					"description": "The case ID this recommendation applies to.",
				},
				"type": map[string]interface{}{
					"type":        "string",
					"enum":        []string{"isolate", "collect_additional", "remediate", "escalate", "monitor", "other"},
					"description": "The category of recommended action.",
				},
				"title": map[string]interface{}{
					"type":        "string",
					"description": "Short title summarizing the recommended action.",
				},
				"rationale": map[string]interface{}{
					"type":        "string",
					"description": "Detailed explanation of why this action is recommended, citing specific evidence.",
				},
				"steps": map[string]interface{}{
					"type": "array",
					"items": map[string]interface{}{
						"type": "string",
					},
					"description": "Ordered list of steps to carry out the recommended action.",
				},
			},
			"required":             []string{"case_id", "type", "title", "rationale", "steps"},
			"additionalProperties": false,
		},
	}
}

// ---------------------------------------------------------------------------
// Tool 19: get_audit_log
// ---------------------------------------------------------------------------

func getAuditLogTool() Tool {
	return Tool{
		Name:        "get_audit_log",
		Description: "Get the hash-chained audit log for a case. Every tool invocation and action is recorded. Returns entries with timestamps, actor, action, tool name, details, and cryptographic hash chain.",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"case_id": map[string]interface{}{
					"type":        "string",
					"description": "The case ID to get the audit log for.",
				},
				"limit": map[string]interface{}{
					"type":        "integer",
					"minimum":     1,
					"maximum":     MaxPageSize,
					"description": "Maximum number of entries to return. Default: 100.",
				},
				"offset": map[string]interface{}{
					"type":        "integer",
					"minimum":     0,
					"description": "Number of entries to skip for pagination. Default: 0.",
				},
			},
			"required":             []string{"case_id"},
			"additionalProperties": false,
		},
	}
}

// ---------------------------------------------------------------------------
// Tool 20: get_process_snapshot
// ---------------------------------------------------------------------------

func getProcessSnapshotTool() Tool {
	return Tool{
		Name:        "get_process_snapshot",
		Description: "Get a snapshot of running processes, services, or scheduled tasks captured during evidence collection. Processes include PID, PPID, image path, command line, and user context. Services include binary path and startup type. Tasks include triggers and actions.",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"case_id": map[string]interface{}{
					"type":        "string",
					"description": "The case ID to get the snapshot for.",
				},
				"type": map[string]interface{}{
					"type":        "string",
					"enum":        []string{"processes", "services", "tasks"},
					"description": "Which type of snapshot data to return.",
				},
			},
			"required":             []string{"case_id", "type"},
			"additionalProperties": false,
		},
	}
}
