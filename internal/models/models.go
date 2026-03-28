package models

import "time"

// Case represents a DFIR investigation case.
type Case struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	Status      string    `json:"status"` // active, closed, archived
}

// Artifact represents a collected evidence artifact.
type Artifact struct {
	ID               string    `json:"id"`
	CaseID           string    `json:"case_id"`
	Type             string    `json:"type"`
	Source           string    `json:"source"`
	CollectionMethod string    `json:"collection_method"`
	CollectorVersion string    `json:"collector_version"`
	PrivilegesUsed   string    `json:"privileges_used"`
	SHA256           string    `json:"sha256"`
	Compression      string    `json:"compression"`
	SizeRaw          int64     `json:"size_raw"`
	SizeCompressed   int64     `json:"size_compressed"`
	CollectedAt      time.Time `json:"collected_at"`
	BlobPath         string    `json:"blob_path"`
}

// Event represents a normalized event from any source.
type Event struct {
	ID         int64     `json:"id"`
	CaseID     string    `json:"case_id"`
	ArtifactID string    `json:"artifact_id"`
	Timestamp  time.Time `json:"timestamp"`
	Source     string    `json:"source"`
	EventID    int       `json:"event_id"`
	Level      string    `json:"level"`
	Channel    string    `json:"channel"`
	Provider   string    `json:"provider"`
	Computer   string    `json:"computer"`
	Message    string    `json:"message"`
	RawData    string    `json:"raw_data"`
}

// CollectionJob tracks a collection operation.
type CollectionJob struct {
	ID                 string     `json:"id"`
	CaseID             string     `json:"case_id"`
	Preset             string     `json:"preset"` // standard, deep
	Status             string     `json:"status"` // pending, running, completed, failed
	Progress           float64    `json:"progress"`
	StartedAt          *time.Time `json:"started_at"`
	CompletedAt        *time.Time `json:"completed_at"`
	Error              string     `json:"error,omitempty"`
	ArtifactsCollected int        `json:"artifacts_collected"`
	Steps              []JobStep  `json:"steps,omitempty"`
}

// JobStep tracks individual collection steps within a job.
type JobStep struct {
	Name     string  `json:"name"`
	Status   string  `json:"status"` // pending, running, completed, failed, skipped
	Progress float64 `json:"progress"`
	Error    string  `json:"error,omitempty"`
}

// YaraRule is a stored YARA rule.
type YaraRule struct {
	ID        string    `json:"id"`
	CaseID    string    `json:"case_id"`
	Name      string    `json:"name"`
	Content   string    `json:"content"`
	CreatedAt time.Time `json:"created_at"`
	CreatedBy string    `json:"created_by"` // user or agent
}

// YaraResult stores YARA scan results.
type YaraResult struct {
	ID         int64     `json:"id"`
	CaseID     string    `json:"case_id"`
	RuleID     string    `json:"rule_id"`
	RuleName   string    `json:"rule_name"`
	ArtifactID string    `json:"artifact_id"`
	Matches    string    `json:"matches"` // JSON array of match details
	ScannedAt  time.Time `json:"scanned_at"`
}

// ActionProposal is an AI-recommended action for user approval.
type ActionProposal struct {
	ID         string     `json:"id"`
	CaseID     string     `json:"case_id"`
	Type       string     `json:"type"`
	Title      string     `json:"title"`
	Rationale  string     `json:"rationale"`
	Steps      string     `json:"steps"` // JSON array of step descriptions
	Status     string     `json:"status"` // pending, approved, rejected, executed
	CreatedAt  time.Time  `json:"created_at"`
	ApprovedAt *time.Time `json:"approved_at,omitempty"`
	ExecutedAt *time.Time `json:"executed_at,omitempty"`
	Result     string     `json:"result,omitempty"`
}

// AuditEntry is an append-only audit log entry.
type AuditEntry struct {
	ID        int64     `json:"id"`
	CaseID    string    `json:"case_id"`
	Timestamp time.Time `json:"timestamp"`
	Actor     string    `json:"actor"` // user, agent, system, collector
	Action    string    `json:"action"`
	Tool      string    `json:"tool,omitempty"`
	Details   string    `json:"details,omitempty"`
	PrevHash  string    `json:"prev_hash"`
	EntryHash string    `json:"entry_hash"`
}

// HostMetadata captures system identification at collection time.
type HostMetadata struct {
	Hostname     string `json:"hostname"`
	MachineSID   string `json:"machine_sid"`
	OSVersion    string `json:"os_version"`
	OSBuild      string `json:"os_build"`
	Architecture string `json:"architecture"`
	BootTime     string `json:"boot_time"`
	Timezone     string `json:"timezone"`
	Domain       string `json:"domain"`
	Users        string `json:"users"` // JSON array
}

// ProcessInfo captures running process data.
type ProcessInfo struct {
	PID            int    `json:"pid"`
	PPID           int    `json:"ppid"`
	Name           string `json:"name"`
	ImagePath      string `json:"image_path"`
	CommandLine    string `json:"command_line"`
	UserContext    string `json:"user_context"`
	StartTime      string `json:"start_time"`
	SessionID      int    `json:"session_id"`
	IntegrityLevel string `json:"integrity_level"`
}

// ServiceInfo captures Windows service data.
type ServiceInfo struct {
	Name           string `json:"name"`
	DisplayName    string `json:"display_name"`
	BinaryPath     string `json:"binary_path"`
	StartupType    string `json:"startup_type"`
	CurrentState   string `json:"current_state"`
	ServiceAccount string `json:"service_account"`
}

// ScheduledTaskInfo captures scheduled task data.
type ScheduledTaskInfo struct {
	Name        string `json:"name"`
	Path        string `json:"path"`
	Triggers    string `json:"triggers"` // JSON
	Actions     string `json:"actions"`  // JSON
	RunAsUser   string `json:"run_as_user"`
	LastRunTime string `json:"last_run_time"`
	Status      string `json:"status"`
}

// NetworkConnection captures network state.
type NetworkConnection struct {
	Protocol    string `json:"protocol"`
	LocalAddr   string `json:"local_addr"`
	LocalPort   int    `json:"local_port"`
	RemoteAddr  string `json:"remote_addr"`
	RemotePort  int    `json:"remote_port"`
	State       string `json:"state"`
	PID         int    `json:"pid"`
	ProcessName string `json:"process_name"`
}

// DNSCacheEntry captures a DNS resolver cache entry.
type DNSCacheEntry struct {
	Name   string `json:"name"`
	Type   string `json:"type"`
	TTL    int    `json:"ttl"`
	Record string `json:"record"`
}

// ARPEntry captures an ARP table entry.
type ARPEntry struct {
	Interface  string `json:"interface"`
	IPAddress  string `json:"ip_address"`
	MACAddress string `json:"mac_address"`
	Type       string `json:"type"`
}

// RouteEntry captures a routing table entry.
type RouteEntry struct {
	Destination string `json:"destination"`
	Netmask     string `json:"netmask"`
	Gateway     string `json:"gateway"`
	Interface   string `json:"interface"`
	Metric      int    `json:"metric"`
}

// NetworkSnapshot aggregates all network state.
type NetworkSnapshot struct {
	Connections []NetworkConnection `json:"connections"`
	DNSCache    []DNSCacheEntry     `json:"dns_cache"`
	ARPTable    []ARPEntry          `json:"arp_table"`
	Routes      []RouteEntry        `json:"routes"`
}

// PersistenceItem is a parsed persistence mechanism.
type PersistenceItem struct {
	ID       string `json:"id"`
	CaseID   string `json:"case_id"`
	Type     string `json:"type"` // registry_run, service, scheduled_task, startup_folder, etc.
	Location string `json:"location"`
	Value    string `json:"value"`
	Details  string `json:"details"`
}

// RegistryKeyValue represents a registry key/value pair.
type RegistryKeyValue struct {
	Path     string `json:"path"`
	Name     string `json:"name"`
	Type     string `json:"type"` // REG_SZ, REG_DWORD, etc.
	Data     string `json:"data"`
	Modified string `json:"modified,omitempty"`
}

// FileMetadata for filesystem metadata collection.
type FileMetadata struct {
	Path         string `json:"path"`
	Size         int64  `json:"size"`
	Created      string `json:"created"`
	Modified     string `json:"modified"`
	Accessed     string `json:"accessed"`
	SHA256       string `json:"sha256,omitempty"`
	IsDirectory  bool   `json:"is_directory"`
	Owner        string `json:"owner,omitempty"`
}

// CollectionConfig holds parameters for a collection job.
type CollectionConfig struct {
	CaseID          string   `json:"case_id"`
	Preset          string   `json:"preset"` // standard, deep
	TimeRangeHours  int      `json:"time_range_hours"`
	IncludeMemory   bool     `json:"include_memory"`
	MemoryApproved  bool     `json:"memory_approved"`
	CustomChannels  []string `json:"custom_channels,omitempty"`
}

// Pagination parameters for list queries.
type PaginationParams struct {
	Cursor   string `json:"cursor,omitempty"`
	Limit    int    `json:"limit"`
	Offset   int    `json:"offset"`
}

// PaginatedResponse wraps a paginated result set.
type PaginatedResponse struct {
	Data       interface{} `json:"data"`
	NextCursor string      `json:"next_cursor,omitempty"`
	Total      int         `json:"total"`
	HasMore    bool        `json:"has_more"`
}

// LLMConfig holds AI provider configuration.
type LLMConfig struct {
	Provider          string `json:"provider"` // anthropic, openai
	APIKey            string `json:"api_key"`
	Model             string `json:"model"`
	MaxTokens         int    `json:"max_tokens"`
	Temperature       float64 `json:"temperature"`
	TimeoutMS         int    `json:"timeout_ms"`
	Retries           int    `json:"retries"`
	RedactionMode     string `json:"redaction_mode"` // off, basic, strict
	DataHandlingNotice string `json:"data_handling_notice"`
}

// AppConfig is the top-level application configuration.
type AppConfig struct {
	APIPort       int       `json:"api_port"`
	CollectorPort int       `json:"collector_port"`
	MCPPort       int       `json:"mcp_port"`
	WorkerPort    int       `json:"worker_port"`
	DataDir       string    `json:"data_dir"`
	LLM           LLMConfig `json:"llm"`
	BindAddress   string    `json:"bind_address"` // must be 127.0.0.1
}
