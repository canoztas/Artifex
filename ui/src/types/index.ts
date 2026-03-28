export interface Case {
  id: string
  name: string
  description: string
  status: 'active' | 'closed' | 'archived'
  created_at: string
  updated_at: string
  host?: HostMetadata
}

export interface HostMetadata {
  hostname: string
  os_version: string
  os_build: string
  architecture: string
  domain: string
  current_user: string
  boot_time: string
  install_date: string
  last_update: string
  timezone: string
}

export interface Artifact {
  id: string
  case_id: string
  type: string
  source: string
  path: string
  size: number
  sha256: string
  collected_at: string
  metadata: Record<string, string>
  blob_path?: string
  size_raw?: number
  size_compressed?: number
  collection_method?: string
  collector_version?: string
  privileges_used?: string
  compression?: string
}

export interface Event {
  id: number
  case_id: string
  timestamp: string
  source: string
  event_id: number
  level: 'Critical' | 'Error' | 'Warning' | 'Information' | 'Verbose'
  provider: string
  channel: string
  message: string
  raw_xml: string
  metadata: Record<string, string>
}

export interface CollectionJob {
  id: string
  case_id: string
  preset: string
  status: 'pending' | 'running' | 'completed' | 'failed'
  progress: number
  started_at: string
  completed_at: string
  steps: JobStep[]
  error: string
  time_range_hours: number
}

export interface JobStep {
  name: string
  status: 'pending' | 'running' | 'completed' | 'failed' | 'skipped'
  started_at: string
  completed_at: string
  items_collected: number
  error: string
}

export interface YaraRule {
  id: string
  case_id: string
  name: string
  content: string
  created_at: string
}

export interface YaraResult {
  id: string
  case_id: string
  rule_id: string
  rule_name: string
  artifact_id: string
  artifact_path: string
  matches: YaraMatch[]
  scanned_at: string
}

export interface YaraMatch {
  rule: string
  namespace: string
  strings: YaraStringMatch[]
}

export interface YaraStringMatch {
  name: string
  offset: number
  data: string
}

export interface ActionProposal {
  id: string
  case_id: string
  type: string
  title: string
  description: string
  rationale: string
  steps: string[]
  status: 'pending' | 'approved' | 'rejected' | 'executed'
  created_at: string
  reviewed_at: string
  executed_at: string
  result: string
  risk_level: 'low' | 'medium' | 'high' | 'critical'
}

export interface AuditEntry {
  id: string
  case_id: string
  timestamp: string
  actor: string
  action: string
  resource_type: string
  resource_id: string
  details: string
  metadata: Record<string, string>
}

export interface PersistenceItem {
  id: string
  case_id: string
  type: string
  name: string
  path: string
  details: string
  suspicious: boolean
  collected_at: string
}

export interface NetworkSnapshot {
  connections: NetworkConnection[]
  dns_cache: DNSCacheEntry[]
  arp_table: ARPEntry[]
  routes: RouteEntry[]
  collected_at: string
}

export interface NetworkConnection {
  protocol: string
  local_address: string
  local_port: number
  remote_address: string
  remote_port: number
  state: string
  pid: number
  process_name: string
}

export interface DNSCacheEntry {
  name: string
  type: string
  data: string
  ttl: number
}

export interface ARPEntry {
  ip_address: string
  mac_address: string
  type: string
  interface: string
}

export interface RouteEntry {
  destination: string
  netmask: string
  gateway: string
  interface: string
  metric: number
}

export interface ProcessInfo {
  pid: number
  name: string
  path: string
  command_line: string
  parent_pid: number
  user: string
  cpu_percent: number
  memory_mb: number
  start_time: string
  status: string
}

export interface ServiceInfo {
  name: string
  display_name: string
  status: string
  start_type: string
  path: string
  account: string
  pid: number
}

export interface ScheduledTaskInfo {
  name: string
  path: string
  status: string
  next_run: string
  last_run: string
  last_result: string
  command: string
  author: string
}

export interface PaginatedResponse<T> {
  items: T[]
  next_cursor?: string
  total: number
  has_more?: boolean
}

// ── Agent Chat ────────────────────────────────────────

export interface AgentStep {
  type: 'thinking' | 'tool_call' | 'tool_result' | 'response'
  timestamp: string
  content?: string
  tool_name?: string
  tool_args?: string
  tool_result?: string
  is_error?: boolean
}

export interface AgentChatResponse {
  answer: string
  steps: AgentStep[]
  error?: string
}

export interface ChatMessage {
  role: 'user' | 'assistant'
  content: string
  steps?: AgentStep[]
  timestamp: string
}
