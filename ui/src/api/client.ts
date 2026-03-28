import type {
  Case,
  Artifact,
  Event,
  CollectionJob,
  YaraRule,
  YaraResult,
  ActionProposal,
  AuditEntry,
  PersistenceItem,
  NetworkSnapshot,
  ProcessInfo,
  PaginatedResponse,
  AgentChatResponse,
} from '../types'

const BASE = '/api'

type RawPaginatedResponse<T> = {
  items?: T[]
  data?: T[]
  next_cursor?: string
  total?: number
  has_more?: boolean
}

type RawArtifact = Partial<Artifact> & {
  id: string
  case_id?: string
  type?: string
  source?: string
  path?: string
  blob_path?: string
  size?: number
  size_raw?: number
  size_compressed?: number
  sha256?: string
  collected_at?: string
  collection_method?: string
  collector_version?: string
  privileges_used?: string
  compression?: string
}

type RawEvent = Partial<Event> & {
  id: number
  case_id?: string
  timestamp?: string
  source?: string
  event_id?: number
  level?: string
  provider?: string
  channel?: string
  message?: string
  raw_xml?: string
  raw_data?: string
  metadata?: Record<string, string>
}

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    headers: {
      'Content-Type': 'application/json',
      ...options?.headers,
    },
    ...options,
  })
  if (!res.ok) {
    const body = await res.text()
    throw new Error(`API error ${res.status}: ${body}`)
  }
  if (res.status === 204) {
    return undefined as T
  }
  return res.json()
}

function normalizeArtifact(raw: RawArtifact): Artifact {
  const path = raw.path || raw.source || raw.blob_path || ''

  return {
    id: raw.id,
    case_id: raw.case_id || '',
    type: raw.type || 'unknown',
    source: raw.source || raw.path || raw.blob_path || raw.type || 'unknown',
    path,
    size: raw.size ?? raw.size_raw ?? 0,
    sha256: raw.sha256 || '',
    collected_at: raw.collected_at || '',
    metadata: raw.metadata ?? {},
    blob_path: raw.blob_path,
    size_raw: raw.size_raw,
    size_compressed: raw.size_compressed,
    collection_method: raw.collection_method,
    collector_version: raw.collector_version,
    privileges_used: raw.privileges_used,
    compression: raw.compression,
  }
}

function normalizeEvent(raw: RawEvent): Event {
  let level: Event['level']
  switch (raw.level) {
    case 'Critical':
    case 'Error':
    case 'Warning':
    case 'Information':
    case 'Verbose':
      level = raw.level
      break
    default:
      level = 'Information'
      break
  }

  return {
    id: raw.id,
    case_id: raw.case_id || '',
    timestamp: raw.timestamp || '',
    source: raw.source || '',
    event_id: raw.event_id ?? 0,
    level,
    provider: raw.provider || '',
    channel: raw.channel || '',
    message: raw.message || '',
    raw_xml: raw.raw_xml || raw.raw_data || '',
    metadata: raw.metadata ?? {},
  }
}

function normalizePaginatedResponse<T>(
  raw: RawPaginatedResponse<T>,
  offset: number,
  limit?: number
): PaginatedResponse<T> {
  const items = raw.items ?? raw.data ?? []
  const total = raw.total ?? items.length
  const resolvedLimit = limit ?? items.length
  const hasMore = raw.has_more ?? offset+items.length < total
  const nextCursor =
    raw.next_cursor ?? (hasMore ? String(offset + resolvedLimit) : undefined)

  return {
    items,
    total,
    has_more: hasMore,
    next_cursor: nextCursor,
  }
}

// ── Cases ──────────────────────────────────────────────

export async function createCase(name: string, description: string): Promise<Case> {
  return request<Case>('/cases', {
    method: 'POST',
    body: JSON.stringify({ name, description }),
  })
}

export async function listCases(): Promise<Case[]> {
  return request<Case[]>('/cases')
}

export async function getCase(id: string): Promise<Case> {
  return request<Case>(`/cases/${id}`)
}

export async function updateCaseStatus(id: string, status: string): Promise<void> {
  return request<void>(`/cases/${id}/status`, {
    method: 'PUT',
    body: JSON.stringify({ status }),
  })
}

export async function deleteCase(id: string): Promise<void> {
  return request<void>(`/cases/${id}`, {
    method: 'DELETE',
  })
}

// ── Collections ────────────────────────────────────────

export async function startCollection(
  caseId: string,
  preset: string,
  timeRangeHours: number
): Promise<CollectionJob> {
  return request<CollectionJob>(`/cases/${caseId}/collections`, {
    method: 'POST',
    body: JSON.stringify({ preset, time_range_hours: timeRangeHours }),
  })
}

export async function listCollections(caseId: string): Promise<CollectionJob[]> {
  return request<CollectionJob[]>(`/cases/${caseId}/collections`)
}

export async function getCollectionStatus(caseId: string, jobId: string): Promise<CollectionJob> {
  return request<CollectionJob>(`/cases/${caseId}/collections/${jobId}`)
}

// ── Artifacts ──────────────────────────────────────────

export async function listArtifacts(
  caseId: string,
  cursor?: string,
  limit?: number
): Promise<PaginatedResponse<Artifact>> {
  const offset = Number.parseInt(cursor || '0', 10)
  const params = new URLSearchParams()
  if (!Number.isNaN(offset) && offset > 0) params.set('offset', String(offset))
  if (limit) params.set('limit', String(limit))
  const qs = params.toString()
  const response = await request<RawPaginatedResponse<RawArtifact>>(
    `/cases/${caseId}/artifacts${qs ? `?${qs}` : ''}`
  )

  const normalized = normalizePaginatedResponse(response, Number.isNaN(offset) ? 0 : offset, limit)
  return {
    ...normalized,
    items: normalized.items.map(normalizeArtifact),
  }
}

export async function getArtifact(caseId: string, artifactId: string): Promise<Artifact> {
  const artifact = await request<RawArtifact>(`/cases/${caseId}/artifacts/${artifactId}`)
  return normalizeArtifact(artifact)
}

export async function getArtifactContent(
  caseId: string,
  artifactId: string,
  offset?: number,
  length?: number
): Promise<Blob> {
  const params = new URLSearchParams()
  if (offset !== undefined) params.set('offset', String(offset))
  if (length !== undefined) params.set('length', String(length))
  const qs = params.toString()
  const res = await fetch(
    `${BASE}/cases/${caseId}/artifacts/${artifactId}/content${qs ? `?${qs}` : ''}`,
  )
  if (!res.ok) {
    throw new Error(`API error ${res.status}: ${await res.text()}`)
  }
  return res.blob()
}

// ── Events ─────────────────────────────────────────────

export async function searchEvents(
  caseId: string,
  query: string,
  options?: {
    cursor?: string
    limit?: number
    level?: string
    source?: string
  }
): Promise<PaginatedResponse<Event>> {
  const offset = Number.parseInt(options?.cursor || '0', 10)
  const params = new URLSearchParams()
  params.set('q', query)
  if (!Number.isNaN(offset) && offset > 0) params.set('offset', String(offset))
  if (options?.limit) params.set('limit', String(options.limit))
  if (options?.level) params.set('level', options.level)
  if (options?.source) params.set('source', options.source)
  const response = await request<RawPaginatedResponse<RawEvent>>(
    `/cases/${caseId}/events?${params.toString()}`
  )

  const normalized = normalizePaginatedResponse(
    response,
    Number.isNaN(offset) ? 0 : offset,
    options?.limit
  )
  return {
    ...normalized,
    items: normalized.items.map(normalizeEvent),
  }
}

export async function getEvent(caseId: string, eventId: number): Promise<Event> {
  const event = await request<RawEvent>(`/cases/${caseId}/events/${eventId}`)
  return normalizeEvent(event)
}

// ── Timeline ───────────────────────────────────────────

export async function getTimeline(
  caseId: string,
  cursor?: string,
  limit?: number,
  timeStart?: string,
  timeEnd?: string
): Promise<PaginatedResponse<Event>> {
  const offset = Number.parseInt(cursor || '0', 10)
  const params = new URLSearchParams()
  if (!Number.isNaN(offset) && offset > 0) params.set('offset', String(offset))
  if (limit) params.set('limit', String(limit))
  if (timeStart) params.set('start', timeStart)
  if (timeEnd) params.set('end', timeEnd)
  const qs = params.toString()
  const response = await request<RawPaginatedResponse<RawEvent>>(
    `/cases/${caseId}/timeline${qs ? `?${qs}` : ''}`
  )

  const normalized = normalizePaginatedResponse(response, Number.isNaN(offset) ? 0 : offset, limit)
  return {
    ...normalized,
    items: normalized.items.map(normalizeEvent),
  }
}

// ── YARA ───────────────────────────────────────────────

export async function createYaraRule(
  caseId: string,
  name: string,
  content: string
): Promise<YaraRule> {
  return request<YaraRule>(`/cases/${caseId}/yara/rules`, {
    method: 'POST',
    body: JSON.stringify({ name, content }),
  })
}

export async function listYaraRules(caseId: string): Promise<YaraRule[]> {
  return request<YaraRule[]>(`/cases/${caseId}/yara/rules`)
}

export async function runYaraScan(
  caseId: string,
  ruleId: string,
  artifactId?: string
): Promise<unknown> {
  return request(`/cases/${caseId}/yara/scan`, {
    method: 'POST',
    body: JSON.stringify({ rule_id: ruleId, artifact_id: artifactId }),
  })
}

export async function getYaraResults(caseId: string, ruleId?: string): Promise<YaraResult[]> {
  const params = new URLSearchParams()
  if (ruleId) params.set('rule_id', ruleId)
  const qs = params.toString()
  return request<YaraResult[]>(
    `/cases/${caseId}/yara/results${qs ? `?${qs}` : ''}`
  )
}

// ── Actions ────────────────────────────────────────────

export async function listActions(caseId: string): Promise<ActionProposal[]> {
  return request<ActionProposal[]>(`/cases/${caseId}/actions`)
}

export async function approveAction(caseId: string, actionId: string): Promise<void> {
  return request<void>(`/cases/${caseId}/actions/${actionId}/approve`, {
    method: 'POST',
  })
}

export async function rejectAction(caseId: string, actionId: string): Promise<void> {
  return request<void>(`/cases/${caseId}/actions/${actionId}/reject`, {
    method: 'POST',
  })
}

export async function executeAction(caseId: string, actionId: string): Promise<unknown> {
  return request(`/cases/${caseId}/actions/${actionId}/execute`, {
    method: 'POST',
  })
}

// ── Audit ──────────────────────────────────────────────

export async function getAuditLog(
  caseId: string,
  limit?: number,
  offset?: number
): Promise<AuditEntry[]> {
  const params = new URLSearchParams()
  if (limit) params.set('limit', String(limit))
  if (offset) params.set('offset', String(offset))
  const qs = params.toString()
  return request<AuditEntry[]>(
    `/cases/${caseId}/audit${qs ? `?${qs}` : ''}`
  )
}

// ── Persistence & Network ──────────────────────────────

export async function getPersistenceItems(caseId: string): Promise<PersistenceItem[]> {
  return request<PersistenceItem[]>(`/cases/${caseId}/persistence`)
}

export async function getNetworkSnapshot(caseId: string): Promise<NetworkSnapshot> {
  return request<NetworkSnapshot>(`/cases/${caseId}/network`)
}

export async function getProcessSnapshot(caseId: string): Promise<ProcessInfo[]> {
  return request<ProcessInfo[]>(`/cases/${caseId}/processes`)
}

// ── Agent Chat ────────────────────────────────────────

export async function agentChat(
  caseId: string,
  message: string,
  history?: { role: string; content: string }[]
): Promise<AgentChatResponse> {
  return request<AgentChatResponse>(`/cases/${caseId}/agent/chat`, {
    method: 'POST',
    body: JSON.stringify({ message, history }),
  })
}
