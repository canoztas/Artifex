import type { ReactNode } from 'react'
import type { Event } from '../types'

type HighlightFn = (text: string) => ReactNode

type EvidenceField = {
  label: string
  value: string
}

type EvidenceData = {
  title: string
  subtitle?: string
  badges: string[]
  fields: EvidenceField[]
  note?: string
}

type PrefetchDetails = {
  executable?: string
  run_count?: number
  prefetch_hash?: string
  observed_timestamp_index?: number
  observed_timestamp_total?: number
}

type ShortcutDetails = {
  shortcut_name?: string
  source_path?: string
  target_path?: string
  arguments?: string
  working_directory?: string
  description?: string
  hotkey?: string
  icon_location?: string
  file_times?: {
    created?: string
    modified?: string
    accessed?: string
  }
}

type JumpListDetails = {
  app_id?: string
  entry_index?: number
  entry_name?: string
  source_path?: string
  target_path?: string
  arguments?: string
  working_directory?: string
  description?: string
  icon_location?: string
  timestamp_basis?: string
  file_times?: {
    created?: string
    modified?: string
    accessed?: string
  }
}

function renderText(text: string, highlightText?: HighlightFn): ReactNode {
  if (!text) return '--'
  return highlightText ? highlightText(text) : text
}

function parseEventPayload(event: Event): Record<string, unknown> | null {
  if (!event.raw_xml) return null
  try {
    const parsed = JSON.parse(event.raw_xml) as Record<string, unknown>
    return parsed && typeof parsed === 'object' ? parsed : null
  } catch {
    return null
  }
}

function getSourceLabel(source: string): string {
  switch (source) {
    case 'lnk_recent':
      return 'Recent shortcut'
    case 'lnk_startup':
      return 'Startup shortcut'
    case 'lnk_desktop':
      return 'Desktop shortcut'
    case 'jumplist_automatic':
      return 'Automatic Jump List'
    case 'jumplist_custom':
      return 'Custom Jump List'
    default:
      return source
  }
}

function buildEvidenceData(event: Event): EvidenceData | null {
  const payload = parseEventPayload(event)
  if (!payload) return null

  if (event.source === 'prefetch') {
    const details = payload as PrefetchDetails
    const executable = details.executable || 'Unknown executable'
    const timestampSlot =
      (details.observed_timestamp_index ?? 0) > 0 &&
      (details.observed_timestamp_total ?? 0) > 0
        ? `Recent timestamp ${details.observed_timestamp_index} of ${details.observed_timestamp_total}`
        : 'No recent execution timestamp stored'

    const fields: EvidenceField[] = [
      { label: 'Executable', value: executable },
      { label: 'Timestamp Slot', value: timestampSlot },
    ]
    if (typeof details.run_count === 'number') {
      fields.push({ label: 'Run Count Field', value: String(details.run_count) })
    }
    if (details.prefetch_hash) {
      fields.push({ label: 'Prefetch Hash', value: details.prefetch_hash })
    }

    const badges = [timestampSlot]
    if (typeof details.run_count === 'number' && details.run_count > 0) {
      badges.push(`Run count field: ${details.run_count}`)
    }

    return {
      title: `Prefetch recorded ${executable}`,
      badges,
      fields,
    }
  }

  if (event.source.startsWith('lnk')) {
    const details = payload as ShortcutDetails
    const label = getSourceLabel(event.source)
    const target = details.target_path || 'Unresolved shortcut target'
    const fields: EvidenceField[] = [
      { label: 'Shortcut Type', value: label },
      { label: 'Shortcut Name', value: details.shortcut_name || '--' },
      { label: 'Target Path', value: target },
      { label: 'Shortcut Path', value: details.source_path || '--' },
    ]
    if (details.arguments) {
      fields.push({ label: 'Arguments', value: details.arguments })
    }
    if (details.working_directory) {
      fields.push({ label: 'Working Directory', value: details.working_directory })
    }
    if (details.description) {
      fields.push({ label: 'Description', value: details.description })
    }
    if (details.hotkey) {
      fields.push({ label: 'Hotkey', value: details.hotkey })
    }
    if (details.icon_location) {
      fields.push({ label: 'Icon', value: details.icon_location })
    }
    if (details.file_times?.modified) {
      fields.push({ label: 'Shortcut Modified', value: details.file_times.modified })
    }

    const badges = [label]
    if (details.shortcut_name) {
      badges.push(details.shortcut_name)
    }

    return {
      title: target,
      subtitle: 'Shortcut reference',
      badges,
      fields,
    }
  }

  if (event.source.startsWith('jumplist')) {
    const details = payload as JumpListDetails
    const label = getSourceLabel(event.source)
    const target = details.target_path || 'Unresolved Jump List target'
    const fields: EvidenceField[] = [
      { label: 'Jump List Type', value: label },
      { label: 'App ID', value: details.app_id || '--' },
      { label: 'Entry Name', value: details.entry_name || '--' },
      { label: 'Target Path', value: target },
      { label: 'Jump List Path', value: details.source_path || '--' },
    ]
    if (typeof details.entry_index === 'number') {
      fields.push({ label: 'Entry Index', value: String(details.entry_index) })
    }
    if (details.arguments) {
      fields.push({ label: 'Arguments', value: details.arguments })
    }
    if (details.working_directory) {
      fields.push({ label: 'Working Directory', value: details.working_directory })
    }
    if (details.description) {
      fields.push({ label: 'Description', value: details.description })
    }
    if (details.icon_location) {
      fields.push({ label: 'Icon', value: details.icon_location })
    }
    if (details.file_times?.modified) {
      fields.push({ label: 'Container Modified', value: details.file_times.modified })
    }

    const badges = [label]
    if (details.app_id) {
      badges.push(`App ID: ${details.app_id}`)
    }
    if (typeof details.entry_index === 'number') {
      badges.push(`Entry ${details.entry_index}`)
    }

    return {
      title: target,
      subtitle: 'Jump List reference',
      badges,
      fields,
      note:
        details.timestamp_basis === 'jumplist_container_time'
          ? 'Timeline timestamp is based on the Jump List container file time.'
          : undefined,
    }
  }

  return null
}

export function EventSummary({
  event,
  highlightText,
}: {
  event: Event
  highlightText?: HighlightFn
}) {
  const evidence = buildEvidenceData(event)
  if (!evidence) {
    return (
      <p className="text-sm text-slate-300 line-clamp-2">
        {renderText(event.message, highlightText)}
      </p>
    )
  }

  return (
    <div className="space-y-2">
      {evidence.subtitle && (
        <p className="text-xs font-medium uppercase tracking-wide text-slate-500">
          {evidence.subtitle}
        </p>
      )}
      <p className="text-sm font-medium text-slate-200">
        {renderText(evidence.title, highlightText)}
      </p>
      {evidence.badges.length > 0 && (
        <div className="flex flex-wrap gap-2">
          {evidence.badges.map((badge) => (
            <span
              key={badge}
              className="inline-flex items-center rounded-full border border-slate-600 bg-slate-900 px-2 py-0.5 text-xs text-slate-300"
            >
              {renderText(badge, highlightText)}
            </span>
          ))}
        </div>
      )}
    </div>
  )
}

export function EventStructuredDetails({
  event,
  highlightText,
}: {
  event: Event
  highlightText?: HighlightFn
}) {
  const evidence = buildEvidenceData(event)
  if (!evidence) return null

  return (
    <div className="space-y-3">
      <div className="grid grid-cols-2 gap-3 text-sm">
        {evidence.fields.map((field) => (
          <div key={`${field.label}:${field.value}`}>
            <span className="text-slate-500">{field.label}:</span>{' '}
            <span className="text-slate-300 break-all">
              {renderText(field.value, highlightText)}
            </span>
          </div>
        ))}
      </div>
      {evidence.note && (
        <p className="text-xs text-slate-500">
          {renderText(evidence.note, highlightText)}
        </p>
      )}
    </div>
  )
}
