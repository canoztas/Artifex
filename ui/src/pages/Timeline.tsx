import { useState, useEffect, useCallback, useRef } from 'react'
import { useParams } from 'react-router-dom'
import {
  Loader2,
  AlertCircle,
  Clock,
  ChevronDown,
  Filter,
} from 'lucide-react'
import { getTimeline } from '../api/client'
import type { Event } from '../types'

function levelColor(level: Event['level']): string {
  switch (level) {
    case 'Critical':
      return 'border-red-500 bg-red-500'
    case 'Error':
      return 'border-red-400 bg-red-400'
    case 'Warning':
      return 'border-amber-400 bg-amber-400'
    case 'Information':
      return 'border-blue-400 bg-blue-400'
    case 'Verbose':
      return 'border-slate-500 bg-slate-500'
    default:
      return 'border-slate-500 bg-slate-500'
  }
}

function levelBadgeColor(level: Event['level']): string {
  switch (level) {
    case 'Critical':
      return 'bg-red-500/15 text-red-400 border-red-500/30'
    case 'Error':
      return 'bg-red-400/15 text-red-400 border-red-400/30'
    case 'Warning':
      return 'bg-amber-400/15 text-amber-400 border-amber-400/30'
    case 'Information':
      return 'bg-blue-400/15 text-blue-400 border-blue-400/30'
    case 'Verbose':
      return 'bg-slate-500/15 text-slate-400 border-slate-500/30'
    default:
      return 'bg-slate-500/15 text-slate-400 border-slate-500/30'
  }
}

function formatTime(iso: string): string {
  if (!iso) return '--'
  const d = new Date(iso)
  return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })
}

function formatDate(iso: string): string {
  if (!iso) return '--'
  return new Date(iso).toLocaleDateString()
}

function toApiDateTime(value: string): string | undefined {
  if (!value) return undefined
  const parsed = new Date(value)
  if (Number.isNaN(parsed.getTime())) return undefined
  return parsed.toISOString()
}

const PAGE_SIZE = 50

export default function Timeline() {
  const { id: caseId } = useParams<{ id: string }>()
  const [events, setEvents] = useState<Event[]>([])
  const [loading, setLoading] = useState(true)
  const [loadingMore, setLoadingMore] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [nextCursor, setNextCursor] = useState<string>('')
  const [total, setTotal] = useState(0)

  // Filters
  const [timeStart, setTimeStart] = useState('')
  const [timeEnd, setTimeEnd] = useState('')
  const [showFilters, setShowFilters] = useState(false)

  const sentinelRef = useRef<HTMLDivElement>(null)

  const load = useCallback(
    async (cursor?: string, append = false) => {
      if (!caseId) return
      try {
        if (append) {
          setLoadingMore(true)
        } else {
          setLoading(true)
        }
        setError(null)
        const data = await getTimeline(
          caseId,
          cursor || undefined,
          PAGE_SIZE,
          toApiDateTime(timeStart),
          toApiDateTime(timeEnd)
        )
        if (append) {
          setEvents((prev) => [...prev, ...(data.items ?? [])])
        } else {
          setEvents(data.items ?? [])
        }
        setNextCursor(data.next_cursor || '')
        setTotal(data.total)
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to load timeline')
      } finally {
        setLoading(false)
        setLoadingMore(false)
      }
    },
    [caseId, timeStart, timeEnd]
  )

  useEffect(() => {
    load()
  }, [load])

  // Infinite scroll
  useEffect(() => {
    if (!sentinelRef.current || !nextCursor) return
    const observer = new IntersectionObserver(
      (entries) => {
        if (entries[0].isIntersecting && nextCursor && !loadingMore) {
          load(nextCursor, true)
        }
      },
      { threshold: 0.1 }
    )
    observer.observe(sentinelRef.current)
    return () => observer.disconnect()
  }, [nextCursor, loadingMore, load])

  // Group events by date
  const groupedEvents: Record<string, Event[]> = {}
  events.forEach((ev) => {
    const date = formatDate(ev.timestamp)
    if (!groupedEvents[date]) groupedEvents[date] = []
    groupedEvents[date].push(ev)
  })

  const [expandedId, setExpandedId] = useState<number | null>(null)

  return (
    <div className="max-w-4xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold text-slate-100">Timeline</h1>
          <p className="text-sm text-slate-400 mt-1">
            Chronological view of {total} events
          </p>
        </div>
        <button
          onClick={() => setShowFilters(!showFilters)}
          className={`flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium border transition-colors ${
            showFilters
              ? 'border-forensic-500 text-forensic-400 bg-forensic-500/10'
              : 'border-slate-600 text-slate-400 hover:bg-slate-700'
          }`}
        >
          <Filter size={16} />
          Filters
        </button>
      </div>

      {/* Filter panel */}
      {showFilters && (
        <div className="mb-6 p-4 bg-slate-800 border border-slate-700 rounded-xl">
          <div className="flex items-end gap-4">
            <div className="flex-1">
              <label className="block text-xs font-medium text-slate-400 mb-1">
                Start Time
              </label>
              <input
                type="datetime-local"
                value={timeStart}
                onChange={(e) => setTimeStart(e.target.value)}
                className="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-lg text-sm text-slate-100 focus:outline-none focus:ring-2 focus:ring-forensic-500"
              />
            </div>
            <div className="flex-1">
              <label className="block text-xs font-medium text-slate-400 mb-1">
                End Time
              </label>
              <input
                type="datetime-local"
                value={timeEnd}
                onChange={(e) => setTimeEnd(e.target.value)}
                className="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-lg text-sm text-slate-100 focus:outline-none focus:ring-2 focus:ring-forensic-500"
              />
            </div>
            <button
              onClick={() => {
                setTimeStart('')
                setTimeEnd('')
              }}
              className="px-4 py-2 text-sm text-slate-400 hover:text-slate-200 border border-slate-600 rounded-lg hover:bg-slate-700"
            >
              Clear
            </button>
          </div>
        </div>
      )}

      {error && (
        <div className="mb-4 p-4 bg-red-500/10 border border-red-500/30 rounded-lg flex items-center gap-3">
          <AlertCircle size={18} className="text-red-400 shrink-0" />
          <p className="text-sm text-red-400">{error}</p>
        </div>
      )}

      {loading && (
        <div className="flex items-center justify-center py-20">
          <Loader2 size={32} className="text-forensic-400 animate-spin" />
        </div>
      )}

      {!loading && events.length === 0 && (
        <div className="text-center py-20">
          <Clock size={48} className="text-slate-600 mx-auto mb-4" />
          <h3 className="text-lg font-medium text-slate-300">No events yet</h3>
          <p className="text-sm text-slate-500 mt-1">
            Events will appear here after collection
          </p>
        </div>
      )}

      {/* Timeline */}
      {!loading && events.length > 0 && (
        <div className="relative">
          {/* Vertical line */}
          <div className="absolute left-6 top-0 bottom-0 w-px bg-slate-700" />

          {Object.entries(groupedEvents).map(([date, dateEvents]) => (
            <div key={date} className="mb-8">
              {/* Date header */}
              <div className="relative flex items-center mb-4 pl-14">
                <div className="absolute left-4 w-5 h-5 bg-slate-800 border-2 border-slate-600 rounded-full flex items-center justify-center">
                  <div className="w-2 h-2 bg-slate-500 rounded-full" />
                </div>
                <span className="text-sm font-semibold text-slate-400">{date}</span>
              </div>

              {/* Events */}
              <div className="space-y-2">
                {dateEvents.map((event) => (
                  <div key={event.id} className="relative pl-14">
                    {/* Dot on the timeline */}
                    <div
                      className={`absolute left-[19px] top-4 w-3 h-3 rounded-full border-2 ${levelColor(event.level)}`}
                    />

                    {/* Event card */}
                    <div
                      className="bg-slate-800 border border-slate-700 rounded-xl p-4 hover:border-slate-600 transition-colors cursor-pointer"
                      onClick={() =>
                        setExpandedId(expandedId === event.id ? null : event.id)
                      }
                    >
                      <div className="flex items-start justify-between gap-4">
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 mb-1.5">
                            <span className="text-xs font-mono text-slate-500">
                              {formatTime(event.timestamp)}
                            </span>
                            <span
                              className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium border ${levelBadgeColor(event.level)}`}
                            >
                              {event.level}
                            </span>
                            <span className="text-xs text-slate-500">
                              {event.source}
                            </span>
                            {event.event_id > 0 && (
                              <span className="text-xs text-slate-600">
                                ID: {event.event_id}
                              </span>
                            )}
                          </div>
                          <p className="text-sm text-slate-300 line-clamp-2">
                            {event.message}
                          </p>
                        </div>
                        <ChevronDown
                          size={16}
                          className={`text-slate-500 shrink-0 transition-transform ${
                            expandedId === event.id ? 'rotate-180' : ''
                          }`}
                        />
                      </div>

                      {/* Expanded details */}
                      {expandedId === event.id && (
                        <div className="mt-4 pt-4 border-t border-slate-700 space-y-3">
                          <div className="grid grid-cols-2 gap-3 text-sm">
                            <div>
                              <span className="text-slate-500">Provider:</span>{' '}
                              <span className="text-slate-300">{event.provider}</span>
                            </div>
                            <div>
                              <span className="text-slate-500">Channel:</span>{' '}
                              <span className="text-slate-300">{event.channel}</span>
                            </div>
                          </div>
                          <div>
                            <p className="text-xs text-slate-500 mb-1">Full Message:</p>
                            <p className="text-sm text-slate-300 whitespace-pre-wrap">
                              {event.message}
                            </p>
                          </div>
                          {event.raw_xml && (
                            <div>
                              <p className="text-xs text-slate-500 mb-1">Raw XML:</p>
                              <pre className="p-3 bg-slate-900 rounded-lg text-xs text-slate-400 font-mono overflow-auto max-h-48">
                                {event.raw_xml}
                              </pre>
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ))}

          {/* Infinite scroll sentinel */}
          <div ref={sentinelRef} className="h-4" />
          {loadingMore && (
            <div className="flex items-center justify-center py-4">
              <Loader2 size={24} className="text-forensic-400 animate-spin" />
              <span className="ml-2 text-sm text-slate-400">Loading more...</span>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
