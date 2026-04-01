import { useState, useCallback, useEffect, useDeferredValue } from 'react'
import { useParams } from 'react-router-dom'
import {
  Loader2,
  AlertCircle,
  Search,
  ChevronDown,
  X,
} from 'lucide-react'
import { searchEvents } from '../api/client'
import { EventSummary, EventStructuredDetails } from '../components/EventEvidence'
import type { Event } from '../types'
import Pagination from '../components/Pagination'

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

function formatDate(iso: string): string {
  if (!iso) return '--'
  return new Date(iso).toLocaleString()
}

function highlightMatch(text: string, query: string): React.ReactNode {
  if (!query.trim()) return text
  const parts = text.split(new RegExp(`(${query.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')})`, 'gi'))
  return parts.map((part, i) =>
    part.toLowerCase() === query.toLowerCase() ? (
      <mark key={i} className="bg-amber-500/30 text-amber-200 rounded px-0.5">
        {part}
      </mark>
    ) : (
      part
    )
  )
}

const PAGE_SIZE = 25

export default function EventSearch() {
  const { id: caseId } = useParams<{ id: string }>()
  const [query, setQuery] = useState('')
  const [submittedQuery, setSubmittedQuery] = useState('')
  const [events, setEvents] = useState<Event[]>([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [total, setTotal] = useState(0)
  const [pageIndex, setPageIndex] = useState(0)
  const [expandedId, setExpandedId] = useState<number | null>(null)
  const [searched, setSearched] = useState(false)

  const [levelFilter, setLevelFilter] = useState('')
  const [sourceFilter, setSourceFilter] = useState('')
  const deferredSourceFilter = useDeferredValue(sourceFilter.trim())

  const doSearch = useCallback(
    (searchQuery: string) => {
      if (!caseId || !searchQuery.trim()) return

      setError(null)
      setSubmittedQuery(searchQuery)
      setSearched(true)
      setExpandedId(null)
      setEvents([])
      setTotal(0)
      setPageIndex(0)
    },
    [caseId]
  )

  useEffect(() => {
    if (!caseId || !searched || !submittedQuery.trim()) return
    const activeCaseId = caseId

    let cancelled = false

    async function loadPage() {
      try {
        setLoading(true)
        setError(null)

        const data = await searchEvents(activeCaseId, submittedQuery, {
          cursor: String(pageIndex * PAGE_SIZE),
          limit: PAGE_SIZE,
          level: levelFilter || undefined,
          source: deferredSourceFilter || undefined,
        })

        if (cancelled) return
        setEvents(data.items ?? [])
        setTotal(data.total)
      } catch (err) {
        if (cancelled) return
        setError(err instanceof Error ? err.message : 'Search failed')
        setEvents([])
        setTotal(0)
      } finally {
        if (!cancelled) {
          setLoading(false)
        }
      }
    }

    loadPage()

    return () => {
      cancelled = true
    }
  }, [caseId, searched, submittedQuery, pageIndex, levelFilter, deferredSourceFilter])

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    const trimmedQuery = query.trim()
    if (!trimmedQuery) return
    doSearch(trimmedQuery)
  }

  const hasActiveFilters = Boolean(levelFilter || sourceFilter.trim())
  const hasNext = (pageIndex + 1) * PAGE_SIZE < total
  const hasPrev = pageIndex > 0

  useEffect(() => {
    setPageIndex(0)
    setExpandedId(null)
  }, [levelFilter, sourceFilter])

  return (
    <div className="max-w-6xl mx-auto">
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-slate-100">Event Search</h1>
        <p className="text-sm text-slate-400 mt-1">
          Search across collected normalized events
        </p>
      </div>

      <form onSubmit={handleSubmit} className="mb-6">
        <div className="relative">
          <Search
            size={18}
            className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-500"
          />
          <input
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search events... (e.g. 'powershell' or '4688')"
            className="w-full pl-11 pr-24 py-3 bg-slate-800 border border-slate-700 rounded-xl text-sm text-slate-100 placeholder:text-slate-500 focus:outline-none focus:ring-2 focus:ring-forensic-500 focus:border-transparent"
            autoFocus
          />
          {query && (
            <button
              type="button"
              onClick={() => {
                setQuery('')
                setSubmittedQuery('')
                setEvents([])
                setTotal(0)
                setError(null)
                setSearched(false)
                setPageIndex(0)
                setExpandedId(null)
              }}
              className="absolute right-20 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300"
            >
              <X size={16} />
            </button>
          )}
          <button
            type="submit"
            disabled={!query.trim() || loading}
            className="absolute right-2 top-1/2 -translate-y-1/2 px-4 py-1.5 bg-forensic-600 hover:bg-forensic-700 text-white rounded-lg text-sm font-medium disabled:opacity-50 disabled:cursor-not-allowed"
          >
            Search
          </button>
        </div>
      </form>

      {searched && total > 0 && (
        <div className="flex items-center gap-4 mb-4">
          <div className="flex items-center gap-2">
            <label className="text-xs text-slate-500">Level:</label>
            <select
              value={levelFilter}
              onChange={(e) => setLevelFilter(e.target.value)}
              className="px-2 py-1 bg-slate-800 border border-slate-700 rounded-lg text-xs text-slate-300 focus:outline-none focus:ring-1 focus:ring-forensic-500"
            >
              <option value="">All</option>
              <option value="Critical">Critical</option>
              <option value="Error">Error</option>
              <option value="Warning">Warning</option>
              <option value="Information">Information</option>
              <option value="Verbose">Verbose</option>
            </select>
          </div>
          <div className="flex items-center gap-2">
            <label className="text-xs text-slate-500">Source:</label>
            <input
              type="text"
              value={sourceFilter}
              onChange={(e) => setSourceFilter(e.target.value)}
              placeholder="Filter source..."
              className="px-2 py-1 bg-slate-800 border border-slate-700 rounded-lg text-xs text-slate-300 placeholder:text-slate-600 focus:outline-none focus:ring-1 focus:ring-forensic-500 w-36"
            />
          </div>
          <span className="ml-auto text-xs text-slate-500">
            {hasActiveFilters ? `${total} filtered results` : `${total} results found`}
          </span>
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

      {!loading && searched && total === 0 && (
        <div className="text-center py-20">
          <Search size={48} className="text-slate-600 mx-auto mb-4" />
          <h3 className="text-lg font-medium text-slate-300">No results found</h3>
          <p className="text-sm text-slate-500 mt-1">
            Try a different search query or adjust filters
          </p>
        </div>
      )}

      {!loading && !searched && (
        <div className="text-center py-20">
          <Search size={48} className="text-slate-700 mx-auto mb-4" />
          <h3 className="text-lg font-medium text-slate-400">
            Enter a search query to begin
          </h3>
          <p className="text-sm text-slate-600 mt-1">
            Search across event messages, sources, providers, and more
          </p>
        </div>
      )}

      {!loading && events.length > 0 && (
        <>
          <div className="space-y-2">
            {events.map((event) => (
              <div
                key={event.id}
                className="bg-slate-800 border border-slate-700 rounded-xl overflow-hidden hover:border-slate-600 transition-colors"
              >
                <div
                  className="flex items-start gap-4 p-4 cursor-pointer"
                  onClick={() =>
                    setExpandedId(expandedId === event.id ? null : event.id)
                  }
                >
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1.5 flex-wrap">
                      <span className="text-xs font-mono text-slate-500">
                        {formatDate(event.timestamp)}
                      </span>
                      <span
                        className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium border ${levelBadgeColor(event.level)}`}
                      >
                        {event.level}
                      </span>
                      <span className="text-xs text-slate-500">{event.source}</span>
                      {event.event_id > 0 && (
                        <span className="text-xs text-slate-600 font-mono">
                          EventID:{event.event_id}
                        </span>
                      )}
                    </div>
                    <EventSummary
                      event={event}
                      highlightText={(text) => highlightMatch(text, submittedQuery)}
                    />
                  </div>
                  <ChevronDown
                    size={16}
                    className={`text-slate-500 shrink-0 mt-1 transition-transform ${
                      expandedId === event.id ? 'rotate-180' : ''
                    }`}
                  />
                </div>

                {expandedId === event.id && (
                  <div className="px-4 pb-4 pt-0 border-t border-slate-700 mt-0 space-y-3">
                    <div className="pt-3 grid grid-cols-2 gap-3 text-sm">
                      <div>
                        <span className="text-slate-500">Provider:</span>{' '}
                        <span className="text-slate-300">{event.provider}</span>
                      </div>
                      <div>
                        <span className="text-slate-500">Channel:</span>{' '}
                        <span className="text-slate-300">{event.channel}</span>
                      </div>
                      <div>
                        <span className="text-slate-500">Event ID:</span>{' '}
                        <span className="text-slate-300">{event.event_id}</span>
                      </div>
                      <div>
                        <span className="text-slate-500">Source:</span>{' '}
                        <span className="text-slate-300">{event.source}</span>
                      </div>
                    </div>
                    <EventStructuredDetails
                      event={event}
                      highlightText={(text) => highlightMatch(text, submittedQuery)}
                    />
                    <div>
                      <p className="text-xs text-slate-500 mb-1">Full Message:</p>
                      <p className="text-sm text-slate-300 whitespace-pre-wrap bg-slate-900 p-3 rounded-lg">
                        {highlightMatch(event.message, submittedQuery)}
                      </p>
                    </div>
                    {event.raw_xml && (
                      <div>
                        <p className="text-xs text-slate-500 mb-1">Raw Data:</p>
                        <pre className="p-3 bg-slate-900 rounded-lg text-xs text-slate-400 font-mono overflow-auto max-h-48">
                          {event.raw_xml}
                        </pre>
                      </div>
                    )}
                  </div>
                )}
              </div>
            ))}
          </div>

          <Pagination
            hasNext={hasNext}
            hasPrev={hasPrev}
            onNext={() => {
              setPageIndex((p) => p + 1)
              setExpandedId(null)
            }}
            onPrev={() => {
              setPageIndex((p) => Math.max(0, p - 1))
              setExpandedId(null)
            }}
            total={total}
            showing={events.length}
            label="events"
          />
        </>
      )}
    </div>
  )
}
