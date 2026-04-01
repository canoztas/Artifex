import { useState, useEffect, useCallback } from 'react'
import { useParams, Link } from 'react-router-dom'
import {
  Loader2,
  AlertCircle,
  Play,
  FileSearch,
  Clock,
  Search,
  Bot,
  ShieldCheck,
  Monitor,
  HardDrive,
} from 'lucide-react'
import {
  getCase,
  listCollections,
  startCollection,
  getCollectionStatus,
  listArtifacts,
  getPersistenceItems,
} from '../api/client'
import type { Case, CollectionJob } from '../types'
import Badge from '../components/Badge'
import CollectionProgress from '../components/CollectionProgress'
import Modal from '../components/Modal'

function formatDate(iso: string): string {
  if (!iso) return '--'
  return new Date(iso).toLocaleString()
}

export default function CaseDetail() {
  const { id } = useParams<{ id: string }>()
  const [caseData, setCaseData] = useState<Case | null>(null)
  const [collections, setCollections] = useState<CollectionJob[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [artifactCount, setArtifactCount] = useState<number | null>(null)
  const [persistenceCount, setPersistenceCount] = useState<number | null>(null)

  // Collection modal
  const [showCollect, setShowCollect] = useState(false)
  const [preset, setPreset] = useState('standard')
  const [timeRange, setTimeRange] = useState(24)
  const [starting, setStarting] = useState(false)

  const load = useCallback(async () => {
    if (!id) return
    try {
      setLoading(true)
      setError(null)
      const [c, cols] = await Promise.all([
        getCase(id),
        listCollections(id),
      ])
      setCaseData(c)
      setCollections(cols ?? [])

      // Load stats in the background (non-blocking)
      listArtifacts(id, undefined, 1)
        .then((r) => setArtifactCount(r.total))
        .catch(() => setArtifactCount(null))
      getPersistenceItems(id)
        .then((r) => setPersistenceCount(r?.length ?? 0))
        .catch(() => setPersistenceCount(null))
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load case')
    } finally {
      setLoading(false)
    }
  }, [id])

  useEffect(() => {
    load()
  }, [load])

  const refreshJob = useCallback(
    async (jobId: string) => {
      if (!id) return
      try {
        const updated = await getCollectionStatus(id, jobId)
        setCollections((prev) =>
          prev.map((j) => (j.id === jobId ? updated : j))
        )
      } catch {
        // Ignore refresh errors
      }
    },
    [id]
  )

  async function handleStartCollection() {
    if (!id) return
    try {
      setStarting(true)
      const job = await startCollection(id, preset, timeRange)
      setCollections((prev) => [job, ...prev])
      setShowCollect(false)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to start collection')
    } finally {
      setStarting(false)
    }
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center py-20">
        <Loader2 size={32} className="text-forensic-400 animate-spin" />
      </div>
    )
  }

  if (error) {
    return (
      <div className="max-w-4xl mx-auto">
        <div className="p-4 bg-red-500/10 border border-red-500/30 rounded-lg flex items-center gap-3">
          <AlertCircle size={18} className="text-red-400 shrink-0" />
          <p className="text-sm text-red-400">{error}</p>
        </div>
      </div>
    )
  }

  if (!caseData) return null

  const statusVariant =
    caseData.status === 'active'
      ? 'success'
      : caseData.status === 'closed'
      ? 'neutral'
      : 'warning'

  const quickLinks = [
    { label: 'Artifacts', path: `/cases/${id}/artifacts`, icon: <FileSearch size={18} />, color: 'text-blue-400' },
    { label: 'Timeline', path: `/cases/${id}/timeline`, icon: <Clock size={18} />, color: 'text-amber-400' },
    { label: 'Events', path: `/cases/${id}/events`, icon: <Search size={18} />, color: 'text-green-400' },
    { label: 'Agent', path: `/cases/${id}/agent`, icon: <Bot size={18} />, color: 'text-purple-400' },
    { label: 'Actions', path: `/cases/${id}/actions`, icon: <ShieldCheck size={18} />, color: 'text-red-400' },
  ]

  return (
    <div className="max-w-6xl mx-auto space-y-6">
      {/* Case header */}
      <div className="bg-slate-800 border border-slate-700 rounded-xl p-6">
        <div className="flex items-start justify-between">
          <div>
            <div className="flex items-center gap-3 mb-2">
              <h1 className="text-2xl font-bold text-slate-100">
                {caseData.name}
              </h1>
              <Badge variant={statusVariant as 'success' | 'neutral' | 'warning'}>
                {caseData.status}
              </Badge>
            </div>
            {caseData.description && (
              <p className="text-sm text-slate-400 max-w-2xl">
                {caseData.description}
              </p>
            )}
            <div className="flex items-center gap-6 mt-4 text-xs text-slate-500">
              <span>Created: {formatDate(caseData.created_at)}</span>
              <span>Updated: {formatDate(caseData.updated_at)}</span>
              <span>ID: {caseData.id}</span>
            </div>
          </div>
          <button
            onClick={() => setShowCollect(true)}
            className="flex items-center gap-2 px-4 py-2 bg-green-600 hover:bg-green-700 text-white rounded-lg text-sm font-medium transition-colors shrink-0"
          >
            <Play size={16} />
            Start Collection
          </button>
        </div>
      </div>

      {/* Quick links */}
      <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-6 gap-4">
        {quickLinks.map((link) => (
          <Link
            key={link.path}
            to={link.path}
            className="bg-slate-800 border border-slate-700 rounded-xl p-4 hover:bg-slate-750 hover:border-slate-600 transition-colors group"
          >
            <div className={`${link.color} mb-2 group-hover:scale-110 transition-transform inline-block`}>
              {link.icon}
            </div>
            <p className="text-sm font-medium text-slate-300 group-hover:text-slate-100">
              {link.label}
            </p>
          </Link>
        ))}
      </div>

      {/* Stats */}
      <div className="grid grid-cols-3 gap-4">
        <div className="bg-slate-800 border border-slate-700 rounded-xl p-5">
          <div className="flex items-center gap-3 mb-2">
            <HardDrive size={18} className="text-blue-400" />
            <span className="text-sm font-medium text-slate-400">Artifacts</span>
          </div>
          <p className="text-2xl font-bold text-slate-100">
            {artifactCount !== null ? artifactCount : '--'}
          </p>
        </div>
        <div className="bg-slate-800 border border-slate-700 rounded-xl p-5">
          <div className="flex items-center gap-3 mb-2">
            <Search size={18} className="text-green-400" />
            <span className="text-sm font-medium text-slate-400">Collections</span>
          </div>
          <p className="text-2xl font-bold text-slate-100">
            {collections.length}
          </p>
        </div>
        <div className="bg-slate-800 border border-slate-700 rounded-xl p-5">
          <div className="flex items-center gap-3 mb-2">
            <Monitor size={18} className="text-amber-400" />
            <span className="text-sm font-medium text-slate-400">Persistence Items</span>
          </div>
          <p className="text-2xl font-bold text-slate-100">
            {persistenceCount !== null ? persistenceCount : '--'}
          </p>
        </div>
      </div>

      {/* Host metadata */}
      {caseData.host && (
        <div className="bg-slate-800 border border-slate-700 rounded-xl p-6">
          <h2 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-4">
            Host Information
          </h2>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {[
              { label: 'Hostname', value: caseData.host.hostname },
              { label: 'OS Version', value: caseData.host.os_version },
              { label: 'Architecture', value: caseData.host.architecture },
              { label: 'Domain', value: caseData.host.domain },
              { label: 'Current User', value: caseData.host.current_user },
              { label: 'Boot Time', value: formatDate(caseData.host.boot_time) },
              { label: 'Timezone', value: caseData.host.timezone },
              { label: 'OS Build', value: caseData.host.os_build },
            ].map((item) => (
              <div key={item.label}>
                <p className="text-xs text-slate-500">{item.label}</p>
                <p className="text-sm text-slate-200 font-mono mt-0.5">
                  {item.value || '--'}
                </p>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Collections */}
      {collections.length > 0 && (
        <div className="space-y-4">
          <h2 className="text-sm font-semibold text-slate-300 uppercase tracking-wider">
            Collections
          </h2>
          {collections.map((job) => (
            <CollectionProgress
              key={job.id}
              job={job}
              onRefresh={() => refreshJob(job.id)}
            />
          ))}
        </div>
      )}

      {/* Start collection modal */}
      <Modal
        open={showCollect}
        onClose={() => setShowCollect(false)}
        title="Start Collection"
        actions={
          <>
            <button
              onClick={() => setShowCollect(false)}
              className="px-4 py-2 text-sm font-medium text-slate-400 hover:text-slate-200 rounded-lg hover:bg-slate-700"
            >
              Cancel
            </button>
            <button
              onClick={handleStartCollection}
              disabled={starting}
              className="flex items-center gap-2 px-4 py-2 bg-green-600 hover:bg-green-700 text-white rounded-lg text-sm font-medium disabled:opacity-50"
            >
              {starting && <Loader2 size={14} className="animate-spin" />}
              Start
            </button>
          </>
        }
      >
        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-slate-300 mb-1.5">
              Collection Preset
            </label>
            <select
              value={preset}
              onChange={(e) => setPreset(e.target.value)}
              className="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-lg text-sm text-slate-100 focus:outline-none focus:ring-2 focus:ring-forensic-500"
            >
              <option value="standard">Standard - Common forensic artifacts</option>
              <option value="deep">Deep - Full system collection</option>
            </select>
          </div>
          <div>
            <label className="block text-sm font-medium text-slate-300 mb-1.5">
              Time Range (hours)
            </label>
            <input
              type="number"
              value={timeRange}
              onChange={(e) => setTimeRange(Number(e.target.value))}
              min={1}
              max={8760}
              className="w-full px-3 py-2 bg-slate-700 border border-slate-600 rounded-lg text-sm text-slate-100 focus:outline-none focus:ring-2 focus:ring-forensic-500"
            />
            <p className="text-xs text-slate-500 mt-1">
              Collect events from the last {timeRange} hours
            </p>
          </div>
        </div>
      </Modal>
    </div>
  )
}
