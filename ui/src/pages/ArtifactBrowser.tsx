import { useState, useEffect, useCallback } from 'react'
import { useParams } from 'react-router-dom'
import {
  Loader2,
  AlertCircle,
  FileSearch,
  Eye,
  Download,
  Filter,
  X,
} from 'lucide-react'
import { listArtifacts, getArtifactContent } from '../api/client'
import type { Artifact } from '../types'
import Pagination from '../components/Pagination'
import Badge from '../components/Badge'
import Modal from '../components/Modal'

const PAGE_SIZE = 25
const LOAD_BATCH_SIZE = 1000

function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`
}

function formatDate(iso: string): string {
  if (!iso) return '--'
  return new Date(iso).toLocaleString()
}

function artifactTypeColor(type: string): string {
  const colors: Record<string, string> = {
    evtx: 'info',
    registry: 'warning',
    prefetch: 'success',
    lnk: 'warning',
    jumplist_automatic: 'info',
    jumplist_custom: 'info',
    filesystem: 'neutral',
  }
  return colors[type.toLowerCase()] || 'default'
}

function artifactLocation(artifact: Artifact): string {
  return artifact.path || artifact.source || artifact.blob_path || '--'
}

function artifactDownloadName(artifact: Artifact): string {
  const candidate = artifact.path || artifact.source || artifact.type || 'artifact'
  return candidate.split(/[\\/]/).pop() || 'artifact'
}

export default function ArtifactBrowser() {
  const { id: caseId } = useParams<{ id: string }>()
  const [artifacts, setArtifacts] = useState<Artifact[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [pageIndex, setPageIndex] = useState(0)
  const [typeFilter, setTypeFilter] = useState('')

  // Preview
  const [previewArtifact, setPreviewArtifact] = useState<Artifact | null>(null)
  const [previewContent, setPreviewContent] = useState<string | null>(null)
  const [previewLoading, setPreviewLoading] = useState(false)

  const load = useCallback(
    async () => {
      if (!caseId) return
      try {
        setLoading(true)
        setError(null)
        const allArtifacts: Artifact[] = []
        let cursor: string | undefined

        do {
          const data = await listArtifacts(caseId, cursor, LOAD_BATCH_SIZE)
          allArtifacts.push(...(data.items ?? []))
          cursor = data.next_cursor
        } while (cursor)

        setArtifacts(allArtifacts)
        setPageIndex(0)
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to load artifacts')
      } finally {
        setLoading(false)
      }
    },
    [caseId]
  )

  useEffect(() => {
    load()
  }, [load])

  useEffect(() => {
    setPageIndex(0)
  }, [typeFilter])

  async function handlePreview(artifact: Artifact) {
    if (!caseId) return
    setPreviewArtifact(artifact)
    setPreviewContent(null)
    setPreviewLoading(true)
    try {
      const blob = await getArtifactContent(caseId, artifact.id, 0, 10240)
      const text = await blob.text()
      setPreviewContent(text)
    } catch {
      setPreviewContent('[Unable to load content preview]')
    } finally {
      setPreviewLoading(false)
    }
  }

  async function handleDownload(artifact: Artifact) {
    if (!caseId) return
    try {
      const blob = await getArtifactContent(caseId, artifact.id)
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = artifactDownloadName(artifact)
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
      URL.revokeObjectURL(url)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Download failed')
    }
  }

  const filteredArtifacts = typeFilter
    ? artifacts.filter((a) =>
        a.type.toLowerCase().includes(typeFilter.toLowerCase())
      )
    : artifacts
  const pageStart = pageIndex * PAGE_SIZE
  const pagedArtifacts = filteredArtifacts.slice(pageStart, pageStart + PAGE_SIZE)

  return (
    <div className="max-w-6xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold text-slate-100">Artifacts</h1>
          <p className="text-sm text-slate-400 mt-1">
            Browse collected forensic artifacts
          </p>
        </div>
        <div className="flex items-center gap-3">
          <div className="relative">
            <Filter size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
            <input
              type="text"
              value={typeFilter}
              onChange={(e) => setTypeFilter(e.target.value)}
              placeholder="Filter by type..."
              className="pl-8 pr-8 py-2 bg-slate-800 border border-slate-700 rounded-lg text-sm text-slate-100 placeholder:text-slate-500 focus:outline-none focus:ring-2 focus:ring-forensic-500 w-48"
            />
            {typeFilter && (
              <button
                onClick={() => setTypeFilter('')}
                className="absolute right-2 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300"
              >
                <X size={14} />
              </button>
            )}
          </div>
        </div>
      </div>

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

      {!loading && filteredArtifacts.length === 0 && (
        <div className="text-center py-20">
          <FileSearch size={48} className="text-slate-600 mx-auto mb-4" />
          <h3 className="text-lg font-medium text-slate-300">No artifacts found</h3>
          <p className="text-sm text-slate-500 mt-1">
            Start a collection to gather forensic artifacts
          </p>
        </div>
      )}

      {!loading && filteredArtifacts.length > 0 && (
        <>
          <div className="bg-slate-800 border border-slate-700 rounded-xl overflow-hidden">
            <table className="w-full">
              <thead>
                <tr className="border-b border-slate-700">
                  <th className="text-left px-5 py-3 text-xs font-semibold text-slate-400 uppercase tracking-wider">
                    Type
                  </th>
                  <th className="text-left px-5 py-3 text-xs font-semibold text-slate-400 uppercase tracking-wider">
                    Source / Path
                  </th>
                  <th className="text-left px-5 py-3 text-xs font-semibold text-slate-400 uppercase tracking-wider">
                    Size
                  </th>
                  <th className="text-left px-5 py-3 text-xs font-semibold text-slate-400 uppercase tracking-wider">
                    Collected
                  </th>
                  <th className="text-left px-5 py-3 text-xs font-semibold text-slate-400 uppercase tracking-wider">
                    SHA256
                  </th>
                  <th className="text-right px-5 py-3 text-xs font-semibold text-slate-400 uppercase tracking-wider">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-700/50">
                {pagedArtifacts.map((artifact) => (
                  <tr
                    key={artifact.id}
                    className="hover:bg-slate-700/30 transition-colors"
                  >
                    <td className="px-5 py-3">
                      <Badge variant={artifactTypeColor(artifact.type) as 'info' | 'warning' | 'success' | 'danger' | 'neutral' | 'default'}>
                        {artifact.type}
                      </Badge>
                    </td>
                    <td className="px-5 py-3">
                      <p className="text-sm text-slate-300 font-mono truncate max-w-xs" title={artifact.source || artifactLocation(artifact)}>
                        {artifact.source || '--'}
                      </p>
                      <p className="text-xs text-slate-500 font-mono truncate max-w-xs mt-0.5" title={artifactLocation(artifact)}>
                        {artifactLocation(artifact)}
                      </p>
                    </td>
                    <td className="px-5 py-3 text-sm text-slate-400 whitespace-nowrap">
                      {formatBytes(artifact.size)}
                    </td>
                    <td className="px-5 py-3 text-sm text-slate-400 whitespace-nowrap">
                      {formatDate(artifact.collected_at)}
                    </td>
                    <td className="px-5 py-3">
                      <span
                        className="text-xs text-slate-500 font-mono truncate block max-w-[140px]"
                        title={artifact.sha256 || '--'}
                      >
                        {artifact.sha256 ? `${artifact.sha256.slice(0, 16)}...` : '--'}
                      </span>
                    </td>
                    <td className="px-5 py-3 text-right">
                      <div className="flex items-center justify-end gap-1">
                        <button
                          onClick={() => handlePreview(artifact)}
                          className="p-2 text-slate-500 hover:text-blue-400 hover:bg-blue-500/10 rounded-lg"
                          title="Preview"
                        >
                          <Eye size={16} />
                        </button>
                        <button
                          onClick={() => handleDownload(artifact)}
                          className="p-2 text-slate-500 hover:text-green-400 hover:bg-green-500/10 rounded-lg"
                          title="Download"
                        >
                          <Download size={16} />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <Pagination
            hasNext={pageStart + PAGE_SIZE < filteredArtifacts.length}
            hasPrev={pageIndex > 0}
            onNext={() => setPageIndex((p) => p + 1)}
            onPrev={() => setPageIndex((p) => Math.max(0, p - 1))}
            total={filteredArtifacts.length}
            showing={pagedArtifacts.length}
            label="artifacts"
          />
        </>
      )}

      {/* Preview modal */}
      <Modal
        open={!!previewArtifact}
        onClose={() => setPreviewArtifact(null)}
        title={`Artifact Preview: ${previewArtifact?.source || ''}`}
        width="max-w-3xl"
      >
        {previewArtifact && (
          <div className="space-y-4">
            <div className="grid grid-cols-2 gap-4 text-sm">
              <div>
                <span className="text-slate-500">Type:</span>{' '}
                <span className="text-slate-200">{previewArtifact.type}</span>
              </div>
              <div>
                <span className="text-slate-500">Size:</span>{' '}
                <span className="text-slate-200">{formatBytes(previewArtifact.size)}</span>
              </div>
              <div className="col-span-2">
                <span className="text-slate-500">Path:</span>{' '}
                <span className="text-slate-200 font-mono text-xs">{artifactLocation(previewArtifact)}</span>
              </div>
              <div className="col-span-2">
                <span className="text-slate-500">SHA256:</span>{' '}
                <span className="text-slate-200 font-mono text-xs">{previewArtifact.sha256 || '--'}</span>
              </div>
            </div>
            <div className="border-t border-slate-700 pt-4">
              <h4 className="text-sm font-medium text-slate-400 mb-2">Content Preview</h4>
              {previewLoading ? (
                <div className="flex items-center justify-center py-8">
                  <Loader2 size={24} className="text-forensic-400 animate-spin" />
                </div>
              ) : (
                <pre className="p-4 bg-slate-900 border border-slate-700 rounded-lg text-xs text-slate-300 font-mono overflow-auto max-h-96 whitespace-pre-wrap break-all">
                  {previewContent}
                </pre>
              )}
            </div>
          </div>
        )}
      </Modal>
    </div>
  )
}
