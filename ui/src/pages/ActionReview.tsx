import { useState, useEffect, useCallback } from 'react'
import { useParams } from 'react-router-dom'
import {
  Loader2,
  AlertCircle,
  ShieldCheck,
  Check,
  X,
  Play,
  AlertTriangle,
  ChevronDown,
  Shield,
} from 'lucide-react'
import {
  listActions,
  approveAction,
  rejectAction,
  executeAction,
} from '../api/client'
import type { ActionProposal } from '../types'
import Badge from '../components/Badge'
import Modal from '../components/Modal'

function formatDate(iso: string): string {
  if (!iso) return '--'
  return new Date(iso).toLocaleString()
}

function statusVariant(status: ActionProposal['status']) {
  switch (status) {
    case 'pending':
      return 'warning' as const
    case 'approved':
      return 'info' as const
    case 'rejected':
      return 'neutral' as const
    case 'executed':
      return 'success' as const
    default:
      return 'default' as const
  }
}

function riskVariant(risk: ActionProposal['risk_level']) {
  switch (risk) {
    case 'critical':
      return 'danger' as const
    case 'high':
      return 'danger' as const
    case 'medium':
      return 'warning' as const
    case 'low':
      return 'info' as const
    default:
      return 'default' as const
  }
}

function riskIcon(risk: ActionProposal['risk_level']) {
  switch (risk) {
    case 'critical':
    case 'high':
      return <AlertTriangle size={14} className="text-red-400" />
    case 'medium':
      return <AlertTriangle size={14} className="text-amber-400" />
    default:
      return <Shield size={14} className="text-blue-400" />
  }
}

type FilterStatus = 'all' | 'pending' | 'approved' | 'rejected' | 'executed'

export default function ActionReview() {
  const { id: caseId } = useParams<{ id: string }>()
  const [actions, setActions] = useState<ActionProposal[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [expandedId, setExpandedId] = useState<string | null>(null)
  const [statusFilter, setStatusFilter] = useState<FilterStatus>('all')

  // Confirm execute modal
  const [executeTarget, setExecuteTarget] = useState<ActionProposal | null>(null)
  const [executing, setExecuting] = useState(false)
  const [executeResult, setExecuteResult] = useState<string | null>(null)

  // Processing states
  const [processingId, setProcessingId] = useState<string | null>(null)

  const load = useCallback(async () => {
    if (!caseId) return
    try {
      setLoading(true)
      setError(null)
      const data = await listActions(caseId)
      setActions(data ?? [])
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load actions')
    } finally {
      setLoading(false)
    }
  }, [caseId])

  useEffect(() => {
    load()
  }, [load])

  async function handleApprove(action: ActionProposal) {
    if (!caseId) return
    try {
      setProcessingId(action.id)
      await approveAction(caseId, action.id)
      setActions((prev) =>
        prev.map((a) =>
          a.id === action.id
            ? { ...a, status: 'approved' as const, reviewed_at: new Date().toISOString() }
            : a
        )
      )
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to approve action')
    } finally {
      setProcessingId(null)
    }
  }

  async function handleReject(action: ActionProposal) {
    if (!caseId) return
    try {
      setProcessingId(action.id)
      await rejectAction(caseId, action.id)
      setActions((prev) =>
        prev.map((a) =>
          a.id === action.id
            ? { ...a, status: 'rejected' as const, reviewed_at: new Date().toISOString() }
            : a
        )
      )
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to reject action')
    } finally {
      setProcessingId(null)
    }
  }

  async function handleExecute() {
    if (!caseId || !executeTarget) return
    try {
      setExecuting(true)
      const result = await executeAction(caseId, executeTarget.id)
      setExecuteResult(JSON.stringify(result, null, 2))
      setActions((prev) =>
        prev.map((a) =>
          a.id === executeTarget.id
            ? {
                ...a,
                status: 'executed' as const,
                executed_at: new Date().toISOString(),
                result: JSON.stringify(result),
              }
            : a
        )
      )
    } catch (err) {
      setExecuteResult(`Error: ${err instanceof Error ? err.message : 'Execution failed'}`)
    } finally {
      setExecuting(false)
    }
  }

  const filteredActions =
    statusFilter === 'all'
      ? actions
      : actions.filter((a) => a.status === statusFilter)

  const pendingCount = actions.filter((a) => a.status === 'pending').length

  if (loading) {
    return (
      <div className="flex items-center justify-center py-20">
        <Loader2 size={32} className="text-forensic-400 animate-spin" />
      </div>
    )
  }

  return (
    <div className="max-w-5xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold text-slate-100">Action Review</h1>
          <p className="text-sm text-slate-400 mt-1">
            Review and approve recommended response actions
            {pendingCount > 0 && (
              <span className="ml-2 inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium bg-amber-500/20 text-amber-400">
                {pendingCount} pending
              </span>
            )}
          </p>
        </div>
      </div>

      {/* Filter tabs */}
      <div className="flex items-center gap-1 mb-6 p-1 bg-slate-800 border border-slate-700 rounded-xl w-fit">
        {(['all', 'pending', 'approved', 'rejected', 'executed'] as FilterStatus[]).map(
          (status) => (
            <button
              key={status}
              onClick={() => setStatusFilter(status)}
              className={`px-3 py-1.5 rounded-lg text-sm font-medium transition-colors ${
                statusFilter === status
                  ? 'bg-forensic-600/20 text-forensic-400'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-700'
              }`}
            >
              {status.charAt(0).toUpperCase() + status.slice(1)}
              {status === 'pending' && pendingCount > 0 && (
                <span className="ml-1.5 text-xs">{pendingCount}</span>
              )}
            </button>
          )
        )}
      </div>

      {error && (
        <div className="mb-4 p-4 bg-red-500/10 border border-red-500/30 rounded-lg flex items-center gap-3">
          <AlertCircle size={18} className="text-red-400 shrink-0" />
          <p className="text-sm text-red-400">{error}</p>
        </div>
      )}

      {filteredActions.length === 0 && (
        <div className="text-center py-20">
          <ShieldCheck size={48} className="text-slate-600 mx-auto mb-4" />
          <h3 className="text-lg font-medium text-slate-300">
            No {statusFilter === 'all' ? '' : statusFilter} actions
          </h3>
          <p className="text-sm text-slate-500 mt-1">
            Action proposals from the agent will appear here
          </p>
        </div>
      )}

      {/* Action cards */}
      <div className="space-y-4">
        {filteredActions.map((action) => (
          <div
            key={action.id}
            className="bg-slate-800 border border-slate-700 rounded-xl overflow-hidden hover:border-slate-600 transition-colors"
          >
            {/* Card header */}
            <div
              className="p-5 cursor-pointer"
              onClick={() =>
                setExpandedId(expandedId === action.id ? null : action.id)
              }
            >
              <div className="flex items-start justify-between gap-4">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-2 flex-wrap">
                    <Badge variant={statusVariant(action.status)}>
                      {action.status}
                    </Badge>
                    <Badge variant={riskVariant(action.risk_level)}>
                      {riskIcon(action.risk_level)}
                      <span className="ml-1">{action.risk_level} risk</span>
                    </Badge>
                    <span className="text-xs text-slate-500">{action.type}</span>
                  </div>
                  <h3 className="text-base font-semibold text-slate-200">
                    {action.title}
                  </h3>
                  <p className="text-sm text-slate-400 mt-1 line-clamp-2">
                    {action.rationale}
                  </p>
                </div>

                <div className="flex items-center gap-2 shrink-0">
                  {/* Action buttons for pending */}
                  {action.status === 'pending' && (
                    <>
                      <button
                        onClick={(e) => {
                          e.stopPropagation()
                          handleApprove(action)
                        }}
                        disabled={processingId === action.id}
                        className="flex items-center gap-1.5 px-3 py-1.5 bg-green-600 hover:bg-green-700 text-white rounded-lg text-sm font-medium disabled:opacity-50"
                      >
                        {processingId === action.id ? (
                          <Loader2 size={14} className="animate-spin" />
                        ) : (
                          <Check size={14} />
                        )}
                        Approve
                      </button>
                      <button
                        onClick={(e) => {
                          e.stopPropagation()
                          handleReject(action)
                        }}
                        disabled={processingId === action.id}
                        className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-700 hover:bg-slate-600 text-slate-300 rounded-lg text-sm font-medium disabled:opacity-50"
                      >
                        <X size={14} />
                        Reject
                      </button>
                    </>
                  )}
                  {/* Execute button for approved */}
                  {action.status === 'approved' && (
                    <button
                      onClick={(e) => {
                        e.stopPropagation()
                        setExecuteTarget(action)
                        setExecuteResult(null)
                      }}
                      className="flex items-center gap-1.5 px-3 py-1.5 bg-amber-600 hover:bg-amber-700 text-white rounded-lg text-sm font-medium"
                    >
                      <Play size={14} />
                      Execute
                    </button>
                  )}
                  <ChevronDown
                    size={16}
                    className={`text-slate-500 transition-transform ${
                      expandedId === action.id ? 'rotate-180' : ''
                    }`}
                  />
                </div>
              </div>
            </div>

            {/* Expanded content */}
            {expandedId === action.id && (
              <div className="px-5 pb-5 border-t border-slate-700 pt-4 space-y-4">
                {/* Description */}
                {action.description && (
                  <div>
                    <h4 className="text-xs font-semibold text-slate-500 uppercase tracking-wider mb-1.5">
                      Description
                    </h4>
                    <p className="text-sm text-slate-300">{action.description}</p>
                  </div>
                )}

                {/* Steps */}
                {action.steps && action.steps.length > 0 && (
                  <div>
                    <h4 className="text-xs font-semibold text-slate-500 uppercase tracking-wider mb-2">
                      Steps
                    </h4>
                    <ol className="space-y-1.5">
                      {action.steps.map((step, i) => (
                        <li key={i} className="flex items-start gap-2">
                          <span className="text-xs font-mono text-slate-600 mt-0.5 w-5 text-right shrink-0">
                            {i + 1}.
                          </span>
                          <span className="text-sm text-slate-300">{step}</span>
                        </li>
                      ))}
                    </ol>
                  </div>
                )}

                {/* Rationale */}
                <div>
                  <h4 className="text-xs font-semibold text-slate-500 uppercase tracking-wider mb-1.5">
                    Rationale
                  </h4>
                  <p className="text-sm text-slate-300">{action.rationale}</p>
                </div>

                {/* Execution result */}
                {action.result && (
                  <div>
                    <h4 className="text-xs font-semibold text-slate-500 uppercase tracking-wider mb-1.5">
                      Execution Result
                    </h4>
                    <pre className="p-3 bg-slate-900 border border-slate-700 rounded-lg text-xs text-slate-300 font-mono overflow-auto max-h-48 whitespace-pre-wrap">
                      {action.result}
                    </pre>
                  </div>
                )}

                {/* Timestamps */}
                <div className="flex items-center gap-6 text-xs text-slate-500 pt-2 border-t border-slate-700/50">
                  <span>Created: {formatDate(action.created_at)}</span>
                  {action.reviewed_at && (
                    <span>Reviewed: {formatDate(action.reviewed_at)}</span>
                  )}
                  {action.executed_at && (
                    <span>Executed: {formatDate(action.executed_at)}</span>
                  )}
                </div>
              </div>
            )}
          </div>
        ))}
      </div>

      {/* Execute confirmation modal */}
      <Modal
        open={!!executeTarget}
        onClose={() => {
          setExecuteTarget(null)
          setExecuteResult(null)
        }}
        title="Execute Action"
        width="max-w-xl"
        actions={
          !executeResult ? (
            <>
              <button
                onClick={() => {
                  setExecuteTarget(null)
                  setExecuteResult(null)
                }}
                className="px-4 py-2 text-sm font-medium text-slate-400 hover:text-slate-200 rounded-lg hover:bg-slate-700"
              >
                Cancel
              </button>
              <button
                onClick={handleExecute}
                disabled={executing}
                className="flex items-center gap-2 px-4 py-2 bg-amber-600 hover:bg-amber-700 text-white rounded-lg text-sm font-medium disabled:opacity-50"
              >
                {executing ? (
                  <Loader2 size={14} className="animate-spin" />
                ) : (
                  <Play size={14} />
                )}
                Confirm Execute
              </button>
            </>
          ) : (
            <button
              onClick={() => {
                setExecuteTarget(null)
                setExecuteResult(null)
              }}
              className="px-4 py-2 text-sm font-medium text-slate-400 hover:text-slate-200 rounded-lg hover:bg-slate-700"
            >
              Close
            </button>
          )
        }
      >
        {executeTarget && !executeResult && (
          <div className="space-y-4">
            {/* Warning for high risk */}
            {(executeTarget.risk_level === 'high' ||
              executeTarget.risk_level === 'critical') && (
              <div className="p-4 bg-red-500/10 border border-red-500/30 rounded-lg flex items-start gap-3">
                <AlertTriangle
                  size={20}
                  className="text-red-400 shrink-0 mt-0.5"
                />
                <div>
                  <p className="text-sm font-medium text-red-400">
                    High Risk Action
                  </p>
                  <p className="text-xs text-red-400/70 mt-1">
                    This action has been classified as{' '}
                    <strong>{executeTarget.risk_level}</strong> risk. It may make
                    irreversible changes to the system. Ensure you understand the
                    implications before proceeding.
                  </p>
                </div>
              </div>
            )}

            {/* Memory acquisition warning */}
            {executeTarget.type.toLowerCase().includes('memory') && (
              <div className="p-4 bg-amber-500/10 border border-amber-500/30 rounded-lg flex items-start gap-3">
                <AlertTriangle
                  size={20}
                  className="text-amber-400 shrink-0 mt-0.5"
                />
                <div>
                  <p className="text-sm font-medium text-amber-400">
                    Memory Acquisition Warning
                  </p>
                  <p className="text-xs text-amber-400/70 mt-1">
                    Memory acquisition will capture a full memory dump of the
                    system. This operation requires significant disk space and
                    may temporarily impact system performance. The process may
                    take several minutes depending on the amount of RAM installed.
                  </p>
                </div>
              </div>
            )}

            <div>
              <h4 className="text-sm font-medium text-slate-300 mb-1">
                {executeTarget.title}
              </h4>
              <p className="text-sm text-slate-400">{executeTarget.description}</p>
            </div>

            {executeTarget.steps && executeTarget.steps.length > 0 && (
              <div>
                <p className="text-xs text-slate-500 mb-2">
                  The following steps will be executed:
                </p>
                <ol className="space-y-1">
                  {executeTarget.steps.map((step, i) => (
                    <li
                      key={i}
                      className="text-sm text-slate-300 flex items-start gap-2"
                    >
                      <span className="text-xs text-slate-600 font-mono mt-0.5">
                        {i + 1}.
                      </span>
                      {step}
                    </li>
                  ))}
                </ol>
              </div>
            )}
          </div>
        )}

        {/* Result display */}
        {executeResult && (
          <div>
            <h4 className="text-sm font-medium text-slate-300 mb-2">
              Execution Result
            </h4>
            <pre className="p-4 bg-slate-900 border border-slate-700 rounded-lg text-xs text-slate-300 font-mono overflow-auto max-h-64 whitespace-pre-wrap">
              {executeResult}
            </pre>
          </div>
        )}
      </Modal>
    </div>
  )
}
