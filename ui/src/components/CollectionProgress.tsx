import { useEffect, useRef } from 'react'
import { Check, Loader2, AlertCircle, Circle, SkipForward } from 'lucide-react'
import type { CollectionJob, JobStep } from '../types'

interface CollectionProgressProps {
  job: CollectionJob
  onRefresh: () => void
}

function StepIcon({ status }: { status: JobStep['status'] }) {
  switch (status) {
    case 'completed':
      return <Check size={16} className="text-green-400" />
    case 'running':
      return <Loader2 size={16} className="text-blue-400 animate-spin" />
    case 'failed':
      return <AlertCircle size={16} className="text-red-400" />
    case 'skipped':
      return <SkipForward size={16} className="text-slate-500" />
    default:
      return <Circle size={16} className="text-slate-600" />
  }
}

function stepStatusColor(status: JobStep['status']): string {
  switch (status) {
    case 'completed':
      return 'text-green-400'
    case 'running':
      return 'text-blue-400'
    case 'failed':
      return 'text-red-400'
    case 'skipped':
      return 'text-slate-500'
    default:
      return 'text-slate-500'
  }
}

export default function CollectionProgress({ job, onRefresh }: CollectionProgressProps) {
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null)

  useEffect(() => {
    if (job.status === 'running' || job.status === 'pending') {
      intervalRef.current = setInterval(onRefresh, 2000)
    }
    return () => {
      if (intervalRef.current) {
        clearInterval(intervalRef.current)
        intervalRef.current = null
      }
    }
  }, [job.status, onRefresh])

  const progressPercent = Math.round(job.progress * 100)

  return (
    <div className="bg-slate-800 border border-slate-700 rounded-xl p-5">
      {/* Header */}
      <div className="flex items-center justify-between mb-4">
        <div>
          <h3 className="text-sm font-semibold text-slate-200">
            Collection: {job.preset}
          </h3>
          <p className="text-xs text-slate-400 mt-0.5">
            Job {job.id.slice(0, 8)}... &middot;{' '}
            {job.status === 'running' ? 'In Progress' : job.status.charAt(0).toUpperCase() + job.status.slice(1)}
          </p>
        </div>
        <span
          className={`text-sm font-semibold ${
            job.status === 'completed'
              ? 'text-green-400'
              : job.status === 'failed'
              ? 'text-red-400'
              : 'text-blue-400'
          }`}
        >
          {progressPercent}%
        </span>
      </div>

      {/* Progress bar */}
      <div className="w-full h-2 bg-slate-700 rounded-full overflow-hidden mb-5">
        <div
          className={`h-full rounded-full transition-all duration-500 ${
            job.status === 'completed'
              ? 'bg-green-500'
              : job.status === 'failed'
              ? 'bg-red-500'
              : 'bg-blue-500'
          }`}
          style={{ width: `${progressPercent}%` }}
        />
      </div>

      {/* Steps */}
      <div className="space-y-2">
        {job.steps?.map((step, i) => (
          <div
            key={i}
            className="flex items-center gap-3 px-3 py-2 rounded-lg bg-slate-700/30"
          >
            <StepIcon status={step.status} />
            <span className={`text-sm flex-1 ${stepStatusColor(step.status)}`}>
              {step.name}
            </span>
            {step.items_collected > 0 && (
              <span className="text-xs text-slate-500">
                {step.items_collected} items
              </span>
            )}
            {step.error && (
              <span className="text-xs text-red-400 truncate max-w-[200px]" title={step.error}>
                {step.error}
              </span>
            )}
          </div>
        ))}
      </div>

      {/* Error message */}
      {job.error && (
        <div className="mt-4 p-3 bg-red-500/10 border border-red-500/30 rounded-lg">
          <p className="text-sm text-red-400">{job.error}</p>
        </div>
      )}
    </div>
  )
}
