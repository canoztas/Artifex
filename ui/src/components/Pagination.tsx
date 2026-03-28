import { ChevronLeft, ChevronRight } from 'lucide-react'

interface PaginationProps {
  hasNext: boolean
  hasPrev: boolean
  onNext: () => void
  onPrev: () => void
  total?: number
  showing?: number
  label?: string
}

export default function Pagination({
  hasNext,
  hasPrev,
  onNext,
  onPrev,
  total,
  showing,
  label = 'items',
}: PaginationProps) {
  return (
    <div className="flex items-center justify-between py-3">
      <div className="text-sm text-slate-400">
        {total !== undefined && (
          <span>
            {showing !== undefined ? `Showing ${showing} of ` : ''}
            {total} {label}
          </span>
        )}
      </div>
      <div className="flex items-center gap-2">
        <button
          onClick={onPrev}
          disabled={!hasPrev}
          className="flex items-center gap-1 px-3 py-1.5 text-sm font-medium rounded-lg border border-slate-600 text-slate-300 hover:bg-slate-700 disabled:opacity-40 disabled:cursor-not-allowed disabled:hover:bg-transparent"
        >
          <ChevronLeft size={16} />
          Previous
        </button>
        <button
          onClick={onNext}
          disabled={!hasNext}
          className="flex items-center gap-1 px-3 py-1.5 text-sm font-medium rounded-lg border border-slate-600 text-slate-300 hover:bg-slate-700 disabled:opacity-40 disabled:cursor-not-allowed disabled:hover:bg-transparent"
        >
          Next
          <ChevronRight size={16} />
        </button>
      </div>
    </div>
  )
}
