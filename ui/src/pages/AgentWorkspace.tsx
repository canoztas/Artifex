import { useState, useCallback, useRef, useEffect } from 'react'
import { useParams } from 'react-router-dom'
import {
  Loader2,
  AlertCircle,
  Bot,
  Send,
  ChevronDown,
  ChevronRight,
  Wrench,
  CheckCircle2,
  XCircle,
  User,
  Sparkles,
} from 'lucide-react'
import { agentChat } from '../api/client'
import type { ChatMessage, AgentStep } from '../types'
import Badge from '../components/Badge'

function formatTime(iso: string): string {
  if (!iso) return '--'
  return new Date(iso).toLocaleTimeString([], {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  })
}

function ToolStepView({ step }: { step: AgentStep }) {
  const [expanded, setExpanded] = useState(false)

  if (step.type === 'tool_call') {
    let argsPreview = step.tool_args || '{}'
    try {
      const parsed = JSON.parse(argsPreview)
      argsPreview = JSON.stringify(parsed, null, 2)
    } catch {
      // keep as-is
    }
    return (
      <div className="flex items-start gap-2 py-1.5 px-3 bg-slate-800/50 rounded-lg border border-slate-700/50 text-xs">
        <Wrench size={14} className="text-forensic-400 mt-0.5 shrink-0" />
        <div className="flex-1 min-w-0">
          <button
            onClick={() => setExpanded(!expanded)}
            className="flex items-center gap-1 text-forensic-300 font-medium hover:text-forensic-200"
          >
            {expanded ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
            <span className="font-mono">{step.tool_name}</span>
          </button>
          {expanded && (
            <pre className="mt-2 p-2 bg-slate-900/60 rounded text-slate-400 font-mono whitespace-pre-wrap break-all text-[11px] max-h-40 overflow-y-auto">
              {argsPreview}
            </pre>
          )}
        </div>
      </div>
    )
  }

  if (step.type === 'tool_result') {
    let resultPreview = step.tool_result || ''
    try {
      const parsed = JSON.parse(resultPreview)
      resultPreview = JSON.stringify(parsed, null, 2)
    } catch {
      // keep as-is
    }
    // Truncate for display
    const truncated = resultPreview.length > 500
    const displayResult = truncated ? resultPreview.slice(0, 500) + '...' : resultPreview

    return (
      <div className="flex items-start gap-2 py-1.5 px-3 bg-slate-800/30 rounded-lg border border-slate-700/30 text-xs">
        {step.is_error ? (
          <XCircle size={14} className="text-red-400 mt-0.5 shrink-0" />
        ) : (
          <CheckCircle2 size={14} className="text-green-400 mt-0.5 shrink-0" />
        )}
        <div className="flex-1 min-w-0">
          <button
            onClick={() => setExpanded(!expanded)}
            className={`flex items-center gap-1 font-medium hover:opacity-80 ${
              step.is_error ? 'text-red-400' : 'text-green-400'
            }`}
          >
            {expanded ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
            <span className="font-mono">{step.tool_name}</span>
            <span className="text-slate-500 font-normal ml-1">
              {step.is_error ? 'error' : 'result'}
            </span>
          </button>
          {expanded && (
            <pre className="mt-2 p-2 bg-slate-900/60 rounded text-slate-400 font-mono whitespace-pre-wrap break-all text-[11px] max-h-60 overflow-y-auto">
              {displayResult}
            </pre>
          )}
        </div>
      </div>
    )
  }

  if (step.type === 'thinking' && step.content) {
    return (
      <div className="text-xs text-slate-500 italic px-3 py-1">
        {step.content.slice(0, 200)}{step.content.length > 200 ? '...' : ''}
      </div>
    )
  }

  return null
}

function ToolStepsGroup({ steps }: { steps: AgentStep[] }) {
  const [collapsed, setCollapsed] = useState(false)
  const toolCalls = steps.filter((s) => s.type === 'tool_call')

  if (steps.length === 0) return null

  return (
    <div className="my-2">
      <button
        onClick={() => setCollapsed(!collapsed)}
        className="flex items-center gap-2 text-xs text-slate-500 hover:text-slate-400 mb-1.5"
      >
        {collapsed ? <ChevronRight size={12} /> : <ChevronDown size={12} />}
        <Wrench size={12} />
        <span>
          {toolCalls.length} tool call{toolCalls.length !== 1 ? 's' : ''}
        </span>
      </button>
      {!collapsed && (
        <div className="space-y-1 ml-2 border-l-2 border-slate-700/50 pl-3">
          {steps.map((step, i) => (
            <ToolStepView key={i} step={step} />
          ))}
        </div>
      )}
    </div>
  )
}

export default function AgentWorkspace() {
  const { id: caseId } = useParams<{ id: string }>()
  const [messages, setMessages] = useState<ChatMessage[]>([])
  const [input, setInput] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const bottomRef = useRef<HTMLDivElement>(null)
  const inputRef = useRef<HTMLTextAreaElement>(null)

  useEffect(() => {
    if (bottomRef.current) {
      bottomRef.current.scrollIntoView({ behavior: 'smooth' })
    }
  }, [messages, loading])

  const handleSubmit = useCallback(
    async (e?: React.FormEvent) => {
      e?.preventDefault()
      const msg = input.trim()
      if (!msg || !caseId || loading) return

      setInput('')
      setError(null)

      const userMsg: ChatMessage = {
        role: 'user',
        content: msg,
        timestamp: new Date().toISOString(),
      }
      setMessages((prev) => [...prev, userMsg])
      setLoading(true)

      try {
        // Build history from previous messages for context
        const history = messages.map((m) => ({
          role: m.role === 'user' ? 'user' : 'assistant',
          content: m.content,
        }))

        const resp = await agentChat(caseId, msg, history)

        const assistantMsg: ChatMessage = {
          role: 'assistant',
          content: resp.answer || resp.error || 'No response from agent.',
          steps: resp.steps,
          timestamp: new Date().toISOString(),
        }
        setMessages((prev) => [...prev, assistantMsg])
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to get agent response')
      } finally {
        setLoading(false)
        inputRef.current?.focus()
      }
    },
    [input, caseId, loading, messages]
  )

  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault()
        handleSubmit()
      }
    },
    [handleSubmit]
  )

  return (
    <div className="max-w-4xl mx-auto flex flex-col h-[calc(100vh-8rem)]">
      {/* Header */}
      <div className="flex items-center gap-3 mb-4">
        <div className="p-2 bg-purple-500/20 rounded-lg">
          <Bot size={24} className="text-purple-400" />
        </div>
        <div>
          <h1 className="text-2xl font-bold text-slate-100">Artifex Agent</h1>
          <p className="text-sm text-slate-400">
            AI-powered DFIR analysis &mdash; ask questions about collected evidence
          </p>
        </div>
        <Badge variant="info" className="ml-auto">Gemini</Badge>
      </div>

      {/* Chat area */}
      <div className="flex-1 overflow-y-auto bg-slate-800/30 border border-slate-700 rounded-xl p-4 space-y-4">
        {messages.length === 0 && !loading && (
          <div className="flex flex-col items-center justify-center h-full text-center py-20">
            <div className="p-4 bg-purple-500/10 rounded-full mb-4">
              <Sparkles size={40} className="text-purple-400" />
            </div>
            <h2 className="text-lg font-semibold text-slate-300 mb-2">
              Start your investigation
            </h2>
            <p className="text-sm text-slate-500 max-w-md">
              Ask the agent to analyze collected evidence, search for indicators of compromise,
              examine persistence mechanisms, or review the timeline of events.
            </p>
            <div className="mt-6 grid grid-cols-2 gap-2 text-xs">
              {[
                'What artifacts have been collected?',
                'Are there any suspicious persistence mechanisms?',
                'Show me the network connections at collection time',
                'Search events for PowerShell execution',
              ].map((suggestion) => (
                <button
                  key={suggestion}
                  onClick={() => {
                    setInput(suggestion)
                    inputRef.current?.focus()
                  }}
                  className="px-3 py-2 bg-slate-700/50 border border-slate-600/50 rounded-lg text-slate-400 hover:bg-slate-700 hover:text-slate-300 text-left transition-colors"
                >
                  {suggestion}
                </button>
              ))}
            </div>
          </div>
        )}

        {messages.map((msg, i) => (
          <div key={i}>
            {msg.role === 'user' ? (
              <div className="flex items-start gap-3 justify-end">
                <div className="max-w-[80%]">
                  <div className="bg-forensic-600/30 border border-forensic-500/30 rounded-xl rounded-tr-sm px-4 py-3">
                    <p className="text-sm text-slate-200 whitespace-pre-wrap">{msg.content}</p>
                  </div>
                  <p className="text-[10px] text-slate-600 mt-1 text-right">
                    {formatTime(msg.timestamp)}
                  </p>
                </div>
                <div className="p-1.5 bg-forensic-500/20 rounded-lg shrink-0">
                  <User size={16} className="text-forensic-400" />
                </div>
              </div>
            ) : (
              <div className="flex items-start gap-3">
                <div className="p-1.5 bg-purple-500/20 rounded-lg shrink-0">
                  <Bot size={16} className="text-purple-400" />
                </div>
                <div className="max-w-[85%]">
                  {/* Tool steps */}
                  {msg.steps && msg.steps.length > 0 && (
                    <ToolStepsGroup steps={msg.steps} />
                  )}

                  {/* Answer */}
                  <div className="bg-slate-700/40 border border-slate-600/40 rounded-xl rounded-tl-sm px-4 py-3">
                    <p className="text-sm text-slate-200 whitespace-pre-wrap leading-relaxed">
                      {msg.content}
                    </p>
                  </div>
                  <p className="text-[10px] text-slate-600 mt-1">
                    {formatTime(msg.timestamp)}
                    {msg.steps && (
                      <span className="ml-2">
                        {msg.steps.filter((s) => s.type === 'tool_call').length} tool calls
                      </span>
                    )}
                  </p>
                </div>
              </div>
            )}
          </div>
        ))}

        {loading && (
          <div className="flex items-start gap-3">
            <div className="p-1.5 bg-purple-500/20 rounded-lg shrink-0">
              <Bot size={16} className="text-purple-400" />
            </div>
            <div className="bg-slate-700/40 border border-slate-600/40 rounded-xl rounded-tl-sm px-4 py-3">
              <div className="flex items-center gap-2">
                <Loader2 size={14} className="text-purple-400 animate-spin" />
                <span className="text-sm text-slate-400">Analyzing evidence...</span>
              </div>
            </div>
          </div>
        )}

        <div ref={bottomRef} />
      </div>

      {/* Error banner */}
      {error && (
        <div className="mt-2 p-3 bg-red-500/10 border border-red-500/30 rounded-lg flex items-center gap-2">
          <AlertCircle size={14} className="text-red-400 shrink-0" />
          <p className="text-xs text-red-400 flex-1">{error}</p>
          <button
            onClick={() => setError(null)}
            className="text-xs text-red-400 hover:text-red-300 underline"
          >
            dismiss
          </button>
        </div>
      )}

      {/* Input area */}
      <form onSubmit={handleSubmit} className="mt-3 flex items-end gap-2">
        <div className="flex-1 relative">
          <textarea
            ref={inputRef}
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="Ask the agent about collected evidence..."
            rows={1}
            disabled={loading}
            className="w-full resize-none bg-slate-800 border border-slate-600 rounded-xl px-4 py-3 pr-12 text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-forensic-500 focus:ring-1 focus:ring-forensic-500/50 disabled:opacity-50 max-h-32"
            style={{ minHeight: '48px' }}
            onInput={(e) => {
              const target = e.target as HTMLTextAreaElement
              target.style.height = 'auto'
              target.style.height = Math.min(target.scrollHeight, 128) + 'px'
            }}
          />
        </div>
        <button
          type="submit"
          disabled={loading || !input.trim()}
          className="p-3 bg-forensic-600 hover:bg-forensic-500 disabled:opacity-40 disabled:cursor-not-allowed rounded-xl text-white transition-colors shrink-0"
        >
          <Send size={18} />
        </button>
      </form>
    </div>
  )
}
