import { useState } from 'react'
import { api, ApiError } from '../../lib/api'

interface RtoExportPanelProps {
  findingNo?: string | null
  commands?: { command: string; label?: string }[]
}

/**
 * Lets the operator select which of a retest's executed (placeholder-ized) commands to append
 * to the live RTO playbook (rto.json). Renders nothing when the record has no captured commands.
 */
export function RtoExportPanel({ findingNo, commands }: RtoExportPanelProps) {
  const list = commands ?? []
  const [selected, setSelected] = useState<Set<number>>(
    () => new Set(list.map((_, i) => i)),
  )
  const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)

  if (list.length === 0) return null

  const toggle = (i: number) =>
    setSelected((prev) => {
      const next = new Set(prev)
      if (next.has(i)) next.delete(i)
      else next.add(i)
      return next
    })

  const handleExport = async () => {
    const chosen = list.filter((_, i) => selected.has(i))
    if (chosen.length === 0) return
    setBusy(true)
    setError(null)
    setMessage(null)
    try {
      const res = await api.exportRtoPlaybook(
        findingNo,
        chosen.map((c) => ({ command: c.command, label: c.label })),
      )
      setMessage(
        `Exported: ${res.added} added, ${res.skipped} skipped (already present).`,
      )
    } catch (e) {
      setError(e instanceof ApiError ? e.message : 'Export failed')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="mt-3 rounded-lg border border-border bg-bg-primary p-4">
      <div className="mb-2 flex items-center justify-between">
        <div className="text-sm font-medium text-text-primary">
          Export commands to RTO playbook
        </div>
        <div className="text-xs text-text-muted">
          {selected.size}/{list.length} selected
        </div>
      </div>
      <p className="mb-3 text-xs text-text-muted">
        These commands ran during this retest with engagement values replaced by{' '}
        <code className="font-mono">{'{{placeholders}}'}</code>. Select which to
        append to the RTO playbook (rto.json). Duplicates are skipped.
      </p>
      <div className="space-y-2">
        {list.map((c, i) => (
          <label
            key={i}
            className="flex items-start gap-2 rounded border border-border bg-terminal-bg p-2"
          >
            <input
              type="checkbox"
              checked={selected.has(i)}
              onChange={() => toggle(i)}
              className="mt-1"
            />
            <div className="min-w-0 flex-1">
              {c.label && (
                <div className="text-xs text-text-secondary">{c.label}</div>
              )}
              <code className="block overflow-x-auto whitespace-pre-wrap break-all font-mono text-xs text-terminal-text">
                {c.command}
              </code>
            </div>
          </label>
        ))}
      </div>
      {error && <p className="mt-2 text-xs text-red-400">{error}</p>}
      {message && <p className="mt-2 text-xs text-green-400">{message}</p>}
      <div className="mt-3 flex justify-end">
        <button
          type="button"
          onClick={handleExport}
          disabled={busy || selected.size === 0}
          className="rounded-lg bg-accent px-3 py-1.5 text-xs font-medium text-white transition-colors hover:bg-accent-hover disabled:opacity-50"
        >
          {busy ? 'Exporting…' : 'Export selected'}
        </button>
      </div>
    </div>
  )
}
