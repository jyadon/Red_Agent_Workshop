import { useMemo, useState } from 'react'
import type { InterruptPayload, ResumeRequest, ReviewDecision } from '../../types/retest'
import { api } from '../../lib/api'
import { LoadingSpinner } from '../common/LoadingSpinner'

interface HITLReviewDialogProps {
  open: boolean
  interrupt: InterruptPayload | null
  loading?: boolean
  onSubmit: (payload: ResumeRequest) => Promise<void>
  onClose: () => void
}

type DecisionType = 'approve' | 'edit' | 'reject'

// Backend masks the AD password / secret inputs to this placeholder before sending the interrupt
// (agent/agent.py _redact_interrupt_secrets). Such tokens are credentials taken from the
// pre-run login, restored server-side at execution -- so they are shown masked and locked here.
const PASSWORD_PLACEHOLDER = '<PASS>'
const isSecretToken = (token: string) => token.includes(PASSWORD_PLACEHOLDER)

interface LocalDecisionState {
  type: DecisionType
  comment: string
  editedCommand: string // fallback raw-string edit when a command can't be tokenized
  editedArgs: string[] // structured per-argument edit (the tool/bin stays locked)
}

export function HITLReviewDialog({
  open,
  interrupt,
  loading = false,
  onSubmit,
  onClose,
}: HITLReviewDialogProps) {
  const initialState = useMemo(() => {
    if (!interrupt) return []
    return interrupt.actions.map((action) => ({
      type: 'approve' as DecisionType,
      comment: '',
      editedCommand:
        typeof action.args.command === 'string' ? action.args.command : '',
      editedArgs: Array.isArray(action.arg_tokens) ? [...action.arg_tokens] : [],
    }))
  }, [interrupt])

  const [decisions, setDecisions] = useState<LocalDecisionState[]>(initialState)

  // Lazily-loaded `<bin> --help` text per action index (advisory; helps spot invalid options).
  const [help, setHelp] = useState<
    Record<number, { loading: boolean; text?: string; error?: string }>
  >({})

  const loadHelp = async (index: number, bin?: string | null) => {
    if (!bin) return
    setHelp((prev) => ({ ...prev, [index]: { loading: true } }))
    try {
      const res = await api.commandHelp(bin)
      setHelp((prev) => ({ ...prev, [index]: { loading: false, text: res.help } }))
    } catch (e) {
      setHelp((prev) => ({
        ...prev,
        [index]: {
          loading: false,
          error: e instanceof Error ? e.message : 'Failed to load help',
        },
      }))
    }
  }

  useMemo(() => {
    setDecisions(initialState)
  }, [initialState])

  if (!open || !interrupt) return null

  const updateDecision = (
    index: number,
    patch: Partial<LocalDecisionState>,
  ) => {
    setDecisions((prev) =>
      prev.map((item, i) => (i === index ? { ...item, ...patch } : item)),
    )
  }

  const updateArg = (index: number, argIndex: number, value: string) => {
    setDecisions((prev) =>
      prev.map((item, i) =>
        i === index
          ? {
              ...item,
              editedArgs: item.editedArgs.map((a, j) =>
                j === argIndex ? value : a,
              ),
            }
          : item,
      ),
    )
  }

  const addArg = (index: number) => {
    setDecisions((prev) =>
      prev.map((item, i) =>
        i === index ? { ...item, editedArgs: [...item.editedArgs, ''] } : item,
      ),
    )
  }

  const removeArg = (index: number, argIndex: number) => {
    setDecisions((prev) =>
      prev.map((item, i) =>
        i === index
          ? {
              ...item,
              editedArgs: item.editedArgs.filter((_, j) => j !== argIndex),
            }
          : item,
      ),
    )
  }

  const handleSubmit = async (autoApproveRemaining = false) => {
    const payload: ResumeRequest = {
      interrupt_id: interrupt.id,
      auto_approve_remaining: autoApproveRemaining,
      decisions: interrupt.actions.map((action, index): ReviewDecision => {
        const local = decisions[index]

        if (local.type === 'approve') {
          return { type: 'approve' }
        }

        if (local.type === 'reject') {
          return {
            type: 'reject',
            comment: local.comment || 'Rejected by user',
          }
        }

        // Structured edit: send {bin (locked), args}. The backend recombines with
        // shlex.join and rejects a changed bin, so an edit can only alter arguments.
        if (action.structured) {
          return {
            type: 'edit',
            edited_args: {
              bin: action.bin ?? undefined,
              args: local.editedArgs,
            },
            comment: local.comment || undefined,
          }
        }

        // Fallback (command could not be tokenized): raw-string edit.
        return {
          type: 'edit',
          edited_args: {
            ...action.args,
            command: local.editedCommand,
          },
          comment: local.comment || undefined,
        }
      }),
    }

    await onSubmit(payload)
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      <div
        className="absolute inset-0 bg-black/60"
        onClick={loading ? undefined : onClose}
      />
      <div className="relative w-full max-w-4xl rounded-xl border border-border bg-bg-secondary p-6 shadow-2xl">
        <div className="mb-4 flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-full bg-accent/10">
            {loading ? (
              <LoadingSpinner size="sm" />
            ) : (
              <svg
                className="h-5 w-5 text-accent"
                fill="none"
                viewBox="0 0 24 24"
                stroke="currentColor"
                strokeWidth={2}
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  d="M12 9v3.75m0 3.75h.007v.008H12v-.008ZM3 12a9 9 0 1 1 18 0 9 9 0 0 1-18 0Z"
                />
              </svg>
            )}
          </div>
          <div>
            <h3 className="text-lg font-semibold text-text-primary">
              Tool Approval Required
            </h3>
            <p className="text-sm text-text-secondary">
              Review each tool call before execution
            </p>
          </div>
        </div>

        <div className="max-h-[60vh] space-y-4 overflow-y-auto pr-2">
          {interrupt.actions.map((action, index) => {
            const local = decisions[index]
            const command =
              typeof action.args.command === 'string'
                ? action.args.command
                : JSON.stringify(action.args, null, 2)

            return (
              <div
                key={action.index}
                className="rounded-lg border border-border bg-bg-primary p-4"
              >
                <div className="mb-2 flex items-center justify-between">
                  <div>
                    <div className="text-sm font-medium text-text-primary">
                      {action.name} #{action.index}
                    </div>
                    <div className="text-xs text-text-muted">
                      {action.allowed_decisions.join(' / ')}
                    </div>
                  </div>
                </div>

                {action.description && (
                  <p className="mb-3 whitespace-pre-wrap text-xs text-text-muted">
                    {action.description}
                  </p>
                )}

                <pre className="mb-3 overflow-x-auto rounded border border-terminal-border bg-terminal-bg p-3 font-mono text-xs text-terminal-text">
                  <code>{command}</code>
                </pre>

                <div className="mb-3 flex flex-wrap gap-2">
                  <button
                    type="button"
                    onClick={() => updateDecision(index, { type: 'approve' })}
                    className={`rounded-lg px-3 py-1.5 text-xs font-medium ${
                      local?.type === 'approve'
                        ? 'bg-green-600 text-white'
                        : 'bg-bg-tertiary text-text-secondary'
                    }`}
                  >
                    Approve
                  </button>
                  <button
                    type="button"
                    onClick={() => updateDecision(index, { type: 'edit' })}
                    className={`rounded-lg px-3 py-1.5 text-xs font-medium ${
                      local?.type === 'edit'
                        ? 'bg-yellow-600 text-white'
                        : 'bg-bg-tertiary text-text-secondary'
                    }`}
                  >
                    Edit
                  </button>
                  <button
                    type="button"
                    onClick={() => updateDecision(index, { type: 'reject' })}
                    className={`rounded-lg px-3 py-1.5 text-xs font-medium ${
                      local?.type === 'reject'
                        ? 'bg-red-600 text-white'
                        : 'bg-bg-tertiary text-text-secondary'
                    }`}
                  >
                    Do Not Run
                  </button>
                </div>

                {local?.type === 'edit' && action.structured && (
                  <div className="mb-3 space-y-2">
                    <label className="block text-xs text-text-muted">
                      Edit arguments (the tool is locked)
                    </label>
                    <div className="flex items-center gap-2">
                      <span className="rounded bg-bg-tertiary px-2 py-1 font-mono text-xs text-text-secondary">
                        {action.bin}
                      </span>
                      <span className="text-xs text-text-muted">locked</span>
                    </div>
                    <div className="space-y-2">
                      {local.editedArgs.map((arg, argIndex) => {
                        // Credential tokens (masked to <PASS> by the server) are locked: they come
                        // from the pre-run login and are restored server-side at execution, so they
                        // are neither editable nor removable here.
                        const secret = isSecretToken(arg)
                        return (
                          <div
                            key={argIndex}
                            className="flex items-center gap-2"
                          >
                            <span className="w-6 shrink-0 text-right text-xs text-text-muted">
                              {argIndex + 1}
                            </span>
                            <input
                              value={secret ? '•••••• (credential)' : arg}
                              readOnly={secret}
                              onChange={
                                secret
                                  ? undefined
                                  : (e) => updateArg(index, argIndex, e.target.value)
                              }
                              title={
                                secret
                                  ? 'Credential from the pre-run login — locked and restored at execution'
                                  : undefined
                              }
                              className={`flex-1 rounded border border-border bg-terminal-bg p-2 font-mono text-xs text-terminal-text outline-none focus:border-accent ${
                                secret ? 'cursor-not-allowed opacity-60' : ''
                              }`}
                            />
                            {secret ? (
                              <span
                                className="px-2 py-1 text-xs text-text-muted"
                                aria-label="Locked credential"
                                title="Locked credential"
                              >
                                🔒
                              </span>
                            ) : (
                              <button
                                type="button"
                                onClick={() => removeArg(index, argIndex)}
                                aria-label="Remove argument"
                                className="rounded px-2 py-1 text-xs text-red-400 hover:bg-bg-tertiary"
                              >
                                ✕
                              </button>
                            )}
                          </div>
                        )
                      })}
                    </div>
                    <button
                      type="button"
                      onClick={() => addArg(index)}
                      className="rounded border border-border px-2 py-1 text-xs text-text-secondary hover:bg-bg-tertiary"
                    >
                      + Add argument
                    </button>
                    <p className="text-xs text-text-muted">
                      Each field is one argument token, passed literally (no shell).
                      The tool binary cannot be changed here.
                    </p>
                    <div className="pt-1">
                      <button
                        type="button"
                        onClick={() => loadHelp(index, action.bin)}
                        disabled={help[index]?.loading}
                        className="rounded border border-border px-2 py-1 text-xs text-text-secondary hover:bg-bg-tertiary disabled:opacity-50"
                      >
                        {help[index]?.loading
                          ? 'Loading…'
                          : `Show ${action.bin} --help`}
                      </button>
                      {help[index]?.error && (
                        <p className="mt-1 text-xs text-red-400">
                          {help[index]?.error}
                        </p>
                      )}
                      {help[index]?.text && (
                        <pre className="mt-2 max-h-48 overflow-auto rounded border border-terminal-border bg-terminal-bg p-2 font-mono text-[11px] text-terminal-text">
                          <code>{help[index]?.text}</code>
                        </pre>
                      )}
                    </div>
                  </div>
                )}

                {local?.type === 'edit' && !action.structured && (
                  <div className="mb-3 space-y-2">
                    <label className="block text-xs text-text-muted">
                      Edited Command
                    </label>
                    <textarea
                      value={local.editedCommand}
                      onChange={(e) =>
                        updateDecision(index, { editedCommand: e.target.value })
                      }
                      className="min-h-[100px] w-full rounded border border-border bg-terminal-bg p-3 font-mono text-xs text-terminal-text outline-none focus:border-accent"
                    />
                  </div>
                )}

                {(local?.type === 'edit' || local?.type === 'reject') && (
                  <div className="space-y-2">
                    <label className="block text-xs text-text-muted">
                      Comment
                    </label>
                    <textarea
                      value={local.comment}
                      onChange={(e) =>
                        updateDecision(index, { comment: e.target.value })
                      }
                      className="min-h-[70px] w-full rounded border border-border bg-bg-secondary p-3 text-sm text-text-primary outline-none focus:border-accent"
                      placeholder="Enter a reason or additional notes"
                    />
                  </div>
                )}
              </div>
            )
          })}
        </div>

        <div className="mt-6 flex justify-end gap-3">
          <button
            onClick={onClose}
            disabled={loading}
            className="rounded-lg border border-border px-4 py-2 text-sm text-text-secondary transition-colors hover:bg-bg-tertiary disabled:opacity-50"
          >
            Close
          </button>
          <button
            onClick={() => handleSubmit(true)}
            disabled={loading}
            title="Apply these decisions, then run every remaining command in this retest without asking again"
            className="rounded-lg border border-accent/50 bg-accent/10 px-4 py-2 text-sm font-medium text-accent transition-colors hover:bg-accent/20 disabled:opacity-50"
          >
            Submit &amp; auto-run the rest
          </button>
          <button
            onClick={() => handleSubmit(false)}
            disabled={loading}
            className="rounded-lg bg-accent px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-accent-hover disabled:opacity-50"
          >
            {loading ? 'Submitting...' : 'Submit'}
          </button>
        </div>
      </div>
    </div>
  )
}