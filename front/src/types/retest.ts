import type { Finding } from './finding'

export type ReviewDecisionType = 'approve' | 'edit' | 'reject'
export type RunStatus = 'idle' | 'running' | 'waiting_human' | 'completed' | 'failed'

export interface InterruptAction {
  index: number
  name: string
  args: Record<string, unknown>
  description?: string
  allowed_decisions: ReviewDecisionType[]
  // Structured-edit fields (backend serialize_interrupt): `bin` is the locked tool,
  // `arg_tokens` are the individually editable argument tokens. `structured` is false when
  // the command could not be tokenized -> fall back to raw-string editing.
  bin?: string | null
  arg_tokens?: string[]
  structured?: boolean
}

export interface InterruptPayload {
  id: string
  actions: InterruptAction[]
  raw?: unknown
}

export interface RunRequest {
  kind: 'verification' | 'rto'
  title?: string
  context: {
    primary_finding_id?: string | null
    findings: Finding[]
  }
  auto_start?: boolean
  input?: Record<string, unknown> | null
  // false (default): auto-execute agent-generated commands without approval
  // true: wait for user approval via the HITL dialog
  require_approval?: boolean
}

export interface RunResponse {
  ok: boolean
  thread_id: string
  kind: 'verification' | 'rto'
  status: RunStatus
  title?: string | null
  interrupt: Record<string, unknown> | null
  final_output: unknown | null
  error: string | null
}

export interface ReviewDecision {
  type: ReviewDecisionType
  edited_args?: Record<string, unknown>
  comment?: string
}

export interface ResumeRequest {
  interrupt_id?: string
  decisions: ReviewDecision[]
  // Apply these decisions, then auto-approve every remaining command in this run (no further
  // review dialogs). Verification threads only.
  auto_approve_remaining?: boolean
}