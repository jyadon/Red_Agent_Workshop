// RTO (Red Team Operations) types. Kept independent from types/retest and useRetest
// so that retest-specific type changes don't leak into RTO (the generic /threads
// transport is shared, but retest-specific types are duplicated here for ownership isolation).

export type RtoRunStatus =
  | 'idle'
  | 'running'
  | 'waiting_human'
  | 'completed'
  | 'failed'

// AD authentication context for a RTO run; domain, user, pass, and dns are all required.
export interface RtoExecutionContext {
  domain: string
  user: string
  pass: string
  dns: string
}

// Request body for POST /threads (kind='rto'); RTO sends an empty findings list.
export interface RtoRunRequest {
  kind: 'rto'
  title?: string
  context: {
    primary_finding_id?: string | null
    findings: unknown[]
  }
  auto_start?: boolean
  input?: Record<string, unknown> | null
  require_approval?: boolean
}

export interface RtoRunResponse {
  ok: boolean
  thread_id: string
  kind: string
  status: RtoRunStatus
  title?: string | null
  interrupt: Record<string, unknown> | null
  final_output: unknown | null
  error: string | null
}
