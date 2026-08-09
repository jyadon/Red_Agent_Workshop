import { useCallback, useEffect, useRef, useState } from 'react'
import { api, THREADS_BASE_URL } from '../lib/api'
import type { Finding } from '../types/finding'
import type {
  InterruptPayload,
  ResumeRequest,
  RunRequest,
  RunResponse,
  RunStatus,
} from '../types/retest'
import { useVerificationHistoryStore } from '../lib/verification-history-store'

export interface VerificationExecutionContext {
  domain: string
  user: string
  pass: string
  dns?: string
  // Collected tenant referenced by Entra verification (used to select among multiple; non-sensitive).
  tenant?: string
}

export interface ActiveRun {
  thread_id: string | null
  // Which finding this run targets; FindingDetail uses it to decide whether to show the live result.
  // null = nothing running yet, or leftover state from a different finding (safe to ignore).
  finding_no: string | null
  status: RunStatus | null
  interrupt: InterruptPayload | null
  chunks: Array<Record<string, unknown>>
  final_output: unknown | null
  error: string | null
}

export function useRetest() {
  const [run, setRun] = useState<ActiveRun>({
    thread_id: null,
    finding_no: null,
    status: null,
    interrupt: null,
    chunks: [],
    final_output: null,
    error: null,
  })
  const [loading, setLoading] = useState(false)

  // History is persisted by the backend (SQLite), so re-sync via fetchRecords when the final event arrives.
  const fetchRecords = useVerificationHistoryStore((s) => s.fetchRecords)

  const esRef = useRef<EventSource | null>(null)
  const currentFindingNoRef = useRef<string | null>(null)
  const currentThreadIdRef = useRef<string | null>(null)

  const closeStream = useCallback(() => {
    esRef.current?.close()
    esRef.current = null
  }, [])

  useEffect(() => {
    return () => {
      closeStream()
    }
  }, [closeStream])

  const startRun = useCallback(
    async (
      finding: Finding,
      executionContext?: VerificationExecutionContext,
      userInstruction?: string,
      requireApproval: boolean = false,
      runtimeVariables?: Record<string, string>,
    ) => {
      setLoading(true)
      closeStream()
      currentFindingNoRef.current = finding.no

      try {
        const body: RunRequest = {
          kind: 'verification',
          title: `${finding.no} ${finding.title}`,
          context: {
            primary_finding_id: finding.no,
            findings: [finding],
          },
          auto_start: true,
          require_approval: requireApproval,
          input: {
            user_instruction: userInstruction ?? null,
            execution_context: executionContext ?? null,
            runtime_variables: runtimeVariables ?? null,
          },
        }

        const res = await api.postAbsolute<RunResponse>(`${THREADS_BASE_URL}/threads`, body)
        currentThreadIdRef.current = res.thread_id

        setRun({
          thread_id: res.thread_id,
          finding_no: finding.no,
          status: res.status,
          interrupt: null,
          chunks: [],
          final_output: null,
          error: null,
        })

        esRef.current = api.sse(`${THREADS_BASE_URL}/threads/${res.thread_id}/stream`, {
          onEvent: (event, data) => {
            if (event === 'status') {
              setRun((prev) => ({
                ...prev,
                status: 'running',
              }))
              return
            }

            if (event === 'chunk') {
              setRun((prev) => ({
                ...prev,
                chunks: [...prev.chunks, data],
              }))
              return
            }

            if (event === 'interrupt') {
              // Auto-approved interrupts (auto-run mode / "auto-run the rest") need no dialog;
              // keep the run visibly running instead of flashing the review modal open/closed.
              if (data.auto_approved) {
                setRun((prev) => ({ ...prev, status: 'running' }))
                return
              }
              setRun((prev) => ({
                ...prev,
                status: 'waiting_human',
                interrupt: (data.interrupt as InterruptPayload) ?? null,
                error: null,
              }))
              return
            }

            if (event === 'resumed') {
              setRun((prev) => ({
                ...prev,
                status: 'running',
                interrupt: null,
                error: null,
              }))
              return
            }

            if (event === 'final') {
              closeStream()
              const finalOutput = data.data ?? null

              setRun((prev) => ({
                ...prev,
                status: 'completed',
                final_output: finalOutput,
                interrupt: null,
                error: null,
              }))
              // Backend already persisted to SQLite, so the frontend only needs to re-fetch.
              const findingNo = currentFindingNoRef.current
              if (findingNo) {
                void fetchRecords(findingNo)
              }

              return
            }

            if (event === 'error') {
              closeStream()
              setRun((prev) => ({
                ...prev,
                status: 'failed',
                error: String(data.message ?? 'Unknown error'),
              }))
              return
            }
          },
          onError: (error) => {
            setRun((prev) => {
              if (prev.status === 'completed' || prev.status === 'waiting_human') {
                return prev
              }

              return {
                ...prev,
                status: 'failed',
                error: error.message,
              }
            })
          },
        })

        return res
      } finally {
        setLoading(false)
      }
    },
    [closeStream, fetchRecords],
  )

  const resumeRun = useCallback(
    async (payload: ResumeRequest) => {
      if (!run.thread_id) {
        throw new Error('No active thread')
      }

      setLoading(true)
      try {
        await api.postAbsolute(`${THREADS_BASE_URL}/threads/${run.thread_id}/resume`, payload)
      } finally {
        setLoading(false)
      }
    },
    [run.thread_id],
  )

  const submitInterruptDecisions = useCallback(
    async (payload: ResumeRequest) => {
      await resumeRun(payload)
    },
    [resumeRun],
  )

  const approveAll = useCallback(async () => {
    if (!run.interrupt) {
      throw new Error('No interrupt to approve')
    }

    const payload: ResumeRequest = {
      interrupt_id: run.interrupt.id,
      decisions: run.interrupt.actions.map(() => ({ type: 'approve' })),
    }

    await resumeRun(payload)
  }, [run.interrupt, resumeRun])

  return {
    run,
    loading,
    startRun,
    resumeRun,
    submitInterruptDecisions,
    approveAll,
    closeStream,
  }
}
