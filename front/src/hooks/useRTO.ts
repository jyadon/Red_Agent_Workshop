import { useCallback, useEffect, useRef, useState } from 'react'
import { api, THREADS_BASE_URL } from '../lib/api'
import type {
  RtoRunRequest,
  RtoRunResponse,
  RtoRunStatus,
  RtoExecutionContext,
} from '../types/rto'

export interface RTORun {
  thread_id: string | null
  status: RtoRunStatus | null
  chunks: Array<Record<string, unknown>>
  final_output: unknown | null
  error: string | null
}

const INITIAL_RUN: RTORun = {
  thread_id: null,
  status: null,
  chunks: [],
  final_output: null,
  error: null,
}

export function useRTO() {
  const [run, setRun] = useState<RTORun>(INITIAL_RUN)
  const [loading, setLoading] = useState(false)
  const esRef = useRef<EventSource | null>(null)

  const closeStream = useCallback(() => {
    esRef.current?.close()
    esRef.current = null
  }, [])

  useEffect(() => {
    return () => {
      closeStream()
    }
  }, [closeStream])

  const reset = useCallback(() => {
    closeStream()
    setRun(INITIAL_RUN)
  }, [closeStream])

  const startRun = useCallback(
    async (ctx: RtoExecutionContext, userInstruction?: string) => {
      setLoading(true)
      closeStream()

      try {
        const body: RtoRunRequest = {
          kind: 'rto',
          // ctx.domain doubles as the target; the server derives target from
          // execution_context.domain, so target is not sent in input.
          title: `RTO ${ctx.domain}`,
          context: { findings: [] },
          auto_start: true,
          input: {
            user_instruction: userInstruction ?? null,
            execution_context: ctx,
          },
        }

        const res = await api.postAbsolute<RtoRunResponse>(`${THREADS_BASE_URL}/threads`, body)

        setRun({
          thread_id: res.thread_id,
          status: res.status,
          chunks: [],
          final_output: null,
          error: null,
        })

        esRef.current = api.sse(`${THREADS_BASE_URL}/threads/${res.thread_id}/stream`, {
          onEvent: (event, data) => {
            if (event === 'status') {
              setRun((prev) => ({ ...prev, status: 'running' }))
              return
            }

            if (event === 'chunk') {
              setRun((prev) => ({ ...prev, chunks: [...prev.chunks, data] }))
              return
            }

            if (event === 'final') {
              closeStream()
              setRun((prev) => ({
                ...prev,
                status: 'completed',
                final_output: data.data ?? null,
                error: null,
              }))
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
              if (prev.status === 'completed') return prev
              return { ...prev, status: 'failed', error: error.message }
            })
          },
        })

        return res
      } finally {
        setLoading(false)
      }
    },
    [closeStream],
  )

  return { run, loading, startRun, reset, closeStream }
}
