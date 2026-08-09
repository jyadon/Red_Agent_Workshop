import { useState, useEffect, useCallback } from 'react'
import { api } from '../lib/api'
import { useFindingsStore, type RawFinding } from '../lib/findings-store'

interface FindingsApiResponse {
  findings: RawFinding[]
  metadata?: {
    title?: string
    generated_at?: string
    total_findings?: number
    company_name?: string
  }
}

export function useFindings() {
  const findings = useFindingsStore((s) => s.findings)
  const loadFromRaw = useFindingsStore((s) => s.loadFromRaw)
  const [loading, setLoading] = useState(findings.length === 0)
  const [error, setError] = useState<string | null>(null)

  const fetchFindings = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const data = await api.get<FindingsApiResponse>('/api/v1/findings')
      // Overwrite the store even with an empty array so deletions/shrinks of findings.json are reflected.
      loadFromRaw(
        data.findings ?? [],
        data.metadata?.title ?? data.metadata?.company_name,
      )
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to fetch findings')
    } finally {
      setLoading(false)
    }
  }, [loadFromRaw])

  useEffect(() => {
    fetchFindings()
  }, [fetchFindings])

  return { findings, loading, error, refetch: fetchFindings }
}

export function useFinding(no: string | undefined) {
  const finding = useFindingsStore((s) =>
    no ? s.findings.find((f) => f.no === no) ?? null : null,
  )

  return { finding, loading: false, error: null }
}
