// Retest history store: in-memory cache + fetch wrappers over the backend SQLite
// API. Persistence lives on the backend (not IndexedDB) so history is shared
// across browsers.
import { create } from 'zustand'
import { buildApiUrl, withAuthHeaders } from './api'

export interface VerificationHistoryItem {
  id: string
  findingNo: string
  threadId: string
  markdown: string
  finalOutput: unknown | null
  finalOutputTruncated: boolean
  createdAt: string
  // Normalized verdict code (resolved/partial/unresolved/inconclusive), computed
  // by the backend; null when it cannot be extracted.
  verdict?: string | null
  // Placeholder-ized commands executed during the run, available for RTO playbook export.
  // Absent/empty for legacy records or runs that executed no commands.
  commands?: { command: string; label?: string }[]
}

interface ListResponse {
  findingNo: string
  count: number
  items: VerificationHistoryItem[]
}

// Latest status per finding: lightweight DTO for list badges (no markdown).
// backend: GET /api/v1/retest-history/summary.
export interface FindingStatusItem {
  findingNo: string
  // Normalized verdict code (resolved/partial/unresolved/inconclusive); null when
  // it cannot be extracted.
  verdict: string | null
  createdAt: string
  threadId: string
}

interface SummaryResponse {
  count: number
  items: FindingStatusItem[]
}

interface VerificationHistoryStore {
  recordsByFinding: Record<string, VerificationHistoryItem[]>
  loadingByFinding: Record<string, boolean>
  errorByFinding: Record<string, string | null>
  // findingNo -> latest status, for list badges. Findings without history are absent.
  statusByFinding: Record<string, FindingStatusItem>
  fetchStatusSummary: () => Promise<void>
  fetchRecords: (findingNo: string) => Promise<VerificationHistoryItem[]>
  getRecords: (findingNo: string) => VerificationHistoryItem[]
  getLatestRecord: (findingNo: string) => VerificationHistoryItem | undefined
  removeRecord: (findingNo: string, recordId: string) => Promise<void>
  clearFindingHistory: (findingNo: string) => Promise<void>
}

async function apiList(findingNo: string): Promise<VerificationHistoryItem[]> {
  const url = buildApiUrl(
    `/api/v1/retest-history?finding_no=${encodeURIComponent(findingNo)}`,
  )
  const res = await fetch(url, { credentials: 'include', headers: withAuthHeaders(undefined, false) })
  if (!res.ok) {
    throw new Error(`HTTP ${res.status}`)
  }
  const data = (await res.json()) as ListResponse
  return Array.isArray(data?.items) ? data.items : []
}

async function apiSummary(): Promise<FindingStatusItem[]> {
  const url = buildApiUrl('/api/v1/retest-history/summary')
  const res = await fetch(url, { credentials: 'include', headers: withAuthHeaders(undefined, false) })
  if (!res.ok) {
    throw new Error(`HTTP ${res.status}`)
  }
  const data = (await res.json()) as SummaryResponse
  return Array.isArray(data?.items) ? data.items : []
}

async function apiDeleteOne(recordId: string): Promise<void> {
  const url = buildApiUrl(`/api/v1/retest-history/${encodeURIComponent(recordId)}`)
  const res = await fetch(url, {
    method: 'DELETE',
    credentials: 'include',
    headers: withAuthHeaders(undefined, false),
  })
  if (!res.ok && res.status !== 404) {
    throw new Error(`HTTP ${res.status}`)
  }
}

async function apiDeleteByFinding(findingNo: string): Promise<void> {
  const url = buildApiUrl(
    `/api/v1/retest-history?finding_no=${encodeURIComponent(findingNo)}`,
  )
  const res = await fetch(url, {
    method: 'DELETE',
    credentials: 'include',
    headers: withAuthHeaders(undefined, false),
  })
  if (!res.ok) {
    throw new Error(`HTTP ${res.status}`)
  }
}

export const useVerificationHistoryStore = create<VerificationHistoryStore>()((set, get) => ({
  recordsByFinding: {},
  loadingByFinding: {},
  errorByFinding: {},
  statusByFinding: {},

  // Fetch latest status for all findings in one request. On failure the existing
  // cache is kept (errors are swallowed so badges don't disappear).
  fetchStatusSummary: async () => {
    try {
      const items = await apiSummary()
      const byFinding: Record<string, FindingStatusItem> = {}
      for (const item of items) byFinding[item.findingNo] = item
      set({ statusByFinding: byFinding })
    } catch {
      // Status is supplementary; a fetch failure must not block the list view.
    }
  },

  fetchRecords: async (findingNo) => {
    set((state) => ({
      loadingByFinding: { ...state.loadingByFinding, [findingNo]: true },
      errorByFinding: { ...state.errorByFinding, [findingNo]: null },
    }))
    try {
      const items = await apiList(findingNo)
      set((state) => ({
        recordsByFinding: { ...state.recordsByFinding, [findingNo]: items },
        loadingByFinding: { ...state.loadingByFinding, [findingNo]: false },
      }))
      return items
    } catch (e) {
      const msg = e instanceof Error ? e.message : 'failed to fetch retest history'
      set((state) => ({
        loadingByFinding: { ...state.loadingByFinding, [findingNo]: false },
        errorByFinding: { ...state.errorByFinding, [findingNo]: msg },
      }))
      return get().recordsByFinding[findingNo] ?? []
    }
  },

  getRecords: (findingNo) => {
    return get().recordsByFinding[findingNo] ?? []
  },

  getLatestRecord: (findingNo) => {
    const records = get().recordsByFinding[findingNo] ?? []
    return records[0]
  },

  removeRecord: async (findingNo, recordId) => {
    await apiDeleteOne(recordId)
    set((state) => {
      const current = state.recordsByFinding[findingNo] ?? []
      return {
        recordsByFinding: {
          ...state.recordsByFinding,
          [findingNo]: current.filter((item) => item.id !== recordId),
        },
      }
    })
  },

  clearFindingHistory: async (findingNo) => {
    await apiDeleteByFinding(findingNo)
    set((state) => {
      const next = { ...state.recordsByFinding }
      delete next[findingNo]
      return { recordsByFinding: next }
    })
  },
}))
