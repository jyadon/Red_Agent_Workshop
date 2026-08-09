// RTO execution history store (backed by the SQLite backend).
import { create } from 'zustand'
import { buildApiUrl, withAuthHeaders } from './api'

export interface RtoHistoryItem {
  id: string
  threadId: string
  domain: string
  markdown: string
  finalOutput: unknown | null
  finalOutputTruncated: boolean
  createdAt: string
}

interface ListResponse {
  count: number
  items: RtoHistoryItem[]
}

interface RtoHistoryStore {
  items: RtoHistoryItem[]
  loading: boolean
  error: string | null
  fetchHistory: () => Promise<void>
  removeRecord: (id: string) => Promise<void>
  clearAll: () => Promise<void>
}

async function apiList(): Promise<RtoHistoryItem[]> {
  const res = await fetch(buildApiUrl('/api/v1/rto-history'), {
    credentials: 'include',
    headers: withAuthHeaders(undefined, false),
  })
  if (!res.ok) throw new Error(`HTTP ${res.status}`)
  const data = (await res.json()) as ListResponse
  return Array.isArray(data?.items) ? data.items : []
}

async function apiDeleteOne(id: string): Promise<void> {
  const res = await fetch(buildApiUrl(`/api/v1/rto-history/${encodeURIComponent(id)}`), {
    method: 'DELETE',
    credentials: 'include',
    headers: withAuthHeaders(undefined, false),
  })
  if (!res.ok && res.status !== 404) throw new Error(`HTTP ${res.status}`)
}

async function apiDeleteAll(): Promise<void> {
  const res = await fetch(buildApiUrl('/api/v1/rto-history'), {
    method: 'DELETE',
    credentials: 'include',
    headers: withAuthHeaders(),
    body: JSON.stringify({ all: true }),
  })
  if (!res.ok) throw new Error(`HTTP ${res.status}`)
}

export const useRtoHistoryStore = create<RtoHistoryStore>()((set, get) => ({
  items: [],
  loading: false,
  error: null,

  fetchHistory: async () => {
    set({ loading: true, error: null })
    try {
      const items = await apiList()
      set({ items, loading: false })
    } catch (e) {
      const msg = e instanceof Error ? e.message : 'failed to fetch rto history'
      set({ loading: false, error: msg })
    }
  },

  removeRecord: async (id) => {
    await apiDeleteOne(id)
    set((state) => ({ items: state.items.filter((i) => i.id !== id) }))
  },

  clearAll: async () => {
    await apiDeleteAll()
    set({ items: [] })
    // Re-sync with the server's actual state as a safeguard.
    await get().fetchHistory()
  },
}))
