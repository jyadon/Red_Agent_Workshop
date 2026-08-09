import { create } from 'zustand'

// Auth context for re-test runs. Held only in SPA memory, never persisted
// (cleared on tab reload).
export interface CachedCredentials {
  domain: string
  user: string
  pass: string
  dns?: string
  cachedAt: number
}

interface CredentialsState {
  credentials: CachedCredentials | null
  setCredentials: (creds: Omit<CachedCredentials, 'cachedAt'>) => void
  clearCredentials: () => void
}

export const useCredentialsStore = create<CredentialsState>((set) => ({
  credentials: null,
  setCredentials: (creds) => {
    set({
      credentials: {
        domain: creds.domain,
        user: creds.user,
        pass: creds.pass,
        dns: creds.dns,
        cachedAt: Date.now(),
      },
    })
  },
  clearCredentials: () => set({ credentials: null }),
}))
