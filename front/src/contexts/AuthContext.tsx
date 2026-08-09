import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useState,
  type FormEvent,
  type ReactNode,
} from 'react'
import { AUTH_UNAUTHORIZED_EVENT, ApiError, api } from '../lib/api'

type AuthState = 'loading' | 'authenticated' | 'login' | 'unreachable'

// How often to re-probe the Agent API while it is unreachable (ms).
const UNREACHABLE_RETRY_MS = 3000

interface AuthContextValue {
  logout: () => Promise<void>
  authRequired: boolean
  username: string | null
  // Server-side command-approval (HITL) gate, from /api/v1/auth/status. Authoritative at runtime
  // for whether the per-run review toggle is shown (independent of the build-time VITE flag).
  commandApprovalEnabled: boolean
}

const AuthContext = createContext<AuthContextValue | null>(null)

// eslint-disable-next-line react-refresh/only-export-components
export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used within AuthProvider')
  return ctx
}

/** Authentication gate: checks /api/v1/auth/status on mount, then renders the app, the login
 *  screen, or -- when the Agent API does not answer -- a distinct "unreachable" screen. */
export function AuthProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<AuthState>('loading')
  const [authRequired, setAuthRequired] = useState(false)
  const [username, setUsername] = useState<string | null>(null)
  const [commandApprovalEnabled, setCommandApprovalEnabled] = useState(false)

  const refresh = useCallback(async () => {
    try {
      const status = await api.authStatus()
      setAuthRequired(status.auth_required)
      setUsername(status.username ?? null)
      setCommandApprovalEnabled(status.command_approval_enabled ?? false)
      setState(status.authenticated ? 'authenticated' : 'login')
    } catch {
      // /api/v1/auth/status needs no session and answers 200 whenever the API is up, so a
      // failure here means the Agent API is unreachable -- not that the user must log in.
      // Showing the login screen would misdirect the user into checking their credentials.
      setState('unreachable')
    }
  }, [])

  useEffect(() => {
    void refresh()
  }, [refresh])

  // Keep re-probing while unreachable. `make dev` starts the frontend and the Agent API in
  // parallel and the API takes longer to boot, so the first probe can lose the race; retrying
  // lets the app recover on its own instead of stranding the user on an error screen.
  useEffect(() => {
    if (state !== 'unreachable') return
    const id = setInterval(() => void refresh(), UNREACHABLE_RETRY_MS)
    return () => clearInterval(id)
  }, [state, refresh])

  // Return to the login screen when any API call responds with 401.
  useEffect(() => {
    const onUnauthorized = () => setState('login')
    window.addEventListener(AUTH_UNAUTHORIZED_EVENT, onUnauthorized)
    return () => window.removeEventListener(AUTH_UNAUTHORIZED_EVENT, onUnauthorized)
  }, [])

  const logout = useCallback(async () => {
    try {
      await api.logout()
    } finally {
      setUsername(null)
      setState('login')
    }
  }, [])

  if (state === 'loading') {
    return (
      <div className="flex min-h-screen items-center justify-center bg-neutral-950 text-neutral-400">
        Loading…
      </div>
    )
  }

  if (state === 'unreachable') {
    return <UnreachableScreen onRetry={() => void refresh()} />
  }

  if (state === 'login') {
    return <LoginScreen onSuccess={() => void refresh()} />
  }

  return (
    <AuthContext.Provider
      value={{ logout, authRequired, username, commandApprovalEnabled }}
    >
      {children}
    </AuthContext.Provider>
  )
}

/** Shown when the Agent API cannot be reached. Retries on its own; no protected content renders. */
function UnreachableScreen({ onRetry }: { onRetry: () => void }) {
  return (
    <div className="flex min-h-screen items-center justify-center bg-neutral-950 px-4">
      <div className="w-full max-w-md rounded-xl border border-neutral-800 bg-neutral-900 p-6 shadow-lg">
        <h1 className="text-lg font-semibold text-white">Cannot reach the Agent API</h1>
        <p className="mt-2 text-sm text-neutral-400">
          The frontend is running, but the backend did not respond. This is not a login problem.
        </p>

        <p className="mt-4 text-xs font-medium text-neutral-300">Things to check</p>
        <ul className="mt-2 list-disc space-y-1 pl-5 text-xs text-neutral-400">
          <li>
            Is the Agent API up? Look at the <code className="text-neutral-300">dev-agent</code>{' '}
            output from <code className="text-neutral-300">make dev</code> for a startup error.
          </li>
          <li>
            Did <code className="text-neutral-300">make install</code> finish? Missing Python
            dependencies stop uvicorn from starting.
          </li>
          <li>
            Verify directly: <code className="text-neutral-300">curl http://localhost:8000/health</code>
          </li>
        </ul>

        <p className="mt-4 text-xs text-neutral-500">
          Retrying automatically every {UNREACHABLE_RETRY_MS / 1000}s.
        </p>

        <button
          type="button"
          onClick={onRetry}
          className="mt-4 w-full rounded-md bg-white px-3 py-2 text-sm font-medium text-neutral-900 transition hover:bg-neutral-200"
        >
          Retry now
        </button>
      </div>
    </div>
  )
}

function LoginScreen({ onSuccess }: { onSuccess: () => void }) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [submitting, setSubmitting] = useState(false)
  // MFA second step: when the first step returns mfa_required, hold this token and switch to code entry.
  const [mfaToken, setMfaToken] = useState<string | null>(null)
  const [code, setCode] = useState('')

  const submit = async (e: FormEvent) => {
    e.preventDefault()
    if (!username || !password || submitting) return
    setSubmitting(true)
    setError(null)
    try {
      const result = await api.login(username, password)
      if (result.mfa_required && result.mfa_token) {
        // Move to the second step: clear the password from memory and switch to code entry.
        setPassword('')
        setMfaToken(result.mfa_token)
        setCode('')
        return
      }
      setPassword('')
      onSuccess()
    } catch (err) {
      if (err instanceof ApiError && err.status === 429) {
        // Temporarily locked out after repeated failures (clears automatically over time).
        setError('Too many login attempts. Please wait a while and try again.')
      } else {
        // Use a single generic message for auth failures to avoid leaking information.
        setError('Login failed. Please check your credentials and try again.')
      }
    } finally {
      setSubmitting(false)
    }
  }

  const submitMfa = async (e: FormEvent) => {
    e.preventDefault()
    if (!mfaToken || !code || submitting) return
    setSubmitting(true)
    setError(null)
    try {
      await api.loginMfa(mfaToken, code)
      setCode('')
      setMfaToken(null)
      onSuccess()
    } catch (err) {
      if (err instanceof ApiError && err.status === 429) {
        setError('Too many attempts. Please wait a while and try again.')
      } else if (err instanceof ApiError && err.status === 401) {
        // Token expired or wrong code; on expiry, return to the first step.
        const expired = /expired|invalid/i.test(err.message)
        setError(
          expired
            ? 'Authentication timed out. Please start over.'
            : 'The verification code is incorrect.',
        )
        if (expired) setMfaToken(null)
      } else {
        setError('Authentication failed. Please try again.')
      }
    } finally {
      setSubmitting(false)
    }
  }

  const backToLogin = () => {
    setMfaToken(null)
    setCode('')
    setError(null)
  }

  if (mfaToken) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-neutral-950 px-4">
        <form
          onSubmit={submitMfa}
          className="w-full max-w-sm rounded-xl border border-neutral-800 bg-neutral-900 p-6 shadow-lg"
        >
          <h1 className="text-lg font-semibold text-white">Two-Factor Authentication</h1>
          <p className="mt-1 text-sm text-neutral-400">
            Enter the 6-digit code shown in your authenticator app
          </p>

          <label className="mt-5 block text-sm text-neutral-300" htmlFor="mfa-code">
            Verification Code
          </label>
          <input
            id="mfa-code"
            type="text"
            inputMode="numeric"
            autoComplete="one-time-code"
            autoFocus
            maxLength={6}
            value={code}
            onChange={(e) => setCode(e.target.value.replace(/\D/g, ''))}
            className="mt-1 w-full rounded-md border border-neutral-700 bg-neutral-950 px-3 py-2 text-center text-lg tracking-[0.4em] text-white outline-none focus:border-neutral-500"
          />

          {error && <p className="mt-3 text-sm text-red-400">{error}</p>}

          <button
            type="submit"
            disabled={submitting || code.length < 6}
            className="mt-5 w-full rounded-md bg-white px-3 py-2 text-sm font-medium text-neutral-900 transition hover:bg-neutral-200 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {submitting ? 'Verifying…' : 'Verify'}
          </button>
          <button
            type="button"
            onClick={backToLogin}
            className="mt-3 w-full text-center text-xs text-neutral-500 hover:text-neutral-300"
          >
            ← Start over from login
          </button>
        </form>
      </div>
    )
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-neutral-950 px-4">
      <form
        onSubmit={submit}
        className="w-full max-w-sm rounded-xl border border-neutral-800 bg-neutral-900 p-6 shadow-lg"
      >
        <h1 className="text-lg font-semibold text-white">Red Agent</h1>
        <p className="mt-1 text-sm text-neutral-400">Please sign in</p>

        <label className="mt-5 block text-sm text-neutral-300" htmlFor="username">
          Username
        </label>
        <input
          id="username"
          type="text"
          autoComplete="username"
          autoFocus
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          className="mt-1 w-full rounded-md border border-neutral-700 bg-neutral-950 px-3 py-2 text-sm text-white outline-none focus:border-neutral-500"
        />

        <label className="mt-4 block text-sm text-neutral-300" htmlFor="password">
          Password
        </label>
        <input
          id="password"
          type="password"
          autoComplete="current-password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          className="mt-1 w-full rounded-md border border-neutral-700 bg-neutral-950 px-3 py-2 text-sm text-white outline-none focus:border-neutral-500"
        />

        {error && <p className="mt-3 text-sm text-red-400">{error}</p>}

        <button
          type="submit"
          disabled={submitting || !username || !password}
          className="mt-5 w-full rounded-md bg-white px-3 py-2 text-sm font-medium text-neutral-900 transition hover:bg-neutral-200 disabled:cursor-not-allowed disabled:opacity-50"
        >
          {submitting ? 'Signing in…' : 'Sign in'}
        </button>
      </form>
    </div>
  )
}
