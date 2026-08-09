const BASE_URL = ((import.meta.env.VITE_API_BASE_URL as string | undefined) || '').replace(/\/$/, '')

export function buildApiUrl(path: string): string {
  const normalizedPath = path.startsWith('/') ? path : `/${path}`

  if (!BASE_URL) return normalizedPath

  if (BASE_URL.endsWith('/api/v1') && normalizedPath.startsWith('/api/v1/')) {
    return `${BASE_URL}${normalizedPath.slice('/api/v1'.length)}`
  }

  return `${BASE_URL}${normalizedPath}`
}

// Falls back to a relative path when unset (dev: Vite proxy, prod: same origin).
export const THREADS_BASE_URL = import.meta.env.VITE_THREADS_BASE_URL || ''

// Auth relies on the server-issued httpOnly session cookie; no key is embedded in the client.
export function withAuthHeaders(headers?: HeadersInit, includeJsonContentType = true): HeadersInit {
  const base: Record<string, string> = {}
  if (includeJsonContentType) base['Content-Type'] = 'application/json'
  return { ...base, ...(headers as Record<string, string> | undefined) }
}

// On a 401, notify the whole app so AuthGate can route to the login screen.
export const AUTH_UNAUTHORIZED_EVENT = 'auth:unauthorized'
function notifyUnauthorized(): void {
  if (typeof window !== 'undefined') {
    window.dispatchEvent(new CustomEvent(AUTH_UNAUTHORIZED_EVENT))
  }
}

// Off by default in production builds to avoid leaking error-body details.
const DEBUG_API_ERRORS =
  import.meta.env.DEV || (import.meta.env.VITE_DEBUG_API_ERRORS as string | undefined) === 'true'

function debugLogApiError(label: string, payload: unknown): void {
  if (!DEBUG_API_ERRORS) return
  // eslint-disable-next-line no-console
  console.error(label, payload)
}

export class ApiError extends Error {
  status: number

  constructor(status: number, message: string) {
    super(message)
    this.name = 'ApiError'
    this.status = status
  }
}

// Extract a display message from an error response, preferring the backend's JSON `detail`.
async function errorMessageFromResponse(response: Response): Promise<string> {
  let message = `API Error: ${response.statusText}`
  try {
    const data = await response.json()
    debugLogApiError('API error response body:', data)
    if (typeof data?.detail === 'string') {
      message = data.detail
    } else if (data?.detail) {
      message = JSON.stringify(data.detail)
    } else {
      message = JSON.stringify(data)
    }
  } catch {
    try {
      const text = await response.text()
      debugLogApiError('API error response text:', text)
      if (text) message = text
    } catch {
      // ignore
    }
  }
  return message
}

async function request<T>(
  path: string,
  options?: RequestInit,
  opts?: { suppressAuthRedirect?: boolean },
): Promise<T> {
  const response = await fetch(buildApiUrl(path), {
    ...options,
    credentials: 'include',
    headers: withAuthHeaders(options?.headers, options?.method !== undefined),
  })

  if (!response.ok) {
    // A 401 usually means an expired session, so route to login. Callers that must not log the
    // user out on a 401 (e.g. a wrong current password on change-password) pass suppressAuthRedirect.
    if (response.status === 401 && !opts?.suppressAuthRedirect) notifyUnauthorized()
    throw new ApiError(response.status, await errorMessageFromResponse(response))
  }

  return response.json()
}

async function requestAbsolute<T>(path: string, options?: RequestInit): Promise<T> {
  const response = await fetch(path, {
    ...options,
    credentials: 'include',
    headers: withAuthHeaders(options?.headers, options?.method !== undefined),
  })

  if (!response.ok) {
    if (response.status === 401) notifyUnauthorized()
    throw new ApiError(response.status, await errorMessageFromResponse(response))
  }

  return response.json()
}

export interface StreamCallbacks {
  onChunk: (content: string) => void
  onMetadata?: (metadata: Record<string, unknown>) => void
  onDone: () => void
  onError: (error: Error) => void
}

async function streamRequest(
  path: string,
  body: unknown,
  callbacks: StreamCallbacks,
  signal?: AbortSignal,
): Promise<void> {
  const response = await fetch(buildApiUrl(path), {
    method: 'POST',
    credentials: 'include',
    headers: withAuthHeaders(),
    body: JSON.stringify(body),
    signal,
  })

  if (!response.ok) {
    if (response.status === 401) notifyUnauthorized()
    throw new ApiError(response.status, `API Error: ${response.statusText}`)
  }

  const reader = response.body?.getReader()
  if (!reader) {
    throw new ApiError(0, 'Response body is not readable')
  }

  const decoder = new TextDecoder()
  let buffer = ''

  try {
    while (true) {
      const { done, value } = await reader.read()
      if (done) break

      buffer += decoder.decode(value, { stream: true })
      const lines = buffer.split('\n')
      buffer = lines.pop() ?? ''

      for (const line of lines) {
        const trimmed = line.trim()
        if (!trimmed || trimmed.startsWith(':')) continue

        if (trimmed === 'data: [DONE]') {
          callbacks.onDone()
          return
        }

        if (trimmed.startsWith('data: ')) {
          const json = trimmed.slice(6)
          try {
            const chunk = JSON.parse(json)
            if (chunk.type === 'metadata' && callbacks.onMetadata) {
              callbacks.onMetadata(chunk)
              continue
            }
            const content = chunk.choices?.[0]?.delta?.content
            if (content) {
              callbacks.onChunk(content)
            }
          } catch {
            // ignore parse errors
          }
        }
      }
    }

    if (buffer.trim() === 'data: [DONE]') {
      callbacks.onDone()
    }
  } finally {
    reader.releaseLock()
  }
}

export interface SSECallbacks {
  onEvent: (event: string, data: Record<string, unknown>) => void
  onError?: (error: Error) => void
}

function sseRequest(
  path: string,
  callbacks: SSECallbacks,
  signal?: AbortSignal,
): EventSource {
  // EventSource cannot send custom headers, so withCredentials carries the session cookie
  // (automatic for same-origin; required alongside allow_credentials=True for cross-origin).
  const es = new EventSource(path, { withCredentials: true })

  const eventTypes = ['status', 'chunk', 'interrupt', 'resumed', 'final', 'error']
  for (const type of eventTypes) {
    es.addEventListener(type, (evt) => {
      try {
        const data = JSON.parse((evt as MessageEvent).data)
        callbacks.onEvent(type, data)
      } catch {
        // ignore parse errors
      }
    })
  }

  es.onerror = () => {
    if (signal?.aborted) return

    // EventSource can fire error even on a normal close; close silently when already CLOSED.
    if (es.readyState === EventSource.CLOSED) {
      es.close()
      return
    }

    callbacks.onError?.(new Error('SSE connection error'))
    es.close()
  }

  signal?.addEventListener('abort', () => es.close())

  return es
}

export interface AuthStatus {
  authenticated: boolean
  auth_required: boolean
  username?: string | null
  // Server-side ENABLE_COMMAND_APPROVAL. Drives the per-run review toggle at runtime so a stale
  // build-time VITE flag can't hide it. Absent on older backends -> treated as false.
  command_approval_enabled?: boolean
}

// Result of the first login step. MFA-enrolled users get ok=false + mfa_required=true + mfa_token,
// to be sent with the TOTP code to /login/mfa. Users without MFA get ok=true (login complete here).
export interface LoginResult {
  ok: boolean
  mfa_required?: boolean
  mfa_token?: string
}

export interface MfaStatus {
  enabled: boolean
  configured: boolean
}

export interface MfaEnrollStart {
  secret: string
  otpauth_uri: string
}

export const api = {
  get: <T>(path: string) => request<T>(path),
  post: <T>(path: string, body?: unknown) =>
    request<T>(path, {
      method: 'POST',
      body: body ? JSON.stringify(body) : undefined,
    }),
  del: <T>(path: string) => request<T>(path, { method: 'DELETE' }),
  getAbsolute: <T>(path: string) => requestAbsolute<T>(path),
  postAbsolute: <T>(path: string, body?: unknown) =>
    requestAbsolute<T>(path, {
      method: 'POST',
      body: body ? JSON.stringify(body) : undefined,
    }),
  stream: streamRequest,
  sse: sseRequest,
  // --- Auth ---
  authStatus: () => request<AuthStatus>('/api/v1/auth/status'),
  login: (username: string, password: string) =>
    request<LoginResult>(
      '/api/v1/login',
      {
        method: 'POST',
        body: JSON.stringify({ username, password }),
      },
      // Don't redirect to login on a bad-credentials 401; show the error inline on the login screen.
      { suppressAuthRedirect: true },
    ),
  loginMfa: (mfaToken: string, code: string) =>
    request<{ ok: boolean }>(
      '/api/v1/login/mfa',
      {
        method: 'POST',
        body: JSON.stringify({ mfa_token: mfaToken, code }),
      },
      { suppressAuthRedirect: true },
    ),
  logout: () => request<{ ok: boolean }>('/api/v1/logout', { method: 'POST' }),
  // --- MFA (TOTP, optional enrollment) ---
  mfaStatus: () => request<MfaStatus>('/api/v1/mfa/status'),
  mfaEnrollStart: () =>
    request<MfaEnrollStart>('/api/v1/mfa/enroll/start', { method: 'POST' }),
  mfaEnrollVerify: (code: string) =>
    request<{ ok: boolean; enabled: boolean }>(
      '/api/v1/mfa/enroll/verify',
      { method: 'POST', body: JSON.stringify({ code }) },
      { suppressAuthRedirect: true },
    ),
  mfaDisable: (code: string) =>
    request<{ ok: boolean; enabled: boolean }>(
      '/api/v1/mfa/disable',
      { method: 'POST', body: JSON.stringify({ code }) },
      { suppressAuthRedirect: true },
    ),
  changePassword: (currentPassword: string, newPassword: string) =>
    request<{ ok: boolean }>(
      '/api/v1/change-password',
      {
        method: 'POST',
        body: JSON.stringify({ current_password: currentPassword, new_password: newPassword }),
      },
      // Don't redirect to login on a wrong-current-password 401; show the error inline in the panel.
      { suppressAuthRedirect: true },
    ),
  // --- Commands ---
  // Advisory `<bin> --help` text, used by the HITL review dialog to help spot invalid options.
  commandHelp: (bin: string) =>
    request<{ ok: boolean; bin: string; help: string }>(
      `/api/v1/commands/help?bin=${encodeURIComponent(bin)}`,
    ),
  // --- RTO playbook ---
  // Append selected placeholder-ized retest commands into the live RTO playbook (rto.json).
  exportRtoPlaybook: (
    findingNo: string | null | undefined,
    commands: { command: string; label?: string }[],
  ) =>
    request<{ ok: boolean; added: number; skipped: number; path: string }>(
      '/api/v1/rto-playbook/export',
      {
        method: 'POST',
        body: JSON.stringify({ findingNo: findingNo ?? undefined, commands }),
      },
    ),
}
