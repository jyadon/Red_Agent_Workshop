import {
  useEffect,
  useMemo,
  useRef,
  useState,
  type FormEvent,
} from "react";
import { api, ApiError } from "../../lib/api";

interface EntraDbItem {
  tenant: string;
  path: string;
  sizeBytes: number;
  modifiedAt: string;
}

interface EntraDbList {
  count: number;
  items: EntraDbItem[];
}

type TokenType = "prt-cookie" | "refresh-token" | "access-token";

// Non-sensitive identity info returned by POST /api/v1/entra/auth (never the token itself).
interface EntraIdentity {
  tenant?: string;
  upn?: string;
  name?: string;
  oid?: string;
  aud?: string;
  mfa?: boolean;
  expiresOn?: string;
  clientId?: string;
}

interface EntraAuthResponse {
  ok: boolean;
  tenant: string;
  session_id: string;
  identity: EntraIdentity;
}

// Session kept from auth success until gather. The browser holds metadata only, never the token.
interface AuthSession {
  id: string;
  tenant: string;
  identity: EntraIdentity;
}

// gather can take minutes on large tenants, so the server starts the job and returns a job_id
// that the frontend polls (avoids upstream response timeouts).
type GatherJobStatus = "running" | "done" | "failed";
interface GatherJob {
  job_id: string;
  tenant: string;
  status: GatherJobStatus;
  database?: string | null;
  error?: string | null;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function formatDate(iso: string): string {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString();
}

// Extract the token value from a paste. If a whole cookie header like
// `x-ms-RefreshTokenCredential=eyJ...` is pasted, pull out just the value.
function extractCookieValue(raw: string): string {
  const t = raw.trim();
  const m = t.match(/x-ms-RefreshTokenCredential\s*=\s*([^;\s]+)/i);
  return m ? m[1] : t;
}

// Base64url-decode a JWT payload (middle segment). Signature is NOT verified.
function decodeJwtPayload(jwt: string): Record<string, unknown> | null {
  const parts = jwt.split(".");
  if (parts.length < 2) return null;
  try {
    const b64 = parts[1].replace(/-/g, "+").replace(/_/g, "/");
    const pad = b64.length % 4 === 0 ? "" : "=".repeat(4 - (b64.length % 4));
    return JSON.parse(atob(b64 + pad)) as Record<string, unknown>;
  } catch {
    return null;
  }
}

interface TokenHint {
  level: "ok" | "warn" | "error";
  message: string;
}

// Client-side sanity check of a pasted PRT cookie before submit (nothing is sent or logged here).
function checkPrtCookie(value: string): TokenHint | null {
  if (!value) return null;
  const parts = value.split(".");
  if (parts.length !== 3) {
    return { level: "error", message: "Not a PRT cookie format." };
  }
  const payload = decodeJwtPayload(value);
  if (!payload) {
    return {
      level: "warn",
      message: "Could not parse the PRT cookie. Please check the value.",
    };
  }
  const iat = typeof payload.iat === "number" ? payload.iat : undefined;
  const hasNonce =
    typeof payload.request_nonce === "string" &&
    payload.request_nonce.length > 0;
  if (iat !== undefined) {
    const ageSec = Math.max(0, Math.floor(Date.now() / 1000 - iat));
    const ageLabel =
      ageSec < 60 ? `${ageSec} sec` : `${Math.floor(ageSec / 60)} min`;
    const nonceLabel = hasNonce ? " · nonce present" : "";
    if (ageSec > 600) {
      return {
        level: "warn",
        message: `${ageLabel} since issuance${nonceLabel}. It may have expired; regenerating and re-pasting is recommended.`,
      };
    }
    return {
      level: "ok",
      message: `Format OK: ${ageLabel} since issuance${nonceLabel}.`,
    };
  }
  return { level: "ok", message: `Format OK${hasNonce ? " · nonce present" : ""}.` };
}

/**
 * Entra data collection (roadrecon) settings panel. auth (token exchange) and gather (collection)
 * are separated server-side, so after auth succeeds you can "re-collect" in the same session
 * without re-fetching the short-lived cookie. Tokens are only sent, never persisted, and
 * credentials are discarded after collection.
 */
export function EntraDataPanel() {
  const [items, setItems] = useState<EntraDbItem[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [confirmTenant, setConfirmTenant] = useState<string | null>(null);
  const [deleting, setDeleting] = useState<string | null>(null);

  const [tenant, setTenant] = useState("");
  const [token, setToken] = useState("");
  const [tokenType, setTokenType] = useState<TokenType>("prt-cookie");
  const [authing, setAuthing] = useState(false);
  const [gathering, setGathering] = useState(false);
  const [collectError, setCollectError] = useState<string | null>(null);
  const [collectOk, setCollectOk] = useState<string | null>(null);
  const [session, setSession] = useState<AuthSession | null>(null);
  const [showHelp, setShowHelp] = useState(false);

  const busy = authing || gathering;

  // Cancellation token so unmount or a re-collect can stop an in-flight polling loop.
  const pollRef = useRef<{ cancelled: boolean } | null>(null);

  useEffect(() => {
    return () => {
      if (pollRef.current) pollRef.current.cancelled = true;
    };
  }, []);

  const tokenHint = useMemo<TokenHint | null>(() => {
    if (tokenType !== "prt-cookie") return null;
    return checkPrtCookie(extractCookieValue(token));
  }, [token, tokenType]);

  // Fetch and return the list too (setItems batches, so callers can't read it immediately).
  async function refresh(): Promise<EntraDbItem[]> {
    try {
      const data = await api.get<EntraDbList>("/api/v1/entra/databases");
      const list = data.items ?? [];
      setItems(list);
      setError(null);
      return list;
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Failed to fetch the list");
      return [];
    }
  }

  useEffect(() => {
    void refresh();
  }, []);

  // Start gather in the background and back-off poll the job (4s for the first minute, then 8s,
  // up to 15 min). Each HTTP request stays short so upstream response timeouts aren't hit.
  async function runGather(s: AuthSession) {
    if (pollRef.current) pollRef.current.cancelled = true;
    const ctl = { cancelled: false };
    pollRef.current = ctl;

    setGathering(true);
    setCollectError(null);
    setCollectOk(null);
    try {
      let job = await api.post<GatherJob>("/api/v1/entra/gather", {
        session_id: s.id,
      });

      const startedAt = Date.now();
      const maxWaitMs = 15 * 60 * 1000;
      while (!ctl.cancelled) {
        if (job.status === "done") {
          setCollectOk(`Collection for ${s.tenant} completed.`);
          await refresh();
          return;
        }
        if (job.status === "failed") {
          setCollectError(
            `${job.error || "Collection failed"} (use "Re-collect" to retry with the same auth)`,
          );
          return;
        }
        if (Date.now() - startedAt > maxWaitMs) {
          setCollectError(
            "Collection timed out. It may still be running server-side. " +
              'Reload the list later, or use "Re-collect" to retry.',
          );
          return;
        }

        await sleep(Date.now() - startedAt > 60_000 ? 8_000 : 4_000);
        if (ctl.cancelled) return;

        try {
          job = await api.get<GatherJob>(
            `/api/v1/entra/gather/jobs/${encodeURIComponent(job.job_id)}`,
          );
        } catch (err) {
          // Job gone (e.g. server restart) -> fall back to checking the collected list for success.
          if (err instanceof ApiError && err.status === 404) {
            const list = await refresh();
            const t = s.tenant.toLowerCase();
            if (list.some((it) => it.tenant.toLowerCase() === t)) {
              setCollectOk(`Collection for ${s.tenant} completed.`);
            } else {
              setCollectError(
                "Could not get the collection job status (server may have restarted). " +
                  'If it is not reflected in the list, use "Re-collect" to retry.',
              );
            }
            return;
          }
          throw err;
        }
      }
    } catch (err) {
      const base = err instanceof ApiError ? err.message : "Collection failed";
      // A 404 on start means the session expired (re-auth needed); otherwise suggest re-collect.
      if (err instanceof ApiError && err.status === 404) {
        setSession(null);
        setCollectError(base);
      } else {
        setCollectError(`${base} (use "Re-collect" to retry with the same auth)`);
      }
    } finally {
      // Only clean up if this is still the active poll; a re-collect may have replaced it.
      if (pollRef.current === ctl) {
        pollRef.current = null;
        setGathering(false);
      }
    }
  }

  // auth -> gather chained automatically, no approval gate in between.
  async function handleCollect(e: FormEvent) {
    e.preventDefault();
    const cookie = extractCookieValue(token);
    if (!tenant.trim() || !cookie) return;
    setAuthing(true);
    setCollectError(null);
    setCollectOk(null);
    let authed: AuthSession | null = null;
    try {
      const res = await api.post<EntraAuthResponse>("/api/v1/entra/auth", {
        tenant: tenant.trim(),
        token: cookie,
        token_type: tokenType,
      });
      authed = {
        id: res.session_id,
        tenant: res.tenant,
        identity: res.identity ?? {},
      };
      setSession(authed);
      setToken(""); // the exchanged cookie is no longer needed; do not keep it
    } catch (err) {
      setCollectError(
        err instanceof ApiError
          ? err.message
          : "Authentication failed (check for an expired/invalid PRT cookie or conditional access)",
      );
      setToken("");
      setShowHelp(true); // open the acquisition steps to prompt a re-fetch on expiry
    } finally {
      setAuthing(false);
    }
    if (authed) await runGather(authed);
  }

  async function discardSession() {
    if (!session) return;
    const id = session.id;
    setSession(null);
    setCollectOk(null);
    try {
      await api.del(`/api/v1/entra/auth/${encodeURIComponent(id)}`);
    } catch {
      // The session also expires via server TTL, so ignore failures (already discarded in the UI).
    }
  }

  async function handleDelete(t: string) {
    setDeleting(t);
    try {
      await api.del(`/api/v1/entra/databases/${encodeURIComponent(t)}`);
      setConfirmTenant(null);
      await refresh();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Deletion failed");
    } finally {
      setDeleting(null);
    }
  }

  const hintColor =
    tokenHint?.level === "error"
      ? "text-red-300"
      : tokenHint?.level === "warn"
        ? "text-yellow-300"
        : "text-green-300";

  return (
    <div className="rounded-xl border border-border bg-bg-secondary p-6">
      <h3 className="mb-1 text-lg font-semibold text-text-primary">
        Entra tenant data collection
      </h3>
      <p className="mb-4 text-sm text-text-secondary">
        Enter a PRT cookie obtained on a device to collect the tenant's data.
        The token is not stored, and credentials are discarded after collection.
      </p>

      <div className="mb-4 rounded-lg border border-border/50 bg-bg-primary p-3">
        <button
          type="button"
          onClick={() => setShowHelp((v) => !v)}
          className="flex w-full items-center justify-between text-left text-sm font-medium text-text-primary"
        >
          <span>How to obtain a PRT cookie</span>
          <span className="text-text-muted">{showHelp ? "▲" : "▼"}</span>
        </button>
        {showHelp && (
          <div className="mt-2 space-y-2 text-xs leading-relaxed text-text-secondary">
            <p>
              Run the acquisition tool on a device already joined to the Entra tenant.
              On success the required value is copied to the clipboard automatically, so paste it straight into the form below.
            </p>
            <p className="text-yellow-300">
              A PRT cookie has a short lifetime, so{" "}
              <strong>paste it immediately after generating it</strong>.
              If it has expired, run the tool again.
            </p>
          </div>
        )}
      </div>

      <form onSubmit={handleCollect} className="mb-6 space-y-3">
        <div className="grid gap-3 sm:grid-cols-2">
          <label className="block">
            <span className="mb-1 block text-xs text-text-muted">
              Tenant name
            </span>
            <input
              type="text"
              value={tenant}
              onChange={(e) => setTenant(e.target.value)}
              placeholder="contoso.onmicrosoft.com"
              disabled={busy}
              className="w-full rounded-lg border border-border bg-bg-primary px-3 py-2 text-sm text-text-primary outline-none focus:border-accent disabled:opacity-50"
            />
          </label>
          <label className="block">
            <span className="mb-1 block text-xs text-text-muted">
              Token type
            </span>
            <select
              value={tokenType}
              onChange={(e) => setTokenType(e.target.value as TokenType)}
              disabled={busy}
              className="w-full rounded-lg border border-border bg-bg-primary px-3 py-2 text-sm text-text-primary outline-none focus:border-accent disabled:opacity-50"
            >
              <option value="prt-cookie">PRT Cookie</option>
              <option value="refresh-token">Refresh Token</option>
              <option value="access-token">Access Token</option>
            </select>
          </label>
        </div>
        <label className="block">
          <span className="mb-1 block text-xs text-text-muted">Token</span>
          <input
            type="password"
            value={token}
            onChange={(e) => setToken(e.target.value)}
            placeholder="Paste the value obtained on the device"
            autoComplete="off"
            disabled={busy}
            className="w-full rounded-lg border border-border bg-bg-primary px-3 py-2 font-mono text-sm text-text-primary outline-none focus:border-accent disabled:opacity-50"
          />
          {tokenHint && (
            <span className={`mt-1 block text-xs ${hintColor}`}>
              {tokenHint.message}
            </span>
          )}
        </label>

        {collectError && (
          <div className="rounded-lg border border-red-500/40 bg-red-500/10 p-3 text-sm text-red-300">
            {collectError}
          </div>
        )}
        {collectOk && (
          <div className="rounded-lg border border-green-500/40 bg-green-500/10 p-3 text-sm text-green-300">
            {collectOk}
          </div>
        )}

        <div className="flex items-center gap-3">
          <button
            type="submit"
            disabled={
              busy ||
              !tenant.trim() ||
              !token.trim() ||
              tokenHint?.level === "error"
            }
            className="rounded-lg bg-accent px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-accent-hover disabled:opacity-50"
          >
            {authing
              ? "Authenticating…"
              : gathering
                ? "Collecting… (may take a few minutes)"
                : "Authenticate & collect"}
          </button>
        </div>
      </form>

      {session && (
        <div className="mb-6 rounded-lg border border-accent/40 bg-accent/10 p-3">
          <div className="text-sm font-medium text-text-primary">
            Authenticated session
          </div>
          <div className="mt-1 space-y-0.5 text-xs text-text-secondary">
            <div>Tenant: {session.tenant}</div>
            {session.identity.upn && <div>User: {session.identity.upn}</div>}
            <div>
              MFA:{" "}
              {session.identity.mfa === undefined
                ? "unknown"
                : session.identity.mfa
                  ? "✓ yes"
                  : "no"}
              {session.identity.expiresOn && (
                <span className="ml-2">
                  Token expiry: {session.identity.expiresOn}
                </span>
              )}
            </div>
          </div>
          <div className="mt-2 flex items-center gap-2">
            <button
              type="button"
              onClick={() => runGather(session)}
              disabled={busy}
              className="rounded-lg bg-accent px-3 py-1.5 text-xs font-medium text-white transition-colors hover:bg-accent-hover disabled:opacity-50"
            >
              {gathering ? "Collecting…" : "Re-collect (same auth)"}
            </button>
            <button
              type="button"
              onClick={discardSession}
              disabled={busy}
              className="rounded-lg border border-border px-3 py-1.5 text-xs text-text-secondary transition-colors hover:bg-bg-tertiary disabled:opacity-50"
            >
              Discard auth
            </button>
          </div>
        </div>
      )}

      <div className="mb-2 text-sm font-medium text-text-primary">
        Collected data
      </div>
      {error && (
        <div className="mb-3 rounded-lg border border-red-500/40 bg-red-500/10 p-3 text-sm text-red-300">
          {error}
        </div>
      )}

      {items.length === 0 ? (
        <div className="rounded-lg border border-border/50 bg-bg-primary p-3 text-sm text-text-muted">
          No collected data.
        </div>
      ) : (
        <div className="space-y-3">
          {items.map((it) => (
            <div
              key={it.tenant}
              className="flex items-center justify-between rounded-lg border border-border/50 bg-bg-primary p-3"
            >
              <div className="min-w-0">
                <div className="truncate text-sm font-medium text-text-primary">
                  {it.tenant}
                </div>
                <div className="text-xs text-text-muted">
                  {formatSize(it.sizeBytes)} · collected {formatDate(it.modifiedAt)}
                </div>
              </div>

              {confirmTenant === it.tenant ? (
                <div className="flex items-center gap-2">
                  <span className="text-xs text-text-secondary">
                    Delete?
                  </span>
                  <button
                    onClick={() => handleDelete(it.tenant)}
                    disabled={deleting === it.tenant}
                    className="rounded-lg bg-red-500 px-3 py-1.5 text-xs font-medium text-white transition-colors hover:bg-red-600 disabled:opacity-50"
                  >
                    {deleting === it.tenant ? "Deleting…" : "Delete"}
                  </button>
                  <button
                    onClick={() => setConfirmTenant(null)}
                    disabled={deleting === it.tenant}
                    className="rounded-lg border border-border px-3 py-1.5 text-xs text-text-secondary transition-colors hover:bg-bg-tertiary"
                  >
                    Cancel
                  </button>
                </div>
              ) : (
                <button
                  onClick={() => setConfirmTenant(it.tenant)}
                  className="rounded-lg border border-border px-3 py-1.5 text-xs text-text-secondary transition-colors hover:bg-bg-tertiary"
                >
                  Delete
                </button>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
