import { useCallback, useEffect, useState, type FormEvent } from "react";
import { ApiError, api, type MfaStatus } from "../../lib/api";
import { useAuth } from "../../contexts/AuthContext";

/** MFA (TOTP) opt-in configuration panel for the Config screen. */
export function MfaPanel() {
  const { authRequired } = useAuth();
  const [status, setStatus] = useState<MfaStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [enroll, setEnroll] = useState<{ secret: string; uri: string } | null>(null);
  const [enrollCode, setEnrollCode] = useState("");
  const [disableCode, setDisableCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    try {
      setStatus(await api.mfaStatus());
    } catch {
      setError("Failed to retrieve MFA status.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  // MFA is meaningless when auth is disabled, so hide the panel entirely.
  if (!authRequired) return null;

  const inputClass =
    "w-full rounded-lg border border-border bg-bg-primary px-3 py-2 text-sm text-text-primary outline-none focus:border-accent disabled:opacity-50";

  async function startEnroll() {
    setError(null);
    setNotice(null);
    setBusy(true);
    try {
      const res = await api.mfaEnrollStart();
      setEnroll({ secret: res.secret, uri: res.otpauth_uri });
      setEnrollCode("");
    } catch (err) {
      setError(
        err instanceof ApiError && err.status === 503
          ? "MFA is not configured on the server (ask an administrator to set MFA_SECRET_KEY)."
          : "Failed to start enrollment.",
      );
    } finally {
      setBusy(false);
    }
  }

  async function verifyEnroll(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      await api.mfaEnrollVerify(enrollCode);
      setEnroll(null);
      setEnrollCode("");
      setNotice("MFA enabled. An authentication code will be required from your next login.");
      await refresh();
    } catch (err) {
      setError(
        err instanceof ApiError && err.status === 401
          ? "The authentication code is incorrect. Check the code shown in your app."
          : "Failed to confirm enrollment.",
      );
    } finally {
      setBusy(false);
    }
  }

  async function disableMfa(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      await api.mfaDisable(disableCode);
      setDisableCode("");
      setNotice("MFA disabled.");
      await refresh();
    } catch (err) {
      setError(
        err instanceof ApiError && err.status === 401
          ? "The authentication code is incorrect."
          : "Failed to disable MFA.",
      );
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="rounded-xl border border-border bg-bg-secondary p-6">
      <h3 className="mb-1 text-lg font-semibold text-text-primary">
        Two-Factor Authentication (MFA)
      </h3>
      <p className="mb-4 text-sm text-text-secondary">
        Protect your login with a one-time code from an authenticator app
        (Google Authenticator, 1Password, etc.). Enrollment is optional.
      </p>

      {loading ? (
        <p className="text-sm text-text-muted">Loading…</p>
      ) : status && !status.configured && !status.enabled ? (
        <p className="text-sm text-amber-400">
          MFA is not configured on this server (ask an administrator to set MFA_SECRET_KEY).
        </p>
      ) : status?.enabled ? (
        <div className="space-y-3">
          <p className="text-sm text-green-400">MFA is enabled for this account.</p>
          <form onSubmit={disableMfa} className="space-y-3">
            <label className="block">
              <span className="mb-1 block text-xs text-text-muted">
                Enter your current authentication code to disable MFA
              </span>
              <input
                type="text"
                inputMode="numeric"
                autoComplete="one-time-code"
                maxLength={6}
                value={disableCode}
                onChange={(e) => {
                  setError(null);
                  setNotice(null);
                  setDisableCode(e.target.value.replace(/\D/g, ""));
                }}
                className={`${inputClass} max-w-[12rem] tracking-[0.3em]`}
              />
            </label>
            {error && <p className="text-sm text-red-400">{error}</p>}
            {notice && <p className="text-sm text-green-400">{notice}</p>}
            <button
              type="submit"
              disabled={busy || disableCode.length < 6}
              className="rounded-lg border border-red-500/50 px-4 py-2 text-sm font-medium text-red-300 transition-colors hover:bg-red-500/10 disabled:opacity-50"
            >
              {busy ? "Disabling…" : "Disable MFA"}
            </button>
          </form>
        </div>
      ) : enroll ? (
        <div className="space-y-4">
          <div>
            <p className="mb-2 text-sm text-text-secondary">
              Register one of the following in your authenticator app.
            </p>
            <div className="rounded-lg border border-border bg-bg-primary p-3">
              <span className="block text-xs text-text-muted">Setup key (manual entry)</span>
              <code className="block break-all font-mono text-sm text-text-primary">
                {enroll.secret}
              </code>
              <span className="mt-2 block text-xs text-text-muted">otpauth URI</span>
              <code className="block break-all font-mono text-xs text-text-secondary">
                {enroll.uri}
              </code>
            </div>
          </div>
          <form onSubmit={verifyEnroll} className="space-y-3">
            <label className="block">
              <span className="mb-1 block text-xs text-text-muted">
                Enter the 6-digit code shown in your app to confirm enrollment
              </span>
              <input
                type="text"
                inputMode="numeric"
                autoComplete="one-time-code"
                autoFocus
                maxLength={6}
                value={enrollCode}
                onChange={(e) => {
                  setError(null);
                  setEnrollCode(e.target.value.replace(/\D/g, ""));
                }}
                className={`${inputClass} max-w-[12rem] tracking-[0.3em]`}
              />
            </label>
            {error && <p className="text-sm text-red-400">{error}</p>}
            <div className="flex gap-3">
              <button
                type="submit"
                disabled={busy || enrollCode.length < 6}
                className="rounded-lg bg-accent px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-accent-hover disabled:opacity-50"
              >
                {busy ? "Verifying…" : "Confirm enrollment"}
              </button>
              <button
                type="button"
                onClick={() => {
                  setEnroll(null);
                  setError(null);
                }}
                className="rounded-lg border border-border px-4 py-2 text-sm text-text-secondary transition-colors hover:bg-bg-primary"
              >
                Cancel
              </button>
            </div>
          </form>
        </div>
      ) : (
        <div className="space-y-3">
          {error && <p className="text-sm text-red-400">{error}</p>}
          {notice && <p className="text-sm text-green-400">{notice}</p>}
          <button
            type="button"
            onClick={startEnroll}
            disabled={busy}
            className="rounded-lg bg-accent px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-accent-hover disabled:opacity-50"
          >
            {busy ? "Preparing…" : "Enroll in MFA"}
          </button>
        </div>
      )}
    </div>
  );
}
