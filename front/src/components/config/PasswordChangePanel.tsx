import { useState, type FormEvent } from "react";
import { ApiError, api } from "../../lib/api";
import { useAuth } from "../../contexts/AuthContext";

/** Login password change panel for the Config screen; hidden when auth is disabled server-side. */
export function PasswordChangePanel() {
  const { authRequired } = useAuth();
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [done, setDone] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  if (!authRequired) return null;

  const MIN = 15;
  const canSubmit =
    !!current &&
    next.length >= MIN &&
    next === confirm &&
    next !== current &&
    !submitting;

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setDone(false);

    if (next.length < MIN) {
      setError(`The new password must be at least ${MIN} characters long.`);
      return;
    }
    if (next !== confirm) {
      setError("The new password confirmation does not match.");
      return;
    }
    if (next === current) {
      setError(
        "The new password must be different from the current password.",
      );
      return;
    }

    setSubmitting(true);
    try {
      await api.changePassword(current, next);
      setDone(true);
      setCurrent("");
      setNext("");
      setConfirm("");
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        setError("The current password is incorrect.");
      } else if (err instanceof ApiError && err.status === 400) {
        setError("The new password does not meet the requirements.");
      } else {
        setError("Failed to change the password.");
      }
    } finally {
      setSubmitting(false);
    }
  }

  const inputClass =
    "w-full rounded-lg border border-border bg-bg-primary px-3 py-2 text-sm text-text-primary outline-none focus:border-accent disabled:opacity-50";

  return (
    <div className="rounded-xl border border-border bg-bg-secondary p-6">
      <h3 className="mb-1 text-lg font-semibold text-text-primary">
        Change Login Password
      </h3>
      <p className="mb-4 text-sm text-text-secondary">
        Change the password used to log in to this site. The new password must be{" "}
        at least {MIN} characters long and hard to guess.
      </p>

      <form onSubmit={handleSubmit} className="space-y-3">
        <label className="block">
          <span className="mb-1 block text-xs text-text-muted">
            Current password
          </span>
          <input
            type="password"
            autoComplete="current-password"
            value={current}
            onChange={(e) => {
              setDone(false);
              setError(null);
              setCurrent(e.target.value);
            }}
            className={inputClass}
          />
        </label>

        <div className="grid grid-cols-2 gap-3">
          <label className="block">
            <span className="mb-1 block text-xs text-text-muted">
              New password
            </span>
            <input
              type="password"
              autoComplete="new-password"
              value={next}
              onChange={(e) => {
                setDone(false);
                setError(null);
                setNext(e.target.value);
              }}
              className={inputClass}
            />
          </label>
          <label className="block">
            <span className="mb-1 block text-xs text-text-muted">
              New password (confirm)
            </span>
            <input
              type="password"
              autoComplete="new-password"
              value={confirm}
              onChange={(e) => {
                setDone(false);
                setError(null);
                setConfirm(e.target.value);
              }}
              className={inputClass}
            />
          </label>
        </div>

        {error && <p className="text-sm text-red-400">{error}</p>}
        {done && (
          <p className="text-sm text-green-400">Password changed.</p>
        )}

        <button
          type="submit"
          disabled={!canSubmit}
          className="rounded-lg bg-accent px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-accent-hover disabled:opacity-50"
        >
          {submitting ? "Changing…" : "Change password"}
        </button>
      </form>
    </div>
  );
}
