import { useState, type FormEvent } from "react";
import { useCredentialsStore } from "../../lib/credentials-store";

/** Config panel for pre-setting AD verification credentials, stored in the memory-only `useCredentialsStore` shared with the retest screen. */
export function AdCredentialsPanel() {
  const creds = useCredentialsStore((s) => s.credentials);
  const setCredentials = useCredentialsStore((s) => s.setCredentials);
  const clearCredentials = useCredentialsStore((s) => s.clearCredentials);

  const [domain, setDomain] = useState(creds?.domain ?? "");
  const [user, setUser] = useState(creds?.user ?? "");
  const [pass, setPass] = useState(creds?.pass ?? "");
  const [dns, setDns] = useState(creds?.dns ?? "");
  const [saved, setSaved] = useState(false);

  // DNS server is required too, since AD checks need it for DC discovery.
  const canSave = !!(domain.trim() && user.trim() && pass.trim() && dns.trim());

  function handleSave(e: FormEvent) {
    e.preventDefault();
    if (!canSave) return;
    setCredentials({
      domain: domain.trim(),
      user: user.trim(),
      pass,
      dns: dns.trim(),
    });
    setSaved(true);
  }

  function handleClear() {
    clearCredentials();
    setDomain("");
    setUser("");
    setPass("");
    setDns("");
    setSaved(false);
  }

  function touched<T>(setter: (v: T) => void) {
    return (v: T) => {
      setSaved(false);
      setter(v);
    };
  }

  const inputClass =
    "w-full rounded-lg border border-border bg-bg-primary px-3 py-2 text-sm text-text-primary outline-none focus:border-accent disabled:opacity-50";

  return (
    <div className="rounded-xl border border-border bg-bg-secondary p-6">
      <h3 className="mb-1 text-lg font-semibold text-text-primary">
        Active Directory Credentials
      </h3>
      <p className="mb-4 text-sm text-text-secondary">
        Pre-configure the target domain user credentials used for Active
        Directory retests.<br />
        The entered credentials are used only temporarily within this retest
        session and are cleared when the page is reloaded.
      </p>

      {creds && (
        <div className="mb-4 flex items-center justify-between rounded-lg border border-border/50 bg-bg-primary p-3">
          <span className="text-sm text-text-secondary">
            Configured:{" "}
            <span className="font-medium text-text-primary">
              {creds.domain}\{creds.user}
            </span>
          </span>
          <button
            type="button"
            onClick={handleClear}
            className="rounded-lg border border-border px-3 py-1.5 text-xs text-text-secondary transition-colors hover:bg-bg-tertiary"
          >
            Clear
          </button>
        </div>
      )}

      <form onSubmit={handleSave} className="space-y-3">
        <label className="block">
          <span className="mb-1 block text-xs text-text-muted">
            Domain name (e.g. corp.local)
          </span>
          <input
            type="text"
            autoComplete="off"
            value={domain}
            onChange={(e) => touched(setDomain)(e.target.value)}
            className={inputClass}
          />
        </label>

        <div className="grid grid-cols-2 gap-3">
          <label className="block">
            <span className="mb-1 block text-xs text-text-muted">Username</span>
            <input
              type="text"
              autoComplete="off"
              value={user}
              onChange={(e) => touched(setUser)(e.target.value)}
              className={inputClass}
            />
          </label>
          <label className="block">
            <span className="mb-1 block text-xs text-text-muted">
              Password
            </span>
            <input
              type="password"
              autoComplete="new-password"
              value={pass}
              onChange={(e) => touched(setPass)(e.target.value)}
              className={inputClass}
            />
          </label>
        </div>

        <label className="block">
          <span className="mb-1 block text-xs text-text-muted">
            DNS server IP address
          </span>
          <input
            type="text"
            autoComplete="off"
            value={dns}
            onChange={(e) => touched(setDns)(e.target.value)}
            className={inputClass}
          />
        </label>

        <div className="flex items-center gap-3">
          <button
            type="submit"
            disabled={!canSave}
            className="rounded-lg bg-accent px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-accent-hover disabled:opacity-50"
          >
            Save
          </button>
          {saved && (
            <span className="text-sm text-green-400">Saved.</span>
          )}
        </div>
      </form>
    </div>
  );
}
