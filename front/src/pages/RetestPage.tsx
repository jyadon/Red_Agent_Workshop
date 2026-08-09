import { useMemo, useState, useEffect } from "react";
import type { Finding } from "../types/finding";
import { useFindings } from "../hooks/useFindings";
import { useRetest } from "../hooks/useRetest";
import { FindingTable } from "../components/findings/FindingTable";
import { FindingDetail } from "../components/findings/FindingDetail";
import { LoadingSpinner } from "../components/common/LoadingSpinner";
import { useNavigate, useParams } from "react-router";
import { api } from "../lib/api";
import { useSocks } from "../contexts/SocksContext";
import { useVerificationHistoryStore } from "../lib/verification-history-store";
import { toStatusKind, type FindingStatusKind } from "../lib/verdict";
import { useCredentialsStore } from "../lib/credentials-store";
import { useRetestSettingsStore } from "../lib/retest-settings-store";
import { PageContainer } from "../components/layout/PageContainer";

export function RetestPage() {
  const navigate = useNavigate();
  const { findingId } = useParams();
  const { active: socksActive } = useSocks();
  const [showContextModal, setShowContextModal] = useState(false);
  const [pendingFinding, setPendingFinding] = useState<Finding | null>(null);
  const [ctxDomain, setCtxDomain] = useState("");
  const [ctxUser, setCtxUser] = useState("");
  const [ctxPass, setCtxPass] = useState("");
  const [ctxDns, setCtxDns] = useState("");
  // When true, the credentials modal only updates the cache and does not start a retest.
  const [credsEditMode, setCredsEditMode] = useState(false);

  const [showTenantModal, setShowTenantModal] = useState(false);
  const [entraTenantOptions, setEntraTenantOptions] = useState<string[]>([]);
  const [selectedTenant, setSelectedTenant] = useState("");

  const [showInputsModal, setShowInputsModal] = useState(false);
  const [inputsValues, setInputsValues] = useState<Record<string, string[]>>(
    {},
  );
  const [inputsError, setInputsError] = useState<string | null>(null);
  const [pendingRuntimeVars, setPendingRuntimeVars] = useState<
    Record<string, string>
  >({});

  const resetContextForm = () => {
    setCtxDomain("");
    setCtxUser("");
    setCtxPass("");
    setCtxDns("");
  };
  const { findings, loading: findingsLoading } = useFindings();
  const {
    run,
    loading: runLoading,
    startRun,
    submitInterruptDecisions,
  } = useRetest();

  // In-memory credentials cache. When set, the modal is skipped on retest.
  const cachedCreds = useCredentialsStore((s) => s.credentials);
  const setCachedCreds = useCredentialsStore((s) => s.setCredentials);
  const clearCachedCreds = useCredentialsStore((s) => s.clearCredentials);

  const openCredsEditor = () => {
    if (!cachedCreds) return;
    setCtxDomain(cachedCreds.domain);
    setCtxUser(cachedCreds.user);
    setCtxPass(cachedCreds.pass);
    setCtxDns(cachedCreds.dns ?? "");
    setPendingFinding(null);
    setCredsEditMode(true);
    setShowContextModal(true);
  };

  const requireApproval = useRetestSettingsStore((s) => s.requireApproval);

  const startRunWithCreds = async (
    finding: Finding,
    ctx: { domain: string; user: string; pass: string; dns?: string },
    runtimeVars: Record<string, string> = {},
  ) => {
    try {
      await startRun(
        finding,
        ctx,
        undefined,
        requireApproval,
        runtimeVars,
      );
    } catch (e) {
      const msg =
        e instanceof Error ? e.message : "Failed to start the retest";
      window.alert(`Failed to start the retest: ${msg}`);
    }
  };

  // For Entra-only findings: AD credentials are not needed, so send blanks and pass
  // only the referenced tenant. When tenant is omitted (0/1 collected), the server
  // auto-resolves to the single collected one.
  const startRunWithEntra = async (
    finding: Finding,
    tenant?: string,
    runtimeVars: Record<string, string> = {},
  ) => {
    try {
      await startRun(
        finding,
        { domain: "", user: "", pass: "", tenant },
        undefined,
        requireApproval,
        runtimeVars,
      );
    } catch (e) {
      const msg =
        e instanceof Error ? e.message : "Failed to start the retest";
      window.alert(`Failed to start the retest: ${msg}`);
    }
  };

  // For non-AD platform findings (platform without "ad"): neither AD credentials nor an
  // Entra tenant are needed; run using data variables ({{id}} etc.) only. No
  // execution_context is attached (the backend allows null and runs with runtime_variables alone).
  const startRunNoCreds = async (
    finding: Finding,
    runtimeVars: Record<string, string> = {},
  ) => {
    try {
      await startRun(
        finding,
        undefined,
        undefined,
        requireApproval,
        runtimeVars,
      );
    } catch (e) {
      const msg =
        e instanceof Error ? e.message : "Failed to start the retest";
      window.alert(`Failed to start the retest: ${msg}`);
    }
  };

  const proceedVerification = async (
    finding: Finding,
    runtimeVars: Record<string, string>,
  ) => {
    setPendingRuntimeVars(runtimeVars);
    const platforms = Array.isArray(finding.platform)
      ? finding.platform
      : finding.platform
        ? [finding.platform]
        : [];
    const isEntraOnly =
      platforms.length > 0 && platforms.every((p) => p === "entra");

    // Entra-only findings need no AD credentials. Check collected tenants; if more than
    // one, show the tenant selection modal (0/1 runs directly).
    if (isEntraOnly) {
      let tenants: string[] = [];
      try {
        const data = await api.get<{ items?: { tenant: string }[] }>(
          "/api/v1/entra/databases",
        );
        tenants = (data.items ?? []).map((i) => i.tenant);
      } catch {
        tenants = [];
      }
      if (tenants.length >= 2) {
        setEntraTenantOptions(tenants);
        setSelectedTenant(tenants[0]);
        setPendingFinding(finding);
        setShowTenantModal(true);
        return;
      }
      await startRunWithEntra(
        finding,
        tenants[0],
        runtimeVars,
      );
      return;
    }

    // Explicitly non-AD platform (no "ad", not empty) => AD credentials not needed.
    // Run directly without execution_context. Findings with no platform set (empty) keep
    // the AD flow, to avoid changing behavior of existing AD findings.
    const needsAdCreds = platforms.length === 0 || platforms.includes("ad");
    if (!needsAdCreds) {
      await startRunNoCreds(finding, runtimeVars);
      return;
    }

    // Findings requiring elevated privileges (required_privilege set) always show the
    // modal even with cached credentials, so the required privilege is surfaced and the
    // right account is reconfirmed (never silently run with a low-privilege account).
    if (cachedCreds && !finding.required_privilege) {
      await startRunWithCreds(
        finding,
        {
          domain: cachedCreds.domain,
          user: cachedCreds.user,
          pass: cachedCreds.pass,
          dns: cachedCreds.dns,
        },
        runtimeVars,
      );
      return;
    }
    setPendingFinding(finding);
    setShowContextModal(true);
  };

  const onStartVerification = async (finding: Finding) => {
    const inputs = finding.verification_inputs ?? [];
    if (inputs.length > 0) {
      setPendingFinding(finding);
      setInputsValues(Object.fromEntries(inputs.map((i) => [i.key, [""]])));
      setInputsError(null);
      setShowInputsModal(true);
      return;
    }
    await proceedVerification(finding, {});
  };

  const initialFinding = useMemo(() => {
    if (!findingId || findings.length === 0) return null;
    return findings.find((f) => f.no === findingId) ?? null;
  }, [findingId, findings]);

  const [detailFinding, setDetailFinding] = useState<Finding | null>(null);
  const [view, setView] = useState<"table" | "detail">("table");

  useEffect(() => {
    if (findingId && findings.length > 0) {
      // When the URL carries an ID, switch to detail view automatically.
      const found = findings.find((f) => f.no === findingId);
      if (found) {
        setDetailFinding(found);
        setView("detail");
      }
    }
  }, [findingId, findings]);

  const activeFinding = detailFinding ?? initialFinding;
  const activeView = view;

  const historyRecords =
    useVerificationHistoryStore((s) => {
      if (!activeFinding) return undefined;
      return s.recordsByFinding[activeFinding.no];
    }) ?? [];
  const fetchHistoryRecords = useVerificationHistoryStore(
    (s) => s.fetchRecords,
  );

  // For list badges: fetch the latest status of all findings (finding_no -> verdict) at once.
  const statusItems = useVerificationHistoryStore((s) => s.statusByFinding);
  const fetchStatusSummary = useVerificationHistoryStore(
    (s) => s.fetchStatusSummary,
  );

  // Fetch history from the backend when the finding changes. SQLite persistence lets the
  // same history be seen across browsers.
  useEffect(() => {
    if (!activeFinding) return;
    void fetchHistoryRecords(activeFinding.no);
  }, [activeFinding, fetchHistoryRecords]);

  // Refetch status each time the list view is shown (refreshes after a retest run).
  useEffect(() => {
    if (activeView !== "table") return;
    void fetchStatusSummary();
  }, [activeView, fetchStatusSummary]);

  // Normalize the summary (findings with history only) into badge display state.
  // Findings without history are absent from statusItems and render as "not run" in FindingRow.
  const statusByFinding = useMemo<Record<string, FindingStatusKind>>(() => {
    const out: Record<string, FindingStatusKind> = {};
    for (const [no, item] of Object.entries(statusItems)) {
      out[no] = toStatusKind(item.verdict, true);
    }
    return out;
  }, [statusItems]);

  const _mfInputs = pendingFinding?.verification_inputs ?? [];
  const _visibleInputs = _mfInputs;

  if (findingsLoading) {
    return (
      <div className="flex h-full items-center justify-center">
        <LoadingSpinner size="lg" />
      </div>
    );
  }

  return (
    <PageContainer className="h-[calc(100vh-7rem)] flex flex-col">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          {activeView !== "table" && (
            <button
              type="button"
              aria-label="Back to list"
              onClick={() => {
                setDetailFinding(null);
                setView("table");
                navigate("/retest");
              }}
              className="rounded-lg p-1.5 text-text-muted hover:bg-bg-tertiary hover:text-text-primary"
            >
              <svg
                aria-hidden="true"
                className="h-5 w-5"
                fill="none"
                viewBox="0 0 24 24"
                stroke="currentColor"
                strokeWidth={2}
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  d="M15.75 19.5 8.25 12l7.5-7.5"
                />
              </svg>
            </button>
          )}
          <h2 className="text-xl font-semibold text-text-primary">
            {activeView === "table" && "Findings"}
            {activeView === "detail" && "Finding Detail"}
          </h2>
        </div>

        {cachedCreds && (
          <div className="flex items-center gap-2 text-xs">
            <span
              className="rounded-full border border-border bg-bg-tertiary px-2 py-1 text-text-muted"
              title={`Credentials cached (cleared on reload)`}
            >
              Credentials:{" "}
              <span className="text-text-primary">
                {cachedCreds.domain}\{cachedCreds.user}
              </span>
            </span>
            <button
              type="button"
              onClick={openCredsEditor}
              className="rounded border border-border px-2 py-1 text-text-muted hover:bg-bg-tertiary hover:text-text-primary"
              aria-label="Edit cached credentials"
            >
              Edit
            </button>
            <button
              type="button"
              onClick={clearCachedCreds}
              className="rounded border border-border px-2 py-1 text-text-muted hover:bg-bg-tertiary hover:text-text-primary"
              aria-label="Discard cached credentials and require re-entry next time"
            >
              Reset
            </button>
          </div>
        )}
      </div>

      {activeView === "table" && (
        <FindingTable
          findings={findings}
          statusByFinding={statusByFinding}
          onViewDetail={(f) => {
            setDetailFinding(f);
            setView("detail");
          }}
        />
      )}

      {activeView === "detail" && activeFinding && (
        <div className="rounded-xl border border-border bg-bg-secondary p-6">
          <FindingDetail
            finding={activeFinding}
            onStartVerification={onStartVerification}
            onClose={() => {
              setDetailFinding(null);
              setView("table");
              navigate("/retest");
            }}
            socksActive={socksActive}
            run={run}
            verificationLoading={runLoading}
            onResume={submitInterruptDecisions}
            historyRecords={historyRecords}
          />
          {showContextModal && (
            <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
              <div className="w-full max-w-md rounded-xl border border-border bg-bg-secondary p-6 shadow-2xl">
                <div className="mb-4 space-y-1">
                  <h3 className="mb-4 text-lg font-bold text-text-primary">
                    {credsEditMode ? "Edit credentials" : "Enter user information"}
                  </h3>
                  <p className="text-[11px] text-text-muted leading-relaxed">
                    {credsEditMode ? (
                      "Saving updates the cached credentials (does not start a retest). The current values are prefilled."
                    ) : (
                      <>
                        Enter the user information for the target domain used in the retest.
                        <br />
                        The entered credentials are used only temporarily within this retest session and are cleared when the page is reloaded.
                      </>
                    )}
                  </p>
                  {pendingFinding?.required_privilege && (
                    <div className="mt-2 flex items-start gap-2 rounded border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-[11px] leading-relaxed text-amber-300">
                      <span aria-hidden="true">⚠</span>
                      <span>
                        This retest requires an account with the{" "}
                        <span className="font-bold">
                          {pendingFinding.required_privilege}
                        </span>{" "}
                        privilege.
                      </span>
                    </div>
                  )}
                </div>

                <div className="space-y-4">
                  <div>
                    <label
                      htmlFor="ctx-domain"
                      className="block text-xs font-medium text-text-muted mb-1"
                    >
                      Domain name (e.g. corp.local)
                    </label>
                    <input
                      id="ctx-domain"
                      type="text"
                      autoComplete="off"
                      value={ctxDomain}
                      onChange={(e) => setCtxDomain(e.target.value)}
                      className="w-full bg-bg-primary border border-border rounded p-2 text-sm text-text-primary outline-none focus:border-accent"
                    />
                  </div>
                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <label
                        htmlFor="ctx-user"
                        className="block text-xs font-medium text-text-muted mb-1"
                      >
                        Username
                      </label>
                      <input
                        id="ctx-user"
                        type="text"
                        autoComplete="off"
                        value={ctxUser}
                        onChange={(e) => setCtxUser(e.target.value)}
                        className="w-full bg-bg-primary border border-border rounded p-2 text-sm text-text-primary outline-none focus:border-accent"
                      />
                    </div>
                    <div>
                      <label
                        htmlFor="ctx-pass"
                        className="block text-xs font-medium text-text-muted mb-1"
                      >
                        Password
                      </label>
                      <input
                        id="ctx-pass"
                        type="password"
                        autoComplete="new-password"
                        value={ctxPass}
                        onChange={(e) => setCtxPass(e.target.value)}
                        className="w-full bg-bg-primary border border-border rounded p-2 text-sm text-text-primary outline-none focus:border-accent"
                      />
                    </div>
                  </div>
                  <div>
                    <label
                      htmlFor="ctx-dns"
                      className="block text-xs font-medium text-text-muted mb-1"
                    >
                      DNS server IP address
                    </label>
                    <input
                      id="ctx-dns"
                      type="text"
                      autoComplete="off"
                      value={ctxDns}
                      onChange={(e) => setCtxDns(e.target.value)}
                      placeholder="10.0.1.10"
                      className="w-full bg-bg-primary border border-border rounded p-2 text-sm text-text-primary outline-none focus:border-accent"
                    />
                  </div>
                </div>

                <div className="mt-6 flex justify-end gap-3">
                  <button
                    type="button"
                    onClick={() => {
                      setShowContextModal(false);
                      resetContextForm();
                      setCredsEditMode(false);
                    }}
                    className="px-4 py-2 text-sm font-medium text-text-muted hover:text-text-primary"
                  >
                    Cancel
                  </button>
                  <button
                    type="button"
                    onClick={async () => {
                      const editing = credsEditMode;
                      const finding = pendingFinding;
                      const ctx = {
                        domain: ctxDomain,
                        user: ctxUser,
                        pass: ctxPass,
                        dns: ctxDns.trim(),
                      };
                      // Cache the entered credentials in the Zustand store for reuse in
                      // later retests. The store is in-memory only (no persist), cleared on reload.
                      if (ctx.domain && ctx.user && ctx.pass) {
                        setCachedCreds({
                          domain: ctx.domain,
                          user: ctx.user,
                          pass: ctx.pass,
                          dns: ctx.dns,
                        });
                      }
                      // Clear the modal form state immediately (leave nothing in component state).
                      setShowContextModal(false);
                      resetContextForm();
                      setCredsEditMode(false);
                      // Edit mode only updates the cache; does not start a retest.
                      if (editing) return;
                      if (!finding) return;
                      await startRunWithCreds(
                        finding,
                        ctx,
                        pendingRuntimeVars,
                      );
                    }}
                    disabled={
                      !(
                        ctxDomain.trim() &&
                        ctxUser.trim() &&
                        ctxPass.trim() &&
                        ctxDns.trim()
                      )
                    }
                    className="rounded-lg bg-accent px-6 py-2 text-sm font-bold text-white hover:bg-accent-hover transition-colors disabled:cursor-not-allowed disabled:opacity-50"
                  >
                    {credsEditMode ? "Save" : "Start Retest"}
                  </button>
                </div>
              </div>
            </div>
          )}

          {showTenantModal && (
            <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
              <div className="w-full max-w-md rounded-xl border border-border bg-bg-secondary p-6 shadow-2xl">
                <div className="mb-4 space-y-1">
                  <h3 className="mb-4 text-lg font-bold text-text-primary">
                    Select Tenant
                  </h3>
                  <p className="text-[11px] text-text-muted leading-relaxed">
                    Multiple collected Entra datasets exist.
                    <br />
                    Select the tenant to reference for this retest.
                  </p>
                </div>

                <select
                  value={selectedTenant}
                  onChange={(e) => setSelectedTenant(e.target.value)}
                  className="w-full bg-bg-primary border border-border rounded p-2 text-sm text-text-primary outline-none focus:border-accent"
                >
                  {entraTenantOptions.map((t) => (
                    <option key={t} value={t}>
                      {t}
                    </option>
                  ))}
                </select>

                <div className="mt-6 flex justify-end gap-3">
                  <button
                    type="button"
                    onClick={() => setShowTenantModal(false)}
                    className="px-4 py-2 text-sm font-medium text-text-muted hover:text-text-primary"
                  >
                    Cancel
                  </button>
                  <button
                    type="button"
                    onClick={async () => {
                      const finding = pendingFinding;
                      const tenant = selectedTenant;
                      setShowTenantModal(false);
                      if (!finding) return;
                      await startRunWithEntra(
                        finding,
                        tenant,
                        pendingRuntimeVars,
                      );
                    }}
                    className="rounded-lg bg-accent px-6 py-2 text-sm font-bold text-white hover:bg-accent-hover transition-colors"
                  >
                    Start Retest
                  </button>
                </div>
              </div>
            </div>
          )}

          {showInputsModal && (
            <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
              <div className="w-full max-w-md rounded-xl border border-border bg-bg-secondary p-6 shadow-2xl">
                <div className="mb-4 space-y-1">
                  <h3 className="mb-4 text-lg font-bold text-text-primary">
                    Enter Target
                  </h3>
                  <p className="text-[11px] text-text-muted leading-relaxed">
                    Enter the values to use for this retest.
                    <br />
                    The entered values are used only for this retest.
                  </p>
                  {pendingFinding?.required_privilege && (
                    <div className="mt-2 flex items-start gap-2 rounded border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-[11px] leading-relaxed text-amber-300">
                      <span aria-hidden="true">⚠</span>
                      <span>
                        This retest requires an account with the{" "}
                        <span className="font-bold">
                          {pendingFinding.required_privilege}
                        </span>{" "}
                        privilege.
                      </span>
                    </div>
                  )}
                </div>


                <div className="space-y-4">
                  {_visibleInputs.map((spec) => {
                    const rows = inputsValues[spec.key] ?? [""];
                    const setRows = (next: string[]) =>
                      setInputsValues((prev) => ({
                        ...prev,
                        [spec.key]: next,
                      }));
                    return (
                      <div key={spec.key}>
                        <label className="block text-xs font-medium text-text-muted mb-1">
                          {spec.label}
                          {spec.required === false ? " (optional)" : ""}
                          {spec.multiple ? " (multiple allowed)" : ""}
                        </label>
                        <div className="space-y-2">
                          {rows.map((row, idx) => (
                            <div key={idx} className="flex items-center gap-2">
                              <input
                                type={spec.secret ? "password" : "text"}
                                autoComplete={
                                  spec.secret ? "new-password" : "off"
                                }
                                value={row}
                                placeholder={spec.placeholder ?? ""}
                                onChange={(e) => {
                                  const next = [...rows];
                                  next[idx] = e.target.value;
                                  setRows(next);
                                }}
                                className="w-full bg-bg-primary border border-border rounded p-2 text-sm text-text-primary outline-none focus:border-accent"
                              />
                              {spec.multiple && rows.length > 1 && (
                                <button
                                  type="button"
                                  aria-label="Remove this row"
                                  onClick={() =>
                                    setRows(rows.filter((_, i) => i !== idx))
                                  }
                                  className="shrink-0 rounded border border-border px-2 py-1 text-xs text-text-muted hover:bg-bg-tertiary hover:text-text-primary"
                                >
                                  Remove
                                </button>
                              )}
                            </div>
                          ))}
                        </div>
                        {spec.multiple && (
                          <button
                            type="button"
                            onClick={() => setRows([...rows, ""])}
                            className="mt-2 rounded border border-border px-2 py-1 text-xs text-text-muted hover:bg-bg-tertiary hover:text-text-primary"
                          >
                            + Add row
                          </button>
                        )}
                      </div>
                    );
                  })}
                </div>

                {inputsError && (
                  <p className="mt-3 text-xs text-red-400">{inputsError}</p>
                )}

                <div className="mt-6 flex justify-end gap-3">
                  <button
                    type="button"
                    onClick={() => {
                      setShowInputsModal(false);
                      setInputsError(null);
                    }}
                    className="px-4 py-2 text-sm font-medium text-text-muted hover:text-text-primary"
                  >
                    Cancel
                  </button>
                  <button
                    type="button"
                    onClick={async () => {
                      const finding = pendingFinding;
                      if (!finding) return;
                      // Validate the declared inputs.
                      const vals: Record<string, string> = {};
                      for (const spec of _visibleInputs) {
                        let tokens = (inputsValues[spec.key] ?? [])
                          .map((s) => s.trim())
                          .filter(Boolean);
                        // Fall back to the default when blank; the default also passes the pattern check below.
                        if (tokens.length === 0 && spec.default) {
                          tokens = [spec.default];
                        }
                        if (tokens.length === 0) {
                          if (spec.required !== false) {
                            setInputsError(
                              `Please enter "${spec.label}"`,
                            );
                            return;
                          }
                          continue;
                        }
                        if (spec.pattern) {
                          let re: RegExp | null = null;
                          try {
                            re = new RegExp(spec.pattern);
                          } catch {
                            re = null;
                          }
                          if (re && tokens.some((t) => !re!.test(t))) {
                            setInputsError(
                              `"${spec.label}" contains a value with an invalid format`,
                            );
                            return;
                          }
                        }
                        // Join validated tokens with spaces (same for multiple and single).
                        vals[spec.key] = tokens.join(" ");
                      }
                      setShowInputsModal(false);
                      setInputsError(null);
                      await proceedVerification(finding, vals);
                    }}
                    className="rounded-lg bg-accent px-6 py-2 text-sm font-bold text-white hover:bg-accent-hover transition-colors"
                  >
                    Next
                  </button>
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </PageContainer>
  );
}
