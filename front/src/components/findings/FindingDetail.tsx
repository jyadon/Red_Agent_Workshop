import { useCallback, useEffect, useRef, useState } from "react";
import type { Finding } from "../../types/finding";
import type { ActiveRun } from "../../hooks/useRetest";
import type { ResumeRequest } from "../../types/retest";
import type { VerificationHistoryItem } from "../../lib/verification-history-store";
import { useVerificationHistoryStore } from "../../lib/verification-history-store";
import { useRetestSettingsStore } from "../../lib/retest-settings-store";
import { useCredentialsStore } from "../../lib/credentials-store";
import { features } from "../../lib/features";
import { useAuth } from "../../contexts/AuthContext";
import { buildApiUrl, withAuthHeaders } from "../../lib/api";
import { LoadingSpinner } from "../common/LoadingSpinner";
import { HITLReviewDialog } from "../retest/HITLReviewDialog";
import { FinalOutputView } from "../retest/FinalOutputView";
import { RtoExportPanel } from "../retest/RtoExportPanel";
import { EntraCollectionNotice } from "../entra/EntraCollectionNotice";
import { extractFinalOutputText } from "../../lib/final-output";
import {
  extractVerdictFromText,
  toVerdictCode,
  getVerdictBadge,
  type VerdictCode,
} from "../../lib/verdict";

interface DCEntry {
  hostname: string;
  ip: string | null;
  discovered_at: number | null;
  discovered_at_iso: string | null;
}

interface FindingDetailProps {
  finding: Finding;
  onClose: () => void;
  onStartVerification?: (finding: Finding) => Promise<void>;
  run?: ActiveRun;
  verificationLoading?: boolean;
  onResume?: (payload: ResumeRequest) => Promise<void>;
  socksActive: boolean;
  historyRecords?: VerificationHistoryItem[];
}

export function FindingDetail({
  finding,
  onClose,
  onStartVerification,
  run,
  verificationLoading = false,
  onResume,
  socksActive,
  historyRecords = [],
}: FindingDetailProps) {
  const removeRecord = useVerificationHistoryStore((s) => s.removeRecord);
  const clearFindingHistory = useVerificationHistoryStore(
    (s) => s.clearFindingHistory,
  );
  const [selectedHistory, setSelectedHistory] = useState<Set<string>>(
    new Set(),
  );
  const requireApproval = useRetestSettingsStore((s) => s.requireApproval);
  const setRequireApproval = useRetestSettingsStore(
    (s) => s.setRequireApproval,
  );
  // Runtime server gate (ENABLE_COMMAND_APPROVAL). Authoritative for showing the review toggle,
  // so a stale build-time VITE flag can never hide the off-switch while the server forces review.
  const { commandApprovalEnabled } = useAuth();
  const cachedCreds = useCredentialsStore((s) => s.credentials);

  const dcCacheDomain = cachedCreds?.domain ?? null;
  const [dcCacheEntries, setDcCacheEntries] = useState<DCEntry[]>([]);
  const [dcCacheLoading, setDcCacheLoading] = useState(false);
  const [dcCacheError, setDcCacheError] = useState<string | null>(null);

  const fetchDcCache = useCallback(async () => {
    if (!dcCacheDomain) {
      setDcCacheEntries([]);
      return;
    }
    setDcCacheLoading(true);
    setDcCacheError(null);
    try {
      const url = buildApiUrl(
        `/api/v1/dc-cache?domain=${encodeURIComponent(dcCacheDomain)}`,
      );
      const res = await fetch(url, {
        credentials: 'include',
        headers: withAuthHeaders(undefined, false),
      });
      if (!res.ok) {
        throw new Error(`HTTP ${res.status}`);
      }
      const data = await res.json();
      const entries: DCEntry[] = Array.isArray(data?.entries)
        ? data.entries
        : [];
      setDcCacheEntries(entries);
    } catch (e) {
      const msg = e instanceof Error ? e.message : "failed to fetch DC cache";
      setDcCacheError(msg);
      setDcCacheEntries([]);
    } finally {
      setDcCacheLoading(false);
    }
  }, [dcCacheDomain]);

  useEffect(() => {
    void fetchDcCache();
  }, [fetchDcCache]);

  // The dc_discovery_completed event can be buried in the LLM output stream, so
  // scan all chunks rather than only the last. The Ref ensures we fire at most
  // once per thread_id.
  const dcRefreshedForThreadRef = useRef<Set<string>>(new Set());
  useEffect(() => {
    const tid = run?.thread_id;
    if (!tid || !run?.chunks?.length) return;
    if (dcRefreshedForThreadRef.current.has(tid)) return;
    const hasDcCompleted = run.chunks.some((c) => {
      if (typeof c !== "object" || !c || !("phase" in c)) return false;
      return (c as { phase?: string }).phase === "dc_discovery_completed";
    });
    if (hasDcCompleted) {
      dcRefreshedForThreadRef.current.add(tid);
      void fetchDcCache();
    }
  }, [run?.thread_id, run?.chunks, fetchDcCache]);

  // Safety net: always refresh once when the run reaches a terminal state, to
  // cover a missed dc_discovery_completed event or DCs absorbed from commands
  // like `nxc smb` that the LLM ran during the retest.
  useEffect(() => {
    if (run?.status === "completed" || run?.status === "failed") {
      void fetchDcCache();
    }
  }, [run?.status, fetchDcCache]);

  // run is owned by RetestPage and persists across findings, so we must confirm
  // it belongs to the currently displayed finding before showing live results;
  // otherwise finding A's result would leak into finding B.
  const isRunForThisFinding = run?.finding_no === finding.no;

  const isCurrentFindingRun =
    isRunForThisFinding &&
    run?.thread_id != null &&
    (run?.status === "running" ||
      run?.status === "waiting_human" ||
      run?.status === "completed" ||
      run?.status === "failed");

  const isSocksCheckEnabled = features.socksCheck;

  // Findings whose platform includes "retest_not_supported" are excluded from
  // automated retest. platform is array-normalized by the backend but may be a
  // single string in hand-edited JSON, so handle both.
  const platforms = Array.isArray(finding.platform)
    ? finding.platform
    : finding.platform
      ? [finding.platform]
      : [];
  const retestNotSupported = platforms.includes("retest_not_supported");

  const handleVerificationClick = () => {
    if (retestNotSupported) return;
    if (isSocksCheckEnabled && !socksActive) {
      alert("Cannot run until the connection is established.");
      return;
    }
    if (verificationLoading) return;
    onStartVerification?.(finding);
  };

  const handleDeleteHistory = (recordId: string) => {
    const ok = window.confirm("Delete this verification history entry?");
    if (!ok) return;
    removeRecord(finding.no, recordId);
  };

  const toggleHistory = (id: string) => {
    setSelectedHistory((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };
  const allHistorySelected =
    historyRecords.length > 0 &&
    historyRecords.every((r) => selectedHistory.has(r.id));
  const toggleAllHistory = () => {
    setSelectedHistory(
      allHistorySelected
        ? new Set()
        : new Set(historyRecords.map((r) => r.id)),
    );
  };
  const handleDeleteSelectedHistory = async () => {
    if (selectedHistory.size === 0) return;
    if (
      !window.confirm(
        `Delete the ${selectedHistory.size} selected verification history entries?`,
      )
    )
      return;
    for (const id of [...selectedHistory]) {
      await removeRecord(finding.no, id);
    }
    setSelectedHistory(new Set());
  };
  const handleClearAllHistory = async () => {
    if (
      !window.confirm(
        `Delete all verification history for this finding? (${historyRecords.length} entries)`,
      )
    )
      return;
    await clearFindingHistory(finding.no);
    setSelectedHistory(new Set());
  };

  const showLiveResult = isRunForThisFinding && run?.final_output != null;
  // Live results carry no separate verdict code, so extract the verdict from the body Markdown.
  const liveVerdict = showLiveResult
    ? extractVerdictFromText(extractFinalOutputText(run?.final_output))
    : null;
  const showHistory = !showLiveResult && historyRecords.length > 0;

  return (
    <>
      <div className="space-y-6">
        <div className="flex items-start justify-between">
          <div className="space-y-2">
            <div className="text-xs text-text-muted">{finding.no}</div>
            <h3 className="text-lg font-semibold text-text-primary">
              {finding.title}
            </h3>
            <div className="text-sm text-text-secondary">
              Risk Level: {finding.risk_level}
            </div>
          </div>
          <button
            onClick={onClose}
            className="rounded-lg p-1 text-text-muted hover:bg-bg-tertiary hover:text-text-primary"
          >
            <svg
              className="h-5 w-5"
              fill="none"
              viewBox="0 0 24 24"
              stroke="currentColor"
              strokeWidth={2}
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                d="M6 18 18 6M6 6l12 12"
              />
            </svg>
          </button>
        </div>

        {/* Skip the summary section entirely when summary is empty so no orphaned heading remains. */}
        {finding.summary?.trim() && (
          <Section title="Summary">
            <p className="whitespace-pre-wrap text-sm leading-relaxed text-text-secondary">
              {finding.summary}
            </p>
          </Section>
        )}

        <Section title="Details">
          <p className="whitespace-pre-wrap text-sm leading-relaxed text-text-secondary">
            {finding.description}
          </p>
        </Section>

        <Section title="Recommended Remediation">
          <p className="whitespace-pre-wrap text-sm leading-relaxed text-text-secondary">
            {finding.recommendation}
          </p>
        </Section>

        <Section title="References">
          <div className="space-y-2">
            {finding.references.length === 0 ? (
              <p className="text-sm text-text-muted">None</p>
            ) : (
              finding.references.map((ref) => (
                <div key={`${ref.name}-${ref.url}`}>
                  <a
                    href={ref.url}
                    target="_blank"
                    rel="noreferrer"
                    className="text-sm text-accent underline"
                  >
                    {ref.name}
                  </a>
                </div>
              ))
            )}
          </div>
        </Section>

        {onStartVerification && <EntraCollectionNotice finding={finding} />}

        {onStartVerification && (
          <div className="mt-6 flex flex-col items-center gap-3 border-t border-border/50 pt-5">
            <button
              onClick={handleVerificationClick}
              disabled={verificationLoading || retestNotSupported}
              title={
                retestNotSupported
                  ? "This finding does not support retesting"
                  : undefined
              }
              className={`inline-flex items-center justify-center gap-2 rounded-md px-6 py-2 text-[13px] font-bold transition-all ${
                retestNotSupported
                  ? "cursor-not-allowed border border-border/50 bg-bg-tertiary text-text-muted opacity-50"
                  : verificationLoading
                    ? "cursor-wait bg-bg-tertiary text-text-muted opacity-50"
                    : !isSocksCheckEnabled || socksActive
                      ? "bg-accent text-white hover:bg-accent-hover shadow-sm shadow-accent/10"
                      : "border border-border/50 bg-bg-tertiary text-text-muted hover:bg-bg-tertiary/80"
              }`}
            >
              {verificationLoading ? (
                <span className="flex items-center gap-2">
                  <span className="h-3.5 w-3.5 animate-spin rounded-full border-2 border-white/30 border-t-white" />
                  Verifying...
                </span>
              ) : (
                "Run Retest"
              )}
            </button>
            {retestNotSupported ? (
              <p className="text-xs text-text-muted">
                This finding does not support retesting.
              </p>
            ) : commandApprovalEnabled ? (
              // Shown whenever the server has command approval enabled (runtime flag), so the
              // off-switch is always available. When checked, the retest pauses once to review the
              // full batch of planned commands before running them.
              <label
                className="flex items-center gap-2 select-none cursor-pointer text-xs text-text-muted hover:text-text-primary"
                title="When checked, the whole set of generated commands is shown for review (approve / edit / reject, or run all) before anything runs"
              >
                <input
                  type="checkbox"
                  checked={requireApproval}
                  onChange={(e) => setRequireApproval(e.target.checked)}
                  disabled={verificationLoading}
                  className="h-4 w-4 rounded border-border accent-accent"
                />
                <span>Review generated commands before execution</span>
              </label>
            ) : null}
          </div>
        )}

        {verificationLoading && (
          <div className="rounded-lg border border-border bg-bg-primary p-4">
            <div className="flex items-center gap-3">
              <LoadingSpinner size="sm" />
              <span className="text-sm text-text-secondary">
                Red Agent is preparing the retest...
              </span>
            </div>
          </div>
        )}

        {isCurrentFindingRun &&
          run?.status === "running" &&
          !run?.interrupt && (
            <div className="rounded-lg border border-border bg-bg-primary p-4">
              <div className="flex items-center gap-3">
                <LoadingSpinner size="sm" />
                <span className="text-sm text-text-secondary">
                  Red Agent is running the retest...
                </span>
              </div>
            </div>
          )}

        {dcCacheDomain && (
          <Section
            title={`Collected domain controller information (domain: ${dcCacheDomain})`}
          >
            <div className="rounded-lg border border-border bg-bg-primary p-4">
              <div className="mb-3 flex items-center justify-between gap-3">
                <div className="text-xs text-text-muted">
                  {dcCacheLoading
                    ? "Loading..."
                    : `${dcCacheEntries.length} cached`}
                  {dcCacheError && (
                    <span className="ml-2 text-red-400">
                      Error: {dcCacheError}
                    </span>
                  )}
                </div>
                <button
                  type="button"
                  onClick={() => void fetchDcCache()}
                  disabled={dcCacheLoading}
                  className="rounded border border-border px-2 py-1 text-xs text-text-muted hover:bg-bg-tertiary hover:text-text-primary disabled:opacity-50"
                >
                  Refresh
                </button>
              </div>

              {dcCacheEntries.length === 0 &&
                !dcCacheLoading &&
                !dcCacheError && (
                  <div className="text-xs text-text-muted">
                    The cache is empty.
                  </div>
                )}

              {dcCacheEntries.length > 0 && (
                <div className="overflow-x-auto">
                  <table className="w-full text-xs">
                    <thead>
                      <tr className="border-b border-border text-text-muted">
                        <th className="py-1 pr-3 text-left font-normal">
                          Hostname
                        </th>
                        <th className="py-1 pr-3 text-left font-normal">
                          IP Address
                        </th>
                        <th className="py-1 text-left font-normal">Discovered At</th>
                      </tr>
                    </thead>
                    <tbody>
                      {dcCacheEntries.map((entry) => (
                        <tr
                          key={entry.hostname}
                          className="border-b border-border/40 last:border-0"
                        >
                          <td className="py-1 pr-3 font-mono text-text-primary">
                            {entry.hostname}
                          </td>
                          <td className="py-1 pr-3 font-mono text-text-secondary">
                            {entry.ip ?? (
                              <span className="text-text-muted">Not retrieved</span>
                            )}
                          </td>
                          <td className="py-1 text-text-muted">
                            {entry.discovered_at_iso
                              ? new Date(
                                  entry.discovered_at_iso,
                                ).toLocaleString()
                              : "-"}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </Section>
        )}

        {showLiveResult && (
          <Section title="Verification Result">
            {liveVerdict && <VerdictBanner kind={liveVerdict} />}
            <FinalOutputView data={run?.final_output} />
          </Section>
        )}

        {showHistory && (
          <Section title="Past Verification History">
            <div className="mb-3 flex flex-wrap items-center gap-3 text-sm">
              <label className="flex items-center gap-2 text-text-muted">
                <input
                  type="checkbox"
                  checked={allHistorySelected}
                  onChange={toggleAllHistory}
                />
                Select All
              </label>
              <button
                type="button"
                onClick={handleDeleteSelectedHistory}
                disabled={selectedHistory.size === 0}
                className="rounded border border-border px-3 py-1.5 text-text-primary transition-colors hover:border-border-hover disabled:cursor-not-allowed disabled:opacity-40"
              >
                Delete Selected{selectedHistory.size > 0 ? ` (${selectedHistory.size})` : ""}
              </button>
              <button
                type="button"
                onClick={handleClearAllHistory}
                className="rounded border border-red-500/40 px-3 py-1.5 text-red-400 transition-colors hover:bg-red-500/10"
              >
                Delete All
              </button>
            </div>
            <div className="space-y-4">
              {historyRecords.map((record, idx) => {
                // Prefer the backend verdict; fall back to extracting it from markdown.
                const recordVerdict =
                  toVerdictCode(record.verdict) ??
                  extractVerdictFromText(record.markdown);
                return (
                <div
                  key={record.id}
                  className="rounded-lg border border-border bg-bg-primary p-4"
                >
                  <div className="mb-3 flex items-start justify-between gap-4">
                    <div className="flex items-start gap-2">
                      <input
                        type="checkbox"
                        checked={selectedHistory.has(record.id)}
                        onChange={() => toggleHistory(record.id)}
                        aria-label="select history record"
                        className="mt-1 shrink-0"
                      />
                      <div>
                        <div className="text-sm font-medium text-text-primary">
                          History {historyRecords.length - idx}
                        </div>
                        <div className="mt-1 text-xs text-text-muted">
                          {new Date(record.createdAt).toLocaleString()}
                        </div>
                      </div>
                    </div>

                    <div className="flex items-start gap-3">
                      <div className="text-right text-xs text-text-muted">
                        <div>thread</div>
                        <div className="font-mono">{record.threadId}</div>
                      </div>

                      <button
                        type="button"
                        onClick={() => handleDeleteHistory(record.id)}
                        className="rounded p-1 text-text-muted transition-colors hover:bg-bg-tertiary hover:text-accent"
                        aria-label="delete history record"
                        title="Delete history"
                      >
                        <svg
                          className="h-4 w-4"
                          fill="none"
                          viewBox="0 0 24 24"
                          stroke="currentColor"
                          strokeWidth={2}
                        >
                          <path
                            strokeLinecap="round"
                            strokeLinejoin="round"
                            d="m14.74 9-.346 9m-4.788 0L9.26 9m9.968-3.21c.342.052.682.107 1.022.166m-1.022-.165L18.16 19.673a2.25 2.25 0 0 1-2.244 2.077H8.084a2.25 2.25 0 0 1-2.244-2.077L4.772 5.79m14.456 0a48.108 48.108 0 0 0-3.478-.397m-12 .562c.34-.059.68-.114 1.022-.165m0 0a48.11 48.11 0 0 1 3.478-.397m7.5 0v-.916c0-1.18-.91-2.164-2.09-2.201a51.964 51.964 0 0 0-3.32 0c-1.18.037-2.09 1.022-2.09 2.201v.916m7.5 0a48.667 48.667 0 0 0-7.5 0"
                          />
                        </svg>
                      </button>
                    </div>
                  </div>

                  {recordVerdict && <VerdictBanner kind={recordVerdict} />}
                  <FinalOutputView data={{ content: record.markdown }} />
                  <RtoExportPanel
                    findingNo={record.findingNo}
                    commands={record.commands}
                  />
                </div>
                );
              })}
            </div>
          </Section>
        )}

        {isRunForThisFinding && run?.error && (
          <Section title="Error">
            <div className="rounded-lg border border-red-900/50 bg-red-950/20 p-4 text-sm text-red-400">
              {run.error}
            </div>
          </Section>
        )}
      </div>

      <HITLReviewDialog
        open={isRunForThisFinding && !!run?.interrupt}
        interrupt={isRunForThisFinding ? run?.interrupt ?? null : null}
        loading={verificationLoading}
        onSubmit={async (payload) => {
          if (!onResume) return;
          await onResume(payload);
        }}
        onClose={async () => {
          // On cancel, reject every action server-side so the thread is definitively
          // ended, leaving no orphaned _THREAD_SECRETS / SOCKS resources / waiting_human threads.
          if (!onResume || !run?.interrupt) return;
          await onResume({
            interrupt_id: run.interrupt.id,
            decisions: run.interrupt.actions.map(() => ({
              type: "reject",
              comment: "User cancelled approval dialog",
            })),
          });
        }}
      />
    </>
  );
}

// Banner shown at the top of retest results highlighting the verdict (resolution status).
function VerdictBanner({ kind }: { kind: VerdictCode }) {
  const badge = getVerdictBadge(kind);
  return (
    <div
      className={`mb-3 inline-flex items-center gap-2 rounded-lg border px-3 py-1.5 text-sm font-bold ${badge.className}`}
    >
      <span className="text-xs font-medium opacity-80">Verdict</span>
      <span>{badge.label}</span>
    </div>
  );
}

function Section({
  title,
  children,
}: {
  title: string;
  children: React.ReactNode;
}) {
  return (
    <div>
      <h4 className="mb-2 text-sm font-medium text-text-muted">{title}</h4>
      {children}
    </div>
  );
}
