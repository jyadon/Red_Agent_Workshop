import { useEffect, useState } from "react";
import { PageContainer } from "../components/layout/PageContainer";
import { LoadingSpinner } from "../components/common/LoadingSpinner";
import { RtoFinalOutputView } from "../components/rto/RtoFinalOutputView";
import { useRTO } from "../hooks/useRTO";
import { useSocks } from "../contexts/SocksContext";
import { features } from "../lib/features";
import {
  extractMarkdownReport,
  downloadMarkdown,
} from "../lib/markdown-export";
import { downloadPdf } from "../lib/pdf-export";
import {
  useRtoHistoryStore,
  type RtoHistoryItem,
} from "../lib/rto-history-store";

export function RTOPage() {
  const { active: socksActive } = useSocks();
  const { run, loading, startRun, reset } = useRTO();

  // RTO requires credentials: domain, username, password, and DNS are all mandatory inputs.
  const [domain, setDomain] = useState("");
  const [user, setUser] = useState("");
  const [pass, setPass] = useState("");
  const [dns, setDns] = useState("");
  const [format, setFormat] = useState<"md" | "pdf">("md");

  const {
    items: history,
    fetchHistory,
    removeRecord,
    clearAll,
  } = useRtoHistoryStore();
  const [selected, setSelected] = useState<RtoHistoryItem | null>(null);

  // Refetch on completion so the history reflects the latest run.
  useEffect(() => {
    fetchHistory();
  }, [fetchHistory]);
  useEffect(() => {
    if (run.status === "completed") fetchHistory();
  }, [run.status, fetchHistory]);

  const running = loading || run.status === "running";
  const hasResult = run.status === "completed" && run.final_output != null;
  // Same gate as retest: without the proxy, commands cannot reach the target range.
  const socksBlocked = features.socksCheck && !socksActive;
  const canExecute =
    domain.trim() !== "" &&
    user.trim() !== "" &&
    pass !== "" &&
    dns.trim() !== "" &&
    !socksBlocked &&
    !running;

  const handleExecute = async () => {
    if (socksBlocked) {
      window.alert("Cannot run until the connection is established.");
      return;
    }
    try {
      await startRun({
        domain: domain.trim(),
        user: user.trim(),
        pass,
        dns: dns.trim(),
      });
    } catch (e) {
      const msg = e instanceof Error ? e.message : "Failed to start RTO";
      window.alert(`Failed to start RTO: ${msg}`);
    }
  };

  const downloadReport = (rawMd: string, domainForName: string) => {
    // Strip display-only highlight markers (whole-line ==...==) on download;
    // inline == (e.g. user==password in observation text) is preserved.
    const md = rawMd.replace(/^==(.+)==$/gm, "$1");
    const stamp = new Date().toISOString().slice(0, 19).replace(/[:T]/g, "-");
    const slug = domainForName.trim().replace(/[^\w.-]+/g, "_") || "domain";
    const base = `rto-report_${slug}_${stamp}`;
    if (format === "pdf") {
      // PDF opens the print dialog (Save as PDF); base becomes the default filename.
      downloadPdf(base, md);
    } else {
      downloadMarkdown(`${base}.md`, md);
    }
  };

  const handleDownload = () =>
    downloadReport(extractMarkdownReport(run.final_output), domain);

  const handleDeleteRecord = async (id: string) => {
    if (!window.confirm("Delete this run history entry?")) return;
    try {
      await removeRecord(id);
      if (selected?.id === id) setSelected(null);
    } catch {
      window.alert("Failed to delete history entry");
    }
  };

  const handleClearAll = async () => {
    if (
      !window.confirm(
        "Delete all run history? This action cannot be undone.",
      )
    )
      return;
    try {
      await clearAll();
      setSelected(null);
    } catch {
      window.alert("Failed to delete history");
    }
  };

  const fmtDate = (iso: string) => {
    const d = new Date(iso);
    return Number.isNaN(d.getTime()) ? iso : d.toLocaleString();
  };

  return (
    <PageContainer className="mx-auto max-w-4xl space-y-8">
      <div>
        <h2 className="text-2xl font-bold text-text-primary">
          Red Team Test
        </h2>
        <p className="mt-2 leading-relaxed text-text-secondary">
          An AI agent automatically runs a Red Team test against the specified Active Directory domain environment.
          <br />
          It executes multiple attacks and maps out the paths that lead to obtaining administrator privileges.
          <br />
          After the attacks run, a report summarizing the results is generated and can be downloaded.
        </p>
      </div>

      {/* Input form */}
      <div className="space-y-4 rounded-xl border border-border bg-bg-secondary p-6">
        <p className="text-xs leading-relaxed text-text-muted">
          Enter the target domain, the credentials used for the test, and the DNS server IP address.
        </p>

        <div>
          <label
            htmlFor="rto-domain"
            className="mb-1 block text-sm font-medium text-text-muted"
          >
            Target Domain          </label>
          <input
            id="rto-domain"
            type="text"
            autoComplete="off"
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
            placeholder="e.g. corp.local"
            disabled={running}
            className="w-full rounded-lg border border-border bg-bg-primary px-3 py-2 text-sm text-text-primary outline-none focus:border-accent disabled:opacity-60"
          />
        </div>

        <div className="grid grid-cols-2 gap-4">
          <div>
            <label
              htmlFor="rto-user"
              className="mb-1 block text-sm font-medium text-text-muted"
            >
              Username            </label>
            <input
              id="rto-user"
              type="text"
              autoComplete="off"
              value={user}
              onChange={(e) => setUser(e.target.value)}
              placeholder="e.g. administrator"
              disabled={running}
              className="w-full rounded-lg border border-border bg-bg-primary px-3 py-2 text-sm text-text-primary outline-none focus:border-accent disabled:opacity-60"
            />
          </div>
          <div>
            <label
              htmlFor="rto-pass"
              className="mb-1 block text-sm font-medium text-text-muted"
            >
              Password            </label>
            <input
              id="rto-pass"
              type="password"
              autoComplete="new-password"
              value={pass}
              onChange={(e) => setPass(e.target.value)}
              disabled={running}
              className="w-full rounded-lg border border-border bg-bg-primary px-3 py-2 text-sm text-text-primary outline-none focus:border-accent disabled:opacity-60"
            />
          </div>
        </div>

        <div>
          <label
            htmlFor="rto-dns"
            className="mb-1 block text-sm font-medium text-text-muted"
          >
            DNS Server IP Address          </label>
          <input
            id="rto-dns"
            type="text"
            autoComplete="off"
            value={dns}
            onChange={(e) => setDns(e.target.value)}
            placeholder="e.g. 10.0.1.10"
            disabled={running}
            className="w-full rounded-lg border border-border bg-bg-primary px-3 py-2 text-sm text-text-primary outline-none focus:border-accent disabled:opacity-60"
          />
        </div>

        {socksBlocked && (
          <div className="rounded-lg border border-warning/40 bg-warning/5 p-3 text-xs text-text-secondary">
            <span className="font-medium text-warning">Cannot run:</span> the SOCKS
            proxy is not connected, so commands cannot reach the target network.
          </div>
        )}

        <div className="flex items-center gap-3">
          <button
            type="button"
            onClick={handleExecute}
            disabled={!canExecute}
            className="rounded-lg bg-accent px-6 py-2 text-sm font-bold text-white transition-colors hover:bg-accent-hover disabled:cursor-not-allowed disabled:opacity-50"
          >
            {running ? "Running..." : "Run"}
          </button>
          {(hasResult || run.status === "failed") && !running && (
            <button
              type="button"
              onClick={reset}
              className="rounded-lg border border-border px-4 py-2 text-sm text-text-secondary hover:bg-bg-tertiary hover:text-text-primary"
            >
              Reset
            </button>
          )}
        </div>
      </div>

      {/* Running */}
      {running && (
        <div className="flex items-center justify-center gap-3 rounded-xl border border-border bg-bg-secondary py-12">
          <LoadingSpinner />
          <span className="text-sm text-text-secondary">
            Running... the agent is investigating the target environment.
          </span>
        </div>
      )}

      {/* Error */}
      {run.status === "failed" && run.error && (
        <div className="rounded-xl border border-red-900/50 bg-red-950/20 p-4 text-sm text-red-400">
          {run.error}
        </div>
      )}

      {/* Final result */}
      {hasResult && (
        <div className="rounded-xl border border-border bg-bg-secondary p-6">
          <div className="mb-4 flex items-center justify-between gap-3">
            <h3 className="text-lg font-semibold text-text-primary">
              Final Result
            </h3>
            <div className="flex items-center gap-2">
              <label htmlFor="rto-dl-format" className="sr-only">
                Download format
              </label>
              <select
                id="rto-dl-format"
                value={format}
                onChange={(e) => setFormat(e.target.value as "md" | "pdf")}
                className="rounded-lg border border-border bg-bg-primary px-2 py-2 text-sm text-text-primary outline-none focus:border-accent"
              >
                <option value="md">Markdown</option>
                <option value="pdf">PDF</option>
              </select>
              <button
                type="button"
                onClick={handleDownload}
                className="flex items-center gap-2 rounded-lg border border-border px-4 py-2 text-sm text-text-secondary transition-colors hover:bg-bg-tertiary hover:text-text-primary"
              >
                <svg
                  className="h-4 w-4"
                  fill="none"
                  viewBox="0 0 24 24"
                  stroke="currentColor"
                  strokeWidth={1.5}
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    d="M3 16.5v2.25A2.25 2.25 0 0 0 5.25 21h13.5A2.25 2.25 0 0 0 21 18.75V16.5M16.5 12 12 16.5m0 0L7.5 12m4.5 4.5V3"
                  />
                </svg>
                {format === "pdf" ? "Download as PDF" : "Download as Markdown"}
              </button>
            </div>
          </div>
          <RtoFinalOutputView data={run.final_output} />
        </div>
      )}

      {/* Run history (DB-persisted, shared) */}
      <div className="rounded-xl border border-border bg-bg-secondary p-6">
        <div className="mb-4 flex items-center justify-between gap-3">
          <h3 className="text-lg font-semibold text-text-primary">Run History</h3>
          {history.length > 0 && (
            <button
              type="button"
              onClick={handleClearAll}
              className="rounded-lg border border-red-900/50 px-3 py-1.5 text-xs text-red-400 transition-colors hover:bg-red-950/20"
            >
              Delete All
            </button>
          )}
        </div>

        {history.length === 0 ? (
          <p className="text-sm text-text-muted">No run history yet.</p>
        ) : (
          <ul className="divide-y divide-border">
            {history.map((item) => (
              <li
                key={item.id}
                className={`flex items-center justify-between gap-3 py-3 ${
                  selected?.id === item.id ? "bg-bg-tertiary/40" : ""
                }`}
              >
                <button
                  type="button"
                  onClick={() => setSelected(item)}
                  className="min-w-0 flex-1 text-left"
                >
                  <div className="truncate text-sm font-medium text-text-primary">
                    {item.domain || "(unknown domain)"}
                  </div>
                  <div className="text-xs text-text-muted">
                    {fmtDate(item.createdAt)}
                  </div>
                </button>
                <div className="flex shrink-0 items-center gap-2">
                  <button
                    type="button"
                    onClick={() => setSelected(item)}
                    className="rounded-lg border border-border px-3 py-1.5 text-xs text-text-secondary transition-colors hover:bg-bg-tertiary hover:text-text-primary"
                  >
                    View
                  </button>
                  <button
                    type="button"
                    onClick={() => handleDeleteRecord(item.id)}
                    className="rounded-lg border border-red-900/50 px-3 py-1.5 text-xs text-red-400 transition-colors hover:bg-red-950/20"
                  >
                    Delete
                  </button>
                </div>
              </li>
            ))}
          </ul>
        )}
      </div>

      {/* Detailed report for the selected history entry */}
      {selected && (
        <div className="rounded-xl border border-border bg-bg-secondary p-6">
          <div className="mb-4 flex items-center justify-between gap-3">
            <div className="min-w-0">
              <h3 className="text-lg font-semibold text-text-primary">
                History
              </h3>
              <p className="truncate text-xs text-text-muted">
                {selected.domain || "(unknown domain)"} — {fmtDate(selected.createdAt)}
              </p>
            </div>
            <div className="flex shrink-0 items-center gap-2">
              <select
                value={format}
                onChange={(e) => setFormat(e.target.value as "md" | "pdf")}
                className="rounded-lg border border-border bg-bg-primary px-2 py-2 text-sm text-text-primary outline-none focus:border-accent"
              >
                <option value="md">Markdown</option>
                <option value="pdf">PDF</option>
              </select>
              <button
                type="button"
                onClick={() => downloadReport(selected.markdown, selected.domain)}
                className="rounded-lg border border-border px-4 py-2 text-sm text-text-secondary transition-colors hover:bg-bg-tertiary hover:text-text-primary"
              >
                {format === "pdf" ? "Download as PDF" : "Download as Markdown"}
              </button>
              <button
                type="button"
                onClick={() => setSelected(null)}
                className="rounded-lg border border-border px-4 py-2 text-sm text-text-secondary transition-colors hover:bg-bg-tertiary hover:text-text-primary"
              >
                Close
              </button>
            </div>
          </div>
          <RtoFinalOutputView
            data={selected.finalOutput ?? { content: selected.markdown }}
          />
        </div>
      )}
    </PageContainer>
  );
}
