import { useState } from "react";
import type { Finding } from "../../types/finding";
import type { FindingStatusKind } from "../../lib/verdict";
import { FindingRow } from "./FindingRow";

interface FindingTableProps {
  findings: Finding[];
  onViewDetail: (finding: Finding) => void;
  // findingNo -> status from latest retest history; unlisted findings are treated as "not executed".
  statusByFinding?: Record<string, FindingStatusKind>;
}

export function FindingTable({
  findings,
  onViewDetail,
  statusByFinding,
}: FindingTableProps) {
  const [searchQuery, setSearchQuery] = useState("");

  const filtered = findings.filter((f) => {
    if (!searchQuery) return true;

    const q = searchQuery.toLowerCase();
    return (
      f.no.toLowerCase().includes(q) ||
      f.title.toLowerCase().includes(q) ||
      f.summary.toLowerCase().includes(q) ||
      f.description.toLowerCase().includes(q)
    );
  });

  return (
    <div className="space-y-3">
      <div className="flex items-center gap-3">
        <input
          type="text"
          placeholder="Search findings..."
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          className="flex-1 rounded-lg border border-border bg-bg-primary px-3 py-2 text-sm text-text-primary placeholder-text-muted outline-none focus:border-accent"
        />
      </div>

      <div className="overflow-hidden rounded-lg border border-border bg-bg-secondary">
        <table className="w-full">
          <thead>
            <tr className="border-b border-border bg-bg-tertiary/50">
              <th className="px-4 py-2.5 text-center text-xs font-medium tracking-wide text-text-muted">
                No.
              </th>
              <th className="w-32 px-4 py-2.5 text-center text-xs font-medium tracking-wide text-text-muted">
                Risk Level
              </th>
              <th className="px-4 py-2.5 text-left text-xs font-medium tracking-wide text-text-muted">
                Finding
              </th>
              <th className="w-36 px-4 py-2.5 text-center text-xs font-medium tracking-wide text-text-muted">
                Status
              </th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border/50">
            {filtered.map((finding) => (
              <FindingRow
                key={finding.no}
                finding={finding}
                onViewDetail={() => onViewDetail(finding)}
                statusKind={statusByFinding?.[finding.no]}
              />
            ))}
          </tbody>
        </table>

        {filtered.length === 0 && (
          <div className="py-12 text-center text-sm text-text-muted bg-bg-primary/30">
            No matching findings found.
          </div>
        )}
      </div>

      <div className="text-xs text-text-muted text-right pr-2">
        Total: {filtered.length}
      </div>
    </div>
  );
}
