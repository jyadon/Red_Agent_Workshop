import { useEffect, useState } from "react";
import { Link } from "react-router";
import type { Finding } from "../../types/finding";
import { api } from "../../lib/api";

/**
 * Notice shown for findings that include Entra ID as a target when no prior
 * roadrecon collection exists, prompting the user toward the Config screen.
 * Never blocks: for combined AD+Entra findings the AD side can still run.
 */
export function EntraCollectionNotice({ finding }: { finding: Finding }) {
  const platforms = Array.isArray(finding.platform)
    ? finding.platform
    : finding.platform
      ? [finding.platform]
      : [];
  const isEntra = platforms.includes("entra");

  // null = loading; number = count of already-collected records
  const [collectedCount, setCollectedCount] = useState<number | null>(null);

  useEffect(() => {
    if (!isEntra) return;
    let cancelled = false;
    api
      .get<{ count: number }>("/api/v1/entra/databases")
      .then((d) => {
        if (!cancelled) setCollectedCount(d.count ?? 0);
      })
      .catch(() => {
        if (!cancelled) setCollectedCount(0);
      });
    return () => {
      cancelled = true;
    };
  }, [isEntra]);

  if (!isEntra) return null;
  if (collectedCount === null) return null;
  if (collectedCount > 0) return null;

  return (
    <div className="rounded-lg border border-yellow-500/40 bg-yellow-500/10 p-4">
      <div className="text-sm font-medium text-yellow-300">
        Prior data collection for Entra ID is required
      </div>
      <p className="mt-1 text-xs leading-relaxed text-text-secondary">
        This finding includes Entra ID as a target. Because prior data collection
        has not been performed, running it as-is will yield an "Unverified" result.
        Please perform data collection from the Config screen.
      </p>
      <Link
        to="/config"
        className="mt-3 inline-flex rounded-lg bg-accent px-3 py-1.5 text-xs font-medium text-white transition-colors hover:bg-accent-hover"
      >
        Collect in Config
      </Link>
    </div>
  );
}
