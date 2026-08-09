import type { Finding } from '../../types/finding'
import {
  getVerdictBadge,
  UNSUPPORTED_BADGE,
  type FindingStatusKind,
} from '../../lib/verdict'

interface FindingRowProps {
  finding: Finding
  onViewDetail: () => void
  // Resolution status from the latest retest history; unset is treated as "not executed".
  statusKind?: FindingStatusKind
}

export function FindingRow({ finding, onViewDetail, statusKind = 'none' }: FindingRowProps) {
  const riskTextColor: Record<string, string> = {
    High: 'text-red-400',
    Medium: 'text-yellow-400',
    Low: 'text-blue-400',
  }
  const riskClass = riskTextColor[finding.risk_level] ?? 'text-text-muted'

  // platform is normalized to an array by the backend, but hand-pasted JSON may be a single string; handle both.
  const platforms = Array.isArray(finding.platform)
    ? finding.platform
    : finding.platform
      ? [finding.platform]
      : []
  const retestNotSupported = platforms.includes('retest_not_supported')

  const statusBadge = getVerdictBadge(statusKind)

  return (
    <tr
      onClick={onViewDetail}
      className="cursor-pointer transition-colors hover:bg-bg-tertiary/50 group"
    >
      {/* 1. No column */}
      <td className="w-16 px-4 py-3.5 text-center font-mono text-xs text-text-muted">
        {finding.no.replace(/^No\./i, '')}
      </td>

      {/* 2. Risk level column */}
      <td className="w-32 px-4 py-3.5 text-center">
        <span className={`text-[11px] text-center font-bold tracking-wider ${riskClass}`}>
          {finding.risk_level}
        </span>
      </td>

      {/* 3. Finding (title) column */}
      <td className="px-4 py-3.5">
        <div className="flex items-center gap-2">
          <span className="truncate text-sm font-medium text-text-primary group-hover:text-accent transition-colors">
            {finding.title}
          </span>
        </div>
      </td>

      {/* 4. Status (resolution status from the latest retest history) column */}
      {/* w-36 + whitespace-nowrap keeps "Partially Resolved" on a single line */}
      <td className="w-36 px-4 py-3.5 text-center">
        {retestNotSupported ? (
          <span
            title="This finding is not eligible for automated retesting"
            className={`inline-block shrink-0 whitespace-nowrap rounded border px-1.5 py-0.5 text-[11px] font-medium tracking-wide ${UNSUPPORTED_BADGE.className}`}
          >
            {UNSUPPORTED_BADGE.label}
          </span>
        ) : (
          <span
            className={`inline-block shrink-0 whitespace-nowrap rounded border px-1.5 py-0.5 text-[11px] font-medium tracking-wide ${statusBadge.className}`}
          >
            {statusBadge.label}
          </span>
        )}
      </td>
    </tr>
  )
}