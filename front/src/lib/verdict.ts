// Retest verdict codes (kept in sync with backend agent/verdict.py); drives list badge display.
// Findings with no retest history are absent from the summary, so the frontend treats them as "not executed".

export type VerdictCode =
  | 'resolved'
  | 'partial'
  | 'unresolved'
  | 'inconclusive'

export type FindingStatusKind = VerdictCode | 'none'

export interface VerdictBadge {
  label: string
  className: string
}

const BADGES: Record<FindingStatusKind, VerdictBadge> = {
  resolved: {
    label: 'Resolved',
    className: 'border-green-500/40 bg-green-500/10 text-green-400',
  },
  partial: {
    label: 'Partially Resolved',
    className: 'border-yellow-500/40 bg-yellow-500/10 text-yellow-400',
  },
  unresolved: {
    label: 'Unresolved',
    className: 'border-red-500/40 bg-red-500/10 text-red-400',
  },
  inconclusive: {
    label: 'Inconclusive',
    className: 'border-border/60 bg-bg-tertiary text-text-muted',
  },
  none: {
    label: 'Not Executed',
    className: 'border-border/40 bg-transparent text-text-muted',
  },
}

export function toStatusKind(
  verdict: string | null | undefined,
  hasRecord: boolean,
): FindingStatusKind {
  if (verdict === 'resolved' || verdict === 'partial' || verdict === 'unresolved') {
    return verdict
  }
  if (verdict === 'inconclusive') return 'inconclusive'
  return hasRecord ? 'inconclusive' : 'none'
}

export function getVerdictBadge(kind: FindingStatusKind): VerdictBadge {
  return BADGES[kind]
}

// Not eligible for automated retest (platform=retest_not_supported); shown as a dedicated badge
// outside FindingStatusKind since it is orthogonal to history-based verdicts.
export const UNSUPPORTED_BADGE: VerdictBadge = {
  label: 'Not Applicable',
  className: 'border-border/60 bg-bg-tertiary text-text-muted whitespace-nowrap',
}

// Verdict extraction from retest-result Markdown (kept in sync with backend agent/verdict.py).
// Priority: (1) the required canonical `Verdict: X` marker line (last one wins, it is the
// report's final line); (2) the LAST verdict/judgement/conclusion heading section; (3) the
// whole body, taking the LAST keyword. Using the last -- not the first -- keyword avoids
// picking up an incidental "Resolved" from an earlier expected-state description.
// "Partially Resolved" precedes "Resolved" so it is not collapsed into the substring "Resolved".
const VERDICT_KEYWORDS: ReadonlyArray<readonly [string, VerdictCode]> = [
  ['Partially Resolved', 'partial'],
  ['Resolved', 'resolved'],
  ['Unresolved', 'unresolved'],
  ['Inconclusive', 'inconclusive'],
  ['Unverified', 'inconclusive'],
]

const PARTIALLY_PREFIX = 'Partially '

// A line carrying the canonical marker: the word "Verdict" followed by a colon (ASCII or
// full-width). Matches both `Verdict: X` and a `## Verdict: X` heading.
const CANONICAL_LINE_RE = /^[^\n]*\bverdict\b[^\n]*[:：].*$/gim
const JUDGMENT_HEADING_RE = /^#{1,6}\s*.*(?:verdict|judgement|judgment|conclusion).*$/gim
const NEXT_HEADING_RE = /\n#{1,6}\s/

function judgmentSection(markdown: string): string | null {
  JUDGMENT_HEADING_RE.lastIndex = 0
  let last: RegExpExecArray | null = null
  for (let m = JUDGMENT_HEADING_RE.exec(markdown); m !== null; m = JUDGMENT_HEADING_RE.exec(markdown)) {
    last = m
  }
  if (last === null) return null
  const rest = markdown.slice(last.index + last[0].length)
  const nxt = NEXT_HEADING_RE.exec(rest)
  return nxt ? rest.slice(0, nxt.index) : rest
}

function matchVerdictFirst(text: string): VerdictCode | null {
  let bestIndex: number | null = null
  let bestCode: VerdictCode | null = null
  for (const [keyword, code] of VERDICT_KEYWORDS) {
    const idx = text.indexOf(keyword)
    if (idx === -1) continue
    if (bestIndex === null || idx < bestIndex) {
      bestIndex = idx
      bestCode = code
    }
  }
  return bestCode
}

function matchVerdictLast(text: string): VerdictCode | null {
  let bestIndex: number | null = null
  let bestCode: VerdictCode | null = null
  for (const [keyword, code] of VERDICT_KEYWORDS) {
    const idx = text.lastIndexOf(keyword)
    if (idx === -1) continue
    if (bestIndex === null || idx > bestIndex) {
      bestIndex = idx
      bestCode = code
    }
  }
  // A bare "Resolved" that is actually the tail of "Partially Resolved" is partial.
  if (
    bestCode === 'resolved' &&
    bestIndex !== null &&
    bestIndex >= PARTIALLY_PREFIX.length &&
    text.slice(bestIndex - PARTIALLY_PREFIX.length, bestIndex) === PARTIALLY_PREFIX
  ) {
    return 'partial'
  }
  return bestCode
}

function canonicalVerdict(markdown: string): VerdictCode | null {
  CANONICAL_LINE_RE.lastIndex = 0
  let code: VerdictCode | null = null
  for (let m = CANONICAL_LINE_RE.exec(markdown); m !== null; m = CANONICAL_LINE_RE.exec(markdown)) {
    const found = matchVerdictFirst(m[0])
    if (found !== null) code = found
  }
  return code
}

/** Extract a normalized verdict code from retest-result Markdown, or null if none found. */
export function extractVerdictFromText(
  markdown: string | null | undefined,
): VerdictCode | null {
  if (!markdown || !markdown.trim()) return null
  const canonical = canonicalVerdict(markdown)
  if (canonical !== null) return canonical
  const section = judgmentSection(markdown)
  if (section !== null) {
    const code = matchVerdictLast(section)
    if (code !== null) return code
  }
  return matchVerdictLast(markdown)
}

/** Normalize a backend verdict string to a VerdictCode (unknown/null -> null). */
export function toVerdictCode(
  verdict: string | null | undefined,
): VerdictCode | null {
  if (
    verdict === 'resolved' ||
    verdict === 'partial' ||
    verdict === 'unresolved' ||
    verdict === 'inconclusive'
  ) {
    return verdict
  }
  return null
}
