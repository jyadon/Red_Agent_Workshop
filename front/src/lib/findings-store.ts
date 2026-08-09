import { create } from 'zustand'
import type {
  Finding,
  VerificationInput,
} from '../types/finding'

interface ReportJson {
  report_metadata?: {
    title?: string
    generated_at?: string
    total_findings?: number
    company_name?: string
  }
  findings: RawFinding[]
}

export interface RawFinding {
  no?: string
  section?: number | string
  // Backend returns an array, but hand-pasted JSON may use a single string; accept both.
  platform?:
    | ('ad' | 'entra' | 'other' | 'retest_not_supported')[]
    | 'ad'
    | 'entra'
    | 'other'
    | 'retest_not_supported'
  title: string
  risk_level: string
  summary: string
  description: string
  recommendation: string
  references?: { name: string; url: string }[]
  // Verification-path fields (from backend findings.json); passed straight through to the retest payload.
  judgment_criteria?: string | null
  verification_inputs?: VerificationInput[]
  required_privilege?: string
}

function rawToFinding(raw: RawFinding, index: number): Finding {
  const no = raw.no ?? `No.${String(raw.section ?? index + 1)}`

  // Always carry platform as an array: it drives verification-path branching (Entra-only skips
  // AD credentials). Dropping it makes finding.platform undefined and breaks the verdict logic.
  const platform = Array.isArray(raw.platform)
    ? raw.platform
    : raw.platform
      ? [raw.platform]
      : undefined

  return {
    no,
    platform,
    title: raw.title,
    risk_level: raw.risk_level,
    summary: raw.summary.replace(/\n+$/, ''),
    description: raw.description.replace(/\n+$/, ''),
    recommendation: raw.recommendation.replace(/\n+$/, ''),
    references: raw.references ?? [],
    // Carry verification-path fields through; the deterministic retest run reads them.
    judgment_criteria: raw.judgment_criteria ?? null,
    verification_inputs: raw.verification_inputs ?? [],
    required_privilege: raw.required_privilege,
  }
}

export type ParseReportResult =
  | {
      ok: true
      findings: Finding[]
      metadata?: ReportJson['report_metadata']
    }
  | {
      ok: false
      error: string
    }

export function parseReportJson(jsonStr: string): ParseReportResult {
  let data: ReportJson
  try {
    data = JSON.parse(jsonStr) as ReportJson
  } catch (e) {
    return {
      ok: false,
      error: `Invalid JSON: ${e instanceof Error ? e.message : String(e)}`,
    }
  }

  if (!data || !Array.isArray(data.findings)) {
    return {
      ok: false,
      error: 'Invalid report shape: "findings" array is missing',
    }
  }

  return {
    ok: true,
    findings: data.findings.map((f, i) => rawToFinding(f, i)),
    metadata: data.report_metadata,
  }
}

interface FindingsStore {
  findings: Finding[]
  reportTitle: string | null

  loadFindings: (findings: Finding[], reportTitle?: string) => void
  loadFromRaw: (rawFindings: RawFinding[], reportTitle?: string) => void
  clearFindings: () => void
  getFinding: (no: string) => Finding | undefined
}

// Backend (`GET /api/v1/findings`) is the single source of truth for findings; not persisted on
// the frontend. On each reload it is empty until the fetch completes, then filled with the latest.
export const useFindingsStore = create<FindingsStore>((setState, getState) => ({
  findings: [],
  reportTitle: null,

  loadFindings: (findings, reportTitle) => {
    setState({
      findings,
      reportTitle: reportTitle ?? null,
    })
  },

  loadFromRaw: (rawFindings, reportTitle) => {
    const findings = rawFindings.map((f, i) => rawToFinding(f, i))
    setState({
      findings,
      reportTitle: reportTitle ?? null,
    })
  },

  clearFindings: () => {
    setState({ findings: [], reportTitle: null })
  },

  getFinding: (no) => {
    return getState().findings.find((f) => f.no === no)
  },
}))