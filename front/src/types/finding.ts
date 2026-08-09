export interface ReferenceItem {
  name: string
  url: string
}


// Mirror of backend's VerificationInput. Only findings that declare these show an
// input form (modal) before re-test execution.
export interface VerificationInput {
  key: string
  label: string
  placeholder?: string
  required?: boolean
  // Default injected into {{key}} when the field is left blank (pattern still validated).
  default?: string
  // Sensitive input (e.g. password): rendered masked; the server stores it in the secret
  // store and redacts it. Placed inside '{{key}}' in the template.
  secret?: boolean
  // Allow multiple values (add/remove UI); joined by spaces into a single variable.
  multiple?: boolean
  // Allowlist regex per value. Validated by the backend default when unspecified.
  pattern?: string
}

export interface Finding {
  no: string
  // Target platforms (defined in findings.json, multiple allowed). ad: on-prem AD /
  // entra: Microsoft Entra ID / other: other (e.g. Linux). retest_not_supported disables
  // the re-test button. Backend normalizes to an array (e.g. ["ad"], ["ad","entra"]).
  platform?: ('ad' | 'entra' | 'other' | 'retest_not_supported')[]
  title: string
  risk_level: string
  summary: string
  description: string
  recommendation: string
  references: ReferenceItem[]
  // Verification-path fields (from findings.json), passed through to the backend on re-test.
  // The backend re-reads findings.json by no and overwrites them, so a stale frontend cannot
  // change what runs; we still send them to keep the payload consistent.
  judgment_criteria?: string | null
  // Input-field declarations. No form is shown on re-test when empty/unspecified.
  verification_inputs?: VerificationInput[]
  // Special account privilege required for re-test (e.g. Domain Admin, SCCM Admin). Set only
  // when needed; the re-test screen warns. Unset means a normal user suffices.
  required_privilege?: string
}