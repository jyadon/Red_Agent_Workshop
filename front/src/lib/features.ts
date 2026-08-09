// Build-time feature flags. Vite statically replaces `import.meta.env.VITE_*`
// at build time, so disabled features are tree-shaken out of the production
// bundle along with their page/nav/routing branches.
//
// Flags are controlled via `.env`. Defaults when unset:
//   VITE_ENABLE_RETEST            Retest execution        (default: enabled)
//   VITE_ENABLE_RTO              Red Team Operations (RTO)     (default: enabled)
//   VITE_ENABLE_COMMAND_APPROVAL Command approval (HITL)  (default: enabled)
//   VITE_ENABLE_SOCKS_CHECK      SOCKS gate on execution  (default: enabled)

function parseFlag(value: string | undefined, defaultValue: boolean): boolean {
  if (value === undefined || value === '') return defaultValue
  const normalized = value.trim().toLowerCase()
  if (normalized === 'false' || normalized === '0' || normalized === 'off') return false
  if (normalized === 'true' || normalized === '1' || normalized === 'on') return true
  return defaultValue
}

export const features = {
  retest: parseFlag(import.meta.env.VITE_ENABLE_RETEST, true),
  rto: parseFlag(import.meta.env.VITE_ENABLE_RTO, true),
  // Command approval (HITL). Default enabled for this workspace. Editing a generated command
  // is no longer an injection surface: commands run with shell=False and an edit may change
  // only the arguments (the tool/binary is locked). Keep in sync with the server-side
  // ENABLE_COMMAND_APPROVAL.
  commandApproval: parseFlag(import.meta.env.VITE_ENABLE_COMMAND_APPROVAL, true),
  // Gate execution on SOCKS liveness. Default enabled: without the proxy, commands
  // cannot reach the target range, so starting a run just wastes a round trip.
  // Disable when the target is reachable without a proxy.
  socksCheck: parseFlag(import.meta.env.VITE_ENABLE_SOCKS_CHECK, true),
} as const

export type FeatureKey = keyof typeof features

export function isFeatureEnabled(key: FeatureKey): boolean {
  return features[key]
}
