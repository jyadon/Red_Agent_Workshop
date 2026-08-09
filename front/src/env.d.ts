/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_API_BASE_URL: string
  readonly VITE_ENABLE_MOCKS: string
  // Build-time feature flags (see src/lib/features.ts)
  readonly VITE_ENABLE_RETEST: string
  readonly VITE_ENABLE_RTO: string
  readonly VITE_ENABLE_COMMAND_APPROVAL: string
}

interface ImportMeta {
  readonly env: ImportMetaEnv
}
