import { create } from 'zustand'

// In-memory only (no persist), so settings reset to defaults on reload.
interface RetestSettingsState {
  // true: require HITL approval of each agent-generated command before running it
  requireApproval: boolean
  setRequireApproval: (value: boolean) => void
}

export const useRetestSettingsStore = create<RetestSettingsState>((set) => ({
  // Default ON for this workspace: every retest pauses for HITL review before running a command.
  // Only takes effect when the command-approval feature is enabled (features.commandApproval /
  // server ENABLE_COMMAND_APPROVAL).
  requireApproval: true,
  setRequireApproval: (value) => set({ requireApproval: value }),
}))
