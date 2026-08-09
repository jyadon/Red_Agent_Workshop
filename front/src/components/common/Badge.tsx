export function RiskBadge({ level }: { level: 'safe' | 'cautious' | 'dangerous' }) {
  const styles = {
    safe: 'bg-green-900/30 text-green-400 border-green-800',
    cautious: 'bg-yellow-900/30 text-yellow-400 border-yellow-800',
    dangerous: 'bg-red-900/30 text-red-400 border-red-800',
  }
  return (
    <span
      className={`inline-flex items-center rounded border px-2 py-0.5 text-xs font-medium ${styles[level]}`}
    >
      {level}
    </span>
  )
}
