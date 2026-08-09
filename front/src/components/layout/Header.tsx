import { useLocation } from 'react-router';
import { useSocks } from '../../contexts/SocksContext';
import { useAuth } from '../../contexts/AuthContext';

const pageTitles: Record<string, string> = {
  '/': 'Home',
  '/retest': 'Retest',
}

export function Header() {
  const location = useLocation()
  const basePath = '/' + (location.pathname.split('/')[1] ?? '')
  const title = pageTitles[basePath] ?? 'Red Agent'
  const socksStatus = useSocks();
  const { logout, authRequired, username } = useAuth()

  return (
    <header className="flex h-14 items-center justify-between border-b border-border bg-bg-secondary px-6 font-sans">
      <h1 className="text-lg font-bold tracking-tight text-text-primary">{title}</h1>

      <div className="flex items-center gap-4">
        {/* SOCKS Status Unit */}
        <div className="flex flex-col items-end gap-1">
          <div className={`flex items-center gap-2 rounded border px-2 py-0.5 ${
            socksStatus.active ? 'border-green-500/50 bg-green-500/5' : 'border-red-500/40 bg-red-500/5'
          }`}>
            <span className={`h-1.5 w-1.5 rounded-full ${socksStatus.active ? 'bg-green-500' : 'bg-red-500'}`} />
            
            <span className={`text-[10px] font-mono font-bold uppercase tracking-wider ${
              socksStatus.active ? 'text-green-500' : 'text-red-400'
            }`}>
              SOCKS {socksStatus.active ? 'Active' : 'Inactive'}
            </span>
          </div>

          {/* Which endpoint was probed, shown once the port answered */}
          {socksStatus.active && socksStatus.host && socksStatus.port !== null && (
            <span className="text-[9px] font-mono text-text-muted opacity-80 px-1 leading-none">
              {socksStatus.host}:{socksStatus.port}
            </span>
          )}
        </div>
        {/* Logged-in user + logout, shown only when auth is enabled */}
        {authRequired && (
          <div className="flex items-center gap-2">
            {username && (
              <span className="text-[11px] font-medium text-text-secondary">{username}</span>
            )}
            <button
              type="button"
              onClick={() => { void logout() }}
              className="rounded border border-border px-2 py-1 text-[11px] font-medium text-text-secondary transition hover:bg-bg-tertiary"
            >
              Logout
            </button>
          </div>
        )}
      </div>
    </header>
  )

  
}
