import { createContext, useContext, useState, useEffect } from 'react';
import type { ReactNode } from 'react';
import { buildApiUrl, withAuthHeaders } from '../lib/api';

// `active` means the SOCKS5 port accepts a TCP connection, i.e. the proxy process is up.
// It cannot confirm that a downstream client is attached -- upstream SOCKS servers expose no
// management API, so port reachability is the only signal available without forking them.
interface SocksStatus {
  active: boolean;
  host: string | null;
  port: number | null;
}

const INACTIVE: SocksStatus = { active: false, host: null, port: null };

const SocksContext = createContext<SocksStatus>(INACTIVE);

export function SocksProvider({ children }: { children: ReactNode }) {
  const [socksStatus, setSocksStatus] = useState<SocksStatus>(INACTIVE);

  useEffect(() => {
    const checkSocks = async () => {
      try {
        const res = await fetch(buildApiUrl('/api/v1/health/socks'), { credentials: 'include', headers: withAuthHeaders(undefined, false) });
        if (!res.ok) {
          setSocksStatus(INACTIVE);
          return;
        }
        const data = await res.json();
        setSocksStatus({
          active: Boolean(data?.active),
          host: typeof data?.host === 'string' ? data.host : null,
          port: typeof data?.port === 'number' ? data.port : null,
        });
      } catch {
        setSocksStatus(INACTIVE);
      }
    };

    checkSocks();
    const interval = setInterval(checkSocks, 5000);
    return () => clearInterval(interval);
  }, []);

  return (
    <SocksContext.Provider value={socksStatus}>
      {children}
    </SocksContext.Provider>
  );
}

export const useSocks = () => useContext(SocksContext);
