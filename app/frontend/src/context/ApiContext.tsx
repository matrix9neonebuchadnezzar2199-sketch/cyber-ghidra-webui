import React, { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react';

const STORAGE_KEY = 'cyberghidra_api_base';

type ApiCtx = {
  apiBase: string;
  setApiBase: (v: string) => void;
};

const Ctx = createContext<ApiCtx | null>(null);

function defaultBase(): string {
  return import.meta.env.VITE_API_URL ?? 'http://localhost:8000';
}

export function ApiProvider({ children }: { children: React.ReactNode }) {
  const [apiBase, setApiBaseState] = useState(defaultBase);

  useEffect(() => {
    try {
      const s = localStorage.getItem(STORAGE_KEY);
      if (s?.trim()) setApiBaseState(s.trim());
    } catch {
      /* ignore */
    }
  }, []);

  const setApiBase = useCallback((v: string) => {
    const t = v.trim();
    setApiBaseState(t || defaultBase());
    try {
      localStorage.setItem(STORAGE_KEY, t || defaultBase());
    } catch {
      /* ignore */
    }
  }, []);

  const value = useMemo(() => ({ apiBase, setApiBase }), [apiBase, setApiBase]);

  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useApiBase(): ApiCtx {
  const x = useContext(Ctx);
  if (!x) throw new Error('useApiBase outside ApiProvider');
  return x;
}
