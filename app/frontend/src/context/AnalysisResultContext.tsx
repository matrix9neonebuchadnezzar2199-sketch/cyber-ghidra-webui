import React, { createContext, useCallback, useContext, useMemo, useState } from 'react';
import type { AnalysisJson } from '../types/analysis';
import { useApiBase } from './ApiContext';

type Ctx = {
  analysisData: AnalysisJson | null;
  loadedFilename: string | null;
  selectedFnIndex: number | null;
  fnSearch: string;
  setFnSearch: (s: string) => void;
  setSelectedFnIndex: (i: number | null) => void;
  loadResultFile: (filename: string) => Promise<boolean>;
  clearAnalysis: () => void;
};

const Ctx = createContext<Ctx | null>(null);

export function AnalysisResultProvider({ children }: { children: React.ReactNode }) {
  const { apiBase } = useApiBase();
  const [analysisData, setAnalysisData] = useState<AnalysisJson | null>(null);
  const [loadedFilename, setLoadedFilename] = useState<string | null>(null);
  const [selectedFnIndex, setSelectedFnIndex] = useState<number | null>(null);
  const [fnSearch, setFnSearch] = useState('');

  const loadResultFile = useCallback(
    async (filename: string) => {
      try {
        const r = await fetch(`${apiBase}/api/results/${encodeURIComponent(filename)}`);
        if (!r.ok) return false;
        const data = (await r.json()) as AnalysisJson;
        setAnalysisData(data);
        setLoadedFilename(filename);
        setSelectedFnIndex(data.functions.length ? 0 : null);
        setFnSearch('');
        return true;
      } catch {
        return false;
      }
    },
    [apiBase],
  );

  const clearAnalysis = useCallback(() => {
    setAnalysisData(null);
    setLoadedFilename(null);
    setSelectedFnIndex(null);
    setFnSearch('');
  }, []);

  const value = useMemo(
    () => ({
      analysisData,
      loadedFilename,
      selectedFnIndex,
      fnSearch,
      setFnSearch,
      setSelectedFnIndex,
      loadResultFile,
      clearAnalysis,
    }),
    [
      analysisData,
      loadedFilename,
      selectedFnIndex,
      fnSearch,
      loadResultFile,
      clearAnalysis,
    ],
  );

  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useAnalysisResult(): Ctx {
  const x = useContext(Ctx);
  if (!x) throw new Error('useAnalysisResult outside AnalysisResultProvider');
  return x;
}
