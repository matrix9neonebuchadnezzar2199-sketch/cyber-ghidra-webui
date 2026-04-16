import { useCallback, useState } from 'react';

export type FlowNavEntry = {
  type: 'callgraph' | 'cfg';
  functionAddress?: string;
  functionName?: string;
};

export function useFlowNavigation() {
  const [stack, setStack] = useState<FlowNavEntry[]>([]);
  const [current, setCurrent] = useState<FlowNavEntry>({ type: 'callgraph' });

  const navigateTo = useCallback((entry: FlowNavEntry) => {
    setCurrent((prev) => {
      setStack((s) => [...s, prev]);
      return entry;
    });
  }, []);

  const goBack = useCallback(() => {
    setStack((s) => {
      if (s.length === 0) return s;
      const prev = s[s.length - 1];
      setCurrent(prev);
      return s.slice(0, -1);
    });
  }, []);

  const canGoBack = stack.length > 0;

  const breadcrumbs: FlowNavEntry[] = [...stack, current];

  return { current, navigateTo, goBack, canGoBack, breadcrumbs };
}
