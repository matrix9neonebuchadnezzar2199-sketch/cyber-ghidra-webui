import React, { useEffect, useState } from 'react';
import { Sidebar, type SidebarSection } from './components/Sidebar';
import { AnalysisView } from './components/AnalysisView';
import { HistoryView } from './components/HistoryView';
import { SettingsView } from './components/SettingsView';
import { useApiBase } from './context/ApiContext';

function AppShell() {
  const { apiBase } = useApiBase();
  const [section, setSection] = useState<SidebarSection>('analyze');
  const [reopenJobId, setReopenJobId] = useState<string | null>(null);

  useEffect(() => {
    if (typeof window === 'undefined') return;
    const sp = new URLSearchParams(window.location.search);
    const fromUrl = sp.get('jobId');
    if (fromUrl) {
      setReopenJobId(fromUrl);
      setSection('analyze');
      sp.delete('jobId');
      const q = sp.toString();
      const next = `${window.location.pathname}${q ? `?${q}` : ''}${window.location.hash || ''}`;
      window.history.replaceState({}, '', next);
    }
  }, []);

  return (
    <div className="apple-page">
      <header className="apple-nav">
        <div className="apple-nav-inner">
          <span className="apple-nav-title">Cyber Ghidra</span>
          <span className="apple-nav-meta">API {apiBase.replace(/^https?:\/\//, '')}</span>
        </div>
      </header>

      <div className="apple-shell">
        <Sidebar active={section} onSelect={setSection} />
        <main className="apple-shell-main">
          {/* Keep mounted so job polling / 解析ワークスペース survives tab switches */}
          <div
            className={section === 'analyze' ? 'apple-view' : 'apple-view apple-view--hidden'}
          >
            <AnalysisView
              reopenJobId={reopenJobId}
              onReopenConsumed={() => setReopenJobId(null)}
            />
          </div>
          <div
            className={section === 'history' ? 'apple-view' : 'apple-view apple-view--hidden'}
          >
            <HistoryView
              onResultOpened={() => setSection('analyze')}
              onOpenJobId={(id) => {
                setReopenJobId(id);
                setSection('analyze');
              }}
            />
          </div>
          <div
            className={section === 'settings' ? 'apple-view' : 'apple-view apple-view--hidden'}
          >
            <SettingsView />
          </div>
        </main>
      </div>
    </div>
  );
}

export default function App() {
  return <AppShell />;
}
