import React, { useCallback, useEffect, useState } from 'react';
import { FileUp, Loader2, RefreshCw } from 'lucide-react';

const API_BASE = import.meta.env.VITE_API_URL ?? 'http://localhost:8000';

type ResultRow = { filename: string; size: number; created: string };

export default function App() {
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [results, setResults] = useState<ResultRow[]>([]);
  const [health, setHealth] = useState<{
    status?: string;
    ghidra_cli?: boolean;
    ghidra?: boolean;
  } | null>(null);
  const [selectedJson, setSelectedJson] = useState<string | null>(null);

  const loadHealth = useCallback(async () => {
    try {
      const r = await fetch(`${API_BASE}/health`);
      setHealth(await r.json());
    } catch {
      setHealth(null);
    }
  }, []);

  const loadResults = useCallback(async () => {
    try {
      const r = await fetch(`${API_BASE}/api/results`);
      const data = await r.json();
      setResults(data.results ?? []);
    } catch {
      setResults([]);
    }
  }, []);

  useEffect(() => {
    void loadHealth();
    void loadResults();
  }, [loadHealth, loadResults]);

  const onUpload = async (files: FileList | null) => {
    if (!files?.length) return;
    setBusy(true);
    setMessage(null);
    const fd = new FormData();
    fd.append('file', files[0]);
    try {
      const r = await fetch(`${API_BASE}/api/upload`, { method: 'POST', body: fd });
      const data = await r.json();
      if (!r.ok) {
        setMessage(typeof data.detail === 'string' ? data.detail : JSON.stringify(data));
      } else {
        setMessage(
          `Accepted job ${data.job_id ?? ''}. Analysis runs in background; refresh the list shortly.`,
        );
        void loadResults();
      }
    } catch (e) {
      setMessage(e instanceof Error ? e.message : 'Upload failed');
    } finally {
      setBusy(false);
    }
  };

  const openResult = async (name: string) => {
    try {
      const r = await fetch(`${API_BASE}/api/results/${encodeURIComponent(name)}`);
      const data = await r.json();
      setSelectedJson(JSON.stringify(data, null, 2));
    } catch {
      setSelectedJson('Could not load result JSON.');
    }
  };

  const ghidraCliFlag = health?.ghidra_cli ?? health?.ghidra;

  return (
    <div style={{ padding: '2rem', maxWidth: 1100, margin: '0 auto' }}>
      <h1 className="neon-text" style={{ fontSize: '2.25rem', textAlign: 'center' }}>
        CYBER GHIDRA WEBUI
      </h1>
      <p style={{ color: 'var(--text-accent)', textAlign: 'center', marginBottom: '1.5rem' }}>
        Headless analysis · JSON export · Local LLM hooks (Ollama / LM Studio) optional
      </p>

      <div
        style={{
          border: '1px solid var(--border-color)',
          padding: '1.25rem',
          marginBottom: '1.25rem',
          background: 'var(--bg-secondary)',
          borderRadius: 8,
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
          <label
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: 8,
              cursor: busy ? 'wait' : 'pointer',
              opacity: busy ? 0.6 : 1,
            }}
          >
            {busy ? <Loader2 size={18} className="spin" aria-hidden /> : <FileUp size={18} aria-hidden />}
            <span>Select binary</span>
            <input
              type="file"
              disabled={busy}
              style={{ display: 'none' }}
              onChange={(e) => void onUpload(e.target.files)}
            />
          </label>
          <button
            type="button"
            onClick={() => {
              void loadResults();
              void loadHealth();
            }}
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: 6,
              padding: '8px 12px',
              background: 'transparent',
              border: '1px solid var(--border-color)',
              color: 'var(--text-primary)',
              cursor: 'pointer',
              borderRadius: 6,
            }}
          >
            <RefreshCw size={16} /> Refresh
          </button>
          <span style={{ color: 'var(--text-muted)', fontSize: 14 }}>
            API: {API_BASE}
          </span>
        </div>
        {message && (
          <p style={{ marginTop: 12, color: 'var(--text-accent)', fontSize: 14 }}>{message}</p>
        )}
        <p style={{ marginTop: 10, fontSize: 13, color: 'var(--text-muted)' }}>
          Backend: {health?.status ?? '…'}
          {ghidraCliFlag !== undefined && ` · Ghidra CLI: ${ghidraCliFlag ? 'ok' : 'missing'}`}
        </p>
      </div>

      <div
        style={{
          display: 'grid',
          gridTemplateColumns: '1fr 1fr',
          gap: '1rem',
        }}
      >
        <div
          style={{
            border: '1px solid var(--border-color)',
            padding: '1rem',
            background: 'var(--bg-secondary)',
            borderRadius: 8,
            minHeight: 200,
          }}
        >
          <h2 style={{ fontSize: '1rem', marginBottom: 12 }}>Completed JSON</h2>
          <ul style={{ listStyle: 'none', padding: 0, margin: 0 }}>
            {results.map((r) => (
              <li key={r.filename} style={{ marginBottom: 8 }}>
                <button
                  type="button"
                  onClick={() => void openResult(r.filename)}
                  style={{
                    background: 'none',
                    border: 'none',
                    color: 'var(--text-accent)',
                    cursor: 'pointer',
                    textDecoration: 'underline',
                    padding: 0,
                    font: 'inherit',
                  }}
                >
                  {r.filename}
                </button>
                <span style={{ color: 'var(--text-muted)', fontSize: 12, marginLeft: 8 }}>
                  {r.size} bytes · {r.created}
                </span>
              </li>
            ))}
            {results.length === 0 && (
              <li style={{ color: 'var(--text-muted)', fontSize: 14 }}>No results yet.</li>
            )}
          </ul>
        </div>
        <div
          style={{
            border: '1px solid var(--border-color)',
            padding: '1rem',
            background: 'var(--bg-secondary)',
            borderRadius: 8,
            minHeight: 200,
            overflow: 'auto',
          }}
        >
          <h2 style={{ fontSize: '1rem', marginBottom: 12 }}>Preview</h2>
          <pre
            style={{
              margin: 0,
              fontSize: 12,
              lineHeight: 1.45,
              whiteSpace: 'pre-wrap',
              wordBreak: 'break-word',
              maxHeight: 420,
              overflow: 'auto',
            }}
          >
            {selectedJson ?? 'Select a result to load JSON.'}
          </pre>
        </div>
      </div>

      <style>{`
        @keyframes spin { to { transform: rotate(360deg); } }
        .spin { animation: spin 1s linear infinite; }
      `}</style>
    </div>
  );
}
