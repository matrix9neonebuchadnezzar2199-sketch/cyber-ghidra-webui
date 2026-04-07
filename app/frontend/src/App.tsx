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
          `ジョブ ${data.job_id ?? ''} を受け付けました。解析完了までしばらくお待ちください。`,
        );
        void loadResults();
      }
    } catch (e) {
      setMessage(e instanceof Error ? e.message : 'アップロードに失敗しました');
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
      setSelectedJson('JSON を読み込めませんでした。');
    }
  };

  const ghidraCliFlag = health?.ghidra_cli ?? health?.ghidra;

  return (
    <div className="apple-page">
      <header className="apple-nav">
        <div className="apple-nav-inner">
          <span className="apple-nav-title">Cyber Ghidra</span>
          <span className="apple-nav-meta">
            API {API_BASE.replace(/^https?:\/\//, '')}
          </span>
        </div>
      </header>

      <main className="apple-main">
        <section className="apple-hero">
          <p className="apple-hero-kicker">マルウェア解析パイプライン</p>
          <h1 className="apple-hero-title">Cyber Ghidra WebUI</h1>
          <p className="apple-hero-lead">
            ヘッドレス解析・JSON 出力・ローカル LLM（Ollama / LM Studio）連携
          </p>
        </section>

        <section className="apple-toolbar">
          <div className="apple-toolbar-row">
            <label className="apple-file-label apple-btn apple-btn-primary">
              {busy ? (
                <Loader2 size={18} className="apple-spin" aria-hidden />
              ) : (
                <FileUp size={18} aria-hidden />
              )}
              バイナリを選択
              <input
                type="file"
                className="apple-file-input"
                disabled={busy}
                onChange={(e) => void onUpload(e.target.files)}
              />
            </label>
            <button
              type="button"
              className="apple-btn apple-btn-outline"
              onClick={() => {
                void loadResults();
                void loadHealth();
              }}
            >
              <RefreshCw size={16} aria-hidden />
              更新
            </button>
          </div>
          {message && <p className="apple-msg">{message}</p>}
          <p className="apple-caption">
            バックエンド: {health?.status ?? '…'}
            {ghidraCliFlag !== undefined &&
              ` · Ghidra CLI: ${ghidraCliFlag ? '利用可能' : '未検出'}`}
          </p>
        </section>

        <div className="apple-grid">
          <section className="apple-panel">
            <h2 className="apple-panel-title">解析結果（JSON）</h2>
            <ul className="apple-result-list">
              {results.map((r) => (
                <li key={r.filename}>
                  <button
                    type="button"
                    className="apple-link"
                    onClick={() => void openResult(r.filename)}
                  >
                    {r.filename}
                  </button>
                  <span className="apple-meta">
                    {r.size} bytes · {r.created}
                  </span>
                </li>
              ))}
              {results.length === 0 && (
                <li className="apple-empty">まだ結果がありません。</li>
              )}
            </ul>
          </section>

          <section className="apple-panel">
            <h2 className="apple-panel-title">プレビュー</h2>
            <pre className="apple-pre">
              {selectedJson ?? '一覧から結果を選択してください。'}
            </pre>
          </section>
        </div>
      </main>
    </div>
  );
}
