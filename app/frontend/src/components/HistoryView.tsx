import React, { useCallback, useEffect, useState } from 'react';
import { ExternalLink, RefreshCw } from 'lucide-react';
import { useApiBase } from '../context/ApiContext';
import { useAnalysisResult } from '../context/AnalysisResultContext';

type JobRow = {
  job_id?: string;
  status?: string;
  filename?: string;
  updated?: string;
  error?: string;
  analysis_json?: string;
};

type ResultRow = { filename: string; size: number; created: string };

type Props = {
  /** 解析 JSON を開いたあと解析タブへ切り替え */
  onResultOpened?: () => void;
};

export function HistoryView({ onResultOpened }: Props) {
  const { apiBase } = useApiBase();
  const { loadResultFile } = useAnalysisResult();
  const [jobs, setJobs] = useState<JobRow[]>([]);
  const [results, setResults] = useState<ResultRow[]>([]);
  const [loading, setLoading] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);

  const loadAll = useCallback(async () => {
    setLoading(true);
    setMsg(null);
    try {
      const [jr, rr] = await Promise.all([
        fetch(`${apiBase}/api/jobs`),
        fetch(`${apiBase}/api/results`),
      ]);
      if (jr.ok) {
        const j = await jr.json();
        setJobs(j.jobs ?? []);
      } else setJobs([]);
      if (rr.ok) {
        const r = await rr.json();
        setResults(r.results ?? []);
      } else setResults([]);
    } catch {
      setMsg('取得に失敗しました。API URL を設定タブで確認してください。');
      setJobs([]);
      setResults([]);
    } finally {
      setLoading(false);
    }
  }, [apiBase]);

  useEffect(() => {
    void loadAll();
  }, [loadAll]);

  const openResult = async (name: string) => {
    const ok = await loadResultFile(name);
    if (ok) {
      setMsg(null);
      onResultOpened?.();
    } else setMsg(`開けませんでした: ${name}`);
  };

  return (
    <div className="apple-history">
      <section className="apple-analyze-hero">
        <h2 className="apple-analyze-title">解析結果履歴</h2>
        <p className="apple-analyze-lead">
          バックエンドに保存されたジョブ状態と <code className="apple-code">*_analysis.json</code>{' '}
          一覧です。行をクリックすると解析ワークスペースに読み込みます（解析タブへ切り替えて表示）。
        </p>
      </section>

      <div className="apple-toolbar apple-toolbar--compact">
        <button
          type="button"
          className="apple-btn apple-btn-outline"
          onClick={() => void loadAll()}
          disabled={loading}
        >
          <RefreshCw size={16} className={loading ? 'apple-spin' : ''} aria-hidden />
          更新
        </button>
        {msg && <p className="apple-msg">{msg}</p>}
      </div>

      <div className="apple-history-grid">
        <section className="apple-panel apple-panel--grow">
          <h3 className="apple-panel-subtitle">ジョブ</h3>
          <div className="apple-table-wrap">
            <table className="apple-table">
              <thead>
                <tr>
                  <th>状態</th>
                  <th>ファイル</th>
                  <th>更新</th>
                </tr>
              </thead>
              <tbody>
                {jobs.map((j) => (
                  <tr key={j.job_id ?? j.filename}>
                    <td>{j.status ?? '—'}</td>
                    <td className="apple-td-break">{j.filename ?? '—'}</td>
                    <td className="apple-td-mono">{j.updated ?? '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            {jobs.length === 0 && <p className="apple-empty">ジョブ履歴がありません。</p>}
          </div>
        </section>

        <section className="apple-panel apple-panel--grow">
          <h3 className="apple-panel-subtitle">解析 JSON（結果）</h3>
          <ul className="apple-history-results">
            {results.map((r) => (
              <li key={r.filename}>
                <button
                  type="button"
                  className="apple-history-open"
                  onClick={() => void openResult(r.filename)}
                >
                  <ExternalLink size={14} aria-hidden />
                  {r.filename}
                </button>
                <span className="apple-meta">
                  {r.size} bytes · {r.created}
                </span>
              </li>
            ))}
          </ul>
          {results.length === 0 && <p className="apple-empty">まだ結果がありません。</p>}
        </section>
      </div>
    </div>
  );
}
