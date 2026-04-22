import React, { useCallback, useEffect, useState } from 'react';
import { ExternalLink, RefreshCw } from 'lucide-react';
import { useApiBase } from '../context/ApiContext';
import { useAnalysisResult } from '../context/AnalysisResultContext';
import { extractOverallRiskFromJob, presentOverallRisk } from '../utils/safetyMeta';

type JobRow = {
  job_id?: string;
  status?: string;
  filename?: string;
  updated?: string;
  error?: string;
  analysis_json?: string;
  analysis_mode?: string;
  static_scan?: Record<string, unknown>;
};

type ResultRow = { filename: string; size: number; created: string };

type Props = {
  onResultOpened?: (filename?: string) => void;
  /** ジョブ行をクリックしたら解析タブで該当ジョブを開く（静析・Ghidra とも） */
  onOpenJobId?: (jobId: string) => void;
};

export function HistoryView({ onResultOpened, onOpenJobId }: Props) {
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
      onResultOpened?.(name);
    } else setMsg(`開けませんでした: ${name}`);
  };

  const openJob = (j: JobRow) => {
    if (!j.job_id) return;
    onOpenJobId?.(j.job_id);
  };

  return (
    <div className="apple-history">
      <section className="apple-analyze-hero">
        <h2 className="apple-analyze-title">解析結果履歴</h2>
        <p className="apple-analyze-lead">
          <strong>ジョブ</strong>にはバックエンドの{' '}
          <code className="apple-code">output/*.status.json</code> に紐づく{' '}
          <strong>静的分析</strong>・<strong>Ghidra</strong> 両方が表示されます（閉じたジョブも再表示可）。
        </p>
        <p className="apple-analyze-hint" style={{ marginTop: 10 }}>
          右欄の <code className="apple-code">*_analysis.json</code> は
          <strong> Ghidra が出力した逆解析</strong>のみです。PDF/Office
          などの結果は行をクリックし <strong>解析</strong>タブの静的分析 JSON
          をご利用ください。
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
          <h3 className="apple-panel-subtitle">ジョブ（静析 / Ghidra）</h3>
          <p className="apple-history-legend" style={{ fontSize: 13, color: 'var(--apple-text-secondary)', margin: '0 0 8px' }}>
            行をクリック → 解析タブで詳細（静析は JSON、Ghidra は可能なら関数ツリーも読み込み）。
          </p>
          <div className="apple-table-wrap">
            <table className="apple-table">
              <thead>
                <tr>
                  <th>種別</th>
                  <th>危険度(静析)</th>
                  <th>ファイル</th>
                  <th>状態</th>
                  <th>更新</th>
                </tr>
              </thead>
              <tbody>
                {jobs.map((j) => {
                  const mode = j.analysis_mode === 'static_only' ? '静析' : 'Ghidra';
                  const rStr = j.analysis_mode === 'static_only' ? extractOverallRiskFromJob(j as unknown as Record<string, unknown>) : null;
                  const rPres = rStr ? presentOverallRisk(rStr) : { label: '—', tone: 'safe' as const };
                  return (
                    <tr
                      key={j.job_id ?? j.filename}
                      className={j.job_id ? 'apple-tr-click' : undefined}
                      onClick={() => openJob(j)}
                      onKeyDown={(e) => {
                        if (e.key === 'Enter' || e.key === ' ') {
                          e.preventDefault();
                          openJob(j);
                        }
                      }}
                      role={j.job_id ? 'button' : undefined}
                      tabIndex={j.job_id ? 0 : undefined}
                    >
                      <td>
                        <span
                          className={
                            j.analysis_mode === 'static_only'
                              ? 'apple-pill apple-pill--static'
                              : 'apple-pill apple-pill--ghidra'
                          }
                        >
                          {mode}
                        </span>
                      </td>
                      <td>
                        {j.analysis_mode === 'static_only' ? (
                          <span
                            className={
                              rPres.tone === 'safe'
                                ? 'apple-risk apple-risk--safe'
                                : rPres.tone === 'warn'
                                  ? 'apple-risk apple-risk--warn'
                                  : rPres.tone === 'danger'
                                    ? 'apple-risk apple-risk--danger'
                                    : 'apple-risk apple-risk--low'
                            }
                          >
                            {rPres.label}
                          </span>
                        ) : (
                      '—'
                        )}
                      </td>
                      <td className="apple-td-break">{j.filename ?? '—'}</td>
                      <td>{j.status ?? '—'}</td>
                      <td className="apple-td-mono" style={{ fontSize: 12 }}>
                        {j.updated ?? '—'}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
            {jobs.length === 0 && <p className="apple-empty">ジョブ履歴がありません。</p>}
          </div>
        </section>

        <section className="apple-panel apple-panel--grow">
          <h3 className="apple-panel-subtitle">Ghidra 逆解析 JSON</h3>
          <p className="apple-history-legend" style={{ fontSize: 13, color: 'var(--apple-text-secondary)', margin: '0 0 8px' }}>
            analyzeHeadless 由来の
            <code className="apple-code"> _analysis.json</code> だけ。静的分析のみのジョブは
            左表から開いてください。
          </p>
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
          {results.length === 0 && <p className="apple-empty">Ghidra の逆解析JSONはまだありません。</p>}
        </section>
      </div>
    </div>
  );
}
