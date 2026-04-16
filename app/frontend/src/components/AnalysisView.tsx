import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { CheckCircle2, FileUp, Loader2, RefreshCw, XCircle } from 'lucide-react';
import { useApiBase } from '../context/ApiContext';
import { useAnalysisResult } from '../context/AnalysisResultContext';
import { AnalysisDetail } from './analysis/AnalysisDetail';
import { FunctionTree } from './analysis/FunctionTree';
import { filterFunctionIndices } from './analysis/functionTreeUtils';

type JobStatus = {
  job_id?: string;
  status: string;
  filename?: string;
  progress_message?: string;
  /** 0–100 when postScript reports [CyberGhidra] PROGRESS N; null before that or when unknown */
  progress_percent?: number | null;
  error?: string;
  analysis_json?: string;
  updated?: string;
};

function statusLabelJa(status: string): string {
  switch (status) {
    case 'queued':
      return 'キュー待ち（ワーカーがジョブを取り込むまで）';
    case 'running':
      return 'Ghidra 解析を実行中';
    case 'completed':
      return '完了';
    case 'failed':
      return '失敗';
    default:
      return status;
  }
}

export function AnalysisView() {
  const { apiBase } = useApiBase();
  const {
    analysisData,
    loadedFilename,
    selectedFnIndex,
    fnSearch,
    setFnSearch,
    setSelectedFnIndex,
    loadResultFile,
  } = useAnalysisResult();

  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [activeJob, setActiveJob] = useState<{ id: string; filename: string; startedAt: number } | null>(
    null,
  );
  const [jobSnapshot, setJobSnapshot] = useState<JobStatus | null>(null);
  const pollRef = useRef<number | null>(null);

  const [health, setHealth] = useState<{
    status?: string;
    ghidra_cli?: boolean;
    ghidra?: boolean;
  } | null>(null);

  const [elapsedPulse, setElapsedPulse] = useState(0);

  const loadHealth = useCallback(async () => {
    try {
      const r = await fetch(`${apiBase}/health`);
      setHealth(await r.json());
    } catch {
      setHealth(null);
    }
  }, [apiBase]);

  useEffect(() => {
    void loadHealth();
  }, [loadHealth]);

  useEffect(() => {
    if (!activeJob) {
      setJobSnapshot(null);
      return;
    }

    const pollOnce = async () => {
      try {
        const r = await fetch(`${apiBase}/api/jobs/${encodeURIComponent(activeJob.id)}`);
        if (!r.ok) return;
        const data = (await r.json()) as JobStatus;
        setJobSnapshot(data);
        if (data.status === 'completed' || data.status === 'failed') {
          if (pollRef.current !== null) {
            window.clearInterval(pollRef.current);
            pollRef.current = null;
          }
          if (data.status === 'completed' && data.analysis_json) {
            const ok = await loadResultFile(data.analysis_json);
            if (!ok) setMessage(`結果を開けませんでした: ${data.analysis_json}`);
          }
        }
      } catch {
        /* ignore */
      }
    };

    void pollOnce();
    pollRef.current = window.setInterval(() => void pollOnce(), 2000);
    return () => {
      if (pollRef.current !== null) {
        window.clearInterval(pollRef.current);
        pollRef.current = null;
      }
    };
  }, [activeJob, apiBase, loadResultFile]);

  useEffect(() => {
    if (!activeJob || !jobSnapshot) return;
    if (jobSnapshot.status !== 'queued' && jobSnapshot.status !== 'running') return;
    const id = window.setInterval(() => setElapsedPulse((t) => t + 1), 500);
    return () => window.clearInterval(id);
  }, [activeJob, jobSnapshot?.status]);

  const elapsedSec = useMemo(() => {
    if (!activeJob || !jobSnapshot) return 0;
    if (jobSnapshot.status !== 'queued' && jobSnapshot.status !== 'running') return 0;
    return Math.floor((Date.now() - activeJob.startedAt) / 1000);
  }, [activeJob, jobSnapshot, elapsedPulse]);

  const onUpload = async (files: FileList | null) => {
    if (!files?.length) return;
    setBusy(true);
    setMessage(null);
    const fd = new FormData();
    fd.append('file', files[0]);
    try {
      const r = await fetch(`${apiBase}/api/upload`, { method: 'POST', body: fd });
      const data = await r.json();
      if (!r.ok) {
        setActiveJob(null);
        setMessage(typeof data.detail === 'string' ? data.detail : JSON.stringify(data));
      } else {
        setActiveJob({
          id: data.job_id as string,
          filename: data.filename as string,
          startedAt: Date.now(),
        });
      }
    } catch (e) {
      setActiveJob(null);
      setMessage(e instanceof Error ? e.message : 'アップロードに失敗しました');
    } finally {
      setBusy(false);
    }
  };

  const filteredIndices = useMemo(() => {
    if (!analysisData) return [];
    return filterFunctionIndices(analysisData.functions, fnSearch);
  }, [analysisData, fnSearch]);

  const onSelectFunctionByAddress = useCallback(
    (address: string) => {
      if (!analysisData) return;
      const i = analysisData.functions.findIndex((f) => f.address === address);
      if (i >= 0) setSelectedFnIndex(i);
    },
    [analysisData, setSelectedFnIndex],
  );

  const ghidraCliFlag = health?.ghidra_cli ?? health?.ghidra;

  return (
    <div className="apple-analyze">
      <section className="apple-analyze-hero">
        <h2 className="apple-analyze-title">解析</h2>
        <p className="apple-analyze-lead">
          検体をアップロードするとワーカーが Ghidra Headless で解析し、関数ツリー・逆コンパイル・文字列・インポートを参照できます。
        </p>
      </section>

      <section className="apple-toolbar apple-toolbar--compact">
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
            onClick={() => void loadHealth()}
          >
            <RefreshCw size={16} aria-hidden />
            接続確認
          </button>
        </div>
        {message && <p className="apple-msg">{message}</p>}

        {activeJob && (
          <div className="apple-job-panel" role="status" aria-live="polite">
            <div className="apple-job-panel-header">
              <span className="apple-job-title">解析ジョブ</span>
              <span className="apple-job-id">{activeJob.id.slice(0, 8)}…</span>
            </div>
            <p className="apple-job-file">{activeJob.filename}</p>

            {!jobSnapshot && (
              <>
                <div className="apple-progress-track apple-progress-track--indeterminate" aria-hidden>
                  <div className="apple-progress-fill" />
                </div>
                <div className="apple-job-row">
                  <Loader2 className="apple-job-icon apple-spin" aria-hidden />
                  <p className="apple-job-status">ジョブ状態を取得しています…</p>
                </div>
              </>
            )}

            {jobSnapshot && (jobSnapshot.status === 'queued' || jobSnapshot.status === 'running') && (
              <>
                {jobSnapshot.status === 'running' &&
                typeof jobSnapshot.progress_percent === 'number' &&
                jobSnapshot.progress_percent >= 0 ? (
                  <div
                    className="apple-progress-track apple-progress-track--determinate"
                    role="progressbar"
                    aria-valuenow={Math.round(jobSnapshot.progress_percent)}
                    aria-valuemin={0}
                    aria-valuemax={100}
                    aria-label="解析の進捗"
                  >
                    <div
                      className="apple-progress-fill apple-progress-fill--determinate"
                      style={{ width: `${Math.min(100, Math.max(0, jobSnapshot.progress_percent))}%` }}
                    />
                  </div>
                ) : (
                  <div className="apple-progress-track apple-progress-track--indeterminate" aria-hidden>
                    <div className="apple-progress-fill" />
                  </div>
                )}
                {jobSnapshot.status === 'running' &&
                  (typeof jobSnapshot.progress_percent !== 'number' || jobSnapshot.progress_percent < 0) && (
                    <p className="apple-job-progress-hint">
                      Ghidra 自動解析・プロジェクト準備中は％表示がありません。postScript 開始後に目安が表示されます。
                    </p>
                  )}
              </>
            )}

            {jobSnapshot?.status === 'completed' && (
              <div className="apple-progress-track apple-progress-track--done" aria-hidden>
                <div className="apple-progress-fill apple-progress-fill--full" />
              </div>
            )}

            {jobSnapshot?.status === 'failed' && (
              <div className="apple-progress-track apple-progress-track--error" aria-hidden>
                <div className="apple-progress-fill apple-progress-fill--full" />
              </div>
            )}

            {jobSnapshot && (
              <div className="apple-job-row">
                {jobSnapshot.status === 'completed' && (
                  <CheckCircle2 className="apple-job-icon apple-job-icon--ok" aria-hidden />
                )}
                {jobSnapshot.status === 'failed' && (
                  <XCircle className="apple-job-icon apple-job-icon--err" aria-hidden />
                )}
                {(jobSnapshot.status === 'queued' || jobSnapshot.status === 'running') && (
                  <Loader2 className="apple-job-icon apple-spin" aria-hidden />
                )}
                <div>
                  <p className="apple-job-status">{statusLabelJa(jobSnapshot.status)}</p>
                  {jobSnapshot.status === 'running' && typeof jobSnapshot.progress_percent === 'number' && (
                    <p className="apple-job-progress-pct">進捗 約 {Math.round(jobSnapshot.progress_percent)} ％</p>
                  )}
                  {(jobSnapshot.status === 'queued' || jobSnapshot.status === 'running') && (
                    <p className="apple-job-elapsed">経過 {elapsedSec} 秒</p>
                  )}
                </div>
              </div>
            )}

            {jobSnapshot?.progress_message &&
              (jobSnapshot.status === 'queued' ||
                jobSnapshot.status === 'running' ||
                jobSnapshot.status === 'failed') && (
                <pre className="apple-job-log">{jobSnapshot.progress_message}</pre>
              )}

            {jobSnapshot?.status === 'failed' && jobSnapshot.error && (
              <p className="apple-job-error">{jobSnapshot.error}</p>
            )}

            <button
              type="button"
              className="apple-btn apple-btn-outline apple-job-dismiss"
              onClick={() => {
                setActiveJob(null);
                setJobSnapshot(null);
              }}
            >
              閉じる
            </button>
          </div>
        )}

        <p className="apple-caption">
          バックエンド: {health?.status ?? '…'}
          {ghidraCliFlag !== undefined && ` · Ghidra CLI: ${ghidraCliFlag ? '利用可能' : '未検出'}`}
        </p>
      </section>

      {analysisData && (
        <section className="apple-workspace" aria-label="解析結果ワークスペース">
          <div className="apple-ws-head">
            <div>
              <h3 className="apple-ws-file">{analysisData.file_name}</h3>
              <p className="apple-ws-meta">
                {loadedFilename && <span className="apple-ws-chip">{loadedFilename}</span>}
                <span className="apple-ws-chip">{analysisData.architecture}</span>
                <span className="apple-ws-chip">{analysisData.compiler}</span>
                <span className="apple-ws-chip">関数 {analysisData.functions.length} 件</span>
                {analysisData.truncated && (
                  <span className="apple-ws-chip apple-ws-chip--warn">一覧は上限で切り詰め</span>
                )}
              </p>
            </div>
          </div>

          <div className="apple-ws-grid">
            <div className="apple-ws-col apple-ws-col--tree">
              <div className="apple-ws-col-head">
                <span>関数</span>
                <span className="apple-ws-col-sub">名前空間ツリー（::） / 検索</span>
              </div>
              <input
                type="search"
                className="apple-fn-search"
                placeholder="名前・アドレス・デコンパイル文で検索…"
                value={fnSearch}
                onChange={(e) => setFnSearch(e.target.value)}
                aria-label="関数検索"
              />
              <div className="apple-fn-tree-wrap">
                <FunctionTree
                  functions={analysisData.functions}
                  indices={filteredIndices}
                  selectedIndex={selectedFnIndex}
                  onSelect={setSelectedFnIndex}
                />
              </div>
            </div>
            <div className="apple-ws-col apple-ws-col--detail">
              <AnalysisDetail
                key={analysisData.file_name}
                data={analysisData}
                selectedFnIndex={selectedFnIndex}
                onSelectFunctionByAddress={onSelectFunctionByAddress}
                loadedFilename={loadedFilename}
              />
            </div>
          </div>
        </section>
      )}

      {!analysisData && (
        <p className="apple-analyze-empty">
          まだ解析データがありません。検体をアップロードするか、履歴から結果を開いてください。
        </p>
      )}
    </div>
  );
}
