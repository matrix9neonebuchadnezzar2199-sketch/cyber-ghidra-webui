import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  CheckCircle2,
  ExternalLink,
  FileUp,
  Loader2,
  Minus,
  Plus,
  RefreshCw,
  ScanLine,
  XCircle,
} from 'lucide-react';
import { useApiBase } from '../context/ApiContext';
import { useAnalysisResult } from '../context/AnalysisResultContext';
import { AnalysisDetail } from './analysis/AnalysisDetail';
import { FunctionTree } from './analysis/FunctionTree';
import { filterFunctionIndices } from './analysis/functionTreeUtils';
import {
  buildStaticScanExecutiveSummary,
  extractOverallRiskFromRecord,
  isRiskConcerning,
  presentOverallRisk,
  staticScanHighlightLines,
} from '../utils/safetyMeta';

const STATIC_SCAN_FONT_LS_KEY = 'cyberghidra_staticScanOutFontPx';

function readInitialStaticScanFontPx(): number {
  if (typeof window === 'undefined') return 14;
  try {
    const s = localStorage.getItem(STATIC_SCAN_FONT_LS_KEY);
    const n = s == null ? NaN : parseInt(s, 10);
    if (Number.isFinite(n) && n >= 10 && n <= 24) return n;
  } catch {
    /* ignore */
  }
  return 14;
}

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
  /** ghidra: ワーカーが analyzeHeadless。static_only: 拡張子/MIME で静的分析のみ */
  analysis_mode?: 'ghidra' | 'static_only';
  static_scan?: Record<string, unknown>;
  ghidra_skipped?: boolean;
  detected_file_type?: string;
  unpack_info?: {
    attempted?: boolean;
    unpacked?: boolean;
    packer_chain?: string;
    /** 旧 status.json 互換 */
    packer_name?: string;
    total_layers?: number;
    original_sha256?: string;
    reason?: string;
  };
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

type AnalysisViewProps = {
  /** 履歴から行クリック → 同じタブ内で当該 job を再表示 */
  reopenJobId?: string | null;
  onReopenConsumed?: () => void;
};

type BatchEntry = {
  key: string;
  jobId: string;
  filename: string;
  analysisMode: 'ghidra' | 'static_only';
  snapshot: JobStatus | null;
  error?: string;
};

function jobStatusLine(status: string, mode?: 'ghidra' | 'static_only') {
  if (mode === 'static_only' && status === 'completed') {
    return '静的分析が完了しました（Ghidra は起動しません）';
  }
  if (mode === 'static_only' && status === 'failed') {
    return '静的分析に失敗しました';
  }
  return statusLabelJa(status);
}

function openJobInNewWindow(jobId: string) {
  if (typeof window === 'undefined' || !jobId) return;
  const u = new URL(window.location.href);
  u.searchParams.set('jobId', jobId);
  window.open(u.toString(), '_blank', 'noopener,noreferrer');
}

export function AnalysisView({ reopenJobId = null, onReopenConsumed = () => undefined }: AnalysisViewProps) {
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
  const [statusMessage, setStatusMessage] = useState<string | null>(null);
  const [activeJob, setActiveJob] = useState<{ id: string; filename: string; startedAt: number } | null>(
    null,
  );
  const [jobSnapshot, setJobSnapshot] = useState<JobStatus | null>(null);
  const pollRef = useRef<number | null>(null);

  const [health, setHealth] = useState<{
    status?: string;
    ghidra_cli?: boolean;
    ghidra?: boolean;
    auto_unpack?: boolean;
  } | null>(null);

  const [elapsedPulse, setElapsedPulse] = useState(0);
  const [archivePassword, setArchivePassword] = useState('infected');
  const [scanBusy, setScanBusy] = useState(false);
  const [scanError, setScanError] = useState<string | null>(null);
  const [scanSummary, setScanSummary] = useState<string | null>(null);
  const [staticScanFontPx, setStaticScanFontPx] = useState(readInitialStaticScanFontPx);
  const [batchEntries, setBatchEntries] = useState<BatchEntry[] | null>(null);
  const [selectedBatchKey, setSelectedBatchKey] = useState<string | null>(null);
  const batchEntriesRef = useRef<BatchEntry[] | null>(null);
  const selectedBatchKeyRef = useRef<string | null>(null);
  const lastGhidraLoadedForJobRef = useRef<string | null>(null);

  batchEntriesRef.current = batchEntries;
  selectedBatchKeyRef.current = selectedBatchKey;

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
    if (batchEntries && batchEntries.length > 0) {
      if (pollRef.current !== null) {
        window.clearInterval(pollRef.current);
        pollRef.current = null;
      }
      return;
    }

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
          if (data.status === 'completed' && data.analysis_mode === 'static_only' && data.static_scan) {
            setScanSummary(JSON.stringify(data.static_scan, null, 2));
            return;
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
  }, [activeJob, apiBase, loadResultFile, batchEntries]);

  useEffect(() => {
    if (!activeJob || !jobSnapshot) return;
    if (jobSnapshot.analysis_mode === 'static_only') return;
    if (jobSnapshot.status !== 'queued' && jobSnapshot.status !== 'running') return;
    const id = window.setInterval(() => setElapsedPulse((t) => t + 1), 500);
    return () => window.clearInterval(id);
  }, [activeJob, jobSnapshot?.status, jobSnapshot?.analysis_mode]);

  const elapsedSec = useMemo(() => {
    if (!activeJob || !jobSnapshot) return 0;
    if (jobSnapshot.status !== 'queued' && jobSnapshot.status !== 'running') return 0;
    return Math.floor((Date.now() - activeJob.startedAt) / 1000);
  }, [activeJob, jobSnapshot, elapsedPulse]);

  const runStaticScan = useCallback(async () => {
    if (!activeJob?.id) return;
    setScanBusy(true);
    setScanError(null);
    setScanSummary(null);
    try {
      const r = await fetch(
        `${apiBase}/api/scan/${encodeURIComponent(activeJob.id)}`,
        { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' },
      );
      const data = (await r.json().catch(() => ({}))) as Record<string, unknown>;
      if (!r.ok) {
        const d = data?.detail;
        setScanError(typeof d === 'string' ? d : r.statusText || '静的分析に失敗しました');
        return;
      }
      setScanSummary(JSON.stringify(data, null, 2));
    } catch (e) {
      setScanError(e instanceof Error ? e.message : '静的分析のリクエストに失敗しました');
    } finally {
      setScanBusy(false);
    }
  }, [apiBase, activeJob?.id]);

  const adjustStaticScanFont = useCallback((delta: number) => {
    setStaticScanFontPx((prev) => {
      const next = Math.min(24, Math.max(10, prev + delta));
      try {
        localStorage.setItem(STATIC_SCAN_FONT_LS_KEY, String(next));
      } catch {
        /* ignore */
      }
      return next;
    });
  }, []);

  const applyEntryToDetail = useCallback(
    (e: BatchEntry) => {
      if (!e.jobId || e.error) return;
      setActiveJob({ id: e.jobId, filename: e.filename, startedAt: Date.now() });
      const s = e.snapshot;
      if (!s) {
        setJobSnapshot(null);
        setScanSummary(null);
        return;
      }
      setJobSnapshot(s);
      if (e.analysisMode === 'static_only' && s.static_scan) {
        setScanSummary(JSON.stringify(s.static_scan, null, 2));
        return;
      }
      setScanSummary(null);
      if (e.analysisMode === 'ghidra' && s.status === 'completed' && s.analysis_json) {
        if (lastGhidraLoadedForJobRef.current !== e.jobId) {
          lastGhidraLoadedForJobRef.current = e.jobId;
          void loadResultFile(s.analysis_json).then((ok) => {
            if (!ok) setMessage('解析JSONを開けませんでした');
          });
        }
      }
    },
    [loadResultFile],
  );

  useEffect(() => {
    if (!reopenJobId) return;
    let cancel = false;
    (async () => {
      setBatchEntries(null);
      setSelectedBatchKey(null);
      setStatusMessage(null);
      setMessage(null);
      setScanError(null);
      setScanSummary(null);
      setJobSnapshot(null);
      lastGhidraLoadedForJobRef.current = null;
      const r = await fetch(`${apiBase}/api/jobs/${encodeURIComponent(reopenJobId)}`);
      if (cancel) return;
      if (!r.ok) {
        if (!cancel) {
          setMessage('履歴のジョブを読み取れませんでした');
          onReopenConsumed();
        }
        return;
      }
      const data = (await r.json()) as JobStatus;
      setActiveJob({
        id: reopenJobId,
        filename: data.filename || '',
        startedAt: Date.now(),
      });
      setJobSnapshot(data);
      if (data.analysis_mode === 'static_only' && data.static_scan) {
        setScanSummary(JSON.stringify(data.static_scan, null, 2));
      } else {
        setScanSummary(null);
      }
      if (data.analysis_mode === 'ghidra' && data.status === 'completed' && data.analysis_json) {
        const ok = await loadResultFile(data.analysis_json);
        if (!ok) setMessage('解析JSONを開けませんでした');
        lastGhidraLoadedForJobRef.current = reopenJobId;
      }
      if (!cancel) onReopenConsumed();
    })();
    return () => {
      cancel = true;
    };
  }, [reopenJobId, apiBase, loadResultFile, onReopenConsumed]);

  useEffect(() => {
    if (!batchEntries?.length) return;
    const tick = async () => {
      const list = batchEntriesRef.current;
      if (!list?.length) return;
      const out: BatchEntry[] = [];
      for (const e of list) {
        if (!e.jobId || e.error) {
          out.push(e);
          continue;
        }
        const r = await fetch(`${apiBase}/api/jobs/${encodeURIComponent(e.jobId)}`);
        if (!r.ok) {
          out.push(e);
          continue;
        }
        const data = (await r.json()) as JobStatus;
        out.push({ ...e, snapshot: data });
      }
      setBatchEntries(out);
      const selK = selectedBatchKeyRef.current;
      const pick =
        out.find((x) => x.key === selK) ||
        out.find((x) => x.jobId && !x.error) ||
        out[0];
      if (pick && pick.jobId && !pick.error) {
        applyEntryToDetail(pick);
      }
    };
    void tick();
    const t = window.setInterval(() => void tick(), 2000);
    return () => window.clearInterval(t);
  }, [apiBase, applyEntryToDetail, batchEntries?.length]);

  const onUpload = async (files: FileList | null) => {
    if (!files?.length) return;
    setBusy(true);
    setMessage(null);
    setStatusMessage(null);
    setScanError(null);
    setScanSummary(null);
    setBatchEntries(null);
    setSelectedBatchKey(null);
    lastGhidraLoadedForJobRef.current = null;
    if (files.length > 1) {
      setActiveJob(null);
      setJobSnapshot(null);
    }
    if (files.length > 1) {
      try {
        const arr = Array.from(files);
        const entries: BatchEntry[] = [];
        for (let i = 0; i < arr.length; i += 1) {
          const file = arr[i];
          const key = `m-${i}-${file.name}`;
          const fd = new FormData();
          fd.append('file', file);
          fd.append('archive_password', archivePassword);
          // eslint-disable-next-line no-await-in-loop
          const r = await fetch(`${apiBase}/api/upload`, { method: 'POST', body: fd });
          // eslint-disable-next-line no-await-in-loop
          const data = (await r.json().catch(() => ({}))) as Record<string, unknown>;
          if (!r.ok) {
            entries.push({
              key,
              jobId: '',
              filename: file.name,
              analysisMode: 'ghidra',
              snapshot: null,
              error:
                typeof data.detail === 'string' ? data.detail : `HTTP ${r.status} ${r.statusText}`,
            });
            continue;
          }
          if (data.archive === true || data.archive === 'true' || data.archive === 1) {
            entries.push({
              key,
              jobId: '',
              filename: file.name,
              analysisMode: 'ghidra',
              snapshot: null,
              error: 'アーカイブは1ファイルずつ選んでください（一括に混ぜない）',
            });
            continue;
          }
          const jid = typeof data.job_id === 'string' ? data.job_id : '';
          if (!jid) {
            entries.push({
              key,
              jobId: '',
              filename: file.name,
              analysisMode: 'ghidra',
              snapshot: null,
              error: 'job_id がありません',
            });
            continue;
          }
          // eslint-disable-next-line no-await-in-loop
          const jr = await fetch(`${apiBase}/api/jobs/${encodeURIComponent(jid)}`);
          let snap: JobStatus | null = null;
          if (jr.ok) {
            snap = (await jr.json()) as JobStatus;
          }
          const am = data.analysis_mode === 'static_only' ? 'static_only' : 'ghidra';
          entries.push({ key, jobId: jid, filename: file.name, analysisMode: am, snapshot: snap });
        }
        setBatchEntries(entries);
        const firstOk = entries.find((e) => e.jobId && !e.error) ?? null;
        if (firstOk) {
          setSelectedBatchKey(firstOk.key);
          applyEntryToDetail(firstOk);
        } else {
          setMessage('一括のうち成功したジョブがありません');
        }
        setStatusMessage(
          `複数件: ${entries.filter((e) => e.jobId && !e.error).length}/${entries.length} 件受理`,
        );
      } catch (e) {
        setMessage(e instanceof Error ? e.message : '一括アップロードに失敗しました');
      } finally {
        setBusy(false);
      }
      return;
    }

    const fd = new FormData();
    fd.append('file', files[0]);
    fd.append('archive_password', archivePassword);
    try {
      const r = await fetch(`${apiBase}/api/upload`, { method: 'POST', body: fd });
      const data = (await r.json()) as Record<string, unknown>;
      if (!r.ok) {
        setActiveJob(null);
        setMessage(typeof data.detail === 'string' ? data.detail : JSON.stringify(data));
      } else {
        const isArchive =
          data.archive === true ||
          data.archive === 'true' ||
          data.archive === 1;
        if (isArchive) {
          const count =
            typeof data.count === 'number' ? data.count : Number(data.count) || 0;
          const jobsList = Array.isArray(data.jobs) ? data.jobs : [];
          setMessage(null);
          setStatusMessage(`アーカイブから ${count} 件のバイナリを検出しました`);
          if (jobsList.length > 0) {
            const entries: BatchEntry[] = [];
            for (let i = 0; i < jobsList.length; i += 1) {
              const j0 = jobsList[i] as {
                job_id?: unknown;
                filename?: unknown;
                analysis_mode?: unknown;
                static_scan?: unknown;
                error?: unknown;
              };
              const fn = typeof j0.filename === 'string' ? j0.filename : `file-${i + 1}`;
              const key = `a-${i}-${fn}`;
              if (j0.error != null && j0.error !== '') {
                entries.push({
                  key,
                  jobId: '',
                  filename: fn,
                  analysisMode: 'ghidra',
                  snapshot: null,
                  error: String(j0.error),
                });
                continue;
              }
              const jid = typeof j0.job_id === 'string' ? j0.job_id : '';
              if (!jid) {
                entries.push({
                  key,
                  jobId: '',
                  filename: fn,
                  analysisMode: 'ghidra',
                  snapshot: null,
                  error: 'job_id がありません',
                });
                continue;
              }
              const jmode = j0.analysis_mode === 'static_only' ? 'static_only' : 'ghidra';
              // eslint-disable-next-line no-await-in-loop
              const jr = await fetch(`${apiBase}/api/jobs/${encodeURIComponent(jid)}`);
              let snap: JobStatus | null = null;
              if (jr.ok) {
                snap = (await jr.json()) as JobStatus;
              } else if (
                jmode === 'static_only' &&
                j0.static_scan &&
                typeof j0.static_scan === 'object'
              ) {
                snap = {
                  job_id: jid,
                  status: 'completed',
                  filename: fn,
                  analysis_mode: 'static_only',
                  static_scan: j0.static_scan as Record<string, unknown>,
                };
              }
              entries.push({ key, jobId: jid, filename: fn, analysisMode: jmode, snapshot: snap });
            }
            setBatchEntries(entries);
            const firstOk = entries.find((e) => e.jobId && !e.error) ?? null;
            if (firstOk) {
              setSelectedBatchKey(firstOk.key);
              applyEntryToDetail(firstOk);
            } else {
              setActiveJob(null);
              setJobSnapshot(null);
            }
          } else {
            setActiveJob(null);
          }
        } else {
          setStatusMessage(null);
          const jid = typeof data.job_id === 'string' ? data.job_id : '';
          const fn = typeof data.filename === 'string' ? data.filename : '';
          if (!jid) {
            setActiveJob(null);
            setMessage('アップロード応答が不正です（job_id がありません）');
          } else {
            setActiveJob({ id: jid, filename: fn, startedAt: Date.now() });
            if (data.analysis_mode === 'static_only') {
              const r = await fetch(`${apiBase}/api/jobs/${encodeURIComponent(jid)}`);
              if (r.ok) {
                setJobSnapshot((await r.json()) as JobStatus);
              } else {
                setJobSnapshot(null);
              }
              if (data.static_scan && typeof data.static_scan === 'object') {
                setScanSummary(JSON.stringify(data.static_scan, null, 2));
              } else {
                setScanSummary(null);
              }
            } else {
              setJobSnapshot(null);
            }
          }
        }
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

  const jobIsStaticOnly = jobSnapshot?.analysis_mode === 'static_only';
  const jobHeaderTitle = !jobSnapshot
    ? '解析ジョブ'
    : jobIsStaticOnly
      ? '静的分析ジョブ'
      : 'Ghidra 解析ジョブ';
  const showGhidraProgress = Boolean(
    jobSnapshot && !jobIsStaticOnly && (jobSnapshot.status === 'queued' || jobSnapshot.status === 'running'),
  );

  return (
    <div
      className={
        analysisData ? 'apple-analyze apple-analyze--with-ws' : 'apple-analyze'
      }
    >
      <section className="apple-analyze-hero">
        <h2 className="apple-analyze-title">解析</h2>
        <p className="apple-analyze-lead">
          「検体を選ぶ」で <strong>複数ファイル</strong>を選べます（一括行は下の一覧・各行で切替）。1
          件のとき従来どおり。<strong>PE/ELF 等</strong>は
          <strong> Ghidra</strong> へ、<strong>PDF / Office</strong> 等は
          <strong> 静的分析</strong>へ、バックエンドが振り分け。ZIP/7z
          はこの欄のパスワードで展開し、<strong>7z や中身用の再展開用 zip のみ同じパスワードで繰り返し展開</strong>（docx/pptx 等は
          1 ファイル扱いで中身の xml/フォントをばらしません）してからジョブ化。一覧の「
          別タブ」で行ごとに別ウィンドウで開けます（一括にアーカイブを混ぜないでください）。
        </p>
        <p className="apple-analyze-hint">
          ジョブ欄の見出しが <strong>「Ghidra 解析」</strong> か <strong>「静的分析」</strong> かで処理が分かれます。PDF/Office
          で Ghidra が出ないのは想定動作です。Ghidra 用の待ちバーはネイティブ系ジョブにだけ表示されます。
        </p>
      </section>

      <section className="apple-toolbar apple-toolbar--compact apple-analyze-toolstrip">
        <div className="apple-toolbar-row">
          <label className="apple-file-label apple-btn apple-btn-primary">
            {busy ? (
              <Loader2 size={18} className="apple-spin" aria-hidden />
            ) : (
              <FileUp size={18} aria-hidden />
            )}
            検体を選択
            <input
              type="file"
              className="apple-file-input"
              multiple
              disabled={busy}
              onChange={(e) => void onUpload(e.target.files)}
              title="Ctrl/Shift で複数可（ZIP は単体向け。混在時は1件ずつ推奨）"
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
        <div className="apple-settings-row" style={{ marginTop: 10 }}>
          <span className="apple-api-hint" style={{ whiteSpace: 'nowrap' }}>
            展開パスワード（各層）
          </span>
          <input
            type="text"
            value={archivePassword}
            onChange={(e) => setArchivePassword(e.target.value)}
            className="apple-settings-input"
            style={{ flex: '0 1 12rem', minWidth: '8rem', fontSize: 13, padding: '6px 10px' }}
            placeholder="infected"
            disabled={busy}
            autoComplete="off"
            spellCheck={false}
            aria-label="アーカイブパスワード"
          />
        </div>
        {statusMessage && (
          <div
            className="apple-archive-status"
            style={{
              marginTop: 10,
              padding: '8px 16px',
              marginBottom: 4,
              fontSize: 14,
              lineHeight: 1.45,
              borderRadius: 10,
              color: '#6ee7b7',
              background: 'rgba(6, 78, 59, 0.28)',
              border: '1px solid rgba(52, 211, 153, 0.35)',
            }}
            role="status"
          >
            {statusMessage}
          </div>
        )}
        {message && <p className="apple-msg">{message}</p>}

        {batchEntries && batchEntries.length > 0 && (
          <div className="apple-batch-queue" role="region" aria-label="一括分析キュー">
            <h4 className="apple-batch-queue-title">ジョブ一覧（{batchEntries.length} 件）</h4>
            <p className="apple-batch-queue-hint">
              行を選ぶと下の詳細が切り替わります。各行のバーは解析の進行（100％で完了）。「別タブ」は当該ジョブの解析を別ウィンドウで表示します。静析は数秒で完了扱いです。
            </p>
            <ul className="apple-batch-list">
              {batchEntries.map((e) => {
                const s = e.snapshot;
                const risk = e.analysisMode === 'static_only' && s?.static_scan
                  ? extractOverallRiskFromRecord(s.static_scan)
                  : null;
                const pr = presentOverallRisk(risk);
                const pct =
                  s?.analysis_mode !== 'static_only' &&
                  typeof s?.progress_percent === 'number' &&
                  s.progress_percent >= 0
                    ? Math.round(s.progress_percent)
                    : null;
                const doneStatic =
                  e.analysisMode === 'static_only' && s?.status === 'completed';
                const failStatic =
                  e.analysisMode === 'static_only' && s?.status === 'failed';
                const doneGh =
                  e.analysisMode === 'ghidra' && s?.status === 'completed';
                const failGh = e.analysisMode === 'ghidra' && s?.status === 'failed';
                return (
                  <li key={e.key} className="apple-batch-item">
                    <div className="apple-batch-item-row">
                      <button
                        type="button"
                        className={
                          e.key === selectedBatchKey
                            ? 'apple-batch-row is-selected'
                            : 'apple-batch-row'
                        }
                        onClick={() => {
                          setSelectedBatchKey(e.key);
                          const cur = batchEntriesRef.current?.find((x) => x.key === e.key);
                          if (cur) applyEntryToDetail(cur);
                        }}
                      >
                        <span className="apple-batch-name">{e.filename}</span>
                        {e.error ? (
                          <span className="apple-batch-status apple-batch-status--err">{e.error}</span>
                        ) : e.analysisMode === 'static_only' ? (
                          <span
                            className={
                              s
                                ? `apple-risk apple-risk--${pr.tone}`
                                : 'apple-batch-status'
                            }
                          >
                            {failStatic
                              ? '失敗'
                              : doneStatic
                                ? '完了'
                                : s
                                  ? pr.label
                                  : '…'}
                          </span>
                        ) : (
                          <span className="apple-batch-gh">
                            {s?.status === 'running' && pct != null
                              ? `Ghidra ${pct}%`
                              : s?.status === 'completed'
                                ? '完了'
                                : s?.status === 'failed'
                                  ? '失敗'
                                  : s?.status || '—'}
                          </span>
                        )}
                      </button>
                      {e.jobId && !e.error ? (
                        <button
                          type="button"
                          className="apple-batch-external"
                          onClick={() => {
                            openJobInNewWindow(e.jobId);
                          }}
                          title="このジョブの解析を別タブで開く"
                        >
                          <ExternalLink size={16} strokeWidth={2.25} aria-hidden />
                          別タブ
                        </button>
                      ) : null}
                    </div>
                    {!e.error && e.jobId
                      ? (() => {
                          if (e.analysisMode === 'static_only') {
                            if (failStatic) {
                              return (
                                <div
                                  className="apple-progress-track apple-progress-track--error"
                                  style={{ marginTop: 4 }}
                                >
                                  <div className="apple-progress-fill apple-progress-fill--full" />
                                </div>
                              );
                            }
                            if (doneStatic) {
                              return (
                                <div
                                  className="apple-progress-track apple-progress-track--done"
                                  style={{ marginTop: 4 }}
                                >
                                  <div className="apple-progress-fill apple-progress-fill--full" />
                                </div>
                              );
                            }
                            if (!s) {
                              return (
                                <div
                                  className="apple-progress-track apple-progress-track--indeterminate"
                                  style={{ marginTop: 4 }}
                                >
                                  <div className="apple-progress-fill" />
                                </div>
                              );
                            }
                            if (s.status === 'running') {
                              return (
                                <div
                                  className="apple-progress-track apple-progress-track--indeterminate"
                                  style={{ marginTop: 4 }}
                                >
                                  <div className="apple-progress-fill" />
                                </div>
                              );
                            }
                            return (
                              <div
                                className="apple-progress-track apple-progress-track--indeterminate"
                                style={{ marginTop: 4 }}
                              >
                                <div className="apple-progress-fill" />
                              </div>
                            );
                          }
                          if (e.analysisMode === 'ghidra' && s) {
                            if (failGh) {
                              return (
                                <div
                                  className="apple-progress-track apple-progress-track--error"
                                  style={{ marginTop: 4 }}
                                >
                                  <div className="apple-progress-fill apple-progress-fill--full" />
                                </div>
                              );
                            }
                            if (doneGh) {
                              return (
                                <div
                                  className="apple-progress-track apple-progress-track--done"
                                  style={{ marginTop: 4 }}
                                >
                                  <div className="apple-progress-fill apple-progress-fill--full" />
                                </div>
                              );
                            }
                            if (s.status === 'running') {
                              if (pct != null) {
                                return (
                                  <div
                                    className="apple-progress-track apple-progress-track--determinate"
                                    style={{ marginTop: 4 }}
                                    role="progressbar"
                                    aria-valuenow={pct}
                                    aria-valuemin={0}
                                    aria-valuemax={100}
                                  >
                                    <div
                                      className="apple-progress-fill apple-progress-fill--determinate"
                                      style={{ width: `${Math.min(100, Math.max(0, pct))}%` }}
                                    />
                                  </div>
                                );
                              }
                              return (
                                <div
                                  className="apple-progress-track apple-progress-track--indeterminate"
                                  style={{ marginTop: 4 }}
                                >
                                  <div className="apple-progress-fill" />
                                </div>
                              );
                            }
                            if (s.status === 'queued') {
                              return (
                                <div
                                  className="apple-progress-track apple-progress-track--indeterminate"
                                  style={{ marginTop: 4 }}
                                >
                                  <div className="apple-progress-fill" />
                                </div>
                              );
                            }
                            return null;
                          }
                          return (
                            <div
                              className="apple-progress-track apple-progress-track--indeterminate"
                              style={{ marginTop: 4 }}
                            >
                              <div className="apple-progress-fill" />
                            </div>
                          );
                        })()
                      : null}
                  </li>
                );
              })}
            </ul>
          </div>
        )}

        {activeJob?.id && (
          <div className="apple-job-panel" role="status" aria-live="polite">
            <div className="apple-job-panel-header">
              <span className="apple-job-title">{jobHeaderTitle}</span>
              <span className="apple-job-id">{activeJob.id.slice(0, 8)}…</span>
            </div>
            {!jobIsStaticOnly && jobSnapshot && (
              <p className="apple-job-note" role="note">
                待ち・進行・失敗（％付き）の表示は<strong>ワーカー上の Ghidra Headless</strong> 向けです。
              </p>
            )}
            {jobIsStaticOnly && jobSnapshot && (
              <p className="apple-job-note" role="note">
                このファイルは <strong>静的分析のみ</strong>です。Ghidra
                ワーカーはキューに乗りません。結果は下の「静的分析」枠の JSON です。
              </p>
            )}
            <p className="apple-job-file">{activeJob.filename}</p>
            {jobIsStaticOnly && jobSnapshot?.detected_file_type ? (
              <p className="apple-job-detected" style={{ fontSize: 13, opacity: 0.9, marginTop: 4 }}>
                推定: {String(jobSnapshot.detected_file_type)}
              </p>
            ) : null}

            {jobSnapshot?.unpack_info?.attempted && (
              <div className="apple-unpack-badge" role="status">
                {jobSnapshot.unpack_info.unpacked ? (
                  <span className="apple-unpack-badge--success">
                    ✓ アンパック済み
                    {(() => {
                      const chain =
                        jobSnapshot.unpack_info.packer_chain ||
                        jobSnapshot.unpack_info.packer_name ||
                        '?';
                      const layers = jobSnapshot.unpack_info.total_layers;
                      return layers != null && layers > 1
                        ? `（${layers}層: ${chain}）`
                        : `（${chain}）`;
                    })()}
                  </span>
                ) : (
                  <span className="apple-unpack-badge--skip">
                    パック未検出 — 元のバイナリで解析
                  </span>
                )}
              </div>
            )}

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

            {showGhidraProgress && jobSnapshot && (
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
                {jobSnapshot.analysis_mode !== 'static_only' &&
                  (jobSnapshot.status === 'queued' || jobSnapshot.status === 'running') && (
                    <Loader2 className="apple-job-icon apple-spin" aria-hidden />
                  )}
                <div>
                  <p className="apple-job-status">
                    {jobStatusLine(
                      jobSnapshot.status,
                      jobSnapshot.analysis_mode === 'static_only' ? 'static_only' : 'ghidra',
                    )}
                  </p>
                  {jobSnapshot.status === 'running' && typeof jobSnapshot.progress_percent === 'number' && (
                    <p className="apple-job-progress-pct">進捗 約 {Math.round(jobSnapshot.progress_percent)} ％</p>
                  )}
                  {(jobSnapshot.status === 'queued' || jobSnapshot.status === 'running') && (
                    <p className="apple-job-elapsed">経過 {elapsedSec} 秒</p>
                  )}
                </div>
              </div>
            )}

            {jobSnapshot?.analysis_mode !== 'static_only' &&
              jobSnapshot?.progress_message &&
              (jobSnapshot.status === 'queued' ||
                jobSnapshot.status === 'running' ||
                jobSnapshot.status === 'failed') && (
                <pre className="apple-job-log">{jobSnapshot.progress_message}</pre>
              )}

            {jobSnapshot?.status === 'failed' && jobSnapshot.error && (
              <p className="apple-job-error">{jobSnapshot.error}</p>
            )}

            <div className="apple-static-scan" role="region" aria-label="静的分析">
              <h4 className="apple-static-scan-title">
                <ScanLine size={16} aria-hidden className="apple-static-scan-ico" />
                静的分析（スキャンモジュール）
              </h4>
              <p className="apple-static-scan-hint">
                {jobIsStaticOnly && jobSnapshot?.status === 'completed' ? (
                  <>
                    このルートはアップロード直後に<strong>自動で</strong>静的分析済みです。Ghidra とは
                    <strong>別</strong>のバックエンド（oletools / pdfid / pefile 等。サーバ設定）です。再取得するには下のボタン。
                  </>
                ) : (
                  <>
                    Ghidra とは<strong>別</strong>のバックエンド処理です。PDF/Office/PE
                    など形式に応じスキャンが走ります（サーバ設定による）。PDF/Office は主にこちらが本線です。
                  </>
                )}
              </p>
              <div className="apple-static-scan-actions">
                <button
                  type="button"
                  className="apple-btn apple-btn-outline"
                  disabled={scanBusy}
                  onClick={() => void runStaticScan()}
                >
                  {scanBusy ? <Loader2 size={16} className="apple-spin" aria-hidden /> : null}
                  静的分析を実行
                </button>
                {scanError && <p className="apple-static-scan-err">{scanError}</p>}
              </div>
              {jobIsStaticOnly && jobSnapshot?.static_scan && (() => {
                const o = jobSnapshot.static_scan;
                const risk = extractOverallRiskFromRecord(o);
                const exec = buildStaticScanExecutiveSummary(o);
                const lines = staticScanHighlightLines(o, 10);
                if (exec.length === 0 && lines.length === 0) return null;
                return (
                  <div className="apple-static-highlights" role="status">
                    {exec.length > 0 && (
                      <div className="apple-static-executive">
                        <p className="apple-static-executive-title">判定の要点（共有・報告用）</p>
                        <p className="apple-static-executive-lead">
                          下の <strong>総合 risk</strong> や「中〜高」の1行所見は、<strong>構造上の指標</strong>（例:
                          外部リレーション件数）で上がることがあります。まずは下表でマクロ等の有無を確認してください。
                        </p>
                        <dl className="apple-static-executive-dl">
                          {exec.map((it, i) => (
                            <div
                              key={i}
                              className={
                                it.level === 'positive'
                                  ? 'apple-static-executive-row is-positive'
                                  : it.level === 'negative' || it.level === 'caution'
                                    ? 'apple-static-executive-row is-warn'
                                    : 'apple-static-executive-row is-neutral'
                              }
                            >
                              <dt className="apple-static-executive-dt">{it.label}</dt>
                              <dd className="apple-static-executive-dd">{it.value}</dd>
                            </div>
                          ))}
                        </dl>
                      </div>
                    )}
                    {lines.length > 0 && (
                      <div className="apple-static-highlights-tech">
                        <p className="apple-static-highlights-title">
                          {isRiskConcerning(risk)
                            ? '技術メモ: 中〜高と判定された生の所見（抜粋）'
                            : '技術メモ（抜粋）'}
                        </p>
                        <ul className="apple-static-highlights-ul">
                          {lines.map((l, i) => (
                            <li key={i} className="apple-static-highlights-li">
                              {l}
                            </li>
                          ))}
                        </ul>
                      </div>
                    )}
                  </div>
                );
              })()}
              {scanSummary && (
                <>
                  <div className="apple-static-scan-prebar">
                    <span className="apple-static-scan-prebar-label">JSON 出力の文字</span>
                    <div className="apple-static-scan-prebar-ctrl" role="group" aria-label="静的分析 JSON の文字サイズ">
                      <button
                        type="button"
                        className="apple-static-scan-font-btn"
                        onClick={() => adjustStaticScanFont(-1)}
                        disabled={staticScanFontPx <= 10}
                        aria-label="1 段階小さく"
                        title="小さく"
                      >
                        <Minus size={16} strokeWidth={2.5} aria-hidden />
                      </button>
                      <span className="apple-static-scan-prebar-value" aria-live="polite">
                        {staticScanFontPx}px
                      </span>
                      <button
                        type="button"
                        className="apple-static-scan-font-btn"
                        onClick={() => adjustStaticScanFont(1)}
                        disabled={staticScanFontPx >= 24}
                        aria-label="1 段階大きく"
                        title="大きく"
                      >
                        <Plus size={16} strokeWidth={2.5} aria-hidden />
                      </button>
                    </div>
                  </div>
                  <pre
                    className="apple-static-scan-pre"
                    style={{ fontSize: staticScanFontPx }}
                    tabIndex={0}
                  >
                    {scanSummary}
                  </pre>
                </>
              )}
            </div>

            <button
              type="button"
              className="apple-btn apple-btn-outline apple-job-dismiss"
              onClick={() => {
                setActiveJob(null);
                setJobSnapshot(null);
                setStatusMessage(null);
                setScanError(null);
                setScanSummary(null);
                setBatchEntries(null);
                setSelectedBatchKey(null);
                lastGhidraLoadedForJobRef.current = null;
              }}
            >
              閉じる
            </button>
          </div>
        )}

        <p className="apple-caption">
          バックエンド: {health?.status ?? '…'}
          {ghidraCliFlag !== undefined && ` · Ghidra CLI: ${ghidraCliFlag ? '利用可能' : '未検出'}`}
          {health?.auto_unpack !== undefined &&
            ` · Auto-Unpack: ${health.auto_unpack ? '有効' : '無効'}`}
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
          まだ <strong>Ghidra 由来の逆解析</strong>（関数ツリー等）がありません。上で
          <strong>ネイティブ実行形式</strong>の検体を送るとワーカー解析後に表示されます。PDF/Office
          など静的分析ジョブではこのエリアは空のままが基本です。ジョブ欄の
          <strong>静的分析 JSON</strong>をご利用ください。履歴から従来の解析を開くこともできます。
        </p>
      )}
    </div>
  );
}
