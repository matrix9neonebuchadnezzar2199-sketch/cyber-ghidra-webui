import React, { useCallback, useEffect, useMemo, useState } from 'react';
import clsx from 'clsx';
import { Download } from 'lucide-react';
import type { AnalysisJson, CfgData } from '../../types/analysis';
import { useApiBase } from '../../context/ApiContext';
import { FlowGraphView } from './FlowGraphView';
import { ProgramCallGraphView } from './ProgramCallGraphView';
import { DecompileView } from './DecompileView';
import { FlowLegend } from './FlowLegend';
import { FlowExportMenu } from './FlowExportMenu';
import { XrefPanel } from './XrefPanel';
import { useFlowNavigation } from './useFlowNavigation';
import { extractSubgraph, filterGraphByName, removeIsolatedNodes } from './graphUtils';

type TabId = 'decompile' | 'flow' | 'strings' | 'imports' | 'entry' | 'suspicious' | 'metadata';

const TABS: { id: TabId; label: string }[] = [
  { id: 'decompile', label: '逆コンパイル' },
  { id: 'flow', label: 'フロー' },
  { id: 'strings', label: '文字列' },
  { id: 'imports', label: 'インポート' },
  { id: 'entry', label: 'エントリ' },
  { id: 'suspicious', label: '疑わしい API' },
  { id: 'metadata', label: 'メタデータ' },
];

type Props = {
  data: AnalysisJson;
  selectedFnIndex: number | null;
  onSelectFunctionByAddress?: (address: string) => void;
  /** 読み込み済みの analysis JSON ファイル名（ダウンロード URL の構築に使用） */
  loadedFilename?: string | null;
};

function findCfgBlockIdForAddress(cfg: CfgData, addr: string | null): string | null {
  if (!addr) return null;
  const direct = cfg.nodes.find((n) => n.id === addr || n.start === addr);
  if (direct) return direct.id;
  for (const n of cfg.nodes) {
    if (n.start <= addr && addr <= n.end) return n.id;
  }
  return null;
}

function buildCallGraphRiskMap(data: AnalysisJson): Map<string, string> {
  const m = new Map<string, string>();
  for (const s of data.suspicious_apis) {
    const f = data.functions.find((fn) => fn.name === s.seen_from);
    if (f) m.set(f.address, 'high');
  }
  for (const fn of data.functions) {
    if (m.has(fn.address)) continue;
    const highs = fn.decompile_insights?.signals.some((x) => x.severity === 'high');
    if (highs) m.set(fn.address, 'medium');
  }
  return m;
}

export function AnalysisDetail({
  data,
  selectedFnIndex,
  onSelectFunctionByAddress,
  loadedFilename,
}: Props) {
  const { apiBase } = useApiBase();
  const [tab, setTab] = useState<TabId>('decompile');
  const [filterStrings, setFilterStrings] = useState('');
  const [filterImports, setFilterImports] = useState('');

  const flowNav = useFlowNavigation();
  const [cgDepth, setCgDepth] = useState<number>(-1);
  const [cgFocusAddr, setCgFocusAddr] = useState<string | null>(null);
  const [hideIsolated, setHideIsolated] = useState(false);
  const [cgSearch, setCgSearch] = useState('');

  const [cfgHighlightBlockId, setCfgHighlightBlockId] = useState<string | null>(null);
  const [decompileHighlightLine, setDecompileHighlightLine] = useState<number | null>(null);

  const fn = selectedFnIndex !== null ? data.functions[selectedFnIndex] : null;

  const callGraphRiskMap = useMemo(() => buildCallGraphRiskMap(data), [data]);

  const filteredCallGraph = useMemo(() => {
    if (!data.call_graph) return null;
    let g = data.call_graph;

    if (cgFocusAddr && cgDepth >= 0) {
      g = extractSubgraph(g, cgFocusAddr, cgDepth);
    }

    if (hideIsolated) {
      g = removeIsolatedNodes(g);
    }

    return g;
  }, [data.call_graph, cgFocusAddr, cgDepth, hideIsolated]);

  const cgSearchMatchIds = useMemo(() => {
    if (!filteredCallGraph || !cgSearch.trim()) return undefined;
    const ids = filterGraphByName(filteredCallGraph, cgSearch).matchIds;
    if (ids.size === 0) return undefined;
    return ids;
  }, [filteredCallGraph, cgSearch]);

  useEffect(() => {
    setCfgHighlightBlockId(null);
    setDecompileHighlightLine(null);
  }, [fn?.address]);

  const filteredStrings = useMemo(() => {
    const q = filterStrings.trim().toLowerCase();
    if (!q) return data.strings;
    return data.strings.filter(
      (s) => s.value.toLowerCase().includes(q) || s.address.toLowerCase().includes(q),
    );
  }, [data.strings, filterStrings]);

  const filteredImports = useMemo(() => {
    const q = filterImports.trim().toLowerCase();
    if (!q) return data.imports;
    return data.imports.filter(
      (r) =>
        r.function.toLowerCase().includes(q) ||
        r.library.toLowerCase().includes(q) ||
        r.address.toLowerCase().includes(q),
    );
  }, [data.imports, filterImports]);

  const onDecompileLineClick = (lineNum: number, addr: string | null) => {
    setDecompileHighlightLine(lineNum);
    setTab('flow');
    if (fn) {
      flowNav.navigateTo({ type: 'cfg', functionAddress: fn.address, functionName: fn.name });
      if (fn.cfg && addr) {
        const bid = findCfgBlockIdForAddress(fn.cfg, addr);
        setCfgHighlightBlockId(bid);
      }
    }
  };

  const onCfgBlockSelect = (blockId: string) => {
    if (!fn?.cfg || !fn.line_address_map) return;
    const lm = fn.line_address_map;
    for (const [lineStr, addr] of Object.entries(lm)) {
      const bid = findCfgBlockIdForAddress(fn.cfg!, addr);
      if (bid === blockId) {
        setDecompileHighlightLine(Number(lineStr));
        return;
      }
    }
  };

  const handleDownloadDecompiled = useCallback(async () => {
    if (!loadedFilename) return;
    const url = `${apiBase}/api/results/${encodeURIComponent(loadedFilename)}/decompiled`;
    try {
      const res = await fetch(url);
      if (!res.ok) {
        const errText = await res.text();
        alert(`ダウンロード失敗 (${res.status}): ${errText}`);
        return;
      }
      const blob = await res.blob();
      const disposition = res.headers.get('Content-Disposition');
      let downloadName = loadedFilename.replace(/\.json$/, '') + '_decompiled.c';
      if (disposition) {
        const match = disposition.match(/filename="?(.+?)"?$/);
        if (match) downloadName = match[1];
      }
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = downloadName;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(a.href);
    } catch {
      alert('ダウンロードに失敗しました。サーバーとの接続を確認してください。');
    }
  }, [apiBase, loadedFilename]);

  return (
    <div className="apple-adetail">
      <div className="apple-adetail-toolbar">
        <button
          type="button"
          className="apple-btn apple-btn-outline"
          onClick={() => void handleDownloadDecompiled()}
          disabled={!loadedFilename}
          title="デコンパイル済みの全関数を .c ファイルとしてダウンロード（AI 分析用）"
        >
          <Download size={16} aria-hidden />
          全デコンパイルコードをダウンロード
        </button>
      </div>
      <div className="apple-adetail-tabs" role="tablist">
        {TABS.map((t) => (
          <button
            key={t.id}
            type="button"
            role="tab"
            aria-selected={tab === t.id}
            className={clsx('apple-adetail-tab', tab === t.id && 'apple-adetail-tab--active')}
            onClick={() => setTab(t.id)}
          >
            {t.label}
          </button>
        ))}
      </div>

      <div className="apple-adetail-body">
        {tab === 'decompile' && (
          <div className="apple-adetail-pane">
            {fn ? (
              <>
                <div className="apple-adetail-fnhead">
                  <span className="apple-adetail-fname">{fn.name}</span>
                  <span className="apple-adetail-fmeta">
                    {fn.address} · {fn.size} bytes
                  </span>
                </div>
                <DecompileView
                  fn={fn}
                  highlightLine={decompileHighlightLine}
                  onLineClick={onDecompileLineClick}
                />
                {fn.xrefs && (fn.xrefs.callers.length > 0 || fn.xrefs.callees.length > 0) && (
                  <XrefPanel
                    xrefs={fn.xrefs}
                    onNavigate={(addr) => {
                      onSelectFunctionByAddress?.(addr);
                    }}
                  />
                )}
              </>
            ) : (
              <p className="apple-adetail-hint">左のツリーから関数を選択してください。</p>
            )}
          </div>
        )}

        {tab === 'flow' && (
          <div className="apple-adetail-pane apple-adetail-pane--flow">
            <p className="apple-flow-ida-lead">
              IDA に近い運用: <strong>コールグラフ</strong>で全体を把握し、必要なら
              <strong>関数内 CFG</strong>へ。ブレッドクラムと「← 戻る」でビューを切り替えます。
            </p>

            <div className="cyber-flow-breadcrumb">
              {flowNav.canGoBack && (
                <button type="button" className="cyber-flow-breadcrumb-back" onClick={flowNav.goBack}>
                  ← 戻る
                </button>
              )}
              {flowNav.breadcrumbs.map((bc, i) => (
                <span key={i} className="cyber-flow-breadcrumb-item">
                  {i > 0 && <span className="cyber-flow-breadcrumb-sep"> › </span>}
                  {bc.type === 'callgraph'
                    ? 'コールグラフ'
                    : bc.functionName ?? bc.functionAddress ?? 'CFG'}
                </span>
              ))}
            </div>

            {flowNav.current.type === 'callgraph' && (
              <>
                <div className="cyber-flow-controls-bar">
                  <input
                    type="search"
                    className="cyber-flow-search"
                    placeholder="関数名・アドレスで検索…"
                    value={cgSearch}
                    onChange={(e) => setCgSearch(e.target.value)}
                  />
                  <FlowExportMenu callGraph={filteredCallGraph} />
                  <label className="cyber-flow-checkbox">
                    <input
                      type="checkbox"
                      checked={hideIsolated}
                      onChange={(e) => setHideIsolated(e.target.checked)}
                    />
                    孤立ノード非表示
                  </label>
                  <label className="cyber-flow-depth-label">
                    深さ制限:
                    <select
                      className="cyber-flow-depth-select"
                      value={cgDepth}
                      onChange={(e) => setCgDepth(Number(e.target.value))}
                    >
                      <option value={-1}>制限なし</option>
                      <option value={1}>1段</option>
                      <option value={2}>2段</option>
                      <option value={3}>3段</option>
                      <option value={5}>5段</option>
                    </select>
                  </label>
                  {cgFocusAddr && (
                    <button
                      type="button"
                      className="cyber-flow-reset-focus"
                      onClick={() => setCgFocusAddr(null)}
                    >
                      フォーカス解除
                    </button>
                  )}
                </div>

                {filteredCallGraph && filteredCallGraph.nodes.length > 0 ? (
                  <ProgramCallGraphView
                    graph={filteredCallGraph}
                    entryPoints={data.entry_points}
                    riskMap={callGraphRiskMap}
                    searchMatchIds={cgSearchMatchIds}
                    onSelectFunctionByAddress={(addr) => {
                      onSelectFunctionByAddress?.(addr);
                      if (cgDepth >= 0) setCgFocusAddr(addr);
                    }}
                    onOpenFunctionCfg={(addr) => {
                      onSelectFunctionByAddress?.(addr);
                      const fnInfo = data.functions.find((f) => f.address === addr);
                      flowNav.navigateTo({
                        type: 'cfg',
                        functionAddress: addr,
                        functionName: fnInfo?.name ?? addr,
                      });
                    }}
                  />
                ) : (
                  <p className="apple-adetail-hint">
                    コールグラフがありません。バックエンド更新後に検体を再解析してください。
                  </p>
                )}
              </>
            )}

            {flowNav.current.type === 'cfg' && (
              <>
                <div className="cyber-flow-controls-bar cyber-flow-controls-bar--cfg">
                  <FlowLegend />
                  <FlowExportMenu cfg={fn?.cfg} funcName={fn?.name} />
                </div>
                {fn ? (
                  fn.cfg ? (
                    <FlowGraphView
                      cfg={fn.cfg}
                      onBlockSelect={onCfgBlockSelect}
                      highlightBlockId={cfgHighlightBlockId}
                    />
                  ) : (
                    <p className="apple-adetail-hint">
                      CFG が含まれていません。バックエンド更新後に検体を再解析してください。
                    </p>
                  )
                ) : (
                  <p className="apple-adetail-hint">左のツリーから関数を選択してください。</p>
                )}
              </>
            )}
          </div>
        )}

        {tab === 'strings' && (
          <div className="apple-adetail-pane">
            <input
              type="search"
              className="apple-table-filter"
              placeholder="文字列・アドレスで絞り込み…"
              value={filterStrings}
              onChange={(e) => setFilterStrings(e.target.value)}
              aria-label="文字列のフィルタ"
            />
            <div className="apple-table-wrap">
              <table className="apple-table">
                <thead>
                  <tr>
                    <th>アドレス</th>
                    <th>値</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredStrings.slice(0, 8000).map((s, i) => (
                    <tr key={`${s.address}-${i}`}>
                      <td className="apple-td-mono">{s.address}</td>
                      <td className="apple-td-break">{s.value}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <p className="apple-adetail-foot">
              表示 {Math.min(filteredStrings.length, 8000)} / {data.strings.length} 件
              {data.strings.length >= 5000 ? '（出力上限付近）' : ''}
            </p>
          </div>
        )}

        {tab === 'imports' && (
          <div className="apple-adetail-pane">
            <input
              type="search"
              className="apple-table-filter"
              placeholder="DLL・関数名・アドレスで絞り込み…"
              value={filterImports}
              onChange={(e) => setFilterImports(e.target.value)}
              aria-label="インポートのフィルタ"
            />
            <div className="apple-table-wrap">
              <table className="apple-table">
                <thead>
                  <tr>
                    <th>ライブラリ</th>
                    <th>関数</th>
                    <th>アドレス</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredImports.map((r, i) => (
                    <tr key={`${r.address}-${i}`}>
                      <td>{r.library || '—'}</td>
                      <td className="apple-td-mono">{r.function}</td>
                      <td className="apple-td-mono">{r.address}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {tab === 'entry' && (
          <div className="apple-adetail-pane">
            <ul className="apple-bullet-list">
              {data.entry_points.map((ep) => (
                <li key={ep} className="apple-td-mono">
                  {ep}
                </li>
              ))}
              {data.entry_points.length === 0 && <li>（エントリポイント情報なし）</li>}
            </ul>
          </div>
        )}

        {tab === 'suspicious' && (
          <div className="apple-adetail-pane">
            <div className="apple-table-wrap">
              <table className="apple-table">
                <thead>
                  <tr>
                    <th>API</th>
                    <th>アドレス</th>
                    <th>参照元関数</th>
                  </tr>
                </thead>
                <tbody>
                  {data.suspicious_apis.map((s) => (
                    <tr key={`${s.name}-${s.address}`}>
                      <td className="apple-td-mono">{s.name}</td>
                      <td className="apple-td-mono">{s.address}</td>
                      <td>{s.seen_from}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {data.suspicious_apis.length === 0 && (
              <p className="apple-adetail-hint">ヒューリスティックで検出された API はありません。</p>
            )}
          </div>
        )}

        {tab === 'metadata' && (
          <div className="apple-adetail-pane">
            <pre className="apple-pre apple-pre--metadata">
              {JSON.stringify(
                {
                  file_name: data.file_name,
                  architecture: data.architecture,
                  compiler: data.compiler,
                  entry_points: data.entry_points,
                  function_count: data.functions.length,
                  string_count: data.strings.length,
                  import_count: data.imports.length,
                  suspicious_apis: data.suspicious_apis,
                  truncated: data.truncated,
                  call_graph_nodes: data.call_graph?.nodes?.length ?? 0,
                  call_graph_edges: data.call_graph?.edges?.length ?? 0,
                },
                null,
                2,
              )}
            </pre>
            <p className="apple-adetail-foot">
              全JSONの表示はブラウザ負荷が大きいため、メタデータのみ表示しています。
              完全なJSONは API (
              <code className="apple-code">GET /api/results/{'{filename}'}</code>) から取得してください。
            </p>
          </div>
        )}
      </div>
    </div>
  );
}
