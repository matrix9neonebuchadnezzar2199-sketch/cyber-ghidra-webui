import React, { useMemo, useState } from 'react';
import clsx from 'clsx';
import type { AnalysisJson } from '../../types/analysis';
import { FlowGraphView } from './FlowGraphView';
import { ProgramCallGraphView } from './ProgramCallGraphView';
import { DecompileView } from './DecompileView';

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
  /** コールグラフのノード選択時に左ツリーの関数を同期（エントリアドレスで一致） */
  onSelectFunctionByAddress?: (address: string) => void;
};

type FlowSubTab = 'cfg' | 'program';

export function AnalysisDetail({ data, selectedFnIndex, onSelectFunctionByAddress }: Props) {
  const [tab, setTab] = useState<TabId>('decompile');
  const [flowSub, setFlowSub] = useState<FlowSubTab>(() =>
    data.call_graph?.nodes?.length ? 'program' : 'cfg',
  );
  const [filterStrings, setFilterStrings] = useState('');
  const [filterImports, setFilterImports] = useState('');

  const fn = selectedFnIndex !== null ? data.functions[selectedFnIndex] : null;

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

  return (
    <div className="apple-adetail">
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
                <DecompileView fn={fn} />
              </>
            ) : (
              <p className="apple-adetail-hint">左のツリーから関数を選択してください。</p>
            )}
          </div>
        )}

        {tab === 'flow' && (
          <div className="apple-adetail-pane apple-adetail-pane--flow">
            <p className="apple-flow-ida-lead">
              IDA に近い運用: まず<strong>コールグラフ（関数間）</strong>で全体を把握し、必要な関数だけ
              <strong>関数内 CFG（基本ブロック）</strong>に入ります。
            </p>
            <div className="apple-flow-subtabs" role="tablist">
              <button
                type="button"
                role="tab"
                aria-selected={flowSub === 'program'}
                className={clsx('apple-flow-subtab', flowSub === 'program' && 'apple-flow-subtab--active')}
                onClick={() => setFlowSub('program')}
              >
                コールグラフ（関数間）
              </button>
              <button
                type="button"
                role="tab"
                aria-selected={flowSub === 'cfg'}
                className={clsx('apple-flow-subtab', flowSub === 'cfg' && 'apple-flow-subtab--active')}
                onClick={() => setFlowSub('cfg')}
              >
                関数内 CFG（基本ブロック）
              </button>
            </div>
            {flowSub === 'program' &&
              (data.call_graph && data.call_graph.nodes.length > 0 ? (
                <>
                  <p className="apple-flow-ida-hint">
                    ノードを<strong>クリック</strong>で左の関数ツリーに同期。<strong>ダブルクリック</strong>
                    で「関数内 CFG」タブへ切り替え（IDA のコールグラフから関数グラフへ入る操作に近いです）。
                  </p>
                  <ProgramCallGraphView
                    graph={data.call_graph}
                    entryPoints={data.entry_points}
                    onSelectFunctionByAddress={onSelectFunctionByAddress}
                    onOpenFunctionCfg={(addr) => {
                      onSelectFunctionByAddress?.(addr);
                      setFlowSub('cfg');
                    }}
                  />
                </>
              ) : (
                <p className="apple-adetail-hint">
                  コールグラフがありません。{' '}
                  <code className="apple-code">auto_analyze.py</code> 更新後に<strong>検体を再解析</strong>
                  すると表示されます（古い JSON には含まれません）。上の「関数内 CFG」で基本ブロック図だけ参照できます。
                </p>
              ))}
            {flowSub === 'cfg' && (
              <>
                {data.call_graph && data.call_graph.nodes.length > 0 ? (
                  <button
                    type="button"
                    className="apple-flow-back"
                    onClick={() => setFlowSub('program')}
                  >
                    ← コールグラフ（関数間）に戻る
                  </button>
                ) : null}
                {fn ? (
                  fn.cfg ? (
                    <FlowGraphView cfg={fn.cfg} />
                  ) : (
                    <p className="apple-adetail-hint">
                      CFG が含まれていません。バックエンドの <code className="apple-code">auto_analyze.py</code>{' '}
                      更新後に<strong>検体を再解析</strong>すると、基本ブロックのフロー図と分岐ラベルが表示されます。
                    </p>
                  )
                ) : (
                  <p className="apple-adetail-hint">
                    左のツリーから関数を選ぶか、コールグラフで関数をクリックしてください。
                  </p>
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
            <pre className="apple-pre apple-pre--metadata">{JSON.stringify(data, null, 2)}</pre>
          </div>
        )}
      </div>
    </div>
  );
}
