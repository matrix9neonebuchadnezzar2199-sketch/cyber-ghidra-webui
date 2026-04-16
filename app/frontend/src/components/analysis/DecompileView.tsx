import React, { useMemo } from 'react';
import clsx from 'clsx';
import type { AnalysisFunction } from '../../types/analysis';
import { analyzeDecompiledText } from './decompileInsights';
import { highlightDecompiledLine } from './decompileHighlight';

type Props = {
  fn: AnalysisFunction;
  highlightLine?: number | null;
  onLineClick?: (lineNum: number, address: string | null) => void;
};

const SEV_CLASS: Record<string, string> = {
  info: 'apple-decomp-signal--info',
  low: 'apple-decomp-signal--low',
  medium: 'apple-decomp-signal--medium',
  high: 'apple-decomp-signal--high',
};

export function DecompileView({ fn, highlightLine, onLineClick }: Props) {
  const code = fn.decompiled_c;
  const lineMap = fn.line_address_map;

  const insights = useMemo(
    () => fn.decompile_insights ?? (code ? analyzeDecompiledText(code) : null),
    [fn.decompile_insights, code],
  );

  const lines = useMemo(() => (code ? code.split(/\r?\n/) : []), [code]);

  if (!code) {
    return (
      <p className="apple-adetail-hint">
        逆コンパイル結果なし（タイムアウト・最適化・シンボル不足など）。再解析または Ghidra 本体で確認してください。
      </p>
    );
  }

  const handleLineClick = (lineNum: number) => {
    if (!onLineClick) return;
    const addr = lineMap?.[String(lineNum)] ?? null;
    onLineClick(lineNum, addr);
  };

  const onRowKeyDown = (e: React.KeyboardEvent, lineNum: number, hasAddr: boolean) => {
    if (!hasAddr) return;
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      handleLineClick(lineNum);
    }
  };

  return (
    <div className="apple-decomp-shell">
      <p className="apple-decomp-disclaimer">
        下のシグナルは<strong>ヒューリスティック</strong>です。パターン一致であり、悪意や耐解析の確定診断ではありません。
        {lineMap && Object.keys(lineMap).length > 0 && (
          <span className="apple-decomp-linkable">
            {' '}
            行をクリックすると CFG の対応ブロックにジャンプします。
          </span>
        )}
      </p>

      {insights && (
        <div className="apple-decomp-toolbar">
          <div className="apple-decomp-stat">
            <span className="apple-decomp-stat-label">行数</span>
            <span className="apple-decomp-stat-val">{insights.stats.line_count}</span>
          </div>
          <div className="apple-decomp-stat">
            <span className="apple-decomp-stat-label">goto</span>
            <span className="apple-decomp-stat-val">{insights.stats.goto_count}</span>
          </div>
          {insights.stats.heavy_goto_flattening && (
            <span className="apple-decomp-badge apple-decomp-badge--warn">goto 多め</span>
          )}
          {insights.stats.opaque_loop_hint && (
            <span className="apple-decomp-badge apple-decomp-badge--muted">無限ループ様</span>
          )}
        </div>
      )}

      {insights && insights.signals.length > 0 && (
        <div className="apple-decomp-signals" aria-label="解析シグナル">
          {insights.signals.map((s) => (
            <span
              key={s.id}
              className={clsx(
                'apple-decomp-signal',
                SEV_CLASS[s.severity] ?? 'apple-decomp-signal--info',
              )}
              title={s.id}
            >
              {s.label}
            </span>
          ))}
        </div>
      )}

      {insights && insights.signals.length === 0 && (
        <p className="apple-decomp-no-signals">この関数のテキストからは特記パターンを検出しませんでした。</p>
      )}

      <div className="apple-decomp-code-wrap">
        <div className="apple-decomp-code">
          {lines.map((line, i) => {
            const lineNum = i + 1;
            const hasAddr = !!lineMap?.[String(lineNum)];
            const isHighlighted = highlightLine === lineNum;

            return (
              <div
                key={i}
                className={clsx(
                  'apple-decomp-row',
                  hasAddr && 'apple-decomp-row--clickable',
                  isHighlighted && 'apple-decomp-row--highlight',
                )}
                onClick={hasAddr ? () => handleLineClick(lineNum) : undefined}
                onKeyDown={(e) => onRowKeyDown(e, lineNum, hasAddr)}
                role={hasAddr ? 'button' : undefined}
                tabIndex={hasAddr ? 0 : undefined}
              >
                <span className="apple-decomp-ln" aria-hidden>
                  {lineNum}
                </span>
                <code
                  className="apple-decomp-line"
                  dangerouslySetInnerHTML={{ __html: highlightDecompiledLine(line) }}
                />
                {hasAddr && (
                  <span className="apple-decomp-addr-hint">{lineMap![String(lineNum)]}</span>
                )}
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
