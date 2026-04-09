import React, { useMemo } from 'react';
import clsx from 'clsx';
import type { AnalysisFunction } from '../../types/analysis';
import { analyzeDecompiledText } from './decompileInsights';
import { highlightDecompiledLine } from './decompileHighlight';

type Props = {
  fn: AnalysisFunction;
};

const SEV_CLASS: Record<string, string> = {
  info: 'apple-decomp-signal--info',
  low: 'apple-decomp-signal--low',
  medium: 'apple-decomp-signal--medium',
  high: 'apple-decomp-signal--high',
};

export function DecompileView({ fn }: Props) {
  const code = fn.decompiled_c;
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

  return (
    <div className="apple-decomp-shell">
      <p className="apple-decomp-disclaimer">
        下のシグナルは<strong>ヒューリスティック</strong>です。パターン一致であり、悪意や耐解析の確定診断ではありません。
      </p>

      {insights ? (
        <div className="apple-decomp-toolbar">
          <div className="apple-decomp-stat">
            <span className="apple-decomp-stat-label">行数</span>
            <span className="apple-decomp-stat-val">{insights.stats.line_count}</span>
          </div>
          <div className="apple-decomp-stat">
            <span className="apple-decomp-stat-label">goto</span>
            <span className="apple-decomp-stat-val">{insights.stats.goto_count}</span>
          </div>
          {insights.stats.heavy_goto_flattening ? (
            <span className="apple-decomp-badge apple-decomp-badge--warn">goto 多め</span>
          ) : null}
          {insights.stats.opaque_loop_hint ? (
            <span className="apple-decomp-badge apple-decomp-badge--muted">無限ループ様</span>
          ) : null}
        </div>
      ) : null}

      {insights && insights.signals.length > 0 ? (
        <div className="apple-decomp-signals" aria-label="解析シグナル">
          {insights.signals.map((s) => (
            <span
              key={s.id}
              className={clsx('apple-decomp-signal', SEV_CLASS[s.severity] ?? 'apple-decomp-signal--info')}
              title={s.id}
            >
              {s.label}
            </span>
          ))}
        </div>
      ) : insights ? (
        <p className="apple-decomp-no-signals">この関数のテキストからは特記パターンを検出しませんでした。</p>
      ) : null}

      <div className="apple-decomp-code-wrap">
        <div className="apple-decomp-code">
          {lines.map((line, i) => (
            <div key={i} className="apple-decomp-row">
              <span className="apple-decomp-ln" aria-hidden>
                {i + 1}
              </span>
              <code
                className="apple-decomp-line"
                dangerouslySetInnerHTML={{ __html: highlightDecompiledLine(line) }}
              />
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
