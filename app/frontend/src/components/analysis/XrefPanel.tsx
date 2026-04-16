import React from 'react';
import type { FunctionXrefs } from '../../types/analysis';

type Props = {
  xrefs: FunctionXrefs;
  onNavigate: (address: string) => void;
};

export function XrefPanel({ xrefs, onNavigate }: Props) {
  return (
    <div className="cyber-xref-panel">
      <div className="cyber-xref-section">
        <h4 className="cyber-xref-heading">呼び出し元 (Callers) — {xrefs.callers.length}件</h4>
        {xrefs.callers.length === 0 ? (
          <p className="cyber-xref-empty">なし（エントリポイントまたは未参照）</p>
        ) : (
          <ul className="cyber-xref-list">
            {xrefs.callers.map((x) => (
              <li key={x.address}>
                <button type="button" className="cyber-xref-link" onClick={() => onNavigate(x.address)}>
                  <span className="cyber-xref-name">{x.name}</span>
                  <span className="cyber-xref-addr">{x.address}</span>
                </button>
              </li>
            ))}
          </ul>
        )}
      </div>
      <div className="cyber-xref-section">
        <h4 className="cyber-xref-heading">呼び出し先 (Callees) — {xrefs.callees.length}件</h4>
        {xrefs.callees.length === 0 ? (
          <p className="cyber-xref-empty">なし（リーフ関数）</p>
        ) : (
          <ul className="cyber-xref-list">
            {xrefs.callees.map((x) => (
              <li key={x.address}>
                <button type="button" className="cyber-xref-link" onClick={() => onNavigate(x.address)}>
                  <span className="cyber-xref-name">{x.name}</span>
                  <span className="cyber-xref-addr">{x.address}</span>
                </button>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}
