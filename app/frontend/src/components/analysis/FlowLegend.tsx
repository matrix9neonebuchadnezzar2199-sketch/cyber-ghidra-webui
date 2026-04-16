import React from 'react';

const ITEMS = [
  { color: '#32d74b', label: '条件成立 (true)', dash: false },
  { color: '#ff453a', label: '条件不成立 (false)', dash: false },
  { color: '#b4b4c8', label: 'fall-through', dash: false },
  { color: '#ff9a40', label: 'バックエッジ (ループ)', dash: true },
  { color: '#a78bfa', label: 'call', dash: true },
  { color: '#00f3ff', label: 'その他', dash: false },
];

export function FlowLegend() {
  return (
    <div className="cyber-flow-legend">
      {ITEMS.map((item) => (
        <div key={item.label} className="cyber-flow-legend-item">
          <svg width="28" height="10" viewBox="0 0 28 10">
            <line
              x1="0"
              y1="5"
              x2="28"
              y2="5"
              stroke={item.color}
              strokeWidth={2.5}
              strokeDasharray={item.dash ? '5 3' : undefined}
              strokeLinecap="round"
            />
          </svg>
          <span className="cyber-flow-legend-label">{item.label}</span>
        </div>
      ))}
    </div>
  );
}
