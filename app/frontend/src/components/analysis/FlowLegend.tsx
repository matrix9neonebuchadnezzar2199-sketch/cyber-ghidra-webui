import React from 'react';

type LegendItem = {
  color: string;
  label: string;
  dash: string | undefined;
};

const ITEMS: LegendItem[] = [
  { color: 'rgba(50, 215, 75, 0.75)', label: '条件成立 (true)', dash: undefined },
  { color: 'rgba(180, 180, 200, 0.5)', label: 'フォールスルー', dash: undefined },
  { color: 'rgba(255, 204, 0, 0.7)', label: '条件分岐（方向未確定）', dash: '3 3' },
  { color: 'rgba(255, 160, 60, 0.75)', label: 'バックエッジ（ループ）', dash: '6 4' },
  { color: 'rgba(167, 139, 250, 0.6)', label: 'call', dash: '4 3' },
  { color: 'rgba(0, 200, 255, 0.42)', label: '無条件ジャンプ / その他', dash: undefined },
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
              strokeDasharray={item.dash}
              strokeLinecap="round"
            />
          </svg>
          <span className="cyber-flow-legend-label">{item.label}</span>
        </div>
      ))}
    </div>
  );
}
