import React from 'react';
import { FlaskConical, History, Settings } from 'lucide-react';
import clsx from 'clsx';

export type SidebarSection = 'analyze' | 'history' | 'settings';

type Props = {
  active: SidebarSection;
  onSelect: (s: SidebarSection) => void;
};

const items: { id: SidebarSection; label: string; icon: React.ReactNode }[] = [
  { id: 'analyze', label: '解析', icon: <FlaskConical size={18} aria-hidden /> },
  { id: 'history', label: '解析結果履歴', icon: <History size={18} aria-hidden /> },
  { id: 'settings', label: '設定', icon: <Settings size={18} aria-hidden /> },
];

export function Sidebar({ active, onSelect }: Props) {
  return (
    <aside className="apple-sidebar" aria-label="メインメニュー">
      <nav className="apple-sidebar-nav">
        {items.map((it) => (
          <button
            key={it.id}
            type="button"
            className={clsx('apple-sidebar-item', active === it.id && 'apple-sidebar-item--active')}
            onClick={() => onSelect(it.id)}
          >
            <span className="apple-sidebar-icon">{it.icon}</span>
            <span className="apple-sidebar-label">{it.label}</span>
          </button>
        ))}
      </nav>
    </aside>
  );
}
