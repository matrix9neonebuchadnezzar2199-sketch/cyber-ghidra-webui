import React, { useEffect, useState } from 'react';
import { Save } from 'lucide-react';
import { useApiBase } from '../context/ApiContext';

export function SettingsView() {
  const { apiBase, setApiBase } = useApiBase();
  const [draft, setDraft] = useState(apiBase);
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    setDraft(apiBase);
  }, [apiBase]);

  const apply = () => {
    setApiBase(draft);
    setSaved(true);
    window.setTimeout(() => setSaved(false), 2000);
  };

  return (
    <div className="apple-settings">
      <section className="apple-analyze-hero">
        <h2 className="apple-analyze-title">設定</h2>
        <p className="apple-analyze-lead">
          フロントエンドから呼び出す Cyber Ghidra API のベース URL を指定します。ブラウザに保存されます。
        </p>
      </section>

      <section className="apple-panel apple-settings-panel">
        <label className="apple-settings-label" htmlFor="api-base">
          API ベース URL
        </label>
        <div className="apple-settings-row">
          <input
            id="api-base"
            type="url"
            className="apple-settings-input"
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
            placeholder="http://localhost:8000"
            autoComplete="off"
            spellCheck={false}
          />
          <button type="button" className="apple-btn apple-btn-primary" onClick={apply}>
            <Save size={16} aria-hidden />
            保存
          </button>
        </div>
        <p className="apple-settings-hint">
          現在: <code className="apple-code">{apiBase}</code>
          {saved && <span className="apple-settings-saved">保存しました</span>}
        </p>
        <p className="apple-settings-note">
          Vite の <code className="apple-code">VITE_API_URL</code> ビルド時指定がある場合は、ここで上書きできます。
        </p>
      </section>
    </div>
  );
}
