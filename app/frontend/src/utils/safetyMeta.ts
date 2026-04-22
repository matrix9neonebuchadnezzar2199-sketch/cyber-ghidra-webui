/** 静的分析 `static_scan` / ジョブ行のリスク表記用 */

const RISK_ORDER: Record<string, number> = {
  safe: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

export function extractOverallRiskFromRecord(staticScan: unknown): string | null {
  if (!staticScan || typeof staticScan !== 'object') return null;
  const r = (staticScan as { overall_risk?: string }).overall_risk;
  return r ? String(r).toLowerCase() : null;
}

export function extractOverallRiskFromJob(job: Record<string, unknown>): string | null {
  const s = job.static_scan;
  return extractOverallRiskFromRecord(s);
}

export type RiskPresentation = { label: string; tone: 'safe' | 'low' | 'warn' | 'danger' };

export function presentOverallRisk(risk: string | null | undefined): RiskPresentation {
  const v = (risk || 'safe').toLowerCase();
  if (v === 'safe' || v === 'none' || v === 'unknown' || v === '') {
    return { label: '安全', tone: 'safe' };
  }
  if (v === 'low') {
    return { label: '低', tone: 'low' };
  }
  if (v === 'medium') {
    return { label: '注意', tone: 'warn' };
  }
  if (v === 'high' || v === 'critical') {
    return { label: v === 'critical' ? '危険' : '警告', tone: 'danger' };
  }
  return { label: v.toUpperCase(), tone: 'low' };
}

export function staticScanHighlightLines(staticScan: unknown, max = 8): string[] {
  if (!staticScan || typeof staticScan !== 'object') return [];
  const o = staticScan as {
    results?: Array<{
      findings?: Array<{ description?: string; risk?: string; rule?: string }>;
    }>;
  };
  const out: string[] = [];
  const pr = (s: string | undefined) => {
    const k = (s || '').toLowerCase();
    return RISK_ORDER[k] ?? 0;
  };
  for (const r of o.results || []) {
    for (const f of r.findings || []) {
      if (pr(f.risk) >= 2) {
        const t = f.rule ? `${f.rule}: ${f.description || ''}` : f.description || '';
        if (t) out.push(`[${(f.risk || '').toUpperCase()}] ${t}`.trim());
        if (out.length >= max) return out;
      }
    }
  }
  return out;
}

export function isRiskConcerning(risk: string | null | undefined): boolean {
  const v = (risk || '').toLowerCase();
  return v === 'medium' || v === 'high' || v === 'critical';
}

/** 静的分析の overall risk が上がっていても、マクロ有無等は別行で明示する */
export type ExecutiveSummaryItem = {
  label: string;
  value: string;
  level: 'positive' | 'neutral' | 'caution' | 'negative';
};

function evYes(v: unknown): boolean {
  if (v == null) return false;
  const s = String(v).toLowerCase().trim();
  return s === 'yes' || s === 'true' || s === '1' || s === '有';
}

function _metaStr(
  m: Record<string, unknown> | undefined,
  key: string,
): { value: string; risk?: string } | undefined {
  if (!m) return undefined;
  const r = m[key] as { value?: unknown; risk?: unknown } | string | number | boolean | undefined;
  if (r == null) return undefined;
  if (typeof r === 'object' && r !== null && 'value' in r) {
    return {
      value: String((r as { value: unknown }).value),
      risk: (r as { risk?: string }).risk != null ? String((r as { risk: unknown }).risk) : undefined,
    };
  }
  return { value: String(r) };
}

/**
 * oletools / binwalk 等の `static_scan` から、レポート上「まず先に」読みたい要点行を作る。
 */
export function buildStaticScanExecutiveSummary(staticScan: unknown): ExecutiveSummaryItem[] {
  if (!staticScan || typeof staticScan !== 'object') return [];
  const o = staticScan as {
    results?: Array<{
      scanner_name?: string;
      metadata?: Record<string, unknown>;
      findings?: Array<{ rule?: string; risk?: string }>;
    }>;
  };
  const out: ExecutiveSummaryItem[] = [];
  for (const r of o.results || []) {
    if (r.scanner_name === 'oletools' && r.metadata) {
      const m = r.metadata;
      const findings = r.findings || [];
      const olevbaFindings = findings.filter(
        (f) => f.rule && String(f.rule).toLowerCase().startsWith('olevba_'),
      );
      if (olevbaFindings.length === 0) {
        out.push({
          label: '悪意のある VBA コード',
          value: '検出されません（oletools/olevba の不審キーワード所見: 0 件）',
          level: 'positive',
        });
      } else {
        const hi = olevbaFindings.filter((f) => String(f.risk || '').toLowerCase() === 'high');
        out.push({
          label: 'VBA 上の不審パターン',
          value: `${olevbaFindings.length} 件（うち高リスク目安: ${hi.length} 件。詳細は JSON / findings 参照）`,
          level: hi.length > 0 ? 'negative' : 'caution',
        });
      }
      const xlm = _metaStr(m, 'XLM Macros');
      if (xlm) {
        if (!evYes(xlm.value) && String(xlm.value).toLowerCase() === 'no') {
          out.push({ label: 'XLM マクロ', value: 'なし（oleid）', level: 'positive' });
        } else {
          out.push({
            label: 'XLM マクロ',
            value: evYes(xlm.value) || /yes/i.test(xlm.value) ? 'あり（要確認）' : xlm.value,
            level: evYes(xlm.value) ? 'caution' : 'neutral',
          });
        }
      }
      const enc = _metaStr(m, 'Encrypted');
      if (enc) {
        const f = String(enc.value).toLowerCase();
        const isEnc = f === 'true' || f === 'yes' || f === '1' || f.includes('password');
        if (!isEnc) {
          out.push({
            label: '文書のパスワード保護 / 暗号化',
            value: 'oleid 上、暗号化としてのフラグは上がりません',
            level: 'positive',
          });
        } else {
          out.push({ label: '文書のパスワード保護 / 暗号化', value: '有 / 要確認', level: 'caution' });
        }
      }
      const ex = _metaStr(m, 'External Relationships');
      if (ex) {
        out.push({
          label: 'OpenXML の外部リレーション数（構造上の数値指標）',
          value: `${ex.value} 件（図表・部品数が多い文書で増えます。マクロの有無・悪性とは直結しません）`,
          level: 'neutral',
        });
      }
    }
    if (r.scanner_name === 'binwalk' && r.metadata && typeof r.metadata === 'object') {
      const em = (r.metadata as { embedded_count?: number }).embedded_count;
      if (typeof em === 'number') {
        if (em === 0) {
          out.push({
            label: '多段の埋め込みペイロード',
            value: 'binwalk: 0 件（大きな二重埋め込みは目立たず）',
            level: 'positive',
          });
        } else {
          out.push({
            label: '多段の埋め込みペイロード',
            value: `binwalk: ${em} 件（詳細は同 JSON）`,
            level: 'caution',
          });
        }
      }
    }
  }
  return out;
}
