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
