import type { CallGraphData, CfgData } from '../../types/analysis';

/* ------------------------------------------------------------------ */
/*  DOT (Graphviz) export                                              */
/* ------------------------------------------------------------------ */

export function cfgToDot(cfg: CfgData, funcName: string): string {
  const lines: string[] = [];
  lines.push('digraph "' + funcName.replace(/"/g, '\\"') + '" {');
  lines.push('  rankdir=TB;');
  lines.push('  node [shape=box, style=rounded, fontname="monospace", fontsize=10];');
  lines.push('  edge [fontname="monospace", fontsize=9];');

  for (const n of cfg.nodes) {
    const label =
      n.start + '\\n' + (n.preview ?? '').replace(/"/g, '\\"').slice(0, 60);
    const extra = n.is_entry ? ', color=green, penwidth=2' : n.is_exit ? ', color=orange' : '';
    lines.push('  "' + n.id + '" [label="' + label + '"' + extra + '];');
  }

  for (const e of cfg.edges) {
    const label = (e.label ?? '').replace(/"/g, '\\"').slice(0, 40);
    const color =
      e.branch_dir === 'true'
        ? 'green'
        : e.branch_dir === 'false'
          ? 'red'
          : e.branch_dir === 'fallthrough'
            ? 'gray'
            : 'cyan';
    lines.push('  "' + e.from + '" -> "' + e.to + '" [label="' + label + '", color=' + color + '];');
  }

  lines.push('}');
  return lines.join('\n');
}

export function callGraphToDot(graph: CallGraphData): string {
  const lines: string[] = [];
  lines.push('digraph "call_graph" {');
  lines.push('  rankdir=TB;');
  lines.push('  node [shape=ellipse, fontname="monospace", fontsize=10];');

  for (const n of graph.nodes) {
    const label = n.name + '\\n' + n.address;
    lines.push('  "' + n.id + '" [label="' + label.replace(/"/g, '\\"') + '"];');
  }

  for (const e of graph.edges) {
    lines.push('  "' + e.from + '" -> "' + e.to + '";');
  }

  lines.push('}');
  return lines.join('\n');
}

/* ------------------------------------------------------------------ */
/*  SVG capture from React Flow viewport                               */
/* ------------------------------------------------------------------ */

export function captureFlowSvg(): string | null {
  const vp = document.querySelector('.react-flow__viewport');
  const raw = vp?.closest('svg') ?? document.querySelector('.react-flow svg');
  if (!raw || !(raw instanceof SVGSVGElement)) return null;
  const svgEl = raw;

  const clone = svgEl.cloneNode(true) as SVGSVGElement;
  clone.style.backgroundColor = '#07050f';
  try {
    const bbox = svgEl.getBBox();
    const pad = 20;
    clone.setAttribute(
      'viewBox',
      `${bbox.x - pad} ${bbox.y - pad} ${bbox.width + pad * 2} ${bbox.height + pad * 2}`,
    );
    clone.setAttribute('width', String(bbox.width + pad * 2));
    clone.setAttribute('height', String(bbox.height + pad * 2));
  } catch {
    /* getBBox can throw if not rendered */
  }

  const serializer = new XMLSerializer();
  return serializer.serializeToString(clone);
}

export function downloadSvg(svgString: string, filename: string) {
  const blob = new Blob([svgString], { type: 'image/svg+xml;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

export function downloadPng(svgString: string, filename: string, scale = 2) {
  const img = new Image();
  const svgBlob = new Blob([svgString], { type: 'image/svg+xml;charset=utf-8' });
  const url = URL.createObjectURL(svgBlob);

  img.onload = () => {
    const canvas = document.createElement('canvas');
    canvas.width = img.width * scale;
    canvas.height = img.height * scale;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;
    ctx.fillStyle = '#07050f';
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    ctx.scale(scale, scale);
    ctx.drawImage(img, 0, 0);

    canvas.toBlob((blob) => {
      if (!blob) return;
      const pngUrl = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = pngUrl;
      a.download = filename;
      a.click();
      URL.revokeObjectURL(pngUrl);
    }, 'image/png');

    URL.revokeObjectURL(url);
  };

  img.src = url;
}

export function downloadText(content: string, filename: string) {
  const blob = new Blob([content], { type: 'text/plain;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}
