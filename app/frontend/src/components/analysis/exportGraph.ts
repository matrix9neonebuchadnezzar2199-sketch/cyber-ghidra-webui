import type { CallGraphData, CfgData } from '../../types/analysis';
import { CYBER_BLUR_ID, CYBER_GRAD_ID } from './CyberFlowEdge';

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

const SVG_NS = 'http://www.w3.org/2000/svg';

/** FlowGraphView の CyberFlowDefs と同一（クローン SVG に defs が無い場合の注入用） */
function injectCyberFlowDefs(svg: SVGSVGElement): void {
  if (svg.getElementById(CYBER_GRAD_ID)) return;

  const defs = document.createElementNS(SVG_NS, 'defs');

  const grad = document.createElementNS(SVG_NS, 'linearGradient');
  grad.setAttribute('id', CYBER_GRAD_ID);
  grad.setAttribute('x1', '0%');
  grad.setAttribute('y1', '0%');
  grad.setAttribute('x2', '100%');
  grad.setAttribute('y2', '0%');
  const stops = [
    ['0%', '#00f3ff'],
    ['45%', '#c56bff'],
    ['100%', '#ff2a6d'],
  ] as const;
  for (const [offset, stopColor] of stops) {
    const stop = document.createElementNS(SVG_NS, 'stop');
    stop.setAttribute('offset', offset);
    stop.setAttribute('stop-color', stopColor);
    grad.appendChild(stop);
  }
  defs.appendChild(grad);

  const filter = document.createElementNS(SVG_NS, 'filter');
  filter.setAttribute('id', CYBER_BLUR_ID);
  filter.setAttribute('x', '-60%');
  filter.setAttribute('y', '-60%');
  filter.setAttribute('width', '220%');
  filter.setAttribute('height', '220%');
  const blur = document.createElementNS(SVG_NS, 'feGaussianBlur');
  blur.setAttribute('stdDeviation', '3.5');
  blur.setAttribute('result', 'b');
  const merge = document.createElementNS(SVG_NS, 'feMerge');
  const mn1 = document.createElementNS(SVG_NS, 'feMergeNode');
  mn1.setAttribute('in', 'b');
  const mn2 = document.createElementNS(SVG_NS, 'feMergeNode');
  mn2.setAttribute('in', 'SourceGraphic');
  merge.appendChild(mn1);
  merge.appendChild(mn2);
  filter.appendChild(blur);
  filter.appendChild(merge);
  defs.appendChild(filter);

  svg.insertBefore(defs, svg.firstChild);
}

export function captureFlowSvg(): string | null {
  const vp = document.querySelector('.react-flow__viewport');
  const raw = vp?.closest('svg') ?? document.querySelector('.react-flow svg');
  if (!raw || !(raw instanceof SVGSVGElement)) return null;
  const svgEl = raw;

  const clone = svgEl.cloneNode(true) as SVGSVGElement;
  injectCyberFlowDefs(clone);
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
