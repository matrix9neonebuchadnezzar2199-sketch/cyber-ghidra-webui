/**
 * ELK-based graph layout for CFG and call graph.
 * Uses elkjs bundled (no Web Worker needed, zero external deps).
 */
import ELK, { type ElkNode } from 'elkjs/lib/elk.bundled.js';
import type { Edge, Node } from '@xyflow/react';
import type { CallGraphData, CallGraphNode, CfgData, CfgNode } from '../../types/analysis';

const elk = new ELK();

/* ------------------------------------------------------------------ */
/*  共通ヘルパー                                                       */
/* ------------------------------------------------------------------ */

interface LayoutResult {
  nodes: Node[];
  edges: Edge[];
}

function toRfNodes(
  elkRoot: ElkNode,
  buildData: (id: string) => Record<string, unknown>,
  nodeType: string,
): Node[] {
  return (elkRoot.children ?? []).map((child) => ({
    id: child.id,
    type: nodeType,
    position: { x: child.x ?? 0, y: child.y ?? 0 },
    data: buildData(child.id),
  }));
}

/* ------------------------------------------------------------------ */
/*  CFG レイアウト                                                     */
/* ------------------------------------------------------------------ */

const CFG_NODE_W = 230;
/** アドレス行 + padding（ELK ノード高さのベース） */
const CFG_NODE_BASE_H = 40;
/** ディスアセンブリ 1 行あたりの高さ（CfgBlockNode / ELK で揃える） */
const CFG_NODE_LINE_H = 18;
const CFG_NODE_MAX_LINES = 4;

function cfgNodeElkHeight(n: CfgNode): number {
  const rawLen = n.disasm?.length ?? 0;
  const linesForSizing = rawLen > 0 ? rawLen : n.preview ? 1 : 0;
  const lineCount = Math.min(Math.max(linesForSizing, 1), CFG_NODE_MAX_LINES);
  return CFG_NODE_BASE_H + CFG_NODE_LINE_H * lineCount;
}

export async function layoutCfgElk(cfg: CfgData, heavy: boolean): Promise<LayoutResult> {
  if (!cfg.nodes.length) return { nodes: [], edges: [] };

  const nodeMap = new Map<string, CfgNode>();
  cfg.nodes.forEach((n) => nodeMap.set(n.id, n));

  const elkGraph: ElkNode = {
    id: 'root',
    layoutOptions: {
      'elk.algorithm': 'layered',
      'elk.direction': 'DOWN',
      'elk.layered.cycleBreaking.strategy': 'DEPTH_FIRST',
      'elk.layered.crossingMinimization.strategy': 'LAYER_SWEEP',
      'elk.layered.nodePlacement.strategy': 'BRANDES_KOEPF',
      'elk.spacing.nodeNode': '36',
      'elk.layered.spacing.nodeNodeBetweenLayers': '68',
      'elk.layered.spacing.edgeNodeBetweenLayers': '24',
      'elk.edgeRouting': 'ORTHOGONAL',
    },
    children: cfg.nodes.map((n) => ({
      id: n.id,
      width: CFG_NODE_W,
      height: cfgNodeElkHeight(n),
    })),
    edges: cfg.edges.map((e, i) => ({
      id: 'e-' + String(i),
      sources: [e.from],
      targets: [e.to],
    })),
  };

  const laid = await elk.layout(elkGraph);

  const rfNodes = toRfNodes(
    laid,
    (id) => {
      const n = nodeMap.get(id);
      return {
        address: n?.start ?? id,
        preview: n?.preview ?? '',
        disasm: n?.disasm ?? [],
        isEntry: n?.is_entry ?? false,
        isExit: n?.is_exit ?? false,
      };
    },
    'cfgBlock',
  );

  const rankMap = new Map<string, number>();
  (laid.children ?? []).forEach((child) => {
    rankMap.set(child.id, child.y ?? 0);
  });

  const rfEdges: Edge[] = cfg.edges.map((e, i) => {
    const srcY = rankMap.get(e.from) ?? 0;
    const tgtY = rankMap.get(e.to) ?? 0;
    const isBack = tgtY < srcY;
    const dir = e.branch_dir ?? 'none';

    return {
      id: `${e.from}->${e.to}-${i}`,
      source: e.from,
      target: e.to,
      type: 'cyber',
      label: heavy ? undefined : e.label,
      data: { kind: e.kind, isBack, branchDir: dir },
    };
  });

  return { nodes: rfNodes, edges: rfEdges };
}

/* ------------------------------------------------------------------ */
/*  コールグラフ レイアウト                                             */
/* ------------------------------------------------------------------ */

const CG_NODE_W = 268;
const CG_NODE_H = 78;

export async function layoutCallGraphElk(
  graph: CallGraphData,
  entryPoints: string[],
): Promise<LayoutResult> {
  if (!graph.nodes.length) return { nodes: [], edges: [] };

  const nodeMap = new Map<string, CallGraphNode>();
  graph.nodes.forEach((n) => nodeMap.set(n.id, n));
  const epSet = new Set(entryPoints);

  const elkGraph: ElkNode = {
    id: 'root',
    layoutOptions: {
      'elk.algorithm': 'layered',
      'elk.direction': 'DOWN',
      'elk.layered.cycleBreaking.strategy': 'DEPTH_FIRST',
      'elk.layered.crossingMinimization.strategy': 'LAYER_SWEEP',
      'elk.layered.nodePlacement.strategy': 'BRANDES_KOEPF',
      'elk.spacing.nodeNode': '34',
      'elk.layered.spacing.nodeNodeBetweenLayers': '60',
      'elk.edgeRouting': 'ORTHOGONAL',
    },
    children: graph.nodes.map((n) => ({
      id: n.id,
      width: CG_NODE_W,
      height: CG_NODE_H,
    })),
    edges: graph.edges.map((e, i) => ({
      id: 'e-' + String(i),
      sources: [e.from],
      targets: [e.to],
    })),
  };

  const laid = await elk.layout(elkGraph);

  const rfNodes = toRfNodes(
    laid,
    (id) => {
      const n = nodeMap.get(id);
      return {
        name: n?.name ?? id,
        address: n?.address ?? id,
        isEntry: epSet.has(n?.address ?? '') || epSet.has(id),
      };
    },
    'callFunc',
  );

  const rfEdges: Edge[] = graph.edges.map((e, i) => ({
    id: `${e.from}->${e.to}-${i}`,
    source: e.from,
    target: e.to,
    type: 'smoothstep',
    style: { stroke: 'rgba(0, 200, 255, 0.42)', strokeWidth: 1.25 },
  }));

  return { nodes: rfNodes, edges: rfEdges };
}
