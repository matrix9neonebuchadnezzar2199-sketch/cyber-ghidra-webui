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
const CFG_NODE_H = 92;

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
      height: CFG_NODE_H,
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

    let stroke = 'rgba(0, 200, 255, 0.42)';
    let strokeWidth = 1.25;
    let dashArray: string | undefined;

    if (isBack) {
      stroke = 'rgba(255, 160, 60, 0.75)';
      strokeWidth = 2.2;
      dashArray = '6 4';
    } else if (dir === 'true') {
      stroke = 'rgba(50, 215, 75, 0.75)';
      strokeWidth = 2;
    } else if (dir === 'false') {
      stroke = 'rgba(255, 69, 58, 0.7)';
      strokeWidth = 2;
    } else if (dir === 'fallthrough') {
      stroke = 'rgba(180, 180, 200, 0.5)';
      strokeWidth = 1.5;
    } else if (dir === 'call') {
      stroke = 'rgba(167, 139, 250, 0.6)';
      strokeWidth = 1.5;
      dashArray = '4 3';
    }

    if (heavy) {
      return {
        id: `${e.from}->${e.to}-${i}`,
        source: e.from,
        target: e.to,
        type: 'smoothstep',
        style: { stroke, strokeWidth, strokeDasharray: dashArray },
      };
    }

    return {
      id: `${e.from}->${e.to}-${i}`,
      source: e.from,
      target: e.to,
      type: 'cyber',
      label: e.label,
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
