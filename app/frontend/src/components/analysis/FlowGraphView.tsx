import React, { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Background,
  Controls,
  MiniMap,
  Panel,
  ReactFlow,
  ReactFlowProvider,
  useEdgesState,
  useNodesState,
  useReactFlow,
  type Edge,
  type Node,
  type NodeTypes,
  type EdgeTypes,
  type ReactFlowInstance,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import type { CfgData, CfgNode } from '../../types/analysis';
import { CfgBlockNode } from './CfgBlockNode';
import { CyberFlowEdge } from './CyberFlowEdge';

const NODE_W = 220;
const NODE_H = 88;
const H_GAP = 44;
const V_GAP = 72;

/** これ以上は Cyber エッジをやめ、ビューポート最適化・ミニマップ省略 */
const CFG_HEAVY_NODES = 55;
const CFG_HEAVY_EDGES = 90;

const nodeTypes = { cfgBlock: CfgBlockNode } satisfies NodeTypes;
const edgeTypes = { cyber: CyberFlowEdge } satisfies EdgeTypes;

/** Topological-style ranks without dagre (no extra npm deps — works in stale Docker node_modules). */
function layoutCfg(cfg: CfgData): { nodes: Node[]; edges: Edge[] } {
  if (!cfg.nodes.length) {
    return { nodes: [], edges: [] };
  }

  const nodeIds = new Set(cfg.nodes.map((n) => n.id));
  const rank = new Map<string, number>();
  cfg.nodes.forEach((n) => rank.set(n.id, 0));

  const entryId = pickEntryNode(cfg.nodes);
  rank.set(entryId, 0);

  const maxIter = nodeIds.size + 24;
  for (let iter = 0; iter < maxIter; iter++) {
    let changed = false;
    for (const e of cfg.edges) {
      if (!nodeIds.has(e.from) || !nodeIds.has(e.to)) continue;
      const next = (rank.get(e.from) ?? 0) + 1;
      if (next > (rank.get(e.to) ?? 0)) {
        rank.set(e.to, next);
        changed = true;
      }
    }
    if (!changed) break;
  }

  const layers = new Map<number, string[]>();
  rank.forEach((r, id) => {
    if (!layers.has(r)) layers.set(r, []);
    layers.get(r)!.push(id);
  });
  layers.forEach((ids) => ids.sort());

  const maxRank = Math.max(0, ...rank.values());
  const positions = new Map<string, { x: number; y: number }>();

  for (let r = 0; r <= maxRank; r++) {
    const ids = layers.get(r);
    if (!ids?.length) continue;
    const step = NODE_W + H_GAP;
    const layerW = ids.length * step - H_GAP;
    let x0 = -layerW / 2;
    ids.forEach((id, i) => {
      positions.set(id, { x: x0 + i * step, y: r * (NODE_H + V_GAP) });
    });
  }

  const rfNodes: Node[] = cfg.nodes.map((n) => ({
    id: n.id,
    type: 'cfgBlock',
    data: {
      address: n.start,
      preview: n.preview,
      disasm: n.disasm,
      isEntry: n.is_entry,
      isExit: n.is_exit,
    },
    position: positions.get(n.id) ?? { x: 0, y: 0 },
  }));

  const heavy = cfg.nodes.length >= CFG_HEAVY_NODES || cfg.edges.length >= CFG_HEAVY_EDGES;
  const rfEdges: Edge[] = cfg.edges.map((e, i) =>
    heavy
      ? {
          id: `${e.from}->${e.to}-${i}`,
          source: e.from,
          target: e.to,
          type: 'smoothstep',
          style: { stroke: 'rgba(0, 200, 255, 0.42)', strokeWidth: 1.25 },
        }
      : {
          id: `${e.from}->${e.to}-${i}`,
          source: e.from,
          target: e.to,
          type: 'cyber',
          label: e.label,
          data: { kind: e.kind },
        },
  );

  return { nodes: rfNodes, edges: rfEdges };
}

function pickEntryNode(nodes: CfgNode[]): string {
  const marked = nodes.find((n) => n.is_entry);
  if (marked) return marked.id;
  if (nodes.length === 1) return nodes[0].id;
  return nodes.reduce((a, b) => (a.start <= b.start ? a : b)).id;
}

function FitViewButton() {
  const { fitView } = useReactFlow();
  return (
    <button
      type="button"
      className="cyber-flow-fit"
      onClick={() => fitView({ padding: 0.12, duration: 250 })}
    >
      全体表示
    </button>
  );
}

type Props = {
  cfg: CfgData;
};

function FlowGraphInner({ cfg }: Props) {
  const initial = useMemo(() => layoutCfg(cfg), [cfg]);
  const [nodes, setNodes, onNodesChange] = useNodesState(initial.nodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(initial.edges);
  const [detailId, setDetailId] = useState<string | null>(null);

  const cfgHeavy =
    cfg.nodes.length >= CFG_HEAVY_NODES || cfg.edges.length >= CFG_HEAVY_EDGES;

  useEffect(() => {
    const next = layoutCfg(cfg);
    setNodes(next.nodes);
    setEdges(next.edges);
    setDetailId(null);
  }, [cfg, setNodes, setEdges]);

  const onInit = useCallback(
    (instance: ReactFlowInstance) => {
      window.requestAnimationFrame(() => {
        instance.fitView({ padding: 0.15, duration: cfgHeavy ? 0 : 200 });
      });
    },
    [cfgHeavy],
  );

  const onNodeClick = useCallback((_: React.MouseEvent, node: Node) => {
    setDetailId(node.id);
  }, []);

  const detailText = useMemo(() => {
    if (!detailId) return '';
    const n = cfg.nodes.find((x) => x.id === detailId);
    if (!n) return '';
    if (n.disasm?.length) return n.disasm.join('\n');
    return n.preview ?? '';
  }, [detailId, cfg.nodes]);

  const detailAddr = useMemo(() => {
    if (!detailId) return '';
    return cfg.nodes.find((x) => x.id === detailId)?.start ?? '';
  }, [detailId, cfg.nodes]);

  return (
    <ReactFlow
      nodes={nodes}
      edges={edges}
      onNodesChange={onNodesChange}
      onEdgesChange={onEdgesChange}
      nodeTypes={nodeTypes}
      edgeTypes={edgeTypes}
      onInit={onInit}
      onNodeClick={onNodeClick}
      minZoom={0.15}
      maxZoom={1.8}
      fitView
      proOptions={{ hideAttribution: true }}
      className="cyber-flow"
      onlyRenderVisibleElements
      nodesDraggable={false}
      nodesConnectable={false}
      elevateNodesOnSelect={false}
    >
      {!cfgHeavy ? <Background color="#1a1528" gap={28} size={1.2} /> : null}
      <Controls className="cyber-controls" />
      {!cfgHeavy ? (
        <MiniMap
          className="cyber-minimap"
          maskColor="rgba(0,0,0,0.75)"
          nodeColor={() => '#00f3ff'}
        />
      ) : null}
      {cfgHeavy ? (
        <Panel position="top-left" className="cyber-flow-perf-panel">
          基本ブロック数が多いため軽量表示です（画面内のみ描画・エッジ簡略・ミニマップ省略）。
        </Panel>
      ) : null}
      <Panel position="top-right">
        <FitViewButton />
      </Panel>
      {detailId ? (
        <Panel position="bottom-center" className="cyber-flow-detail">
          <div className="cyber-flow-detail-inner">
            <div className="cyber-flow-detail-head">
              <span className="cyber-flow-detail-addr">{detailAddr}</span>
              <button type="button" className="cyber-flow-detail-close" onClick={() => setDetailId(null)}>
                閉じる
              </button>
            </div>
            <pre className="cyber-flow-detail-pre">
              {detailText || '（このブロックの命令行がありません。再解析で disasm が付与されます。）'}
            </pre>
          </div>
        </Panel>
      ) : null}
    </ReactFlow>
  );
}

export function FlowGraphView({ cfg }: Props) {
  if (cfg.truncated && !cfg.nodes.length) {
    return (
      <div className="cyber-flow-empty">
        <p>
          この関数の CFG は大きすぎるか取得に失敗しました
          {cfg.reason ? `（${cfg.reason}）` : ''}
          {cfg.error ? ` — ${cfg.error}` : ''}
        </p>
      </div>
    );
  }

  if (!cfg.nodes.length) {
    return <p className="apple-adetail-hint">基本ブロックがありません。</p>;
  }

  return (
    <div className="cyber-flow-wrap">
      <ReactFlowProvider>
        <FlowGraphInner cfg={cfg} />
      </ReactFlowProvider>
    </div>
  );
}
