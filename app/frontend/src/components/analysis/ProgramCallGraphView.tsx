import React, { useCallback, useEffect, useMemo, useState } from 'react';
import clsx from 'clsx';
import {
  Background,
  Controls,
  Handle,
  MiniMap,
  Panel,
  Position,
  ReactFlow,
  ReactFlowProvider,
  useEdgesState,
  useNodesState,
  useReactFlow,
  type Edge,
  type Node,
  type NodeProps,
  type NodeTypes,
  type ReactFlowInstance,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import type { CallGraphData, CallGraphNode } from '../../types/analysis';

const NODE_W = 260;
const NODE_H = 76;
const H_GAP = 40;
const V_GAP = 64;

/** これ以上はミニマップ・背景を省略し、初期 fitView のアニメを止める */
const HEAVY_NODES = 70;
const HEAVY_EDGES = 120;

const CallFuncNode = React.memo(function CallFuncNode({ data }: NodeProps) {
  const d = data as { name: string; address: string; isEntry?: boolean };
  const tip = `${d.name}\n${d.address}`;
  return (
    <div
      className={clsx('cyber-block', 'cyber-block--func', d.isEntry && 'cyber-block--entry')}
    >
      <Handle type="target" position={Position.Top} className="cyber-handle" />
      <div className="cyber-block-name">{d.name}</div>
      <div className="cyber-block-addr cyber-block-addr--sub">{d.address}</div>
      <div className="cyber-block-tip cyber-block-tip--func" role="tooltip">
        <pre className="cyber-block-tip-pre">{tip}</pre>
      </div>
      <Handle type="source" position={Position.Bottom} className="cyber-handle" />
    </div>
  );
});

const nodeTypes = { callFunc: CallFuncNode } satisfies NodeTypes;

function layoutCallGraph(
  graph: CallGraphData,
  entryPoints: string[],
): { nodes: Node[]; edges: Edge[] } {
  if (!graph.nodes.length) {
    return { nodes: [], edges: [] };
  }

  const nodeIds = new Set(graph.nodes.map((n) => n.id));
  const rank = new Map<string, number>();
  graph.nodes.forEach((n) => rank.set(n.id, 0));

  const entryId = pickCallGraphEntry(graph.nodes, entryPoints);
  rank.set(entryId, 0);

  const maxIter = nodeIds.size + 24;
  for (let iter = 0; iter < maxIter; iter++) {
    let changed = false;
    for (const e of graph.edges) {
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

  const epSet = new Set(entryPoints);
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

  const rfNodes: Node[] = graph.nodes.map((n) => ({
    id: n.id,
    type: 'callFunc',
    data: {
      name: n.name,
      address: n.address,
      isEntry: epSet.has(n.address) || epSet.has(n.id),
    },
    position: positions.get(n.id) ?? { x: 0, y: 0 },
  }));

  /** ビルトイン smoothstep のみ（CyberFlowEdge の per-edge defs / ぼかし / アニメは大規模で致命的に重い） */
  const rfEdges: Edge[] = graph.edges.map((e, i) => ({
    id: `${e.from}->${e.to}-${i}`,
    source: e.from,
    target: e.to,
    type: 'smoothstep',
    style: { stroke: 'rgba(0, 200, 255, 0.42)', strokeWidth: 1.25 },
  }));

  return { nodes: rfNodes, edges: rfEdges };
}

function pickCallGraphEntry(nodes: CallGraphNode[], entryPoints: string[]): string {
  for (const ep of entryPoints) {
    const found = nodes.find((n) => n.address === ep || n.id === ep);
    if (found) return found.id;
  }
  if (nodes.length === 1) return nodes[0].id;
  return nodes.reduce((a, b) => (a.address <= b.address ? a : b)).id;
}

function FitViewButton() {
  const { fitView } = useReactFlow();
  return (
    <button
      type="button"
      className="cyber-flow-fit"
      onClick={() => fitView({ padding: 0.1, duration: 200 })}
    >
      全体表示
    </button>
  );
}

type Props = {
  graph: CallGraphData;
  entryPoints: string[];
  onSelectFunctionByAddress?: (address: string) => void;
  onOpenFunctionCfg?: (address: string) => void;
};

function ProgramCallGraphInner({
  graph,
  entryPoints,
  onSelectFunctionByAddress,
  onOpenFunctionCfg,
}: Props) {
  const initial = useMemo(() => layoutCallGraph(graph, entryPoints), [graph, entryPoints]);
  const [nodes, setNodes, onNodesChange] = useNodesState(initial.nodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(initial.edges);
  const [detailId, setDetailId] = useState<string | null>(null);

  const isHeavy =
    graph.nodes.length >= HEAVY_NODES || graph.edges.length >= HEAVY_EDGES;

  useEffect(() => {
    const next = layoutCallGraph(graph, entryPoints);
    setNodes(next.nodes);
    setEdges(next.edges);
    setDetailId(null);
  }, [graph, entryPoints, setNodes, setEdges]);

  const onInit = useCallback(
    (instance: ReactFlowInstance) => {
      window.requestAnimationFrame(() => {
        instance.fitView({
          padding: 0.12,
          duration: isHeavy ? 0 : 200,
        });
      });
    },
    [isHeavy],
  );

  const onNodeClick = useCallback(
    (_: React.MouseEvent, node: Node) => {
      setDetailId(node.id);
      onSelectFunctionByAddress?.(node.id);
    },
    [onSelectFunctionByAddress],
  );

  const onNodeDoubleClick = useCallback(
    (_: React.MouseEvent, node: Node) => {
      onOpenFunctionCfg?.(node.id);
    },
    [onOpenFunctionCfg],
  );

  const detail = useMemo(() => {
    if (!detailId) return null;
    return graph.nodes.find((x) => x.id === detailId) ?? null;
  }, [detailId, graph.nodes]);

  return (
    <ReactFlow
      nodes={nodes}
      edges={edges}
      onNodesChange={onNodesChange}
      onEdgesChange={onEdgesChange}
      nodeTypes={nodeTypes}
      onInit={onInit}
      onNodeClick={onNodeClick}
      onNodeDoubleClick={onNodeDoubleClick}
      minZoom={0.08}
      maxZoom={1.6}
      fitView
      proOptions={{ hideAttribution: true }}
      className="cyber-flow"
      onlyRenderVisibleElements
      nodesDraggable={false}
      nodesConnectable={false}
      elevateNodesOnSelect={false}
    >
      {!isHeavy ? <Background color="#1a1528" gap={28} size={1.2} /> : null}
      <Controls className="cyber-controls" />
      {!isHeavy ? (
        <MiniMap
          className="cyber-minimap"
          maskColor="rgba(0,0,0,0.75)"
          nodeColor={() => '#a78bfa'}
          pannable
          zoomable
        />
      ) : null}
      <Panel position="top-right">
        <FitViewButton />
      </Panel>
      {isHeavy || graph.truncated ? (
        <Panel position="top-left" className="cyber-flow-perf-panel">
          {isHeavy ? (
            <span>
              大規模のため軽量表示です（画面内のノード／エッジのみ描画・単純なエッジ・ミニマップ省略）。
            </span>
          ) : null}
          {isHeavy && graph.truncated ? <br /> : null}
          {graph.truncated ? (
            <span>
              {isHeavy ? 'さらに' : ''}解析側の上限により一部ノードのみが含まれています。
            </span>
          ) : null}
        </Panel>
      ) : null}
      {detail ? (
        <Panel position="bottom-center" className="cyber-flow-detail">
          <div className="cyber-flow-detail-inner">
            <div className="cyber-flow-detail-head">
              <span className="cyber-flow-detail-title">{detail.name}</span>
              <span className="cyber-flow-detail-addr">{detail.address}</span>
              <button type="button" className="cyber-flow-detail-close" onClick={() => setDetailId(null)}>
                閉じる
              </button>
            </div>
            <p className="cyber-flow-detail-hint">
              各箱は 1 関数です。命令レベルの流れは「関数内 CFG」で基本ブロックごとに表示されます。
            </p>
            {onOpenFunctionCfg ? (
              <button
                type="button"
                className="cyber-flow-open-cfg"
                onClick={() => onOpenFunctionCfg(detail.address)}
              >
                この関数の CFG を開く
              </button>
            ) : null}
          </div>
        </Panel>
      ) : null}
    </ReactFlow>
  );
}

export function ProgramCallGraphView({
  graph,
  entryPoints,
  onSelectFunctionByAddress,
  onOpenFunctionCfg,
}: Props) {
  if (graph.error && !graph.nodes.length) {
    return (
      <div className="cyber-flow-empty">
        <p>コールグラフの取得に失敗しました{graph.error ? ` — ${graph.error}` : ''}</p>
      </div>
    );
  }

  if (!graph.nodes.length) {
    return (
      <p className="apple-adetail-hint">
        コールグラフにノードがありません。バックエンド更新後に<strong>検体を再解析</strong>してください。
      </p>
    );
  }

  return (
    <div className="cyber-flow-wrap">
      <ReactFlowProvider>
        <ProgramCallGraphInner
          graph={graph}
          entryPoints={entryPoints}
          onSelectFunctionByAddress={onSelectFunctionByAddress}
          onOpenFunctionCfg={onOpenFunctionCfg}
        />
      </ReactFlowProvider>
    </div>
  );
}
