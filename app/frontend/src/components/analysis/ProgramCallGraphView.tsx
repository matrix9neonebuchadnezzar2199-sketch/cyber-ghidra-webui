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
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import type { CallGraphData } from '../../types/analysis';
import { layoutCallGraphElk } from './elkLayout';

const HEAVY_NODES = 70;
const HEAVY_EDGES = 120;

const CallFuncNode = React.memo(function CallFuncNode({ data }: NodeProps) {
  const d = data as {
    name: string;
    address: string;
    isEntry?: boolean;
    riskLevel?: string;
    dim?: boolean;
  };
  const tip = `${d.name}\n${d.address}`;
  const riskClass = d.riskLevel ? `cyber-block--risk-${d.riskLevel}` : '';

  return (
    <div
      className={clsx(
        'cyber-block',
        'cyber-block--func',
        d.isEntry && 'cyber-block--entry',
        riskClass,
        d.dim && 'cyber-block--dim',
      )}
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
  riskMap?: Map<string, string>;
  searchMatchIds?: Set<string>;
};

function ProgramCallGraphInner({
  graph,
  entryPoints,
  onSelectFunctionByAddress,
  onOpenFunctionCfg,
  riskMap,
  searchMatchIds,
}: Props) {
  const [nodes, setNodes, onNodesChange] = useNodesState<Node>([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState<Edge>([]);
  const [layoutReady, setLayoutReady] = useState(false);
  const [detailId, setDetailId] = useState<string | null>(null);
  const { fitView } = useReactFlow();

  const isHeavy =
    graph.nodes.length >= HEAVY_NODES || graph.edges.length >= HEAVY_EDGES;

  useEffect(() => {
    let cancelled = false;
    setLayoutReady(false);

    layoutCallGraphElk(graph, entryPoints).then((result) => {
      if (cancelled) return;
      if (riskMap && riskMap.size > 0) {
        result.nodes.forEach((n) => {
          const risk = riskMap.get(n.id);
          if (risk) {
            (n.data as Record<string, unknown>).riskLevel = risk;
          }
        });
      }
      if (searchMatchIds && searchMatchIds.size > 0) {
        result.nodes.forEach((n) => {
          if (!searchMatchIds.has(n.id)) {
            (n.data as Record<string, unknown>).dim = true;
          }
        });
      }
      setNodes(result.nodes);
      setEdges(result.edges);
      setDetailId(null);
      setLayoutReady(true);
    });

    return () => {
      cancelled = true;
    };
  }, [graph, entryPoints, riskMap, searchMatchIds, setNodes, setEdges]);

  useEffect(() => {
    if (!layoutReady) return;
    const timer = requestAnimationFrame(() => {
      fitView({ padding: 0.12, duration: isHeavy ? 0 : 200 });
    });
    return () => cancelAnimationFrame(timer);
  }, [layoutReady, fitView, isHeavy]);

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

  if (!layoutReady) {
    return (
      <div className="cyber-flow-loading">
        <p>コールグラフのレイアウトを計算しています…</p>
      </div>
    );
  }

  return (
    <ReactFlow
      nodes={nodes}
      edges={edges}
      onNodesChange={onNodesChange}
      onEdgesChange={onEdgesChange}
      nodeTypes={nodeTypes}
      onNodeClick={onNodeClick}
      onNodeDoubleClick={onNodeDoubleClick}
      minZoom={0.05}
      maxZoom={1.6}
      fitView
      proOptions={{ hideAttribution: true }}
      className="cyber-flow"
      onlyRenderVisibleElements
      nodesDraggable
      nodesConnectable={false}
      elevateNodesOnSelect={false}
    >
      {!isHeavy && <Background color="#1a1528" gap={28} size={1.2} />}
      <Controls className="cyber-controls" />
      {!isHeavy && (
        <MiniMap
          className="cyber-minimap"
          maskColor="rgba(0,0,0,0.75)"
          nodeColor={() => '#a78bfa'}
          pannable
          zoomable
        />
      )}
      <Panel position="top-right">
        <FitViewButton />
      </Panel>
      {(isHeavy || graph.truncated) && (
        <Panel position="top-left" className="cyber-flow-perf-panel">
          {isHeavy && (
            <span>大規模のため軽量表示です。ノードはドラッグ移動可能です。</span>
          )}
          {isHeavy && graph.truncated && <br />}
          {graph.truncated && (
            <span>
              {isHeavy ? 'さらに' : ''}解析側の上限により一部ノードのみが含まれています。
            </span>
          )}
        </Panel>
      )}
      {detail && (
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
              クリックで左ツリー同期。ダブルクリックで関数内 CFG へ。
            </p>
            {onOpenFunctionCfg && (
              <button
                type="button"
                className="cyber-flow-open-cfg"
                onClick={() => onOpenFunctionCfg(detail.address)}
              >
                この関数の CFG を開く
              </button>
            )}
          </div>
        </Panel>
      )}
    </ReactFlow>
  );
}

export function ProgramCallGraphView({
  graph,
  entryPoints,
  onSelectFunctionByAddress,
  onOpenFunctionCfg,
  riskMap,
  searchMatchIds,
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
          riskMap={riskMap}
          searchMatchIds={searchMatchIds}
        />
      </ReactFlowProvider>
    </div>
  );
}
