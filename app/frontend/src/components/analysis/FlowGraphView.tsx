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
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import type { CfgData } from '../../types/analysis';
import { CfgBlockNode } from './CfgBlockNode';
import { CYBER_BLUR_ID, CYBER_GRAD_ID, CyberFlowEdge } from './CyberFlowEdge';
import { layoutCfgElk } from './elkLayout';

/** 全 CyberFlowEdge が参照する SVG defs を 1 回だけ描画する */
function CyberFlowDefs() {
  return (
    <svg style={{ position: 'absolute', width: 0, height: 0 }}>
      <defs>
        <linearGradient id={CYBER_GRAD_ID} x1="0%" y1="0%" x2="100%" y2="0%">
          <stop offset="0%" stopColor="#00f3ff" />
          <stop offset="45%" stopColor="#c56bff" />
          <stop offset="100%" stopColor="#ff2a6d" />
        </linearGradient>
        <filter id={CYBER_BLUR_ID} x="-60%" y="-60%" width="220%" height="220%">
          <feGaussianBlur stdDeviation="3.5" result="b" />
          <feMerge>
            <feMergeNode in="b" />
            <feMergeNode in="SourceGraphic" />
          </feMerge>
        </filter>
      </defs>
    </svg>
  );
}

const CFG_HEAVY_NODES = 55;
const CFG_HEAVY_EDGES = 90;

const nodeTypes = { cfgBlock: CfgBlockNode } satisfies NodeTypes;
const edgeTypes = { cyber: CyberFlowEdge } satisfies EdgeTypes;

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
  onBlockSelect?: (address: string) => void;
  highlightBlockId?: string | null;
};

function FlowGraphInner({ cfg, onBlockSelect, highlightBlockId }: Props) {
  const [nodes, setNodes, onNodesChange] = useNodesState<Node>([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState<Edge>([]);
  const [layoutReady, setLayoutReady] = useState(false);
  const [detailId, setDetailId] = useState<string | null>(null);
  const { fitView, setCenter } = useReactFlow();

  const cfgHeavy =
    cfg.nodes.length >= CFG_HEAVY_NODES || cfg.edges.length >= CFG_HEAVY_EDGES;

  useEffect(() => {
    let cancelled = false;
    setLayoutReady(false);

    layoutCfgElk(cfg, cfgHeavy).then((result) => {
      if (cancelled) return;
      setNodes(result.nodes);
      setEdges(result.edges);
      setDetailId(null);
      setLayoutReady(true);
    });

    return () => {
      cancelled = true;
    };
  }, [cfg, cfgHeavy, setNodes, setEdges]);

  useEffect(() => {
    if (!layoutReady) return;
    const timer = requestAnimationFrame(() => {
      fitView({ padding: 0.15, duration: cfgHeavy ? 0 : 200 });
    });
    return () => cancelAnimationFrame(timer);
  }, [layoutReady, fitView, cfgHeavy]);

  useEffect(() => {
    if (!highlightBlockId || !layoutReady) return;
    const target = nodes.find((n) => n.id === highlightBlockId);
    if (target) {
      setCenter(target.position.x + 115, target.position.y + 46, { zoom: 1.2, duration: 300 });
      setDetailId(highlightBlockId);
    }
  }, [highlightBlockId, layoutReady, nodes, setCenter]);

  const onNodeClick = useCallback(
    (_: React.MouseEvent, node: Node) => {
      setDetailId(node.id);
      onBlockSelect?.(node.id);
    },
    [onBlockSelect],
  );

  const detailNode = useMemo(() => {
    if (!detailId) return null;
    return cfg.nodes.find((x) => x.id === detailId) ?? null;
  }, [detailId, cfg.nodes]);

  const detailText = detailNode?.disasm?.length
    ? detailNode.disasm.join('\n')
    : detailNode?.preview ?? '';

  if (!layoutReady) {
    return (
      <div className="cyber-flow-loading">
        <p>レイアウトを計算しています…</p>
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
      edgeTypes={edgeTypes}
      onNodeClick={onNodeClick}
      minZoom={0.1}
      maxZoom={2.0}
      fitView
      proOptions={{ hideAttribution: true }}
      className="cyber-flow"
      onlyRenderVisibleElements
      nodesDraggable
      nodesConnectable={false}
      elevateNodesOnSelect={false}
    >
      <CyberFlowDefs />
      {!cfgHeavy && <Background color="#1a1528" gap={28} size={1.2} />}
      <Controls className="cyber-controls" />
      {!cfgHeavy && (
        <MiniMap
          className="cyber-minimap"
          maskColor="rgba(0,0,0,0.75)"
          nodeColor={() => '#00f3ff'}
        />
      )}
      {cfgHeavy && (
        <Panel position="top-left" className="cyber-flow-perf-panel">
          基本ブロック数が多いため軽量表示です。ノードはドラッグ移動可能です。
        </Panel>
      )}
      <Panel position="top-right">
        <FitViewButton />
      </Panel>
      {detailNode && (
        <Panel position="bottom-center" className="cyber-flow-detail">
          <div className="cyber-flow-detail-inner">
            <div className="cyber-flow-detail-head">
              <span className="cyber-flow-detail-addr">{detailNode.start}</span>
              <span className="cyber-flow-detail-range">→ {detailNode.end}</span>
              <button type="button" className="cyber-flow-detail-close" onClick={() => setDetailId(null)}>
                閉じる
              </button>
            </div>
            <pre className="cyber-flow-detail-pre">
              {detailText || '（命令行がありません。再解析で disasm が付与されます。）'}
            </pre>
          </div>
        </Panel>
      )}
    </ReactFlow>
  );
}

export function FlowGraphView({ cfg, onBlockSelect, highlightBlockId }: Props) {
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
        <FlowGraphInner
          cfg={cfg}
          onBlockSelect={onBlockSelect}
          highlightBlockId={highlightBlockId}
        />
      </ReactFlowProvider>
    </div>
  );
}
