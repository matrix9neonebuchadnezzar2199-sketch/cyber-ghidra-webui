import { BaseEdge, EdgeLabelRenderer, getSmoothStepPath, type EdgeProps } from '@xyflow/react';

/**
 * Cyber-style edge: neon gradient + animated “power” dashes + branch label.
 */
export function CyberFlowEdge({
  id,
  sourceX,
  sourceY,
  targetX,
  targetY,
  sourcePosition,
  targetPosition,
  markerEnd,
  label,
}: EdgeProps) {
  const [path, labelX, labelY] = getSmoothStepPath({
    sourceX,
    sourceY,
    sourcePosition,
    targetX,
    targetY,
    targetPosition,
  });

  const safe = id.replace(/[^a-zA-Z0-9_-]/g, '_');
  const gid = `cg-${safe}-grad`;
  const fid = `cg-${safe}-blur`;

  return (
    <>
      <defs>
        <linearGradient id={gid} x1="0%" y1="0%" x2="100%" y2="0%">
          <stop offset="0%" stopColor="#00f3ff" />
          <stop offset="45%" stopColor="#c56bff" />
          <stop offset="100%" stopColor="#ff2a6d" />
        </linearGradient>
        <filter id={fid} x="-60%" y="-60%" width="220%" height="220%">
          <feGaussianBlur stdDeviation="3.5" result="b" />
          <feMerge>
            <feMergeNode in="b" />
            <feMergeNode in="SourceGraphic" />
          </feMerge>
        </filter>
      </defs>
      <BaseEdge
        id={id}
        path={path}
        markerEnd={markerEnd}
        style={{ stroke: `url(#${gid})`, strokeWidth: 2.5 }}
      />
      <path
        d={path}
        fill="none"
        stroke={`url(#${gid})`}
        strokeWidth={9}
        strokeLinecap="round"
        opacity={0.28}
        filter={`url(#${fid})`}
        pointerEvents="none"
      />
      <path
        d={path}
        fill="none"
        stroke="#7dffb3"
        strokeWidth={1.5}
        strokeLinecap="round"
        strokeDasharray="3 14"
        className="cyber-edge-flow"
        pointerEvents="none"
      />
      {label != null && String(label).length > 0 && (
        <EdgeLabelRenderer>
          <div
            className="cyber-edge-label-host"
            style={{
              transform: `translate(-50%, -50%) translate(${labelX}px, ${labelY}px)`,
            }}
          >
            <span className="cyber-edge-label">{String(label)}</span>
          </div>
        </EdgeLabelRenderer>
      )}
    </>
  );
}
