import { BaseEdge, EdgeLabelRenderer, getSmoothStepPath, type EdgeProps } from '@xyflow/react';

/**
 * Cyber-style edge: shared gradient/filter defs + animated dashes + branch label.
 * <defs> are defined once in FlowGraphView via <CyberFlowDefs />.
 */

export const CYBER_GRAD_ID = 'cyber-edge-grad';
export const CYBER_BLUR_ID = 'cyber-edge-blur';

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

  return (
    <>
      <BaseEdge
        id={id}
        path={path}
        markerEnd={markerEnd}
        style={{ stroke: `url(#${CYBER_GRAD_ID})`, strokeWidth: 2.5 }}
      />
      <path
        d={path}
        fill="none"
        stroke={`url(#${CYBER_GRAD_ID})`}
        strokeWidth={9}
        strokeLinecap="round"
        opacity={0.28}
        filter={`url(#${CYBER_BLUR_ID})`}
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
