import { BaseEdge, EdgeLabelRenderer, getSmoothStepPath, type EdgeProps } from '@xyflow/react';

/**
 * Cyber-style edge: shared gradient/filter defs + animated dashes (call graph),
 * or solid branch colors for CFG when `data.branchDir` / `data.isBack` are set.
 * <defs> are defined once in FlowGraphView via <CyberFlowDefs />.
 */

export const CYBER_GRAD_ID = 'cyber-edge-grad';
export const CYBER_BLUR_ID = 'cyber-edge-blur';

/** branch_dir → ストローク色（CFG）。undefined のみグラデーション（コールグラフ等で data なしの場合） */
function resolveCfgStroke(branchDir?: string, isBack?: boolean): string | null {
  if (isBack) return 'rgba(255, 160, 60, 0.75)';
  if (branchDir === undefined) return null;
  switch (branchDir) {
    case 'true':
      return 'rgba(50, 215, 75, 0.75)';
    case 'false':
      return 'rgba(255, 69, 58, 0.7)';
    case 'fallthrough':
      return 'rgba(180, 180, 200, 0.5)';
    case 'call':
      return 'rgba(167, 139, 250, 0.6)';
    case 'conditional':
      return 'rgba(255, 204, 0, 0.7)';
    case 'unconditional':
    case 'none':
      return 'rgba(0, 200, 255, 0.42)';
    default:
      return 'rgba(0, 200, 255, 0.42)';
  }
}

function resolveDashArray(branchDir?: string, isBack?: boolean): string | undefined {
  if (isBack) return '6 4';
  if (branchDir === 'call') return '4 3';
  if (branchDir === 'conditional') return '3 3';
  return undefined;
}

function resolveStrokeWidth(branchDir?: string, isBack?: boolean): number {
  if (isBack) return 2.2;
  if (branchDir === 'true' || branchDir === 'false') return 2;
  if (branchDir === 'conditional') return 2;
  if (branchDir === 'fallthrough' || branchDir === 'call') return 1.5;
  return 2.5;
}

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
  data,
}: EdgeProps) {
  const [path, labelX, labelY] = getSmoothStepPath({
    sourceX,
    sourceY,
    sourcePosition,
    targetX,
    targetY,
    targetPosition,
  });

  const branchDir = (data as Record<string, unknown> | undefined)?.branchDir as string | undefined;
  const isBack = (data as Record<string, unknown> | undefined)?.isBack as boolean | undefined;

  const solidColor = resolveCfgStroke(branchDir, isBack);
  const dashArray = resolveDashArray(branchDir, isBack);
  const strokeWidth = resolveStrokeWidth(branchDir, isBack);

  const useCfgMode = solidColor !== null;

  if (useCfgMode) {
    return (
      <>
        <BaseEdge
          id={id}
          path={path}
          markerEnd={markerEnd}
          style={{
            stroke: solidColor,
            strokeWidth,
            strokeDasharray: dashArray,
          }}
        />
        <path
          d={path}
          fill="none"
          stroke={solidColor}
          strokeWidth={strokeWidth + 4}
          strokeLinecap="round"
          strokeDasharray={dashArray}
          opacity={0.15}
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
