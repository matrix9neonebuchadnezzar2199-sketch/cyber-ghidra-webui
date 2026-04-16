import React, { useState } from 'react';
import { Handle, Position, type NodeProps } from '@xyflow/react';
import clsx from 'clsx';

export type CfgBlockData = {
  address: string;
  preview?: string;
  disasm?: string[];
  isEntry?: boolean;
  isExit?: boolean;
};

export function CfgBlockNode({ data }: NodeProps) {
  const d = data as CfgBlockData;
  const [showTip, setShowTip] = useState(false);

  const disasm: string[] = (d.disasm as string[]) ?? [];
  const hasMore = disasm.length > 4;
  const displayLines = hasMore ? disasm.slice(0, 3) : disasm.slice(0, 4);
  const usePreviewFallback = disasm.length === 0 && Boolean(d.preview);
  const linesToShow = usePreviewFallback ? [String(d.preview)] : displayLines;
  const tipLines = disasm.length > 0 ? disasm : d.preview ? [d.preview] : [];

  return (
    <div
      className={clsx(
        'cyber-block',
        'cyber-block--cfg-node',
        d.isEntry && 'cyber-block--entry',
        d.isExit && 'cyber-block--exit',
      )}
      onMouseEnter={() => {
        if (tipLines.length > 0) setShowTip(true);
      }}
      onMouseLeave={() => setShowTip(false)}
    >
      <Handle type="target" position={Position.Top} className="cyber-handle" />
      <div className="cyber-block-addr-row">
        <span className="cyber-block-addr">{d.address}</span>
        {d.isEntry && (
          <span className="cfg-node-badge cfg-node-badge--entry" aria-label="エントリ">
            ENTRY
          </span>
        )}
        {d.isExit && (
          <span className="cfg-node-badge cfg-node-badge--exit" aria-label="出口">
            EXIT
          </span>
        )}
      </div>
      {linesToShow.length > 0 && (
        <div className="cfg-node-disasm-wrap">
          {linesToShow.map((line, i) => (
            <div key={i} className="cfg-node-disasm-line">
              {line}
            </div>
          ))}
          {hasMore && (
            <div className="cfg-node-disasm-more">他 {disasm.length - 3} 行</div>
          )}
        </div>
      )}
      {showTip && tipLines.length > 0 && (
        <div className="cyber-block-tip" role="tooltip">
          <pre className="cyber-block-tip-pre">{tipLines.join('\n')}</pre>
        </div>
      )}
      <Handle type="source" position={Position.Bottom} className="cyber-handle" />
    </div>
  );
}
