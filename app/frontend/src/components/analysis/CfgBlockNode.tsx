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
  const tipLines =
    d.disasm && d.disasm.length > 0 ? d.disasm : d.preview ? [d.preview] : [];

  return (
    <div
      className={clsx(
        'cyber-block',
        tipLines.length > 0 && 'cyber-block--has-tip',
        d.isEntry && 'cyber-block--entry',
        d.isExit && 'cyber-block--exit',
      )}
    >
      <Handle type="target" position={Position.Top} className="cyber-handle" />
      <div className="cyber-block-addr">{d.address}</div>
      {d.preview ? <div className="cyber-block-ins">{d.preview}</div> : null}
      {tipLines.length > 0 ? (
        <div className="cyber-block-tip" role="tooltip">
          <pre className="cyber-block-tip-pre">{tipLines.join('\n')}</pre>
        </div>
      ) : null}
      <Handle type="source" position={Position.Bottom} className="cyber-handle" />
    </div>
  );
}
