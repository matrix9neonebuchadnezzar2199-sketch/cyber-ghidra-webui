import React, { useMemo, useState } from 'react';
import { ChevronDown, ChevronRight } from 'lucide-react';
import clsx from 'clsx';
import type { AnalysisFunction } from '../../types/analysis';
import { buildFunctionTree, type FuncTreeNode } from './functionTreeUtils';

type Props = {
  functions: AnalysisFunction[];
  indices: number[];
  selectedIndex: number | null;
  onSelect: (index: number) => void;
};

function TreeRows({
  node,
  depth,
  functions,
  selectedIndex,
  onSelect,
  defaultOpenDepth,
}: {
  node: FuncTreeNode;
  depth: number;
  functions: AnalysisFunction[];
  selectedIndex: number | null;
  onSelect: (index: number) => void;
  defaultOpenDepth: number;
}) {
  const [open, setOpen] = useState(depth < defaultOpenDepth);

  if (node.segment === 'root') {
    return (
      <>
        {node.children.map((c) => (
          <TreeRows
            key={c.pathKey}
            node={c}
            depth={depth}
            functions={functions}
            selectedIndex={selectedIndex}
            onSelect={onSelect}
            defaultOpenDepth={defaultOpenDepth}
          />
        ))}
        {node.leafIndices.map((idx) => (
          <FunctionRow
            key={`leaf-${idx}`}
            idx={idx}
            fn={functions[idx]}
            depth={depth}
            selected={selectedIndex === idx}
            onSelect={onSelect}
          />
        ))}
      </>
    );
  }

  const hasFolder = node.children.length > 0 || node.leafIndices.length > 0;
  return (
    <div className="apple-ft-folder">
      {hasFolder && (
        <button
          type="button"
          className="apple-ft-row apple-ft-row--folder"
          style={{ paddingLeft: 8 + depth * 12 }}
          onClick={() => setOpen((o) => !o)}
        >
          <span className="apple-ft-chevron">{open ? <ChevronDown size={14} /> : <ChevronRight size={14} />}</span>
          <span className="apple-ft-seg">{node.segment}</span>
          <span className="apple-ft-count">{node.leafIndices.length}</span>
        </button>
      )}
      {open && (
        <>
          {node.children.map((c) => (
            <TreeRows
              key={c.pathKey}
              node={c}
              depth={depth + 1}
              functions={functions}
              selectedIndex={selectedIndex}
              onSelect={onSelect}
              defaultOpenDepth={defaultOpenDepth}
            />
          ))}
          {node.leafIndices.map((idx) => (
            <FunctionRow
              key={`leaf-${idx}`}
              idx={idx}
              fn={functions[idx]}
              depth={depth + 1}
              selected={selectedIndex === idx}
              onSelect={onSelect}
            />
          ))}
        </>
      )}
    </div>
  );
}

function FunctionRow({
  idx,
  fn,
  depth,
  selected,
  onSelect,
}: {
  idx: number;
  fn: AnalysisFunction;
  depth: number;
  selected: boolean;
  onSelect: (index: number) => void;
}) {
  return (
    <button
      type="button"
      className={clsx('apple-ft-row apple-ft-row--fn', selected && 'apple-ft-row--selected')}
      style={{ paddingLeft: 8 + depth * 12 }}
      onClick={() => onSelect(idx)}
    >
      <span className="apple-ft-name">{fn.name}</span>
      <span className="apple-ft-addr">{fn.address}</span>
    </button>
  );
}

export function FunctionTree({ functions, indices, selectedIndex, onSelect }: Props) {
  const root = useMemo(() => buildFunctionTree(functions, indices), [functions, indices]);

  return (
    <div className="apple-ft">
      <TreeRows
        node={root}
        depth={0}
        functions={functions}
        selectedIndex={selectedIndex}
        onSelect={onSelect}
        defaultOpenDepth={2}
      />
    </div>
  );
}
