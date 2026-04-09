import type { AnalysisFunction } from '../../types/analysis';

export type FuncTreeNode = {
  segment: string;
  pathKey: string;
  children: FuncTreeNode[];
  /** indices into `functions` array */
  leafIndices: number[];
};

function insert(node: FuncTreeNode, parts: string[], fnIndex: number, depth: number): void {
  if (depth >= parts.length) {
    node.leafIndices.push(fnIndex);
    return;
  }
  const seg = parts[depth];
  let child = node.children.find((c) => c.segment === seg);
  if (!child) {
    child = {
      segment: seg,
      pathKey: node.pathKey ? `${node.pathKey}::${seg}` : seg,
      children: [],
      leafIndices: [],
    };
    node.children.push(child);
  }
  insert(child, parts, fnIndex, depth + 1);
}

function sortTree(node: FuncTreeNode): void {
  node.children.sort((a, b) => a.segment.localeCompare(b.segment, undefined, { sensitivity: 'base' }));
  for (const c of node.children) sortTree(c);
}

/** Build namespace tree from `::` segments (Ghidra-style). */
export function buildFunctionTree(functions: AnalysisFunction[], indices: number[]): FuncTreeNode {
  const root: FuncTreeNode = { segment: 'root', pathKey: '', children: [], leafIndices: [] };
  for (const idx of indices) {
    const fn = functions[idx];
    const parts = fn.name.includes('::')
      ? fn.name.split('::').map((p) => p.trim()).filter(Boolean)
      : [fn.name];
    const safe = parts.length ? parts : [fn.name];
    insert(root, safe, idx, 0);
  }
  sortTree(root);
  return root;
}

export function filterFunctionIndices(
  functions: AnalysisFunction[],
  query: string,
): number[] {
  const q = query.trim().toLowerCase();
  if (!q) return functions.map((_, i) => i);
  const out: number[] = [];
  for (let i = 0; i < functions.length; i++) {
    const f = functions[i];
    if (
      f.name.toLowerCase().includes(q) ||
      f.address.toLowerCase().includes(q) ||
      (f.decompiled_c && f.decompiled_c.toLowerCase().includes(q))
    ) {
      out.push(i);
    }
  }
  return out;
}
