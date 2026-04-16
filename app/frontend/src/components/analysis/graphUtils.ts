import type { CallGraphData } from '../../types/analysis';

/**
 * 指定した関数から depth 段の呼び出し先・呼び出し元だけを抽出。
 * depth=0 でその関数のみ、depth=1 で直接の呼び出し先/元。
 */
export function extractSubgraph(
  graph: CallGraphData,
  centerAddr: string,
  depth: number,
): CallGraphData {
  if (depth < 0) return graph;

  const forwardAdj = new Map<string, string[]>();
  const reverseAdj = new Map<string, string[]>();

  for (const e of graph.edges) {
    if (!forwardAdj.has(e.from)) forwardAdj.set(e.from, []);
    forwardAdj.get(e.from)!.push(e.to);
    if (!reverseAdj.has(e.to)) reverseAdj.set(e.to, []);
    reverseAdj.get(e.to)!.push(e.from);
  }

  const reachable = new Set<string>();

  const bfs = (start: string, adj: Map<string, string[]>) => {
    const queue: [string, number][] = [[start, 0]];
    const visited = new Set<string>();
    while (queue.length > 0) {
      const [id, d] = queue.shift()!;
      if (visited.has(id) || d > depth) continue;
      visited.add(id);
      reachable.add(id);
      for (const neighbor of adj.get(id) ?? []) {
        if (!visited.has(neighbor)) {
          queue.push([neighbor, d + 1]);
        }
      }
    }
  };

  bfs(centerAddr, forwardAdj);
  bfs(centerAddr, reverseAdj);

  return {
    truncated: graph.truncated,
    nodes: graph.nodes.filter((n) => reachable.has(n.id)),
    edges: graph.edges.filter((e) => reachable.has(e.from) && reachable.has(e.to)),
  };
}

/**
 * 孤立ノード（inもoutもないノード）を除去。
 */
export function removeIsolatedNodes(graph: CallGraphData): CallGraphData {
  const connected = new Set<string>();
  for (const e of graph.edges) {
    connected.add(e.from);
    connected.add(e.to);
  }
  return {
    ...graph,
    nodes: graph.nodes.filter((n) => connected.has(n.id)),
  };
}

/**
 * ノード名フィルタ（部分一致）。
 */
export function filterGraphByName(
  graph: CallGraphData,
  query: string,
): { matchIds: Set<string> } {
  const q = query.trim().toLowerCase();
  if (!q) return { matchIds: new Set() };
  const matchIds = new Set<string>();
  for (const n of graph.nodes) {
    if (n.name.toLowerCase().includes(q) || n.address.toLowerCase().includes(q)) {
      matchIds.add(n.id);
    }
  }
  return { matchIds };
}
