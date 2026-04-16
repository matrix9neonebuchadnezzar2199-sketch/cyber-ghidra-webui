/** Shape of *_analysis.json from Ghidra headless auto_analyze.py */

/** CFG exported from Ghidra (basic blocks + edges with branch hints) */
export type CfgNode = {
  id: string;
  start: string;
  end: string;
  preview?: string;
  /** Disassembly lines in this block (hover / detail) */
  disasm?: string[];
  is_entry?: boolean;
  is_exit?: boolean;
};

export type CfgEdge = {
  from: string;
  to: string;
  kind: string;
  label: string;
  /** "true" | "false" | "fallthrough" | "unconditional" | "call" | "conditional" | "none" */
  branch_dir?: string;
};

export type CfgData = {
  truncated?: boolean;
  reason?: string;
  error?: string;
  nodes: CfgNode[];
  edges: CfgEdge[];
};

/** Whole-program function call graph (entry → callees → …) */
export type CallGraphNode = {
  id: string;
  name: string;
  address: string;
};

export type CallGraphEdge = {
  from: string;
  to: string;
  kind: string;
  label: string;
};

export type CallGraphData = {
  truncated?: boolean;
  error?: string;
  nodes: CallGraphNode[];
  edges: CallGraphEdge[];
};

export type DecompileSignalSeverity = 'info' | 'low' | 'medium' | 'high';

export type DecompileSignal = {
  id: string;
  severity: DecompileSignalSeverity;
  label: string;
};

export type DecompileStats = {
  line_count: number;
  goto_count: number;
  opaque_loop_hint?: boolean;
  heavy_goto_flattening?: boolean;
};

/** Regex heuristics on decompiler output (anti-analysis / obfuscation hints) */
export type DecompileInsights = {
  signals: DecompileSignal[];
  stats: DecompileStats;
};

export type XrefEntry = {
  name: string;
  address: string;
};

export type FunctionXrefs = {
  callers: XrefEntry[];
  callees: XrefEntry[];
};

export type AnalysisFunction = {
  name: string;
  address: string;
  size: number;
  decompiled_c: string | null;
  /** Present after re-analysis with extended auto_analyze.py */
  cfg?: CfgData | null;
  /** Present after re-analysis: pattern-based hints on decompiled C */
  decompile_insights?: DecompileInsights | null;
  /** Line number (1-based) → address (from decompiler markup) */
  line_address_map?: Record<string, string> | null;
  /** Cross-references (callers / callees) */
  xrefs?: FunctionXrefs | null;
};

export type AnalysisStringRow = {
  address: string;
  value: string;
};

export type AnalysisImportRow = {
  library: string;
  function: string;
  address: string;
};

export type AnalysisExportRow = {
  address: string;
  kind: string;
};

export type SuspiciousApiRow = {
  name: string;
  address: string;
  seen_from: string;
};

export type AnalysisJson = {
  file_name: string;
  architecture: string;
  compiler: string;
  entry_points: string[];
  functions: AnalysisFunction[];
  strings: AnalysisStringRow[];
  imports: AnalysisImportRow[];
  exports: AnalysisExportRow[];
  suspicious_apis: SuspiciousApiRow[];
  truncated: boolean;
  /** After extended auto_analyze: inter-function calls */
  call_graph?: CallGraphData | null;
};
