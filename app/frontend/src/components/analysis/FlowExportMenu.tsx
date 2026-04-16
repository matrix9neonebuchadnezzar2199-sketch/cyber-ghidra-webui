import React, { useState } from 'react';
import { Download } from 'lucide-react';
import type { CallGraphData, CfgData } from '../../types/analysis';
import {
  cfgToDot,
  callGraphToDot,
  captureFlowSvg,
  downloadSvg,
  downloadPng,
  downloadText,
} from './exportGraph';

type Props = {
  cfg?: CfgData | null;
  callGraph?: CallGraphData | null;
  funcName?: string;
};

export function FlowExportMenu({ cfg, callGraph, funcName }: Props) {
  const [open, setOpen] = useState(false);

  const handleSvg = () => {
    const svg = captureFlowSvg();
    if (svg) {
      downloadSvg(svg, `${funcName ?? 'flow'}.svg`);
    }
    setOpen(false);
  };

  const handlePng = () => {
    const svg = captureFlowSvg();
    if (svg) {
      downloadPng(svg, `${funcName ?? 'flow'}.png`);
    }
    setOpen(false);
  };

  const handleDot = () => {
    if (cfg && cfg.nodes.length > 0) {
      downloadText(cfgToDot(cfg, funcName ?? 'function'), `${funcName ?? 'cfg'}.dot`);
    } else if (callGraph && callGraph.nodes.length > 0) {
      downloadText(callGraphToDot(callGraph), 'call_graph.dot');
    }
    setOpen(false);
  };

  return (
    <div className="cyber-export-menu-container">
      <button type="button" className="cyber-export-btn" onClick={() => setOpen((o) => !o)}>
        <Download size={14} />
        エクスポート
      </button>
      {open && (
        <div className="cyber-export-dropdown">
          <button type="button" onClick={handleSvg}>
            SVG
          </button>
          <button type="button" onClick={handlePng}>
            PNG (2x)
          </button>
          <button type="button" onClick={handleDot}>
            DOT (Graphviz)
          </button>
        </div>
      )}
    </div>
  );
}
