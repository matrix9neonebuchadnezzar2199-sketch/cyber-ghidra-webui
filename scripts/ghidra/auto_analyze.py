# -*- coding: utf-8 -*-
# CyberGhidra Headless PostScript — auto_analyze.py
# Jython 2.7 (Ghidra built-in)
# @category CyberGhidra
# @name auto_analyze
# @description Export metadata, decompilation, and heuristics to JSON under /app/output

from __future__ import print_function

import json
import codecs
import re

from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.symbol import SymbolType
from ghidra.util.task import TaskMonitor

MAX_FUNCTIONS = 1000
MAX_STRINGS = 5000
MAX_IMPORT_ROWS = 20000
# CFG per function (IDA-like flow graph); keep limits so JSON stays bounded
MAX_CFG_BLOCKS = 96
MAX_CFG_EDGES = 220
MAX_CFG_DISASM = 14
MAX_CALL_GRAPH_NODES = 450
MAX_CALL_GRAPH_EDGES = 1400

SUSPICIOUS_NAMES = frozenset([
    "VirtualAlloc", "VirtualProtect", "CreateRemoteThread",
    "WriteProcessMemory", "NtUnmapViewOfSection", "URLDownloadToFile",
    "InternetOpen", "HttpSendRequest", "WinExec", "ShellExecute",
    "CryptEncrypt", "CryptDecrypt", "RegSetValue", "CreateService",
])

# Headless may invoke run() automatically on some Ghidra builds; trailing run() also fires — guard once.
_run_already = False

# Monotonic % for stdout lines: [CyberGhidra] PROGRESS N  → ghidra-worker parses → progress_percent
_progress_last = [0]


def _progress_reset():
    _progress_last[0] = 0


def _progress_emit(pct):
    try:
        p = max(0, min(100, int(pct)))
        if p > _progress_last[0]:
            _progress_last[0] = p
            println(u"[CyberGhidra] PROGRESS " + str(p))
    except Exception:
        pass


def _function_count_cap(fm):
    """Upper bound for export loop (respect MAX_FUNCTIONS cap)."""
    try:
        c = fm.getFunctionCount(True)
        if c is not None:
            return max(1, min(MAX_FUNCTIONS, int(c)))
    except Exception:
        pass
    return MAX_FUNCTIONS


def _safe_filename(name):
    if name is None:
        return "unknown"
    return re.sub(r'[^A-Za-z0-9._-]+', "_", str(name))[:200]


def _analyze_decompiled_c(text):
    """
    Heuristic signals on decompiler output (anti-analysis, obfuscation hints).
    Regex-only; complements human review — not a verdict.
    """
    out = {"signals": [], "stats": {}}
    if text is None:
        return out
    try:
        if isinstance(text, unicode):
            t = text
        else:
            t = unicode(text, "utf-8", "replace")
    except NameError:
        t = str(text)
    except Exception:
        t = str(text)

    lines = t.splitlines()
    line_count = len(lines)
    goto_count = sum(1 for ln in lines if re.search(ur"\bgoto\b", ln))
    out["stats"] = {
        "line_count": line_count,
        "goto_count": goto_count,
        "opaque_loop_hint": bool(re.search(ur"while\s*\(\s*1\s*\)|for\s*\(\s*;\s*;\s*\)", t)),
        "heavy_goto_flattening": goto_count >= 10,
    }

    # (id, severity, pattern, label_ja) — first match wins per id via seen set
    seen = set()
    rules = [
        (u"anti_debug", u"high", ur"\bIsDebuggerPresent\b|\bCheckRemoteDebuggerPresent\b",
         u"デバッガ検出系 API（耐解析の典型）"),
        (u"nt_query_process", u"high", ur"NtQueryInformationProcess|ZwQueryInformationProcess",
         u"プロセス情報取得（DebugObject 等に利用されがち）"),
        (u"output_debug", u"medium", ur"\bOutputDebugString[A-Za-z]*\b",
         u"OutputDebugString 系"),
        (u"tls_callback", u"medium", ur"TlsAlloc|TlsGetValue|TlsSetValue",
         u"TLS / 初期化まわり（エントリ以外の実行経路）"),
        (u"timing", u"medium", ur"\b(GetTickCount|QueryPerformanceCounter|Sleep)\s*\(",
         u"時間・遅延（反デバッグ・レース回避の手掛かり）"),
        (u"memory_exec", u"high", ur"\b(VirtualAlloc|VirtualProtect|VirtualAllocEx)\s*\(",
         u"メモリ属性変更・動的確保（シェルコード・パッキャーで頻出）"),
        (u"thread_inject", u"high",
         ur"\b(CreateRemoteThread|WriteProcessMemory|NtCreateThreadEx|RtlCreateUserThread)\b",
         u"他プロセス書込・スレッド生成（インジェクションの手掛かり）"),
        (u"network", u"medium",
         ur"\b(URLDownloadToFile|InternetOpen|HttpSendRequest|WinHttp|socket|connect)\b",
         u"ネットワーク API"),
        (u"crypto_api", u"medium", ur"\b(CryptEncrypt|CryptDecrypt|BCrypt|CryptGenRandom)\b",
         u"暗号 API"),
        (u"registry_persist", u"low", ur"\b(RegSetValue|RegCreateKey|CreateService)\b",
         u"レジストリ／サービス永続化の手掛かり"),
        (u"seh_obfuscation", u"low", ur"__except|__try|SetUnhandledExceptionFilter",
         u"例外処理（制御フロー難読化で使われがち）"),
        (u"indirect_call", u"medium", ur"\(\s*\*\s*\w+\s*\)\s*\(",
         u"関数ポインタ呼び出し多め（間接コール・動的解決）"),
        (u"opaque_predicate_like", u"low",
         ur"if\s*\(\s*0u?\s*==|if\s*\(\s*1\s*==|if\s*\(\s*!\s*1\s*\)",
         u"常真/常偽に見える条件（オペーク述語の可能性）"),
        (u"string_decrypt_loop", u"low", ur"for\s*\([^)]*\)\s*\{[^}]*\^",
         u"ループ内 XOR 等（文字列復号の可能性）"),
    ]

    for sid, sev, pat, label in rules:
        if sid in seen:
            continue
        try:
            if re.search(pat, t, re.MULTILINE):
                out["signals"].append({"id": sid, "severity": sev, "label": label})
                seen.add(sid)
        except Exception:
            pass

    if out["stats"].get("heavy_goto_flattening"):
        if u"goto_flatten" not in seen:
            out["signals"].append({
                "id": u"goto_flatten",
                "severity": u"medium",
                "label": u"goto が多い（制御フロー平坦化・難読化コンパイラの可能性）",
            })
            seen.add(u"goto_flatten")

    if out["stats"].get("opaque_loop_hint"):
        if u"infinite_loop" not in seen:
            out["signals"].append({
                "id": u"infinite_loop",
                "severity": u"low",
                "label": u"無限ループ様の構造（難読化・待機ループの可能性）",
            })
            seen.add(u"infinite_loop")

    try:
        fun_n = len(re.findall(ur"\bFUN_[0-9a-fA-F]+\b", t))
        if fun_n >= 14 and u"ghidra_thunk" not in seen:
            out["signals"].append({
                "id": u"ghidra_thunk",
                "severity": u"info",
                "label": u"未命名呼び出し(FUN_*)が多い（インポート・PLT・静的リンク先の追跡が必要）",
            })
    except Exception:
        pass

    return out


def _collect_strings(program, out, monitor):
    listing = program.getListing()
    data_iter = listing.getDefinedData(True)
    count = 0
    while data_iter.hasNext() and count < MAX_STRINGS:
        data = data_iter.next()
        dt = data.getDataType()
        if dt is None:
            continue
        dname = dt.getName().lower()
        if "string" not in dname and "unicode" not in dname:
            continue
        try:
            val = data.getDefaultValueRepresentation()
        except Exception:
            val = str(data.getValue())
        if val is None or len(val) < 4:
            continue
        out.append({
            "address": str(data.getAddress()),
            "value": val,
        })
        count += 1


def _disasm_lines(program, block, monitor):
    """Disassembly lines for one basic block (hover / detail in UI)."""
    listing = program.getListing()
    out = []
    try:
        from ghidra.program.model.address import AddressRangeImpl
        rng = AddressRangeImpl(block.getMinAddress(), block.getMaxAddress())
        it = listing.getInstructions(rng, True)
        while it.hasNext() and len(out) < MAX_CFG_DISASM:
            ins = it.next()
            try:
                out.append(ins.toString())
            except Exception:
                out.append(str(ins))
    except Exception:
        pass
    return out


def _last_instruction_in_block(program, block, monitor):
    """Last disassembled instruction in a basic block (for branch labels)."""
    listing = program.getListing()
    try:
        from ghidra.program.model.address import AddressRangeImpl
        rng = AddressRangeImpl(block.getMinAddress(), block.getMaxAddress())
        it = listing.getInstructions(rng, True)
    except Exception:
        return None
    last = None
    try:
        while it.hasNext():
            last = it.next()
    except Exception:
        return last
    return last


def _block_id_containing(blocks, addr):
    """Map an address to this function's block id (min address string)."""
    if addr is None:
        return None
    try:
        for cb in blocks:
            if cb.getMinAddress().equals(addr):
                return str(cb.getMinAddress())
        for cb in blocks:
            if cb.contains(addr):
                return str(cb.getMinAddress())
    except Exception:
        pass
    return str(addr)


def _edge_label(program, src_block, ref, monitor):
    """Human-oriented label: conditional uses last insn; fall-through explicit."""
    try:
        ft = ref.getFlowType()
    except Exception:
        ft = None
    name = "flow"
    if ft is not None:
        try:
            name = ft.getName()
        except Exception:
            name = str(ft)
    last = _last_instruction_in_block(program, src_block, monitor)
    ins_s = ""
    if last is not None:
        try:
            ins_s = last.toString()
        except Exception:
            ins_s = str(last)
    try:
        cond = ft is not None and ft.isConditional()
    except Exception:
        cond = False
    if cond:
        if ins_s:
            return u"if (" + ins_s + u") → 分岐"
        return u"条件分岐"
    try:
        if ft is not None and ft.isFallthrough():
            return u"順行 (fall-through)"
    except Exception:
        pass
    if ins_s:
        return ins_s[:100]
    return name


def _build_cfg(program, func, monitor):
    """Control-flow graph: basic blocks + edges with branch hints (IDA-style data)."""
    from ghidra.program.model.block import SimpleBlockModel

    blocks = []
    try:
        model = SimpleBlockModel(program)
        bit = model.getCodeBlocksContaining(func.getBody(), monitor)
        while bit.hasNext():
            blocks.append(bit.next())
    except Exception as ex:
        return {"truncated": True, "error": str(ex), "nodes": [], "edges": []}

    if len(blocks) > MAX_CFG_BLOCKS:
        return {
            "truncated": True,
            "reason": "too_many_blocks",
            "nodes": [],
            "edges": [],
        }

    entry_str = str(func.getEntryPoint())
    nodes = []
    for cb in blocks:
        sid = str(cb.getMinAddress())
        dlines = _disasm_lines(program, cb, monitor)
        preview = ""
        try:
            li = _last_instruction_in_block(program, cb, monitor)
            if li is not None:
                preview = li.toString()[:140]
        except Exception:
            pass
        if not preview and dlines:
            preview = dlines[-1][:140]
        nodes.append({
            "id": sid,
            "start": str(cb.getMinAddress()),
            "end": str(cb.getMaxAddress()),
            "preview": preview,
            "disasm": dlines,
            "is_entry": (sid == entry_str),
            "is_exit": False,
        })

    node_ids = set(n["id"] for n in nodes)
    edges = []
    for cb in blocks:
        src_id = str(cb.getMinAddress())
        try:
            dit = cb.getDestinations(monitor)
        except Exception:
            continue
        while dit.hasNext():
            if len(edges) >= MAX_CFG_EDGES:
                return {
                    "truncated": True,
                    "reason": "too_many_edges",
                    "nodes": nodes,
                    "edges": edges,
                }
            ref = dit.next()
            dest_blk = None
            try:
                dest_blk = ref.getDestinationBlock()
            except Exception:
                dest_blk = None
            dest_addr = None
            try:
                dest_addr = ref.getDestinationAddress()
            except Exception:
                dest_addr = None
            if dest_blk is not None:
                tid = str(dest_blk.getMinAddress())
            elif dest_addr is not None:
                tid = _block_id_containing(blocks, dest_addr)
            else:
                continue
            if tid not in node_ids:
                nodes.append({
                    "id": tid,
                    "start": tid,
                    "end": tid,
                    "preview": u"(外部 / 他関数)",
                    "disasm": [],
                    "is_entry": False,
                    "is_exit": False,
                })
                node_ids.add(tid)
            try:
                ft = ref.getFlowType()
                kind = ft.getName() if ft is not None else "unknown"
            except Exception:
                kind = "unknown"
            label = _edge_label(program, cb, ref, monitor)
            edges.append({
                "from": src_id,
                "to": tid,
                "kind": kind,
                "label": label,
            })

    has_out = set(e["from"] for e in edges)
    for n in nodes:
        n["is_exit"] = n["id"] not in has_out

    return {"truncated": False, "nodes": nodes, "edges": edges}


def _build_call_graph(program, monitor):
    """Function-level call graph: entry → … → returns (whole program overview)."""
    fm = program.getFunctionManager()
    it = fm.getFunctions(True)
    funcs = []
    while it.hasNext() and len(funcs) < MAX_CALL_GRAPH_NODES:
        funcs.append(it.next())

    addr_set = set()
    nodes = []
    for f in funcs:
        aid = str(f.getEntryPoint())
        addr_set.add(aid)
        nodes.append({
            "id": aid,
            "name": f.getName(),
            "address": aid,
        })

    edges = []
    edge_seen = set()
    for f in funcs:
        src = str(f.getEntryPoint())
        try:
            called = f.getCalledFunctions(monitor)
            for cf in called:
                tgt = str(cf.getEntryPoint())
                if tgt not in addr_set:
                    continue
                key = (src, tgt)
                if key in edge_seen or len(edges) >= MAX_CALL_GRAPH_EDGES:
                    continue
                edge_seen.add(key)
                edges.append({
                    "from": src,
                    "to": tgt,
                    "kind": "call",
                    "label": u"call",
                })
        except Exception:
            pass

    return {
        "truncated": len(funcs) >= MAX_CALL_GRAPH_NODES,
        "nodes": nodes,
        "edges": edges,
    }


def _collect_imports(program, out):
    sym_table = program.getSymbolTable()
    sym_iter = sym_table.getSymbolIterator(True)
    rows = 0
    while sym_iter.hasNext() and rows < MAX_IMPORT_ROWS:
        sym = sym_iter.next()
        if not sym.isExternal():
            continue
        if sym.getSymbolType() != SymbolType.FUNCTION:
            continue
        parent = sym.getParentNamespace()
        lib = parent.getName() if parent is not None else ""
        out.append({
            "library": lib,
            "function": sym.getName(),
            "address": str(sym.getAddress()),
        })
        rows += 1


def run():
    global _run_already
    if _run_already:
        return
    _run_already = True

    monitor = TaskMonitor.DUMMY
    program = getCurrentProgram()
    if program is None:
        println("[CyberGhidra] No program loaded")
        return

    result = {
        "file_name": program.getName(),
        "architecture": program.getLanguage().getLanguageID().getIdAsString(),
        "compiler": str(program.getCompilerSpec().getCompilerSpecID()),
        "entry_points": [],
        "functions": [],
        "strings": [],
        "imports": [],
        "exports": [],
        "suspicious_apis": [],
        "truncated": False,
        "call_graph": None,
    }

    sym_table = program.getSymbolTable()
    try:
        epi = sym_table.getExternalEntryPointIterator()
        while epi.hasNext():
            addr = epi.next()
            result["entry_points"].append(str(addr))
    except Exception:
        pass

    # Mirror entry points as exports (Program has no single getEntryPoint(); avoid bogus API)
    result["exports"] = [
        {"address": ep, "kind": "external_entry_point"} for ep in result["entry_points"]
    ]

    decomp = DecompInterface()
    if not decomp.openProgram(program):
        println("[CyberGhidra] Decompiler could not open program")
        return

    _progress_reset()
    _progress_emit(4)

    fm = program.getFunctionManager()
    n_total = _function_count_cap(fm)
    _progress_emit(5)

    func_iter = fm.getFunctions(True)
    count = 0
    suspicious_seen = {}

    while func_iter.hasNext() and count < MAX_FUNCTIONS:
        func = func_iter.next()
        count += 1
        func_info = {
            "name": func.getName(),
            "address": str(func.getEntryPoint()),
            "size": func.getBody().getNumAddresses(),
            "decompiled_c": None,
            "cfg": None,
        }
        try:
            dres = decomp.decompileFunction(func, 60, monitor)
            if dres is not None and dres.decompileCompleted():
                df = dres.getDecompiledFunction()
                if df is not None:
                    func_info["decompiled_c"] = df.getC()
        except Exception:
            pass

        try:
            if func_info.get("decompiled_c"):
                func_info["decompile_insights"] = _analyze_decompiled_c(func_info["decompiled_c"])
        except Exception:
            func_info["decompile_insights"] = None

        try:
            func_info["cfg"] = _build_cfg(program, func, monitor)
        except Exception as ex:
            func_info["cfg"] = {"truncated": True, "error": str(ex), "nodes": [], "edges": []}

        result["functions"].append(func_info)

        try:
            called = func.getCalledFunctions(monitor)
            for cf in called:
                nm = cf.getName()
                if nm in SUSPICIOUS_NAMES and nm not in suspicious_seen:
                    suspicious_seen[nm] = {
                        "name": nm,
                        "address": str(cf.getEntryPoint()),
                        "seen_from": func.getName(),
                    }
        except Exception:
            pass

        try:
            pct_fn = 5 + int(75 * count / float(n_total))
            _progress_emit(pct_fn)
        except Exception:
            pass

    if func_iter.hasNext():
        result["truncated"] = True

    _progress_emit(82)

    result["suspicious_apis"] = list(suspicious_seen.values())

    _progress_emit(84)
    _collect_strings(program, result["strings"], monitor)
    _progress_emit(88)
    _collect_imports(program, result["imports"])
    _progress_emit(90)

    try:
        _progress_emit(92)
        result["call_graph"] = _build_call_graph(program, monitor)
    except Exception as ex:
        result["call_graph"] = {
            "truncated": True,
            "error": str(ex),
            "nodes": [],
            "edges": [],
        }

    _progress_emit(96)

    out_name = _safe_filename(program.getName()) + "_analysis.json"
    out_path = "/app/output/" + out_name
    try:
        _progress_emit(98)
        with codecs.open(out_path, "w", "utf-8") as fh:
            fh.write(json.dumps(result, indent=2, ensure_ascii=False))
        _progress_emit(100)
        println("[CyberGhidra] Analysis complete: " + out_path)
    except Exception as ex:
        println("[CyberGhidra] Failed to write JSON: " + str(ex))


run()
