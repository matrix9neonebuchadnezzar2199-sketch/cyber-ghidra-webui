# Ghidra Headless postScript (Jython 2.7)
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

SUSPICIOUS_NAMES = frozenset([
    "VirtualAlloc", "VirtualProtect", "CreateRemoteThread",
    "WriteProcessMemory", "NtUnmapViewOfSection", "URLDownloadToFile",
    "InternetOpen", "HttpSendRequest", "WinExec", "ShellExecute",
    "CryptEncrypt", "CryptDecrypt", "RegSetValue", "CreateService",
])


def _safe_filename(name):
    if name is None:
        return "unknown"
    return re.sub(r'[^A-Za-z0-9._-]+', "_", str(name))[:200]


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


def _collect_exports(program, out):
    try:
        ep = program.getEntryPoint()
        if ep is not None:
            out.append({"name": "entry", "address": str(ep)})
    except Exception:
        pass


def run():
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
    }

    sym_table = program.getSymbolTable()
    try:
        epi = sym_table.getExternalEntryPointIterator()
        while epi.hasNext():
            addr = epi.next()
            result["entry_points"].append(str(addr))
    except Exception:
        pass

    decomp = DecompInterface()
    if not decomp.openProgram(program):
        println("[CyberGhidra] Decompiler could not open program")
        return

    fm = program.getFunctionManager()
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
        }
        try:
            dres = decomp.decompileFunction(func, 60, monitor)
            if dres is not None and dres.decompileCompleted():
                df = dres.getDecompiledFunction()
                if df is not None:
                    func_info["decompiled_c"] = df.getC()
        except Exception:
            pass

        result["functions"].append(func_info)

        try:
            called = func.getCalledFunctions(monitor)
            while called.hasNext():
                cf = called.next()
                nm = cf.getName()
                if nm in SUSPICIOUS_NAMES and nm not in suspicious_seen:
                    suspicious_seen[nm] = {
                        "name": nm,
                        "address": str(cf.getEntryPoint()),
                        "seen_from": func.getName(),
                    }
        except Exception:
            pass

    if func_iter.hasNext():
        result["truncated"] = True

    result["suspicious_apis"] = list(suspicious_seen.values())

    _collect_strings(program, result["strings"], monitor)
    _collect_imports(program, result["imports"])
    result["exports"] = []
    try:
        _collect_exports(program, result["exports"])
    except Exception:
        pass

    out_name = _safe_filename(program.getName()) + "_analysis.json"
    out_path = "/app/output/" + out_name
    try:
        with codecs.open(out_path, "w", "utf-8") as fh:
            fh.write(json.dumps(result, indent=2, ensure_ascii=False))
        println("[CyberGhidra] Analysis complete: " + out_path)
    except Exception as ex:
        println("[CyberGhidra] Failed to write JSON: " + str(ex))
