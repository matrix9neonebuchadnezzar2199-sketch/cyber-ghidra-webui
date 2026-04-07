"""
LLM-based annotation of Ghidra analysis JSON (OpenAI-compatible chat completions).
"""

from __future__ import annotations

import hashlib
import json
import os
from typing import Any

import httpx

LLM_API_URL = os.environ.get("LLM_API_URL", "http://host.docker.internal:11434/v1").rstrip("/")
LLM_MODEL = os.environ.get("LLM_MODEL", "deepseek-coder-v2:16b")
LLM_TIMEOUT = int(os.environ.get("LLM_TIMEOUT_SEC", "120"))
# Set to 1 to request JSON mode (Ollama / some OpenAI-compatible servers)
LLM_USE_JSON_MODE = os.environ.get("LLM_USE_JSON_MODE", "1").strip().lower() in ("1", "true", "yes")

SYSTEM_PROMPT = """You are a malware reverse engineering assistant.
Given a decompiled C function from Ghidra, provide:
1. A concise summary of what the function does (1-3 sentences, in Japanese).
2. A risk_level: "high", "medium", or "low".
3. risk_reasons: list of specific suspicious behaviors observed.
4. ioc_candidates: list of objects with "type" and "value" for hardcoded IPs, URLs, domains, file paths, registry keys, or mutex names found in the code (empty list if none).

Respond ONLY in valid JSON with keys: summary, risk_level, risk_reasons, ioc_candidates."""


def build_function_prompt(func: dict[str, Any]) -> str:
    code = func.get("decompiled_c") or "(decompilation unavailable)"
    name = func.get("name", "?")
    addr = func.get("address", "?")
    return f"Function: {name} at {addr}\n\n```c\n{code}\n```"


def select_target_functions(
    analysis: dict[str, Any],
    strategy: str,
    top_n: int = 50,
) -> list[dict[str, Any]]:
    functions = analysis.get("functions") or []

    if strategy == "suspicious_only":
        apis = analysis.get("suspicious_apis") or []
        suspicious_callers = {a.get("seen_from") for a in apis if a.get("seen_from")}
        suspicious_names = {a.get("name") for a in apis if a.get("name")}
        targets = [
            f
            for f in functions
            if f.get("name") in suspicious_callers or f.get("name") in suspicious_names
        ]
        if len(targets) < 5:
            with_code = [f for f in functions if f.get("decompiled_c")]
            cap = max(top_n, 20)
            targets = with_code[:cap]
        return targets

    if strategy == "top_n":
        with_code = [f for f in functions if f.get("decompiled_c")]
        with_code.sort(key=lambda f: int(f.get("size") or 0), reverse=True)
        return with_code[:top_n]

    # "all"
    return [f for f in functions if f.get("decompiled_c")]


async def annotate_function(
    client: httpx.AsyncClient,
    func: dict[str, Any],
    model: str,
) -> dict[str, Any]:
    user_msg = build_function_prompt(func)
    payload: dict[str, Any] = {
        "model": model,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_msg},
        ],
        "temperature": 0.1,
    }
    if LLM_USE_JSON_MODE:
        payload["response_format"] = {"type": "json_object"}

    url = f"{LLM_API_URL}/chat/completions"
    resp = await client.post(url, json=payload, timeout=LLM_TIMEOUT)
    resp.raise_for_status()
    body = resp.json()
    content = body["choices"][0]["message"]["content"]
    if not isinstance(content, str):
        content = str(content)

    try:
        parsed = json.loads(content)
    except json.JSONDecodeError:
        parsed = {
            "summary": (content or "")[:500],
            "risk_level": "unknown",
            "risk_reasons": [],
            "ioc_candidates": [],
        }

    iocs = parsed.get("ioc_candidates") or []
    if iocs and isinstance(iocs[0], str):
        iocs = [{"type": "string", "value": x} for x in iocs]

    code = func.get("decompiled_c") or ""
    h = hashlib.sha256(code.encode("utf-8", errors="replace")).hexdigest()

    return {
        "function_name": func.get("name", ""),
        "address": func.get("address", ""),
        "summary": parsed.get("summary", ""),
        "risk_level": parsed.get("risk_level", "unknown"),
        "risk_reasons": parsed.get("risk_reasons") or [],
        "ioc_candidates": iocs,
        "decompiled_c_hash": f"sha256:{h[:16]}",
    }
