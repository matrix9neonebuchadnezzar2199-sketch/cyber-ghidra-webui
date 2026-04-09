import type { DecompileInsights, DecompileSignalSeverity } from '../../types/analysis';

/**
 * Client-side mirror of auto_analyze._analyze_decompiled_c (for old JSON without insights).
 * Keep rule IDs aligned with scripts/ghidra/auto_analyze.py when changing either side.
 */
export function analyzeDecompiledText(text: string | null): DecompileInsights {
  const empty: DecompileInsights = {
    signals: [],
    stats: { line_count: 0, goto_count: 0 },
  };
  if (!text?.trim()) return empty;

  const lines = text.split(/\r?\n/);
  const line_count = lines.length;
  let goto_count = 0;
  for (const ln of lines) {
    if (/\bgoto\b/i.test(ln)) goto_count++;
  }

  const opaque_loop_hint = /while\s*\(\s*1\s*\)|for\s*\(\s*;\s*;\s*\)/.test(text);
  const heavy_goto_flattening = goto_count >= 10;

  const stats: DecompileInsights['stats'] = {
    line_count,
    goto_count,
    opaque_loop_hint,
    heavy_goto_flattening,
  };

  const seen = new Set<string>();
  const signals: DecompileInsights['signals'] = [];

  const rules: { id: string; severity: DecompileSignalSeverity; re: RegExp; label: string }[] = [
    {
      id: 'anti_debug',
      severity: 'high',
      re: /\bIsDebuggerPresent\b|\bCheckRemoteDebuggerPresent\b/i,
      label: 'デバッガ検出系 API（耐解析の典型）',
    },
    {
      id: 'nt_query_process',
      severity: 'high',
      re: /NtQueryInformationProcess|ZwQueryInformationProcess/,
      label: 'プロセス情報取得（DebugObject 等に利用されがち）',
    },
    {
      id: 'output_debug',
      severity: 'medium',
      re: /\bOutputDebugString[A-Za-z]*\b/,
      label: 'OutputDebugString 系',
    },
    {
      id: 'tls_callback',
      severity: 'medium',
      re: /\bTlsAlloc\b|\bTlsGetValue\b|\bTlsSetValue\b/,
      label: 'TLS / 初期化まわり（エントリ以外の実行経路）',
    },
    {
      id: 'timing',
      severity: 'medium',
      re: /\b(GetTickCount|QueryPerformanceCounter|Sleep)\s*\(/,
      label: '時間・遅延（反デバッグ・レース回避の手掛かり）',
    },
    {
      id: 'memory_exec',
      severity: 'high',
      re: /\b(VirtualAlloc|VirtualProtect|VirtualAllocEx)\s*\(/,
      label: 'メモリ属性変更・動的確保（シェルコード・パッキャーで頻出）',
    },
    {
      id: 'thread_inject',
      severity: 'high',
      re: /\b(CreateRemoteThread|WriteProcessMemory|NtCreateThreadEx|RtlCreateUserThread)\b/,
      label: '他プロセス書込・スレッド生成（インジェクションの手掛かり）',
    },
    {
      id: 'network',
      severity: 'medium',
      re: /\b(URLDownloadToFile|InternetOpen|HttpSendRequest|WinHttp|socket|connect)\b/,
      label: 'ネットワーク API',
    },
    {
      id: 'crypto_api',
      severity: 'medium',
      re: /\b(CryptEncrypt|CryptDecrypt|BCrypt|CryptGenRandom)\b/,
      label: '暗号 API',
    },
    {
      id: 'registry_persist',
      severity: 'low',
      re: /\b(RegSetValue|RegCreateKey|CreateService)\b/,
      label: 'レジストリ／サービス永続化の手掛かり',
    },
    {
      id: 'seh_obfuscation',
      severity: 'low',
      re: /__except|__try|SetUnhandledExceptionFilter/,
      label: '例外処理（制御フロー難読化で使われがち）',
    },
    {
      id: 'indirect_call',
      severity: 'medium',
      re: /\(\s*\*\s*\w+\s*\)\s*\(/,
      label: '関数ポインタ呼び出し多め（間接コール・動的解決）',
    },
    {
      id: 'opaque_predicate_like',
      severity: 'low',
      re: /if\s*\(\s*0u?\s*==|if\s*\(\s*1\s*==|if\s*\(\s*!\s*1\s*\)/,
      label: '常真/常偽に見える条件（オペーク述語の可能性）',
    },
    {
      id: 'string_decrypt_loop',
      severity: 'low',
      re: /for\s*\([^)]*\)\s*\{[^}]*\^/,
      label: 'ループ内 XOR 等（文字列復号の可能性）',
    },
  ];

  for (const r of rules) {
    if (seen.has(r.id)) continue;
    try {
      if (r.re.test(text)) {
        signals.push({ id: r.id, severity: r.severity, label: r.label });
        seen.add(r.id);
      }
    } catch {
      /* ignore */
    }
  }

  if (heavy_goto_flattening && !seen.has('goto_flatten')) {
    signals.push({
      id: 'goto_flatten',
      severity: 'medium',
      label: 'goto が多い（制御フロー平坦化・難読化コンパイラの可能性）',
    });
    seen.add('goto_flatten');
  }

  if (opaque_loop_hint && !seen.has('infinite_loop')) {
    signals.push({
      id: 'infinite_loop',
      severity: 'low',
      label: '無限ループ様の構造（難読化・待機ループの可能性）',
    });
    seen.add('infinite_loop');
  }

  const funN = (text.match(/\bFUN_[0-9a-fA-F]+\b/g) ?? []).length;
  if (funN >= 14 && !seen.has('ghidra_thunk')) {
    signals.push({
      id: 'ghidra_thunk',
      severity: 'info',
      label: '未命名呼び出し(FUN_*)が多い（インポート・PLT・静的リンク先の追跡が必要）',
    });
  }

  return { signals, stats };
}
