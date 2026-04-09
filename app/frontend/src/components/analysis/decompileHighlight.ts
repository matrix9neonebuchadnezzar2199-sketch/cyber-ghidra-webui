/**
 * Escape + lightweight C-like highlighting for decompiler text (display only).
 */

function escapeHtml(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

const KW =
  /\b(void|int|char|long|short|unsigned|float|double|if|else|while|for|do|switch|case|default|break|continue|return|goto|struct|union|enum|sizeof|typedef|static|const|volatile|extern|inline|register|NULL|size_t|uint8_t|uint16_t|uint32_t|uint64_t|int8_t|int16_t|int32_t|int64_t)\b/g;

export function highlightDecompiledLine(line: string): string {
  const cmt = line.indexOf('//');
  if (cmt >= 0) {
    const code = line.slice(0, cmt);
    const rest = line.slice(cmt);
    return styleCode(escapeHtml(code)) + `<span class="apple-decomp-comment">${escapeHtml(rest)}</span>`;
  }
  return styleCode(escapeHtml(line));
}

function styleCode(escaped: string): string {
  let s = escaped.replace(KW, '<span class="apple-decomp-kw">$1</span>');
  s = s.replace(/\b(FUN_[0-9a-fA-F]+|DAT_[0-9a-fA-F]+)\b/g, '<span class="apple-decomp-ghidra">$1</span>');
  s = s.replace(/\b(0x[0-9a-fA-F]+)\b/g, '<span class="apple-decomp-num">$1</span>');
  return s;
}
