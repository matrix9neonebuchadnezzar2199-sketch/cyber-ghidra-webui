#!/usr/bin/env bash
# バックエンド品質: ruff + pytest（app/backend で実行）
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT/app/backend"

if ! command -v ruff &>/dev/null; then
  echo "Install ruff: pip install -r requirements.txt -r requirements-dev.txt" >&2
  exit 1
fi

echo "==> ruff check"
ruff check .
echo "==> ruff format (check)"
ruff format --check .
echo "==> pytest (scanners)"
python -m pytest
