#!/bin/sh
set -e
cd /app

# node_modules は named volume（Linux）。ホストの Windows 版 esbuild と混ざると Vite が失敗する。
# @esbuild/linux-x64 が無ければ、このコンテナ内で npm ci し直す。
if [ ! -d node_modules/@esbuild/linux-x64 ] || [ ! -d node_modules/@xyflow/react ]; then
  echo "[frontend] npm ci — installing Linux native deps inside container (not using host node_modules)..."
  npm ci
fi

exec "$@"
