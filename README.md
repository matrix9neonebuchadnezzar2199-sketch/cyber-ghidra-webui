# Cyber Ghidra WebUI
リバースエンジニアリング用 Docker 管理ツール

## UI

フロントエンドは [awesome-design-md-jp / Apple Japan](https://github.com/matrix9neonebuchadnezzar2199-sketch/awesome-design-md-jp/tree/main/design-md/apple) の `DESIGN.md`（タイポグラフィ・カラー・ピル型 CTA・ナビのすりガラス）に準拠しています。

## 起動方法
1. Windows側で start.bat を実行
2. AMD/NVIDIA環境を選択
3. ブラウザで http://localhost:3001 を開く

### `requirements.txt` を変えたあと（`ModuleNotFoundError` 対策）

バックエンドの依存は **イメージビルド時** に `/opt/venv` へ入ります。`docker-compose.yml` で `./app/backend:/app` とマウントしていても、venv はマウントで上書きされないため、**`app/backend/requirements.txt` を更新したらイメージを再ビルド**してください。

```bash
docker compose build backend
docker compose up -d
```

## 環境
- GPU: Radeon 7900XT
- CPU: 7800X3D
- OS: Windows 11 + WSL2 + Docker Desktop

## LLM アノテーション（`POST /api/annotate/{job_id}`）

- 既定の `strategy=suspicious_only` は対象関数が少なく、数分以内に完了しやすいです。
- **`strategy=all` はデコンパイル済み関数が多いと LLM 呼び出しが連続し、数十分以上かかったり、ブラウザや curl のタイムアウトに当たることがあります。** 同期処理の安全策として、関数数が **`ANNOTATE_ALL_MAX_FUNCTIONS`（既定 100）** を超える `all` は 400 で拒否します。緩和する場合は環境変数で上限を上げるか、`top_n` を利用してください（非同期キューは Phase 2c 予定）。

## スモークテスト

- WSL2 / Linux: `bash scripts/smoke_test.sh`（引数省略時は `/bin/ls` のコピーを使用）
- Windows: `powershell -File scripts/smoke_test.ps1`（アップロードに `curl.exe` を使用。プロキシが異なる環境では `Invoke-RestMethod` へ統一するなど調整してください）