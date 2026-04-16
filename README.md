# Cyber Ghidra WebUI
リバースエンジニアリング用 Docker 管理ツール

## UI

フロントエンドは [awesome-design-md-jp / Apple Japan](https://github.com/matrix9neonebuchadnezzar2199-sketch/awesome-design-md-jp/tree/main/design-md/apple) の `DESIGN.md`（タイポグラフィ・カラー・ピル型 CTA・ナビのすりガラス）に準拠しています。

## 起動方法
1. Windows側で start.bat を実行
2. AMD/NVIDIA環境を選択
3. ブラウザで http://localhost:3001 を開く

### ワーカーのスケールについて

`ghidra-worker` はファイルシステムベースのキュー（`queue/pending/` → `queue/processing/` → `queue/done/`）を
使用しており、**ワーカーは 1 インスタンスのみ**を前提としています。

```bash
# これは非対応（ジョブの競合が発生します）
docker compose up -d --scale ghidra-worker=2
```

複数ワーカーでの並列解析が必要な場合は、Redis や PostgreSQL ベースのジョブキュー
（arq, Celery 等）への移行を検討してください。

### `requirements.txt` を変えたあと（`ModuleNotFoundError` 対策）

バックエンドの依存は **イメージビルド時** に `/opt/venv` へ入ります。`docker-compose.yml` で `./app/backend:/app` とマウントしていても、venv はマウントで上書きされないため、**`app/backend/requirements.txt` を更新したらイメージを再ビルド**してください。

```bash
docker compose build backend
docker compose up -d
```

バックエンドイメージの Java は **Ghidra 11.3.1+ 向けに JDK 21**（Eclipse Temurin をマルチステージで `/opt/java/openjdk` に配置。`javac` 含む）です。

## 使い方

### 暗号化アーカイブの自動展開

パスワード付き ZIP / 7z ファイルをアップロードすると、自動で展開して中のバイナリを個別に解析します。

- デフォルトパスワード: `infected`
- UI のパスワード欄で任意のパスワードを指定可能
- 複数バイナリを含むアーカイブは全ファイルを個別ジョブとして登録
- ZIP 爆弾対策: 展開後の合計サイズが `MAX_EXTRACT_SIZE_MB`（デフォルト 500 MB）を超えると中断
- 展開処理は backend コンテナ内で完結し、ホストには影響しません

環境変数:

| 変数名 | デフォルト | 説明 |
|---|---|---|
| `MAX_EXTRACT_SIZE_MB` | `500` | 展開後の合計サイズ上限（MB） |

### 検体ファイルの隔離

アップロードされたバイナリ（アーカイブから展開されたものを含む）は Docker の名前付きボリューム `cyber_input` に保存されます。ホスト側のファイルエクスプローラーには表示されないため、ウイルス対策ソフトによる誤検知や誤実行のリスクがありません。

- 解析完了後、ghidra-worker がボリューム内のバイナリを自動削除します
- ボリュームを手動でクリアする場合: `docker volume rm cyber-ghidra-webui-main_cyber_input`
- ボリュームの中身を確認する場合: `docker run --rm -v cyber-ghidra-webui-main_cyber_input:/data alpine ls -la /data`

> **注意**: プロジェクトルートに残っている `./input/` フォルダは今後使用しません。既存ファイルがあれば削除して構いません。

## LLM アノテーション（`POST /api/annotate/{job_id}`）

解析済みジョブに対して LLM による関数アノテーションを実行します。
リクエストは **202 Accepted** を即座に返し、バックグラウンドで処理します。

### 基本フロー

```bash
# 1. アノテーション開始（202 が返る）
curl -X POST http://localhost:8000/api/annotate/{job_id} \
  -H "Content-Type: application/json" \
  -d '{"strategy":"suspicious_only"}'
# → { "status": "accepted", "annotate_id": "...", ... }

# 2. 進捗ポーリング
curl http://localhost:8000/api/annotate/status/{annotate_id}
# → { "status": "running", "completed_functions": 12, "total_functions": 30, ... }

# 3. 完了後に結果取得
curl http://localhost:8000/api/annotate/result/{annotate_id}
```

### strategy

- `suspicious_only`（既定）: 疑わしい API を呼んでいる関数のみ。対象が少なく数分以内に完了しやすい
- `top_n`: デコンパイル済み関数をサイズ降順で上位 N 件（`top_n` パラメータで指定）
- `all`: デコンパイル済み全関数。関数数が **`ANNOTATE_ALL_MAX_FUNCTIONS`（既定 100）** を超える場合は 400 で拒否

### 環境変数

| 変数 | 既定値 | 説明 |
|---|---|---|
| `LLM_API_URL` | `http://host.docker.internal:11434/v1` | OpenAI 互換 API（Ollama 等） |
| `LLM_MODEL` | `llama3` | 使用モデル |
| `LLM_TIMEOUT_SEC` | `120` | 1 関数あたりの LLM タイムアウト |
| `LLM_USE_JSON_MODE` | `1` | JSON モードを要求するか |
| `ANNOTATE_ALL_MAX_FUNCTIONS` | `100` | `strategy=all` の上限 |

## スモークテスト

- WSL2 / Linux: `bash scripts/smoke_test.sh`（引数省略時は `/bin/ls` のコピーを使用）
- Windows: `powershell -File scripts/smoke_test.ps1`（アップロードに `curl.exe` を使用。プロキシが異なる環境では `Invoke-RestMethod` へ統一するなど調整してください）