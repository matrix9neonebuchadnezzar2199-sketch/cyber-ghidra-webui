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

バックエンドの依存は **イメージビルド時** に `/opt/venv` へ入ります。現行の `docker-compose.yml` では **`backend` / `ghidra-worker` に `./app/backend` のホストマウントはありません**（アプリコードはイメージに焼き込み）。そのため **`app/backend/requirements.txt` を変えたら必ずイメージを再ビルド**してください。

一方、`./scripts/ghidra` はコンテナ内 `/ghidra-scripts` に **バインドマウント**されるため、`auto_analyze.py` 等の変更は **再ビルドなしで** `ghidra-worker` 再起動後に反映されます（Python 依存の追加は上記とおり再ビルドが必要）。

```bash
docker compose build backend ghidra-worker
docker compose up -d
```

**Python（`main.py`・`sample_pipeline.py` 等）の改修**は `requirements.txt` 変更と同様、**イメージ再ビルド**しないと反映されません（`git pull` 直後の「PDF がまだ Ghidra に行く」等は、未コミット/未再ビルド/レイヤーキャッシュの疑い。確実に反映したい場合は
`docker compose build --no-cache backend ghidra-worker` を実行してください）。フロントは `./app/frontend` ビルドなので、UI 変更は `docker compose build frontend` か Compose のフロントサービスに従います。

バックエンドイメージの Java は **Ghidra 11.3.1+ 向けに JDK 21**（Eclipse Temurin をマルチステージで `/opt/java/openjdk` に配置。`javac` 含む）です。

## 使い方

### 暗号化アーカイブの自動展開

パスワード付き ZIP / 7z をアップロードすると、**UI で指定したパスワード**（未指定時は `infected`）で**最外層を展開**し、出てきたファイルのうち **再び zip/7z なら同じパスワードで展開**を繰り返し、**最終的に残る非アーカイブ**を個別ジョブにします。ネストの深さは `NESTED_ARCHIVE_MAX_DEPTH` で打ち止め、それ以上はそのパスを検体として扱います。

- デフォルトパスワード: `infected`（全層で同じ文字列を試行）
- 複数ファイルを含む / 入れ子アーカイブの**累積展開**は、合計で `MAX_EXTRACT_SIZE_MB` まで
- 展開処理は backend コンテナ内で完結

環境変数:

| 変数名 | デフォルト | 説明 |
|---|---|---|
| `MAX_EXTRACT_SIZE_MB` | `500` | 展開累積の合計サイズ上限（MB） |
| `NESTED_ARCHIVE_MAX_DEPTH` | `32` | zip/7z の入れ子を何階層まで展開するか |

### 検体ファイルの隔離

アップロードされたバイナリ（アーカイブから展開されたものを含む）は Docker の名前付きボリューム `cyber_input` に保存されます。ホスト側のファイルエクスプローラーには表示されないため、ウイルス対策ソフトによる誤検知や誤実行のリスクがありません。

- **Ghidra 解析に成功した**ジョブについて、ghidra-worker が `/app/input` 上の検体を削除します（失敗・タイムアウト時は静的分析用に検体を残します）
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

## 静的解析スキャナー（`GET/POST /api/scan/*`）

アップロード済みジョブの検体に対し、oletools / pdfid / pefile / LIEF / capa / binwalk / androguard 等の**静的解析**をバックエンド上で実行します（YARA は未実装スタブ）。Ghidra 解析完了を待たず、キュー登録直後に実行可能です（検体が `/app/input` 上に存在する必要があります）。

| メソッド | パス | 説明 |
|----------|------|------|
| `GET` | `/api/scan/scanners` | 登録済みスキャナー一覧（`name` / `supported_types` / `match_all`） |
| `POST` | `/api/scan/{job_id}` | 当該ジョブのファイルをスキャン。body `{"scanners": ["pdfid", ...]}` 省略時は MIME に応じ自動選択 |

**検体パス解決**: `queue/pending` / `queue/processing` / `queue/done` いずれかの `{job_id}.json` 内 `filepath`、または `output/{job_id}.status.json` の `filename` から `/app/input` 上の実ファイルを参照します。

`curl` の例（`job_id` をアップロードレスポンスの値に置き換え）:

```bash
curl -sS http://localhost:8000/api/scan/scanners
curl -sS -X POST "http://localhost:8000/api/scan/YOUR_JOB_ID" \
  -H "Content-Type: application/json" -d '{}'
# 特定スキャナーのみ: -d '{"scanners":["pdfid","binwalk"]}'
```

依存追加は `app/backend/requirements.txt` 経由のため、変更後は **`docker compose build backend`（`ghidra-worker` を触った場合は併せて再ビルド）**を実行してください。Docker イメージに `binwalk` と `libmagic1` が含まれます。

## テスト（バックエンド・スキャナー）

`app/backend` をカレントにし、仮想環境で依存を入れたうえで実行します。

```bash
cd app/backend
pip install -r requirements.txt -r requirements-dev.txt
python -m pytest
# またはプロジェクトルートから一括
bash scripts/quality_check.sh
```

- テスト本体: `app/backend/scanners/tests/`（レジストリ、runner、プラグイン、**FastAPI 経由の API 結合**を含む）
- `oletools` の警告（pyparsing 非推奨）が表示される場合があります（依存側の挙動）

## コード品質（Ruff）

[Ruff](https://docs.astral.sh/ruff/) による `lint` と `format` の確認を行います。`pyproject.toml` は `app/backend` にあり、レガシー行の `main.py` / `worker.py` / `annotator.py` は**除外**（新規 `scanners/` 等の品質にフォーカス）しています。

```bash
cd app/backend
pip install -r requirements.txt -r requirements-dev.txt
ruff check .
ruff format --check .
```

Windows / Linux 共通の一括実行: `scripts/quality_check.ps1` または `scripts/quality_check.sh`（`ruff check` → `ruff format --check` → `pytest`）。

## スモークテスト（E2E）

- WSL2 / Linux: `bash scripts/smoke_test.sh`（引数省略時は `/bin/ls` のコピーを使用）
- Windows: `powershell -File scripts/smoke_test.ps1`（アップロードに `curl.exe` を使用。プロキシが異なる環境では `Invoke-RestMethod` へ統一するなど調整してください）

フローは「ヘルス → unipacker → 検体アップロード → ジョブ完了まで待機」です。静的解析 API は上記 **「静的解析スキャナー」** または結合テスト（`scanners/tests/test_api_integration.py`）で補完できます。

### 想定操作フロー（参考）

1. ブラウザで検体をアップロード（または `POST /api/upload`）し `job_id` を取得
2. （任意）`POST /api/scan/{job_id}` で静的分析を実行
3. Ghidra 完了待ち `GET /api/jobs/{job_id}` まで待機
4. （任意）`POST /api/annotate/{job_id}` で LLM 注釈