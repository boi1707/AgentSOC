# Operations reference

[README](../README.md) | [SOC integrations](integrations.vi.md) | [Upgrade and backup](UPGRADE.md)

Run commands from the repository root. Keep runtime credentials in the untracked `.env`.

## Local development

Muốn chạy từng process khi phát triển frontend:

```powershell
.\.venv\Scripts\python.exe -m uvicorn src.api.main:app --host 127.0.0.1 --port 8000 --no-access-log
# Terminal thứ hai:
.\.venv\Scripts\python.exe -m src.worker
# Terminal thứ ba, trong frontend:
npm ci
npm run dev
```

Vite proxy API cùng origin; không bật CORS wildcard. Production static build được FastAPI phục vụ.

Console dùng CSS riêng và compiler JavaScript của Tailwind, không cần scanner native Oxide.
Các utility Tailwind được khai báo rõ bằng `@source inline(...)` trong `frontend/src/style.css`;
khi thêm utility mới, cập nhật danh sách này. Build sẽ báo lỗi nếu bật lại auto-scan hoặc thêm
nguồn scan ngoài. Cách này giúp build trên Windows có Application Control mà không đổi chính
sách bảo mật; `npm run build` vẫn là lệnh build chuẩn.

## Docker

Không sửa Wazuh stack đã triển khai riêng. Container API giữ cổng 8000 và `/ingest` cho integration.
Worker dùng chung volume SQLite, không publish cổng. Frontend được multi-stage build và serve cùng API.

```bash
cp .env.example .env
# Tạo hai key khác nhau, điền vào INGEST_KEY và APPROVE_KEY:
python3 -c "import secrets; print(secrets.token_urlsafe(32)); print(secrets.token_urlsafe(32))"
mkdir -p data
sudo chown 10001:10001 data
docker compose up -d --build --wait
make health
```

Mặc định bind `127.0.0.1`. Chỉ đổi `BIND_IP=10.8.0.1` khi WireGuard hiện có đã hoạt động.
Image dùng Python 3.12; host Ubuntu 22.04 không cần cài Python 3.12 nếu chỉ chạy Docker.
Script `bash scripts/setup.sh` là tùy chọn chuẩn bị key/config/data và cần Python 3.12+ trên host;
nó không cài hoặc chỉnh Wazuh/VPN/firewall. Không dùng `EMBEDDED_WORKER=1` cùng worker container.

Demo Docker hoàn toàn riêng, volume riêng:

```bash
make demo
make replay
# UI demo: http://127.0.0.1:8001/console
make demo-down
```

`make down` giữ volume/data. Đọc [nâng cấp và backup](UPGRADE.md) trước khi thay version đang có dữ liệu.

## Wazuh và API

Giữ `scripts/custom-agentsoc`, bearer INGEST_KEY và `POST /ingest`. Wazuh integration/rules hiện có
ở `config/wazuh/`; việc cài chúng vào manager do operator thực hiện riêng.
WAZUH_SOURCE_ID do server cấu hình, không tin source field do payload/model gửi.
Wazuh level 0–15 được kiểm tra; level dưới 7 giữ contract cũ: accepted=false/below_level_7.
Alert hợp lệ thiếu entity vẫn lưu uncorrelated, không mất dữ liệu hay gom vào unknown bucket.

| Endpoint | Auth | Chức năng |
| --- | --- | --- |
| `/live` | Không | Liveness |
| `/health` | Không | DB + counters tương thích |
| `/ready` | Không | DB và worker heartbeat mới |
| `POST /ingest` | Bearer | Raw + normalized durable ingestion |
| `/api/v1/auth/login`, `/auth/me`, `/auth/logout` | Session | Đăng nhập/session/CSRF |
| `/api/v1/overview`, `/system` | Viewer | Global metrics, timeline và health |
| `/api/v1/alerts`, `/alerts/{id}` | Viewer | Filter/pagination và raw/normalized detail |
| `/api/v1/incidents`, `/incidents/{id}` | Viewer | Workflow, evidence, runs, actions |
| `POST /api/v1/incidents/{id}/notes`, `PATCH .../workflow` | Analyst | Audited writes |
| `POST /api/v1/incidents/{id}/replay` | Analyst | Run mới từ parent snapshot/cutoff |
| `/api/v1/runs/{id}`, `/ledger`, `/ledger/{id}` | Viewer | Steps, tools, outputs và usage |
| `POST /api/v1/incidents/{id}/response` | Approver | Decision + current proposal run ID |
| `/api/v1/audit` | Viewer | Actor/action/target/result |
| `POST /api/v1/users` | Admin | Tạo operator |

Các path viết tắt ở cùng hàng đều thuộc `/api/v1`. Xem `/docs` của API để có OpenAPI schema.
Pagination limit tối đa 100, sort received/created + ID ổn định. Alerts hỗ trợ severity, source,
entity, correlation status, thời gian và search; incidents có workflow/severity/source/entity/time.
Số tổng hợp tính trên toàn bộ tập filter, không chỉ trang hiện tại. JSON hỏng trả 400, schema sai
422, body vượt 256 KiB trả 413; errors API v1 có envelope nhất quán và không echo raw sensitive input.

## Cấu hình

`.env.example` không có secret thật. Hai key bắt buộc khác nhau, dài ít nhất 24 ký tự.

| Nhóm | Biến |
| --- | --- |
| Storage/network | DB, BIND_IP, WAZUH_SOURCE_ID |
| Identity | INGEST_KEY, APPROVE_KEY, ADMIN_USERNAME, ADMIN_PASSWORD, SESSION_COOKIE_SECURE |
| AI | LLM_MODE=mock/live, LLM_URL, LLM_API_KEY, LLM_MODEL, MIN_CONFIDENCE |
| Correlation | QUIET_SECONDS, GAP_SECONDS, HI_LEVEL, CAP, HOST_IPS JSON, HOST_NAMES |
| Worker | POLL_SECONDS, EMBEDDED_WORKER=0, JOB_LEASE_SECONDS=120 |
| Response | RESPONSE_MODE=dry-run/ssh, GATEWAY, SSH_KEY, KNOWN_HOSTS |
| Notifications | TG_TOKEN và TG_CHAT cùng cấu hình hoặc cùng để trống |
| Operations/demo | LOG_LEVEL, DEMO_MODE, DEMO_DB |
| External integrations | THEHIVE_URL, THEHIVE_KEY, SHUFFLE_HOOK, VT_KEY, VT_EXCLUDE_IPS, VT_REQUEST_INTERVAL, VT_DAILY_LIMIT |

Live bắt buộc HTTPS endpoint tương thích JSON chat completion, credentials/model đầy đủ. Provider
URL chỉ lấy từ cấu hình server, không từ model/API. Không tự fallback live → mock. Ollama/local HTTP
chưa thêm trong lần này, không tải model nặng. Thêm hostname thực vào HOST_NAMES; token hóa theo mẫu
không cam kết loại bỏ mọi loại PII. Model max output 2048 tokens/call; input cap 256 KiB/call.

## Kiểm thử và vận hành

```powershell
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m ruff check src scripts tests
.\.venv\Scripts\python.exe -m ruff format --check src scripts tests
# Trong frontend:
npm run typecheck
npm run lint
npm run build
npm run test:e2e
```

Browser test dùng Chrome có sẵn trên Windows hoặc Playwright Chromium; Linux chạy
`npx playwright install --with-deps chromium` trong frontend trước browser test.
Test tạo DB riêng, đi qua HTTP thật, worker process riêng và SQLite thật, nhưng dùng mock AI/dry-run;
không gửi Telegram, chạy SSH thật hoặc tiêu tiền cloud API. Live integration chưa được bật tự động.

```bash
make logs
# API: data/logs/agentsoc.log; worker: data/logs/agentsoc-worker.log
python -m scripts.check_leaks --db data/agentsoc.db
python -m scripts.metrics --db data/agentsoc.db --ground-truth data/labels.csv
python -m scripts.replay alerts.json --url http://127.0.0.1:8000 --speed 10
```

Replay CLI nhận JSON/JSONL, speed 0 gửi ngay, 1 thời gian thật, 10 nhanh gấp 10. Timed replay cần
source timestamp có timezone và thứ tự tăng dần. Replay investigation trong console khác replay
alert: tạo run mới từ evidence snapshot/cutoff, không ghi đè run cũ hay thực thi response.

CSV đánh giá dùng `alert_id,label` (attack/benign), khác schema kế hoạch redteam. Precision/recall ở
cấp alert, review tính là không dự đoán attack; pending/excluded và label thiếu inbox được đếm riêng.
Mock bị loại mặc định. Chi phí chỉ có khi đủ usage và cung cấp cả hai đơn giá qua
`--input-usd-per-million`, `--output-usd-per-million`; thiếu số đo trả null, không bịa 0.
