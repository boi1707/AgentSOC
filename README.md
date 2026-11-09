# AgentSOC

Ứng dụng SOC self-hosted cho chuyên viên vận hành: **Wazuh → inbox bền vững → correlation →
Net/Host/Judge → investigation ledger → human review**. Console React/TypeScript/Tailwind,
FastAPI và worker riêng, dùng SQLite; không mang một hệ microservices nặng sang VPS.

Mặc định **không seed dữ liệu**, `LLM_MODE=mock`, `RESPONSE_MODE=dry-run`. Mock được gắn nhãn,
không phải đánh giá an ninh thật. Không tự tải model, sửa Wazuh/VPN/firewall hay triển khai VPS.

## TheHive, Shuffle và VirusTotal

Đã có các tích hợp tùy chọn, mặc định tắt:

- **TheHive:** hàng đợi case bền vững, lưu remote ID, cập nhật verdict/reputation và kết quả response.
- **VirusTotal:** chỉ tra tối đa ba IP công cộng mỗi incident, cache 24 giờ, quota dùng chung trong SQLite.
- **Shuffle:** webhook sau Approve có kết quả; outbox/retry và event ID cố định, không tự thực thi chặn IP.

Approve vẫn ở AgentSOC. Chế độ demo không gọi các dịch vụ ngoài. Trang incident và System health
hiển thị trạng thái queue/kết quả; cấu hình không đồng nghĩa kết nối đã được xác minh.
Xem [hướng dẫn tích hợp và triển khai](docs/integrations.vi.md), [.env.example](.env.example)
và [chi tiết TheHive](docs/thehive.md). Không đưa key thật hoặc URL webhook vào Git.

Kết quả kiểm tra patch và giới hạn build/browser local được ghi riêng trong
[validation-integrations.md](docs/validation-integrations.md); chưa xác minh tích hợp trên VPS.

## Giao diện

Ảnh chụp từ ứng dụng chạy local với database demo cách ly: dữ liệu synthetic được gửi qua
HTTP ingestion, worker xử lý bằng mock AI và response ở chế độ dry-run. Các số liệu trong ảnh
minh họa luồng vận hành, không phải kết quả đánh giá phát hiện trên hệ thống thật.

![AgentSOC console: tổng quan cảnh báo, incident và hàng đợi điều tra](docs/images/console-overview.png)

<details>
<summary>System health trên mobile</summary>

<img src="docs/images/system-health-mobile.png" alt="AgentSOC System health trên màn hình mobile: database, worker và cấu hình provider" width="390" />

</details>

## Chạy local trên Windows

Cần Python 3.12+ và Node.js 22.12+. Mở đúng folder AgentSOC:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.lock
.\.venv\Scripts\python.exe -m scripts.dev --build
```

Mở **http://127.0.0.1:8000/console**. Launcher tạo `.env` nếu thiếu, sinh hai key ứng dụng
khác nhau khi trống, build console rồi chạy API + worker tách process. Không in key ra log.
Đăng nhập `ADMIN_USERNAME` (mặc định `admin`) bằng `ADMIN_PASSWORD`, hoặc `APPROVE_KEY` trong
`.env` khi admin password để trống. Bootstrap chỉ chạy nếu chưa có users.

`ADMIN_PASSWORD` nếu được đặt phải có ít nhất 24 ký tự. Thay đổi biến này không đổi mật khẩu
của tài khoản đã tồn tại trong database. `.env`, database, phiên đăng nhập và mật khẩu local
không được đưa lên Git; bản clone mới không có sẵn tài khoản hay mật khẩu dùng chung.

VS Code: **Tasks → Run Task → AgentSOC: local application**. Có task riêng cho demo và backend tests.
Chạy Linux tương đương với `.venv/bin/python`; không cần Bash cho launcher local.

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

## Demo cách ly

```powershell
.\.venv\Scripts\python.exe -m scripts.dev --demo --build
# Terminal khác, gửi fixture qua ingestion thật:
.\.venv\Scripts\python.exe -m scripts.replay datasets/demo.jsonl --url http://127.0.0.1:8001 --fresh
```

Mở **http://127.0.0.1:8001/console**. Demo dùng `data/demo/agentsoc.db` (hoặc DEMO_DB), không dùng DB
production; lưu cờ synthetic ở alert/case và hiển thị trong UI. Demo bắt buộc mock/dry-run, tắt
Telegram, không SSH. Không seed trực tiếp case/verdict: fixture đi qua inbox, worker, tools và agents.
`--fresh` chỉ dùng demo lại; không dùng khi đối chiếu nhãn dựa trên ID cũ.

## Console

- Overview: global aggregates, time series alert thật theo received time và backlog.
- Alerts: filter/pagination phía server, normalized envelope, JSON gốc và liên kết incident.
- Incidents/detail: workflow riêng, evidence inventory, entity, run timeline, Net/Host/Judge, notes.
- Investigation ledger: guarded input, structured output, tool/citations, attempts, usage và error.
- Response review: eligibility phía server, approve/reject và lịch sử; không nhận target do UI chọn.
- System health: DB, worker heartbeat, job age/dead letters, last alert và provider attribution.
- Audit: actor, operation, target, time và result. UTC ở storage, timezone rõ trên giao diện.

Không có graph, threat-intel hay ATT&CK coverage giả. Null/No data nghĩa là chưa có số đo.
Provider configured không có nghĩa reachable; Wazuh không được gọi connected chỉ vì API đang chạy.

## Phân quyền và response

| Role | Quyền |
| --- | --- |
| viewer | Đọc console/evidence/ledger |
| analyst | Viewer + notes, workflow và replay |
| approver | Analyst + approve/reject response |
| admin | Approver + tạo operator qua System health/API |

Session cookie HttpOnly/SameSite=Strict, CSRF token ở memory; không lưu credential trong localStorage.
Khi dùng HTTPS đặt `SESSION_COOKIE_SECURE=1`. Dùng localhost/VPN hoặc HTTPS, không public HTTP reviewer.
Client legacy HTTP Basic `reviewer`/APPROVE_KEY vẫn có qua `/cases`; đây là credential compatibility
có quyền duyệt, không cấp cho viewer/analyst. Mỗi operator nên có tài khoản riêng.

Mọi response vẫn cần người duyệt. Server kiểm tra lại attack/confidence/groundedness, IP nguồn từ
network evidence được cite, protected networks và mode. Mock/synthetic không được SSH. Intent/actor
được lưu trước executor; approve lặp không thực thi lại. Crash/timeout mơ hồ là action_unknown, không
retry SSH. `blocked` chưa có nghĩa đã verification nftables: verification_status vẫn not_verified.

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

`make down` giữ volume/data. Đọc [nâng cấp và backup](docs/UPGRADE.md) trước khi thay version đang có dữ liệu.

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

## Tài liệu và giới hạn

- [Kiến trúc và trạng thái](docs/ARCHITECTURE.md)
- [Khảo sát AgentSOC/AiSOC, SHA và license](docs/ARCHITECTURE_COMPARISON.md)
- [Triển khai cùng hạ tầng hiện hữu](docs/DEPLOYMENT.md)
- [Migration, backup, rollback và tương thích](docs/UPGRADE.md)
- [Phạm vi nghiệm thu](docs/IMPLEMENTATION.md)
- [Kết quả kiểm thử local và các mục chưa xác minh](docs/VALIDATION.md)

Chưa đo RAM/CPU/throughput trên VPS đang chạy Wazuh, độ chính xác bằng nhãn thật hay chi phí model
thật. Không dùng số mock làm số liệu đồ án. SQLite hiện dành cho một workspace; chưa SSO,
multi-tenant, audit chống sửa hoặc notification spool/retry. Docker và kết nối VPS/Wazuh/LLM/
Telegram/SSH chỉ được đánh dấu đạt sau khi chạy ở môi trường tương ứng. Không publish datastore.
License của dependencies được giữ tại `/THIRD_PARTY_NOTICES.txt` trong console build.
