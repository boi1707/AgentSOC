# AgentSOC
An evidence-driven LLM system for security incident analysis and human-reviewed response.

Backend prototype: Wazuh → gom incident → pseudonymization → ba tác tử
network/endpoint/judge → SQLite ledger → người duyệt → dry-run hoặc SSH forced command.

## Kiến trúc

![Sơ đồ kiến trúc AgentSOC: lab local kết nối WireGuard tới VPS và Cloud LLM](docs/images/architecture.svg)

Sơ đồ thiết kế AgentSOC, trích từ tài liệu HTML; không biểu thị hạ tầng đã triển khai thực tế.

## Chạy trên Windows

Yêu cầu Python 3.12+; bản này được kiểm thử local trên Python 3.14.

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
Copy-Item .env.example .env
.\.venv\Scripts\python.exe -c "import secrets; print(secrets.token_urlsafe(32)); print(secrets.token_urlsafe(32))"
```

Điền hai chuỗi khác nhau vào `INGEST_KEY` và `APPROVE_KEY` trong `.env`.
Không commit `.env`, database, log thật hoặc khóa SSH.

```powershell
.\.venv\Scripts\python.exe -m uvicorn src.api.main:app --host 127.0.0.1 --port 8000
```

Mở <http://127.0.0.1:8000/cases>, đăng nhập user `reviewer`, password là `APPROVE_KEY`.
Chạy demo từ terminal khác:

```powershell
.\.venv\Scripts\python.exe -m scripts.replay --url http://127.0.0.1:8000 --fresh
```

Alert level ≥12 được xử lý ở vòng worker tiếp theo; alert khác chờ 30 giây im lặng.
Approve ở mặc định `dry-run` chỉ ghi nhận mô phỏng, **không chặn IP thật**.
Mock có thể cố tình trả `attack` cho fixture demo; không phải bằng chứng về khả năng phát hiện.

## Demo offline và kiểm thử

```powershell
.\.venv\Scripts\python.exe -m scripts.replay
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m ruff check src scripts tests
.\.venv\Scripts\python.exe -m scripts.metrics --db data/agentsoc.db
```

Demo offline dùng database tạm, không cần `.env`, API key, VPS hay mạng.
Test mock HTTP/SSH, không gọi Cloud LLM hay tường lửa thật.

## Docker

Tạo `.env` với hai key hợp lệ như trên. Trên VPS Linux:

```bash
mkdir -p data
sudo chown 10001:10001 data
docker compose up -d --build
docker compose ps
```

Mặc định bind localhost; chỉ đặt `BIND_IP=10.8.0.1` sau khi WireGuard đã hoạt động.
Container chạy user UID 10001, filesystem read-only ngoài volume dữ liệu. Chỉ dùng **một
process/replica/worker cho mỗi database**. Không chạy `--workers 2` hoặc hai instance cùng DB.

## API

| Endpoint | Xác thực | Mục đích |
| --- | --- | --- |
| `GET /health` | Không | Kiểm tra DB và chế độ chạy |
| `POST /ingest` | Bearer `INGEST_KEY` | Nhận alert Wazuh, level ≥7, ID chống trùng |
| `GET /cases` | HTTP Basic `reviewer` / `APPROVE_KEY` | Trang bằng chứng và duyệt |
| `GET /api/cases` | Reviewer | Danh sách case, khôi phục token cục bộ |
| `POST /approve/{id}` | Reviewer + `X-AgentSOC-Review: 1` | Duyệt một lần |
| `POST /reject/{id}` | Reviewer + header như trên | Từ chối một lần |

HTTP Basic chỉ dùng localhost, tunnel WireGuard hoặc HTTPS; không publish HTTP ra Internet.
Khóa không đi trong query string. Trang review không tải CDN/tài nguyên ngoài.

## LLM và quyền hành động

- Mặc định `LLM_MODE=mock`, `RESPONSE_MODE=dry-run`.
- Live cần `LLM_MODE=live`, `LLM_URL` HTTPS tương thích JSON chat completion,
  `LLM_API_KEY`, `LLM_MODEL`. Chọn model hỗ trợ `response_format=json_object` và temperature 0.
- Luôn pseudonymize cả payload và system prompt; egress guard chạy trước lời gọi mạng.
  Không có tùy chọn tắt ẩn danh trên service đang chạy.
- IP riêng/nonglobal, IPv6, email, mẫu API key, hostname đã cấu hình, user/path được che;
  IPv4 công cộng được giữ để phân tích IOC. Đây là **pseudonymization theo mẫu**, không
  cam kết phát hiện mọi dữ liệu cá nhân trong chuỗi tùy ý. Thêm hostname thật vào `HOST_NAMES`.
- Ledger lưu prompt messages, response, evidence IDs, token usage, thời gian và loại lỗi.
  Giá trị thật và bảng ánh xạ nằm cục bộ trong DB; bảo vệ volume/backup ở cấp hệ điều hành.
- Chặn chỉ hợp lệ nếu attack, confidence ≥ ngưỡng, evidence IDs hợp lệ và IP là **nguồn
  của alert mạng đã được trích dẫn**, không thuộc mạng bảo vệ.
- Mock không được cấu hình SSH. Xem [hướng dẫn triển khai](docs/DEPLOYMENT.md) trước khi bật SSH.

## Trạng thái phạm vi

Đã có backend, SQLite inbox bền vững, ba tác tử, reviewer UI, dry-run, Telegram adapter,
SSH adapter, gateway forced command, Wazuh integration/rules, demo, audit metrics, CI.

Chưa kiểm chứng trên hạ tầng thật: Docker image, Wazuh/Snort/Sysmon, WireGuard, Telegram,
Cloud LLM và nftables end-to-end. Cần VPS/lab, key và thông tin truy cập để hoàn tất phần đó.
Precision/recall, ablation A–D, hiệu quả giảm false positive, chi phí USD và độ trễ mục tiêu
chưa được đo. Không dùng kết quả mock làm số liệu đồ án.

Xem [kế hoạch nghiệm thu](docs/IMPLEMENTATION.md) và [triển khai hạ tầng](docs/DEPLOYMENT.md).
