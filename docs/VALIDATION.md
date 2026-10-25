# Kiểm chứng local — 2026-10-25

Môi trường: Windows, Python 3.14.4, virtualenv riêng trong repo.

- Pytest: 48 bài kiểm tra, bao gồm egress fail-closed, private/link-local/IPv6,
  nguyên vẹn token roundtrip, phân biệt IP nguồn, queue/restart, ledger, schema output lỗi,
  groundedness/confidence, xác thực API, giới hạn body, HTML escaping, CSRF header,
  dry-run, từ chối IP sai, atomic claim và forced command gateway.
- Ruff lint/format và compileall cho source/scripts.
- Demo offline: 2 alert tổng hợp → 1 case pending → 3 ledger calls mock, không gọi mạng/SSH.
- Uvicorn local bind 127.0.0.1:8000: `/health` OK, reviewer page 200 sau đăng nhập.
- HTTP replay: 2 alert được nhận; approve trả dry_run, approve lặp trả 409.
- Audit DB demo: 3 ledger calls, 0 prompt khớp mẫu guard, 0 token API (mock).
- `.env`, database và khóa private được Git ignore; không đưa vào commit.

Chưa chạy Docker build (máy không có lệnh docker), LLM API live, Wazuh, Snort/Sysmon,
WireGuard, Telegram hoặc SSH/nftables thật. GitHub Actions được cấu hình cho Python 3.12/3.14,
không coi là đã pass cho đến khi workflow thực sự chạy trên GitHub.

Số liệu mock xác nhận luồng phần mềm, không xác nhận precision/recall hoặc hiệu quả bảo mật.
