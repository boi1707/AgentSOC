# Phạm vi nghiệm thu AgentSOC v2

## Đã triển khai trong repo

- Console React/TypeScript/Tailwind/Lucide: overview, alerts/detail, incidents/detail, role outcomes,
  run/ledger timeline, response queue/history, system health, audit và operator creation.
- Versioned API, server pagination/filter/sort và global aggregates; cùng origin, typed request/read schemas.
- Server-side sessions, viewer/analyst/approver/admin, HttpOnly/SameSite cookie, CSRF và write audit.
- Wazuh adapter giữ raw/normalized/source/external ID/time/schema; network, Sysmon, Linux auth, FIM/generic.
- Idempotency source/external ID; alert không có safe entity được giữ uncorrelated, không gom unknown.
- Correlation received-time/entity, dedup/count/all original evidence links; CAP chỉ cắt model context.
- Additive migration giữ dữ liệu prototype, backup script, không dựng run metadata lịch sử giả.
- API không khởi chạy worker mặc định; worker riêng dùng SQLite job claim/lease/heartbeat/retry/dead-letter.
- Investigation run có snapshot/cutoff, prompt/provider/model attribution, typed role results và step states.
- Ba read-only tools scoped/bounded, dùng parameter binding, deadline, audit và guarded results.
- Egress guard trước model, input cap, output token cap, mock/live provider boundary, không silent fallback.
- Replay tạo run mới, cutoff enforce ở retrieval, không ghi đè actionable verdict, Telegram hoặc response.
- Response lưu intent trước executor, actor/evidence/mode/result; policy recheck và atomic single execution.
- Response crash/timeout action_unknown, không tự SSH retry; verification chưa đo ghi not_verified.
- Demo database/volume riêng, synthetic ở storage/UI, pipeline thật + mock, không seed AI outcomes.
- Docker multi-stage console/runtime, API + worker, private data volume, default localhost, log rotation.
- CI có backend, console/browser và Docker jobs; chỉ có kết quả CI sau khi owner push và workflow chạy.

## Cần nghiệm thu trên môi trường thật (không làm tự động ở lần này)

1. Docker build/up trên daemon Linux; mapping UID 10001, persistence và migrations của deployment thực.
2. Alert Wazuh/Snort/Sysmon thực tế qua integration đang triển khai; adapter fixtures không thay kiểm tra này.
3. Hosted LLM thật, quota/error, model response_format và usage; opt-in test cần --live-provider.
4. Telegram thật và SSH/gateway/nftables TTL 1h; không gọi chúng khi demo/test.
5. Load, RAM/CPU/disk cạnh Wazuh, retention và giới hạn SQLite ở lưu lượng mong muốn.
6. Ground truth thật, precision/recall, latency/chi phí và ablation; không dùng mock làm kết quả phát hiện.

## Giới hạn còn lại

Single workspace, chưa SSO/multi-tenant/RLS; chưa PostgreSQL adapter. SQLite write serialization và
rebuild pending window mỗi tick chưa benchmark. Chưa audit append-only/chống sửa; notifications vẫn
best-effort, integration không có pre-ingest spool. Pattern/tokenization không loại bỏ mọi PII tùy ý.
Không có local LLM/Ollama, entity graph, threat-intel hay detection engine mới. Verification SSH thực
không tự probe nftables; không suy ra connected từ configured. Legacy reviewer credential vẫn có
quyền duyệt để tương thích, cần hạn chế quyền truy cập credential đó.

## Acceptance path đã tự động hóa

Fixture Wazuh → custom integration/HTTP thật → SQLite → worker process riêng → correlation →
read-only tools → mock Net/Host/Judge → run/ledger → API/React → note/review dry-run. Browser smoke
bắt đầu từ DB rỗng, không seed case/outcome, kiểm tra các màn hình và không có JavaScript page error.
Unit/integration tests còn kiểm migration, leases, retry, RBAC/CSRF, duplicate approval, scoped replay,
SQL-bound filters/aggregates và absence của credentials/restore map trong API.

Xem ARCHITECTURE.md, ARCHITECTURE_COMPARISON.md, DEPLOYMENT.md và UPGRADE.md để có quyết định chi tiết.