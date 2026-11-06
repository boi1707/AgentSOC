# AgentSOC và AiSOC: khảo sát implementation

Khảo sát ngày 2026-11-06. AgentSOC nền: `45e4dcd081c80f002db8ff70b496657940f6fc0b`.
AiSOC tham khảo: `6d0a49702d03e01382f0be962fb37fc91399cfcf`.
Checkout sparse, chỉ đọc, tại `.reference/aisoc` và được Git ignore. Không chạy stack AiSOC.

## Trạng thái trước nâng cấp

AgentSOC có `/ingest` với bearer token, SQLite inbox bền vững, Grouper theo IP, Net/Host/Judge,
pseudonymization/egress guard, ledger, HTTP Basic reviewer, dry-run/SSH forced command, Telegram,
script replay/audit và tests. Worker chạy trong lifespan API; chưa có lease/retry/job table,
session/RBAC, run snapshot, console React hoặc API phân trang cho toàn bộ dữ liệu.
Schema nền là `inbox`, `cases`, `ledger`, `actions` trong `src/storage.py`.

## Đường chạy AiSOC đã đọc

| Phần | Implementation và caller đã kiểm tra | Áp dụng ở AgentSOC |
| --- | --- | --- |
| Ingest | `services/ingest/main.go`, `internal/handler/handler.go`: handler có publisher/normalizer boundary | Wazuh adapter tách riêng; lưu raw + normalized và source identity |
| Correlation | `services/fusion/app/workers/consumer.py` gọi FusionEngine, event validation, alert sink và durable failure paths | Correlation riêng trong worker; transaction tạo incident, evidence links và job |
| API | `services/api/app/main.py` include API router; `app/api/v1/endpoints/cases.py` có case lifecycle và investigation proxy | API `/api/v1`, read models, note/workflow, pagination và actor checks |
| Investigation | `services/agents/app/main.py` include investigate router; `api/investigate.py` chọn orchestrator và gọi streaming investigation; `investigator/orchestrator.py` gọi ledger | Run riêng, snapshot, trạng thái từng bước; giữ Net/Host/Judge thay vì mang topology phức tạp sang |
| LLM privacy | `services/agents/app/llm/contract.py::safe_ainvoke` validate, cap input, mở egress session, gọi model, khôi phục cục bộ | Một gateway `src/llm.py`, guard cả system/payload, input/output budget và metadata provider |
| Provider routing | `infra/litellm/config.yaml` mô tả task aliases; contract dùng model pins/config qua gateway | Provider interface nhỏ; mock hoặc HTTPS OpenAI-compatible, không thêm gateway service |
| Ledger | `services/agents/app/investigator/ledger.py`, được gọi từ orchestrator, lưu run/event/artifact | SQLite runs/steps/ledger, tool audit, usage có thể null, legacy metadata không được bịa |
| Response | `services/actions/app/api/router.py`: authorize approver, durable claim, `_dispatch_claimed` gọi executor | Intent bền vững trước executor, session actor, atomic claim, action_unknown không retry |
| Console | `apps/web/src/app/(app)/dashboard/page.tsx` dùng DashboardView; DashboardView dùng metricsApi/SWR; `src/lib/api.ts` ưu tiên same-origin | React/Vite/TypeScript/Tailwind, same-origin API, real aggregates và honest empty/error/stale states |

Đây là xác minh bằng đọc implementation/caller, không phải chứng nhận các tính năng upstream đã chạy
trong môi trường này. `docs/audit/REPOSITORY_REALITY.md` của upstream là audit lịch sử (ghi v8.1.0),
không được dùng như kết quả kiểm thử mới ở SHA tham khảo. README/architecture của upstream cũng đã đọc
để đối chiếu đường ingest → fusion → agents → governed actions.

## Hoãn lại

- Không mang Kafka, Redis, Qdrant, Neo4j, ClickHouse, OpenSearch hoặc detection corpus sang. Wazuh
  đã phát hiện alert; AgentSOC không thêm detection engine trong lần này.
- Không dùng toàn bộ microservices, realtime broker hay multi-tenant framework; một workspace,
  một API và worker riêng phù hợp phạm vi hiện tại. Chưa benchmark tài nguyên hay throughput.
- Không thêm LangGraph/agent loop: fixed plan ba read-only tools và ba vai trò đủ cho đường hiện có.
- Không tự tải Ollama/model local hoặc mở HTTP provider; hosted provider vẫn bắt buộc HTTPS.
- Không chép policy auto-response upstream: mọi response AgentSOC tiếp tục cần người duyệt.
- Không dựng entity graph/threat-intel/ATT&CK coverage giả từ dữ liệu không có.

## License

AiSOC có MIT License, copyright `2024-present AiSOC contributors`; đã đọc `LICENSE` tại SHA trên.
Lần nâng cấp này viết mới implementation AgentSOC, chỉ tham khảo kiến trúc/đường gọi, không chép mã,
component hoặc asset upstream. Do đó không đổi license của repo nhóm hay gắn copyright upstream vào
mã viết mới. Repo nền AgentSOC chưa có LICENSE; quyết định cấp phép toàn repo thuộc chủ sở hữu.
Các thư viện frontend được bundle có notice riêng tại `frontend/public/THIRD_PARTY_NOTICES.txt`.

## Kiến trúc cuối cùng

Modular monolith FastAPI/SQLite + worker riêng + console React được build và phục vụ cùng origin.
Chi tiết schema, trạng thái, lease/retry, cutoff replay và các giới hạn nằm trong
[ARCHITECTURE.md](ARCHITECTURE.md). Không sửa Wazuh stack, VPN, firewall hay triển khai VPS.
