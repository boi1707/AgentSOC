# AI Core Evidence Hardening — báo cáo kỹ thuật

Ngày kiểm tra local: **26/11/2026**. Phạm vi: giữ nguyên kiến trúc AgentSOC,
bổ sung bằng chứng, bảo vệ dữ liệu ra ngoài và kiểm tra tính nhất quán của verdict.
Phạm vi phát hành của đợt này dừng ở pull request để review.

## 1. Mã nguồn và phạm vi xác minh

| Mục | Giá trị |
| --- | --- |
| Repository local | `E:\Capstone1\AgentSOC` |
| Nhánh ban đầu | `feat/assistant-focused-fallback` |
| Commit ban đầu | `24d371b1bf4bf83bb27d9969ce847e4998ad4610` |
| Working tree ban đầu | Sạch |
| Nhánh thực hiện | `feat/ai-core-evidence-hardening` |
| Baseline Python 3.12 | **308 passed, 1 skipped**, 105.46 giây |
| Phụ thuộc backend | Đồng bộ từ `requirements-dev.lock` bằng `uv pip sync` |

Không tìm thấy `AGENTS.md` áp dụng trong repository hoặc các thư mục cha đã kiểm tra.
Sau khi fetch, `origin/main` trùng revision production do người dùng cung cấp,
`bdea31061af3bb2ed9c46d495e66f2976329aeb0`. Git xác nhận commit phát triển ban đầu
là tổ tiên của revision này. Cả hai trỏ đến tree `e6b791440978880a8fdaaaf8fa8982ff7e5362e6`.
Nhánh feature được fast-forward đến `origin/main` trước khi commit các thay đổi, giữ nguyên diff.
Theo báo cáo audit VPS do người dùng cung cấp, checksum SHA256 của Python source trong release
và container đang chạy trùng nhau, working tree release sạch, DB qua integrity check và ở schema v3.

## 2. Nguyên nhân và thay đổi

### FIX-01 — Bằng chứng Sysmon

Normalizer trước đây chỉ giữ tập trường hẹp nên mất process GUID/PID và đường dẫn file đích.
`src/adapters/wazuh.py` bổ sung allowlist EventData và system metadata, kiểm tra kiểu,
giới hạn kích thước từng trường. Nhóm command line tối đa 8192 ký tự, đường dẫn 2048,
hashes/details/queryResults 4096; các ID và trường ngắn có giới hạn riêng.
Không sao chép raw Windows message và không tạo trường tùy chọn khi thiếu.

Giữ Wazuh alert `id` riêng với Sysmon `eventRecordID`; chuẩn hóa mới dùng
`schema_version=2`. Normalized records và frozen snapshots đã tồn tại được giữ nguyên.
Cơ chế cũ backfill các hàng có `normalized IS NULL` vẫn tồn tại; đây không phải
thao tác tái chuẩn hóa toàn bộ lịch sử. `HOST_IPS` vẫn do cấu hình quyết định.

### FIX-02 — Pseudonymization và egress guard

`src/anon.py` khám phá danh tính trước khi render để token map ổn định khi đảo thứ tự
trường. Bổ sung parent user, domain account, SID, UNC host, DNS nội bộ nhận diện được,
đường dẫn user và tham số credentials. Secret đã cấu hình được che trước danh tính.
Giữ GUID, PID, evidence ID, executable name và hash hữu ích trong các fixture kiểm tra.

Xử lý riêng tên user/host trùng schema hoặc enum để không làm hỏng `role`, `kind`,
`verdict` hay bỏ lọt typed identity. Guard vẫn kiểm tra cả messages trước HTTP I/O,
bao gồm JSON lồng/escaped và secret cấu hình. Tool args và result dùng chung bước
khám phá danh tính. Đây là bảo vệ theo pattern và cấu trúc đã biết, **không phải bộ
phát hiện mọi PII**; chuỗi bí mật tùy ý không có pattern vẫn cần chính sách bổ sung.

### FIX-03 — Hiện tại và lịch sử

Judge nhận `evidence_scope=current_incident`; related historical alerts và previous AI
investigations nằm trong `historical_context`, có `citable_for_current_verdict=false`.
Related-alert query loại hàng thuộc incident hiện tại, giữ entity scope và replay cutoff.
Chung endpoint không được mô tả như quan hệ nhân quả. Prompt tiếp tục coi log/tool
content là dữ liệu không đáng tin cậy, không phải chỉ dẫn thực thi.

### FIX-04 — Grounding và containment

Verdict có `supporting_evidence`, `contradicting_evidence`, `missing_data`.
Attack yêu cầu reason không rỗng, supporting IDs hiện tại nhất quán với primary citations,
và analyst finding hiện tại có `suspicious=true` cite phần hỗ trợ đó. Citation sai,
thiếu/không nhất quán, contradiction hoặc missing data chuyển `review`.

`grounded` giữ nguyên tỷ lệ ID hợp lệ trong danh sách citation chính đã deduplicate,
version `citation-ratio-v1`; chính sách hỗ trợ là `current-support-v1`. Metric này xác nhận
citation, **không chứng minh mọi phát biểu ngôn ngữ tự nhiên đều đúng**.
Host-only attack có thể được phân loại nhưng không có containment target.
Chỉ nguồn của current cited network evidence được xem xét làm `block_ip`;
target ngoài phạm vi chuyển review, verdict không phải attack luôn có `block_ip=null`.
Confidence threshold và authorization/response gate không bị hạ hoặc bỏ qua.

### FIX-05 — VirusTotal SHA256 bất đồng bộ

Trích SHA256 64 hex từ trường canonical `hashes`/`sha256`, lowercase, deduplicate,
tối đa 3 hash/incident. Hỗ trợ hashes thuần hoặc `SHA256=`/`SHA256:`; không dùng MD5/SHA1.
Tra GET `/api/v3/files/{sha256}` chỉ khi có `VT_KEY` và opt-in `VT_SHA256_ENABLED=1`.
Mặc định flag là `0`; có thể tồn tại pending hash job khi chưa bật sender.
Không upload file, raw alert, đường dẫn hoặc nội dung filesystem.

IP và hash dùng chung `vt_budget`: interval, daily quota UTC và cooldown sau 401/403/429.
Mỗi tick xử lý tối đa một item đến hạn; cache riêng từng loại 24 giờ, durable lease và
fencing chống kết quả của sender đã mất lease. HTTP timeout 5 giây, không follow redirect.
401/403 cooldown ít nhất 1 giờ, 429 ít nhất 60 giây, Retry-After dạng số tối đa 24 giờ;
lỗi khác retry sau 60 giây. Queue chưa có giới hạn tổng số lần retry; cần theo dõi lỗi kéo dài.
Chỉ ghi mã HTTP/loại exception, không ghi response body hoặc key.

API giữ `virustotal` cho IP, thêm `virustotal_hashes` cho hash; report có
`indicator_type`. TheHive mirror phân biệt cả hai. UI chỉ thêm trạng thái hash reputation.
404 là `not_found`, không chứng minh an toàn. Enrichment không tự sửa verdict/confidence
hoặc quyền Approve. Không thay Shuffle workflow.

### FIX-06 — Bỏ qua vai trò rỗng

Role không có evidence trả deterministic no-evidence finding, lưu step `skipped` và
audit `analysis.role_skipped`; không đánh failed, không tạo provider ledger/usage giả.
Host-only/net-only dùng một analyst có dữ liệu và Judge; mixed vẫn dùng cả hai analyst.
Prompt version mới là `v3`; lịch sử không đổi. Test kế toán cost được cập nhật theo
hai provider calls thực tế, thay vì ba calls trước tối ưu.

### FIX-07 — Aggregation

Fingerprint bỏ metadata biến động `id`, `timestamp`, `eventRecordID`, `systemTime`,
`utcTime`. Giữ process GUID/PID, target, hash/DNS/registry và `creationUtcTime` vì
thời điểm tạo file có ý nghĩa bảo mật. Giữ evidence cap, dropped count, raw ID tracking,
mixed correlation và sensor isolation; không viết lại correlation engine.

### FIX-08 — Regression

Ba file mới: `test_sysmon_evidence.py`, `test_evidence_privacy_grounding.py`,
`test_vt_sha256.py`. Bao phủ Event 1/3/10/11, registry/DNS, trường thiếu/sai/oversize,
snapshot cũ, aggregation, nested privacy, field-order, guard, scope/cutoff, supporting
citations, empty roles, hash validation/cache/retry/lease/budget/API/TheHive và upgrade v3.
Suite cũ tiếp tục kiểm tra Snort/generic, Assistant/Telegram, injection, HMAC/RBAC,
approval, response dry-run/pfSense, replay và integrations.

## 3. Database và tương thích

Migration **v4** thêm `vt_hash_jobs`, `vt_hash_cache` và due index; không thay bảng IP,
budget, raw inbox, evidence snapshots hoặc verdict lịch sử. Migration chạy trong
transaction của Store và có schema marker 4. Test upgrade dùng source archive commit
24d371b để tạo DB v3 thật rồi mở bằng source mới, kiểm tra job/cache/budget IP còn nguyên,
hash tables rỗng và mở lại idempotent. Migration lab/backup/rollback tests cũ được
cập nhật nhận v4. Docker validator cũng được cập nhật nhận v4 nhưng chưa chạy Docker.

## 4. Kết quả kiểm tra local

| Kiểm tra | Kết quả |
| --- | --- |
| Full pytest trước PR | **400 passed, 1 skipped**, 1 cảnh báo, 126.22 giây |
| Kiểm tra lại fixture Sysmon, privacy, SHA256 và migration | **99 passed** qua hai lượt test tập trung |
| Ruff check | PASS |
| Ruff format --check | PASS, 73 Python files |
| Frontend npm ci / typecheck / lint / production build | PASS |
| Playwright browser E2E hiện có | 3 passed |
| git diff --check | PASS; chỉ có thông báo chuyển đổi CRLF/LF |
| Scan secret dài đã cấu hình trong file thay đổi | PASS; không thay thế review secret/PII tổng quát |
| Offline replay / Bash syntax | PASS |
| Docker local | Không có Docker CLI. Workflow PR chạy Docker và kiểm tra rollback trên Linux |
| Live LLM / VirusTotal / Telegram / TheHive / pfSense / VPS | Không gọi trong validation |

Backend dùng fixture, mocked HTTP/provider và database tạm; paid-provider test được skip
mặc định. Còn cảnh báo deprecation Starlette/httpx. Browser suite hiện có kiểm tra luồng
chung, không phải bộ browser test riêng cho từng trạng thái SHA256.

## 5. Các file thay đổi

| Nhóm | File |
| --- | --- |
| Evidence, privacy, grounding | `src/adapters/wazuh.py`, `src/incident.py`, `src/anon.py`, `src/agents.py`, `src/tools.py` |
| Durable run / provider | `src/llm.py`, `src/providers.py`, `src/storage.py` |
| Reputation, config, migration | `src/virustotal.py`, `src/settings.py`, `src/migrations.py`, `.env.example` |
| Tích hợp/API | `src/integrations.py`, `src/thehive.py`, `scripts/integrations.py` |
| Validation | `scripts/migration_lab.py`, `scripts/validate_docker.py` |
| Frontend | `frontend/src/main.tsx`, `types.ts`, `i18n/en.json`, `i18n/vi.json` |
| Tests mới | `tests/test_sysmon_evidence.py`, `test_evidence_privacy_grounding.py`, `test_vt_sha256.py` |
| Tests cập nhật | `tests/test_audit.py`, `test_upgrade.py`, `test_migration_readiness.py` |
| Tài liệu | `README.md`, `docs/integrations.vi.md`, `docs/ARCHITECTURE.md`, báo cáo này |

Không chỉnh `.env`, secrets, lockfile/dependencies, workflow Shuffle hoặc cấu hình production.

## 6. Safety, giới hạn và bước triển khai sau phê duyệt

Giữ `RESPONSE_MODE=dry-run`, `PFSENSE_LIVE_ENABLED=0`, `MIN_CONFIDENCE=0.85`,
`HI_LEVEL=12`, `CAP=40`; không sửa LLM_MODE hay HOST_IPS của deployment.
Trong `.env` local, `PFSENSE_LIVE_ENABLED` đang không khai báo, nên dùng default `False`
của ứng dụng; `.env.example` tiếp tục ghi rõ `0`. Không sửa `.env` để thay giá trị này.
Assistant vẫn read-only; không thêm quyền approve, command execution hoặc firewall write.
Các giá trị production do người dùng cung cấp không được hardcode thành host mapping mới.

Kết quả tương thích source ở trên áp dụng cho baseline. Kiểm tra với Cloud LLM,
dịch vụ thật và dataset production nằm ngoài phạm vi xác minh của bản thay đổi này.

Kế hoạch sau khi có phê duyệt, chưa thực hiện:

1. Dùng kết quả CI Docker/Linux trên PR và revision production đã đối chiếu để review.
   Kiểm tra chính sách dữ liệu thực tế trước khi bật tra cứu hash.
2. Dừng consumer ghi khi cần cutover; tạo backup SQLite nhất quán bằng SQLite backup API,
   kiểm integrity và thử restore trên bản sao. Không copy riêng file `.db` đang có WAL.
3. Chạy source/image mới trên bản sao DB, kiểm migration v4, API/worker, replay và snapshot.
   Giữ hash lookup tắt trước khi chấp thuận egress/quota; giữ dry-run và pfSense live tắt.
4. Sau review mới triển khai staged, smoke test evidence/prompt đã redacted, step skipped,
   approval eligibility, queue/cache và TheHive mirror. Không thử chặn thật để smoke test.
5. Theo dõi review rate, provider errors, guard rejects, queue backlog và VT quota.

Rollback: dừng API/worker mới, lưu backup hiện trạng trước rollback, dùng image trước đã
kiểm chứng trên **bản sao** DB migrated. Schema v4 additive có thể để nguyên nhưng không
khẳng định image production chưa biết sẽ tương thích. Nếu cần restore backup trước upgrade,
phải quyết định cách giữ các alert/action mới phát sinh; restore DB có thể mất dữ liệu sau
backup. Image rollback khác database rollback. Không drop bảng hoặc rewrite evidence.

## 7. Tham chiếu kỹ thuật

- [Microsoft Sysmon event semantics](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon).
- [VirusTotal API v3: file report GET](https://docs.virustotal.com/reference/file-info).
