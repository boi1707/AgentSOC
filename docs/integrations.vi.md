# Kết nối TheHive, Shuffle và VirusTotal

Phần này mở rộng AgentSOC hiện có; không cài lại Wazuh, VPN, TheHive hoặc Shuffle.
Các tích hợp mặc định tắt. API key và URL webhook thật chỉ nằm trong `.env` trên máy triển khai.

## Luồng hoạt động

1. Wazuh gửi alert vào inbox có xác thực của AgentSOC.
2. Worker gom incident, chạy Net/Host/Judge và lưu kết quả + hàng đợi tích hợp trong cùng transaction SQLite.
3. VirusTotal tra tối đa ba IP công cộng của incident. Kết quả reputation là thông tin bổ sung sau phân tích,
   không tự thay verdict, tăng confidence hoặc cho phép chặn IP.
4. TheHive nhận case, verdict, ID bằng chứng và kết quả VirusTotal đã có. Nếu VT về sau, worker cập nhật lại
   description của case. Chỉ phần nội dung mirror được quản lý, không import toàn bộ alert thô.
5. Người duyệt bấm Approve trong AgentSOC. Quy tắc bảo vệ IP, live/mock và dry-run/SSH giữ nguyên.
6. AgentSOC lưu kết quả response và sự kiện Shuffle trong cùng transaction. Worker gửi webhook sau đó.
   Shuffle không có quyền thay thế việc duyệt, không được dùng webhook này để chặn IP lần thứ hai.

| Thành phần | Cấu hình | Dữ liệu gửi |
| --- | --- | --- |
| TheHive | `THEHIVE_URL`, `THEHIVE_KEY` | Case ID AgentSOC, verdict, bằng chứng tham chiếu, trạng thái response, reputation VT |
| Shuffle | `SHUFFLE_HOOK` | Event ID, Case ID, Action ID, IP mục tiêu, mode và kết quả response |
| VirusTotal | `VT_KEY` | Chỉ IP công cộng; không gửi alert, file, domain, URL, user hoặc hostname |

Replay không tạo công việc tích hợp mới. Demo mode không thực hiện network I/O của cả ba tích hợp,
ngay cả khi có cấu hình từ môi trường. Case synthetic không được enqueue sang các tích hợp bên ngoài.

## Cấu hình VPS

Thêm các biến bên dưới vào `.env` của AgentSOC, không phải `.env` của TheHive/Shuffle. Không commit file này.

```dotenv
THEHIVE_URL=http://10.8.0.1:9000
THEHIVE_KEY=
SHUFFLE_HOOK=
VT_KEY=
VT_EXCLUDE_IPS=160.250.132.244
VT_REQUEST_INTERVAL=16
VT_DAILY_LIMIT=500
```

- TheHive: dùng Service account thuộc organisation dự án, có quyền đọc/tạo/cập nhật case. Cấu hình cả URL
  và key hoặc để trống cả hai. API v1 phải cho phép query `listCase`, POST case và PATCH case.
- Shuffle: mở một workflow riêng, thêm Webhook trigger, lưu và khởi động trigger, sao chép URL thật.
  Đặt hostname/IP và cổng để **container worker AgentSOC** truy cập được, ví dụ IP WireGuard của VPS.
  Giữ nguyên đường dẫn webhook; không dùng URL trang workflow hoặc API key người dùng thay cho webhook.
  URL có thể chứa credential; không chụp màn hình, log hoặc commit nó. Không cần key admin Shuffle trong AgentSOC.
- VirusTotal: lấy API key của tài khoản phù hợp cho lab và điền `VT_KEY`. Để trống thì không tra.
  `VT_EXCLUDE_IPS` là danh sách IP công cộng phân cách bằng dấu phẩy mà bạn không muốn gửi ra ngoài,
  ví dụ IP VPS hoặc egress của tổ chức. IP private, VPN, loopback, link-local, multicast và reserved luôn bị bỏ qua.
- Dùng HTTP ở mạng WireGuard/Docker tin cậy; dùng HTTPS khi đi qua mạng không tin cậy.

VirusTotal ghi rõ IP được queried có thể đi vào dataset chia sẻ của họ. Public API giới hạn 4 request/phút,
500 request/ngày và có điều kiện sử dụng phi thương mại. Code dùng tối thiểu 16 giây giữa các request,
đếm theo ngày UTC và lưu budget trong SQLite để không reset khi restart; cache 24 giờ cho cùng IP.
Các ứng dụng khác dùng chung key có thể tiêu thụ cùng quota, nên vẫn phải xử lý 429. Đây không phải cam kết
một gói API sẽ phù hợp với mọi loại triển khai SOC.

Nguồn chính thức:
- https://docs.virustotal.com/reference/ip-info
- https://docs.virustotal.com/reference/public-vs-premium-api
- https://docs.strangebee.com/thehive/api-docs
- https://shuffler.io/docs/triggers

## Workflow Shuffle cần tạo trên giao diện

Repo cung cấp sender và hợp đồng event, không tự tạo workflow hoặc credential trong Shuffle của bạn.

1. Tạo workflow tên `AgentSOC response notifications`, thêm Webhook trigger và bật trigger.
2. Dùng `event_id` để kiểm tra/lưu dấu nhận trùng trước khi thực hiện tác vụ có tác dụng phụ.
   Sender truyền cùng giá trị trong JSON, `Idempotency-Key` và `X-AgentSOC-Event-ID`.
   Header này **không có nghĩa Shuffle mặc định tự chống trùng**. Cần cấu hình bước dedupe ở workflow
   hoặc một receiver có kho lưu bền vững; nếu chưa có, chỉ dùng notification chấp nhận khả năng lặp.
3. Phân nhánh theo `status`, `mode` và `blocked`:
   - `mode=dry-run`, `status=dry_run`: thông báo thử nghiệm, không ghi "IP đã chặn".
   - `mode=ssh`, `status=blocked`, `blocked=true`: lệnh gateway trả thành công; vẫn kiểm tra
     `verification_status=not_verified`, chưa phải bằng chứng độc lập xác nhận rule hoạt động.
   - `block_failed`/`action_unknown`: thông báo cần kiểm tra thủ công, không tự gọi lại chặn IP.
4. Nếu thêm Telegram, cấu hình credential trong Shuffle; gửi event/case ID và kết quả phù hợp.
   Không gửi toàn bộ evidence, thông tin nhận dạng hoặc API key vào tin nhắn. Telegram trực tiếp của AgentSOC
   vẫn là thông báo phân tích hiện có, khác thông báo kết quả response của workflow này.
5. Lưu workflow, bật Webhook, dán URL vào `SHUFFLE_HOOK`, rồi recreate AgentSOC sau khi kiểm tra.

Ví dụ payload minh họa, không phải file workflow import:

```json
{
  "schema_version": 1,
  "event_id": "unique-persisted-event-id",
  "event": "response.completed",
  "case_id": "local-case-id",
  "action_id": 7,
  "decision": "approve",
  "ip": "192.168.20.50",
  "status": "dry_run",
  "mode": "dry-run",
  "blocked": false,
  "verification_status": "not_verified",
  "completed_at": 1794210000.0
}
```

Chưa Approve thì không có event. Reject không gửi event trong phiên bản này. Nếu API chết khi action đang
thực thi, phục hồi lease phát event `action_unknown`, không khẳng định đã chặn và không chạy lại SSH.
Sender chỉ gửi một công việc mỗi tick, retry backoff tối đa một giờ, lưu mã lỗi ngắn, không lưu response body.
HTTP 2xx chỉ xác nhận nhận webhook, không chứng minh mọi node của workflow đã thành công.
Mất acknowledgement sau khi Shuffle đã nhận có thể dẫn đến nhận lại cùng event ID (at-least-once delivery).

## Triển khai code sau khi tự push GitHub

1. Không ghi đè `.env`, thư mục `data` hoặc cấu hình stack khác. Sao lưu `.env` và SQLite bằng
   `python -m scripts.backup --db data/agentsoc.db --output /duong-dan-backup-moi/agentsoc.db`.
   Không dùng `cp` lên một SQLite đang ghi WAL. Giữ commit/image cũ để rollback.
2. Kiểm tra working tree và commit sẽ triển khai; fetch/pull có kiểm soát. Áp dụng **một** patch tổng hợp
   hoặc cập nhật source qua Git, không áp dụng thêm patch TheHive cũ lên bản tổng hợp này.
3. Cài dependencies test trong venv từ `requirements-dev.lock` và chạy pytest, ruff, frontend build/lint.
4. Chạy `docker compose config --quiet`, sau đó `docker compose build agentsoc-backend agentsoc-worker`.
5. Chạy `docker compose up -d --no-deps agentsoc-backend agentsoc-worker`. Không cần `down`, không dùng `down -v`.
   Migration chỉ thêm bảng và index; không xóa incident, alert, action hoặc ledger cũ.
6. Xem `docker compose ps` và System health. Queue/configuration không chứng minh external service reachable.
7. Gửi một alert test qua đường ingest đã có xác thực; không gửi key qua chat. Kiểm tra lần lượt VT, TheHive,
   rồi quyết định dry-run trên console và event webhook. Tránh tạo nhiều case test ngoài ý muốn.

Các incident đã hoàn thành trước lần nâng cấp **không tự backfill**. Để chọn một case cũ có chủ đích:

```bash
python -m scripts.integrations --db data/agentsoc.db --case CASE_ID --queue-case
```

Lệnh chỉ queue mirror/VT, không phân tích lại, không Approve và không tạo event Shuffle. Worker đang chạy
có thể gửi case ngay sau đó. Không queue case demo vào database production.

## Theo dõi và lỗi

- Incident detail: panel **Case integrations** hiển thị remote ID TheHive, kết quả VT và tình trạng event Shuffle.
- System health: **External integrations** hiển thị enabled/configured, số tác vụ mỗi state và số lỗi.
- `python -m scripts.integrations --db data/agentsoc.db` đọc tối đa 100 dòng mỗi queue; thêm `--case ID` để lọc.
- 401/403: kiểm tra key, account và quyền; không reset mật khẩu stack chỉ từ một mã lỗi.
- VirusTotal 404 là `not_found`, không đồng nghĩa IP sạch; 429 tạm dừng theo Retry-After (giới hạn thời gian hợp lý).
- TheHive `CreateOutcomeUnknown`: worker đã checkpoint trước POST nhưng không có phản hồi chắc chắn.
  Nó chỉ tìm lại bằng tag `agentsoc-id:CASE_ID`, không tự POST lần hai. Phải tra case theo tag trước khi xử lý
  thủ công trạng thái này. Nếu nhiều case cùng tag, báo `ReconciliationRequired` và không chọn ngẫu nhiên.
  Lỗi 401/403/429/503 của truy vấn đối soát không xóa checkpoint `creating`; sửa key hoặc khôi phục dịch vụ
  không tự cho phép POST lại một lần tạo case chưa rõ kết quả.
- TheHive description là phần AgentSOC quản lý; thay đổi ở bản mirror có thể ghi đè chỉnh sửa tay vào
  description khi dữ liệu local đổi. Không tự sửa status đóng case, comment, task hoặc observable.
- Tất cả error body/exception text/credential được giữ ngoài operational log tích hợp.

Tắt một tích hợp bằng cách để trống biến tương ứng rồi recreate AgentSOC. Queue và mapping giữ nguyên
để có thể tiếp tục. Không đổi endpoint sang instance khác trong khi dùng lại mapping remote ID cũ.
Không reset database để chữa lỗi kết nối. Rollback code về commit trước vẫn giữ các bảng mở rộng;
phục hồi database chỉ khi cần và sau khi dừng writer.

## Kiểm chứng và giới hạn

Tests dùng HTTP mock, SQLite thật và HTTP API AgentSOC để kiểm tra pipeline, không dùng key thật,
không gọi VirusTotal/LLM trả phí, không SSH chặn IP thật. Có browser tests cho panel và điều hướng.
Vẫn cần kiểm tra end-to-end với TheHive 5.2.7-1 và workflow Shuffle trên VPS sau triển khai.
Việc cài stack, quyền Docker socket, khởi động sau reboot và backup của stack ngoài repo là công việc riêng;
không được coi là đã xác minh chỉ vì test code đạt.

Kết quả kiểm tra local và các giới hạn môi trường của lần áp dụng patch nằm trong
[validation-integrations.md](validation-integrations.md). Build console dùng compiler JavaScript
và danh sách utility Tailwind tường minh, không cần scanner native Oxide bị chặn bởi Windows
Application Control. Luôn build trước khi chạy browser tests để kiểm tra giao diện hiện tại.
