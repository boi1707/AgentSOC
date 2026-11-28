# Triển khai AgentSOC cùng hạ tầng hiện có

Wazuh, Docker, WireGuard và firewall của operator đã triển khai riêng. Lần nâng cấp không cài lại,
merge compose, thay rule routing, thay SSH config, load nftables hoặc deploy VPS tự động.
Các file `config/wazuh`, `config/wireguard`, gateway script là mẫu/compatibility, không tự áp dụng.

## Local và chuẩn bị VPS

Xem README để chạy Windows/Linux với launcher `python -m scripts.dev --build`.
Trên VPS chỉ chạy image Docker không cần Node/Python 3.12 trên host; Docker build console bằng Node
22 rồi đóng vào runtime Python 3.12. API và worker dùng cùng image, hai process/container riêng.

1. Backup database đang dùng trước khi upgrade, theo [UPGRADE.md](UPGRADE.md).
2. Tạo `.env` từ `.env.example`; giữ các key cũ nếu đang có dữ liệu. INGEST_KEY và APPROVE_KEY
   phải khác nhau, ít nhất 24 ký tự. ADMIN_PASSWORD riêng được khuyến nghị cho bootstrap admin mới.
3. Bắt đầu với `LLM_MODE=mock`, `RESPONSE_MODE=dry-run`, TG_TOKEN/TG_CHAT để trống.
4. Tạo `data`, đặt owner UID/GID 10001 để container non-root ghi được; bảo vệ raw DB/backup/key.
5. `docker compose up -d --build --wait`. API mặc định publish localhost:8000; worker không publish port.
6. Mở `/console`, đăng nhập admin, tạo account riêng theo vai trò. `/live`, `/health`, `/ready` là
   các probe khác nhau; readiness chưa đạt nếu chưa thấy heartbeat worker mới.

```bash
mkdir -p data
sudo chown 10001:10001 data
docker compose up -d --build --wait
docker compose ps
make health
docker compose logs --tail=100
```

Chỉ đổi `BIND_IP=10.8.0.1` nếu interface WireGuard hiện hữu đã có địa chỉ đó. Đây là ví dụ topology,
không khẳng định địa chỉ VPS của operator. Docker published ports cần kiểm tra ở host; đừng suy ra
UFW đã kiểm soát mọi port container. Không publish datastore hoặc provider endpoint.
Nếu dùng reverse proxy HTTPS hiện hữu, đặt SESSION_COOKIE_SECURE=1; app không cấu hình proxy thay bạn.

## Wazuh integration đang có

`POST /ingest` và bearer INGEST_KEY giữ tương thích `scripts/custom-agentsoc`. Hook URL vẫn trỏ API
port 8000 (hoặc IP/port đã cấu hình từ trước), không trỏ frontend dev server. Không cần đổi stack
Wazuh để bật console mới.

Nếu cài integration mới thủ công: script phải ở `/var/ossec/integrations/custom-agentsoc`, interpreter
Python 3, owner/mode theo chính sách manager. `config/wazuh/integration.xml` và `local_rules.xml`
là mẫu để operator tự review/merge đúng phiên bản; repo không tự chép chúng vào manager/container.
INGEST_KEY thật chỉ đặt cục bộ. Giữ source ID ổn định qua WAZUH_SOURCE_ID để tránh reimport trùng.

Cách xác minh sau một alert mới:

- Alerts hiển thị external ID, source, received time, schema version và raw/normalized JSON.
- Alert không có entity vẫn có trong filter uncorrelated. Không kỳ vọng case giả cho unknown data.
- Incident có evidence links, correlation reason và run/job riêng.
- Ledger có tool calls và Net/Host/Judge, mode/provider/model attribution, usage nếu có.
- System health hiển thị last alert/worker fresh; Wazuh connection không được tự gán connected.

## Provider

Hosted: `LLM_MODE=live`, HTTPS `LLM_URL`, `LLM_API_KEY`, `LLM_MODEL` hỗ trợ chat completion JSON,
response_format=json_object và temperature=0. Không đặt key trong URL. URL chỉ lấy từ server config;
API/typed tools không nhận arbitrary URL. Không tự fallback live → mock khi lỗi.

Mock không gọi cloud và luôn có nhãn. Local HTTP/Ollama chưa được triển khai; không thêm model service
hoặc mặc định tải model vào VPS. Test live chỉ chạy khi operator chủ động cấp cờ `--live-provider`;
lần chạy test thông thường không tiêu tiền API.

## Response/notifications

Giữ dry-run cho đến khi tự nghiệm thu trên lab. SSH adapter và `scripts/gateway_block.py` giữ chính
sách cũ: forced command, host key đã pin, protected networks và source IP từ network evidence có cite.
Không có bước nâng cấp nào thêm public key, đổi firewall hoặc thực thi chặn. Không dùng accept-new.
Nếu operator tự bật SSH, cần review gateway/known_hosts/key permissions và validate hệ thống thật
riêng; mock/synthetic/replay không được tạo response thật. Action_unknown phải kiểm tra tay trước
bất kỳ thao tác tiếp theo; hệ thống không tự retry SSH.

Telegram là tùy chọn, chỉ gửi ID/verdict; failure không làm mất run. Demo/test luôn tắt Telegram.
Giữ các mẫu gateway hiện có để tương thích; không load `config/gateway.nft` lên firewall hiện hữu
như một phần của việc nâng cấp console.

### Mạng được bảo vệ khi xét đích phản ứng

AgentSOC mặc định bảo vệ `10.8.0.0/24`, `192.168.10.0/24`, `127.0.0.0/8` và
`169.254.0.0/16`. `PROTECTED_NETWORKS` bổ sung các mạng IPv4 cho từng triển khai.
Để trống hoặc bỏ biến sẽ giữ cả bốn mạng. Các mục được phân cách bằng dấu phẩy, bỏ khoảng
trắng quanh từng mục và bỏ mạng trùng theo thứ tự xuất hiện. Dùng địa chỉ mạng kèm độ dài
prefix, hoặc `/32` nếu chỉ bảo vệ một host. IPv6, địa chỉ thiếu prefix, netmask dạng chấm,
prefix không hợp lệ, mục rỗng giữa các dấu phẩy và CIDR có host bit đều làm startup thất bại.

Ví dụ cho topology đã mô tả trong đợt rà soát:

```dotenv
LLM_MODE=live
RESPONSE_MODE=dry-run
PFSENSE_LIVE_ENABLED=0
PROTECTED_NETWORKS=192.168.119.0/24,172.22.50.0/24,10.100.27.254/32
```

Giữ giá trị `GATEWAY` hiện có nếu là địa chỉ IPv4 hợp lệ. Backend và worker dùng chung
`env_file: .env` trong Compose, kiểm tra cả hai biến khi khởi động và luôn bảo vệ
`GATEWAY` dưới dạng `/32`, kể cả trong dry-run. `PROTECTED_NETWORKS` từ chối đích phản ứng
trong các dải đã khai báo. `PFSENSE_ALLOWED_NETWORKS` giới hạn riêng phạm vi nguồn được phép
của adapter pfSense. Ví dụ trên vẫn để `10.100.27.10/32` ngoài danh sách mạng bị bảo vệ.

Trước rollout, xác nhận topology, sao lưu SQLite và ghi lại digest image cùng cấu hình
hiện hành. Thử trên staging dùng bản sao SQLite, kiểm tra cả hai service nhận cùng cấu
hình, readiness và từ chối các địa chỉ hạ tầng với evidence đã được trích dẫn. Khi rollback
image, xác minh lại phạm vi bảo vệ. Image cũ bỏ qua `PROTECTED_NETWORKS`, nên giữ dry-run
và tạm dừng thao tác duyệt cho đến khi khôi phục guard. Thay đổi này không thêm migration.

## Demo Docker tách riêng

```bash
make demo
make replay
# http://127.0.0.1:8001/console
make demo-down
```

Standalone `docker-compose.demo.yml` có project/volume riêng, clear TG credentials và ép mock/dry-run.
Production `DB` không được dùng khi DEMO_MODE=1. Không dùng fixture demo như dữ liệu quan sát thực.

## Vận hành và giới hạn kiểm chứng

Log API `data/logs/agentsoc.log`, worker `data/logs/agentsoc-worker.log`: JSON, 10 MiB/file,
5 backup mỗi process. Docker json-file cũng rotate 10m/5. Không ghi raw refused prompt, exception
message hoặc secrets. SQLite/backup vẫn chứa evidence thật và restore map nên cần quyền OS phù hợp.

Nếu API lên nhưng ready=503: kiểm tra worker container/process và heartbeat. Nếu job dead-letter:
đọc error code/attempts, sửa cấu hình hoặc kết nối, tạo investigation replay có chủ đích. Không reset
DB để né lỗi. Lỗi ProviderHTTP401 khác ConnectError/429/5xx; các lỗi tạm thời có retry/backoff hữu hạn.

Chưa đo RAM/CPU/throughput cạnh Wazuh trên VPS, chưa xác minh Docker trong môi trường không có daemon,
chưa gọi LLM/Telegram/SSH thật ở lần nâng cấp này. Browser smoke dùng synthetic + mock và dry-run.
Xem [ARCHITECTURE.md](ARCHITECTURE.md) về storage, lease, replay cutoff và giới hạn single workspace.
