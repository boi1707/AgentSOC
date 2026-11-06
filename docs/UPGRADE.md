# Nâng cấp từ prototype (`45e4dcd`)

## Backup trước khi chạy phiên bản mới

Không xóa data, không chạy compose down -v và không reset DB. Dùng SQLite backup API để bao gồm
committed WAL; copy riêng file `.db` khi process đang ghi có thể thiếu dữ liệu.

```powershell
.\.venv\Scripts\python.exe -m scripts.backup --db data/agentsoc.db --output data/backups/before-v2.db
```

Trên Linux dùng `.venv/bin/python`. Bảo vệ backup như raw telemetry; script từ chối ghi đè backup cũ.
Trong Docker có thể chạy module backup bằng `docker compose exec -T agentsoc-backend python -m
scripts.backup --db data/agentsoc.db --output data/backups/before-v2.db` nếu image đang có module.
Với image prototype chưa có module, dùng Python host hoặc dừng process trước khi sao lưu toàn bộ data.

## Migration

1. Dừng API/worker cũ để tránh hai generation cùng ghi DB.
2. Backup và giữ `.env`, SSH key, known_hosts. Không thay khóa ứng dụng bằng khóa sample.
3. Cập nhật dependencies từ `requirements-dev.lock` (local) hoặc build Docker image mới.
4. Build console bằng `npm ci && npm run build` trong `frontend`, hoặc để Docker multi-stage build.
5. Khởi động API rồi worker mới. Store tự chạy additive migration dưới write transaction.
6. Kiểm tra `/health`, `/ready` và trang System health; so số alert/case/ledger/action với backup.

Các bảng `inbox`, `cases`, `ledger`, `actions` và ID cũ được giữ. Thêm cột và bảng mới, không DROP,
không seed AI outcomes, không chế run/provider metadata cho lịch sử thiếu thông tin.
Normalized backfill từ raw legacy là bước xác định, không chạy model. Liên kết incident-alert cũ
được tái tạo từ raw_ids, với rationale ghi rõ là legacy, không giả thành correlation reason gốc.

Case queued cũ được worker thêm job/run để tiếp tục. Case đã hoàn tất không tự phân tích lại.
Intent response v2 có cửa sổ 60s; API/worker chỉ chuyển intent executing quá hạn sang action_unknown,
không đụng intent còn hiệu lực khi có API process khác đang thực thi. Intent legacy không có lease
được đánh dấu unknown khi phục hồi. Không tự SSH lại. Lease job AI
hết hạn mới được retry theo attempt budget; đó không phải retry response.

## Contract thay đổi có chủ đích

- API deployment mặc định **không** tạo worker trong lifespan. Chạy `python -m src.worker` riêng.
  `EMBEDDED_WORKER=1` chỉ để phát triển single-process có chủ đích, không bật cùng worker riêng.
- Alert Wazuh hợp lệ thiếu correlation entity vẫn nhận/lưu, status uncorrelated thay vì trả 422.
  Malformed JSON là 400, schema sai là 422. Ngưỡng level 7 vẫn giữ cho `/ingest`.
- Ledger có tool steps ngoài ba model calls. Đếm `agent IN ('net','host','judge')` nếu cần số LLM calls.
- `/console` là UI mới; `/cases`, `/api/cases`, `/approve/{id}`, `/reject/{id}` và integration cũ vẫn có.
- UI mới dùng session/RBAC. Bootstrap admin lần đầu dùng ADMIN_PASSWORD hoặc APPROVE_KEY nếu để trống.
  Biến admin chỉ dùng lúc bootstrap; thay `.env` không âm thầm reset password đã hash trong users.
- Source ngoài ID mặc định `wazuh` có internal ID prefix; external_id và raw id vẫn còn.
- Demo fixture không gửi vào service production bằng script replay; dùng DEMO_MODE=1/database riêng.
- Role/state metadata mới thiếu ở lịch sử được trả null/"No data". Không có parent run lịch sử thì
  không hứa tái hiện chính xác bằng chứng của một investigation chưa từng được ghi snapshot.

## Rollback

Giữ image/checkout cũ cùng backup trước nâng cấp. Nếu cần rollback, dừng cả API và worker, giữ lại
DB mới để điều tra, rồi khôi phục **bản sao** backup trước migration vào đường DB dành cho version cũ.
Không trỏ code prototype vào DB v2: prototype có INSERT theo positional columns không tương thích
với cột mới. Không thực hiện rollback trong lúc có SSH action đang chạy; xác minh gateway thủ công.
