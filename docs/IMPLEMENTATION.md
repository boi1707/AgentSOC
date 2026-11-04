# Phạm vi triển khai AgentSOC

## Hoàn thành trong repo

- Chuẩn hóa Snort JSON và Sysmon Wazuh, map IP WireGuard → LAN.
- Gom theo IP liên quan trong 10 phút, im lặng 30 giây hoặc level ≥12; dedupe có giữ nguồn/đích.
- Tối đa 40 dòng context, ưu tiên mức nghiêm trọng cao; hiển thị số dòng bị cắt.
- Inbox SQLite chống trùng ID, case UUID, phục hồi hàng đợi sau restart.
- Pseudonymization một mapping mỗi incident, quét độc lập trước egress, không có ANON=0.
- Ba agent network/host/judge, Pydantic schema, lọc ID bịa và hạ verdict khi không đủ bằng chứng.
- Judge nhận bằng chứng đã che cùng kết luận, không chỉ nhận văn bản tóm tắt.
- Ledger lưu messages/response/usage/duration/error, riêng DB cho mapping và log thật.
- UI review có xác thực, escape HTML, header chống CSRF, approve/reject và claim nguyên tử.
- Chặn mặc định dry-run; SSH pin host key; gateway chỉ cho phép subnet attacker của lab.
- Ledger hành động, trạng thái action_unknown nếu crash/timeout không rõ kết quả.
- Fixture/demo offline, replay API JSON/JSONL theo tốc độ, đánh giá nhãn alert và GitHub Actions.
- Log JSON stdout/file, xoay file, lọc secret và stack không chứa exception message.
- Health/metrics bền vững qua restart, audit lần bị guard chặn với placeholder an toàn.
- Script setup VPS, mẫu WireGuard/authorized_keys, runtime/dev dependency lock.

## Khác với code mẫu HTML

Không dùng Wazuh `shuffle` gửi vào endpoint generic: dùng integration riêng có bearer token.
Không cho secret vào URL review. Không dùng `StrictHostKeyChecking=accept-new` khi chặn.
Không tự retry lệnh chặn bị gián đoạn và không tự động hành động từ verdict.
Tỷ lệ gộp cảnh báo là consolidation, **không** đồng nghĩa tỷ lệ giảm false positive.
Các ngưỡng 80%, latency 10–15s, leakage=0 là mục tiêu cần đo trên tập test, không phải kết quả.

## Chưa hoàn thành vì phụ thuộc môi trường thật

1. VPS Ubuntu, Docker, Wazuh stack, WireGuard và firewall.
2. Gateway Snort 3/nftables, Windows Sysmon/Wazuh agent, Kali và định tuyến qua gateway.
3. Xác nhận field/rule đúng phiên bản Wazuh/Snort, forward alert thật vào inbox.
4. Gọi LLM thật bằng dữ liệu lab đã rà soát, test lỗi/quota và kiểm tra ledger.
5. Telegram thật; SSH forced command, block TTL 1h và kiểm tra trước/sau duyệt.
6. Bộ dữ liệu gán nhãn, replay cố định và ablation A–D. Raw baseline chỉ xây riêng cho dữ liệu
   lab tổng hợp, không tắt guard của dịch vụ production.
7. Thu thập số đo thật. Công cụ metrics đã tính precision/recall cấp alert từ CSV,
   latency end-to-end và USD khi có usage/đơn giá; chưa có tập nhãn và kết quả thực nghiệm.

## Giới hạn prototype

- Một reviewer shared credential, chưa có RBAC/multi-user hoặc audit danh tính cá nhân.
- SQLite và worker đơn: không scale nhiều replicas; inbox được dựng lại mỗi vòng nên cần benchmark
  hoặc queue riêng khi traffic lớn. LLM calls tuần tự, có timeout 30 giây mỗi call.
- Wazuh integration gửi một lần; nếu dịch vụ ngừng, cần replay từ alerts.json, chưa có spool/retry
  bền vững trước khi nhận vào inbox. Sau khi nhận, hàng đợi là durable.
- Lỗi phân tích chuyển review, không tự retry LLM để tránh chi phí lặp ngoài ý muốn.
- Ledger là audit vận hành, chưa phải append-only/chống sửa bằng mật mã.
- Token hóa bằng regex/danh sách, không phải chứng minh loại bỏ toàn bộ PII.
- Telegram best-effort, thất bại không làm mất case; chưa có hàng đợi retry thông báo.
- IP blocking IPv4 lab; script gateway mặc định chỉ chặn 192.168.20.0/24, trừ gateway .1.

## Nghiệm thu trên lab

- Không đăng nhập: `/cases` bị 401; sai bearer: `/ingest` bị 401.
- Gửi Snort và Sysmon cùng host: một case, ba ledger calls; raw IP không nằm trong prompt.
- Chưa approve: nft set trống. Reject: không có SSH. Duyệt lặp: 409.
- Key forced-command chạy `id` phải bị từ chối; IP máy bảo vệ không được chặn.
- Approve hợp lệ: nft có đúng IP nguồn; lưu action và xác nhận hết hạn sau 1 giờ.
- Restart service trước phân tích: alert vẫn còn. Crash khi đang chặn: action_unknown, kiểm tra tay.
- Export cùng bộ alert và nhãn trước khi so sánh các cấu hình, ghi rõ phiên bản/model/seed/date.
