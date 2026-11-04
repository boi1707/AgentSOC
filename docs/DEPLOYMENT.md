# Triển khai VPS và lab

## Bố trí

VPS 10.8.0.1: Wazuh manager/indexer/dashboard và AgentSOC.
Gateway 10.8.0.2: Snort 3, nftables, Wazuh agent.
Windows 10.8.0.3 / LAN 192.168.10.20: Sysmon, Wazuh agent.
Kali LAN 192.168.20.50: chỉ thực hiện bài kiểm tra trong lab được phép.

Kali và Windows phải ở hai subnet, đi qua gateway. Nếu hai máy trao đổi trực tiếp bypass
gateway thì chặn nftables sẽ không ngăn được lưu lượng. Đặt IP thật vào HOST_IPS/HOST_NAMES.

## VPS

1. Dùng Ubuntu tương thích với bản Wazuh chọn; cài Docker và WireGuard theo tài liệu chính thức.
   Bắt đầu theo sizing Wazuh, đo RAM/CPU/disk trên tải thực tế; chưa xác nhận cấu hình 8 GB đủ.
2. Tạo user SSH và kiểm tra đăng nhập mới trước khi đổi chính sách SSH/firewall.
3. WireGuard: VPS .1, gateway .2, Windows .3, laptop quản trị .4. Private key sinh và giữ từng máy.
4. Firewall chỉ cho SSH quản trị và UDP WireGuard; Wazuh/AgentSOC bind WireGuard, không 0.0.0.0.
   Published ports Docker cần kiểm tra riêng, không giả định UFW đã chặn mọi port container.
5. Cài Wazuh theo phiên bản chính thức. Repo này không chứa compose Wazuh, cert hay password mặc định.
6. Clone repo, tạo `.env` từ [mẫu](../.env.example), giữ `dry-run`, tạo volume UID 10001 rồi chạy
   `docker compose up -d --build`. Khởi động WireGuard trước Docker nếu bind 10.8.0.1.

Có thể dùng `bash scripts/setup.sh` nếu host đã có Python 3.12+, venv, Docker Compose,
`ip` và `ssh-keygen`. Script tạo key/config và chuẩn bị quyền data, không cài Wazuh hay VPN.
Mẫu WireGuard theo từng máy nằm trong [config/wireguard](../config/wireguard/).

## Wazuh manager → AgentSOC

Chép [custom-agentsoc](../scripts/custom-agentsoc) vào `/var/ossec/integrations/custom-agentsoc`.
Đặt owner `root:wazuh`, mode `750`, interpreter Python 3 có trong manager/container.
Merge [integration.xml](../config/wazuh/integration.xml) vào `ossec_config`, thay API key cục bộ.
Merge [local_rules.xml](../config/wazuh/local_rules.xml) vào cấu hình rules; tránh trùng rule IDs.
Kiểm tra bằng `wazuh-logtest` với alert thật rồi restart manager theo cách cài Wazuh của bạn.

Nếu Wazuh ở container, 10.8.0.1 phải route được từ container. Integration/rules phải mount vào
container manager; cài file chỉ trên host sẽ không tự xuất hiện trong container.
Không dùng biến Telegram hoặc API key thật trong các file đã commit.

Snort 3 phải bật `alert_json` với fields `timestamp src_addr dst_addr dst_port proto msg sid`,
agent đọc `/var/log/snort/alert_json.txt` với `log_format=json`. Field thực tế cần kiểm tra trên
bản Snort/Wazuh đã cài. Windows bật Sysmon, agent gửi EventChannel Sysmon theo hướng dẫn Wazuh.

## Gateway forced command (chỉ sau khi dry-run đã nghiệm thu)

Review [gateway.nft](../config/gateway.nft), load bằng `sudo nft -f config/gateway.nft` trên gateway
và tích hợp vào cơ chế persist hiện có. Không flush ruleset đang dùng. Xác nhận gateway forward
IP và routing hoạt động. Script mặc định chỉ cho phép chặn máy thuộc subnet attacker 192.168.20/24,
không cho .0, .1, .255. Nếu đổi topology, sửa script, protected networks và test cùng lúc.

Cài [gateway_block.py](../scripts/gateway_block.py) thành `/usr/local/bin/agentsoc-block`, owner
root, mode 755, xác nhận `/usr/bin/env python3` và `/usr/sbin/nft` tồn tại trên gateway.
Tạo key riêng trên VPS trong `data/block_key`, không dùng lại khóa SSH quản trị.
Chỉ gắn public key vào authorized_keys gateway với options:

```text
from="10.8.0.1",restrict,command="/usr/local/bin/agentsoc-block" ssh-ed25519 REPLACE_PUBLIC_KEY agentsoc
```

Root SSH phải cho forced command nhưng không mở đăng nhập root bằng password. Kiểm tra cấu hình
hiện tại trước khi sửa; không thay thế SSH config bằng snippet này.
Pin host key vào `data/known_hosts` sau khi so fingerprint qua kênh tin cậy; không tin mù kết quả
`ssh-keyscan`. UID 10001 trong container cần đọc private key và known_hosts, không world-readable.

Chạy thử âm tính trên gateway: `SSH_ORIGINAL_COMMAND=id /usr/local/bin/agentsoc-block` phải exit 2.
Kiểm tra `ssh -i data/block_key root@10.8.0.2 id` cũng không được chạy `id`.
Sau đó mới đặt `LLM_MODE=live`, cấu hình model và giữ dry-run để rà verdict.
Cuối cùng bật `RESPONSE_MODE=ssh` khi đã chuẩn bị đầy đủ. Không có bước nào tự chặn nếu chưa approve.

## Nguồn chính thức

- [Wazuh custom integrations](https://documentation.wazuh.com/current/user-manual/manager/integration-with-external-apis.html)
- [Wazuh installation](https://documentation.wazuh.com/current/installation-guide/index.html)
- [WireGuard quick start](https://www.wireguard.com/quickstart/)
- [Snort 3 documentation](https://docs.snort.org/)
- [Docker Compose service reference](https://docs.docker.com/reference/compose-file/services/)
- [FastAPI lifespan](https://fastapi.tiangolo.com/advanced/events/)
