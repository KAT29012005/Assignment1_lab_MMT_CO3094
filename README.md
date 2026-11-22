# Assignment 1 — Distributed Client-Server Collaboration Application


```

## Cài đặt

```bash
cd Assignment1_Lab_MMT
python -m venv .venv
source .venv/bin/activate         # Linux/macOS
# .venv\Scripts\activate           # Windows
pip install -r requirements.txt
```

Yêu cầu: Python 3.10 trở lên.

## Chạy nhanh

Đề bài mục 7 (Design Requirements — User Interface) cho phép CLI **hoặc** GUI.
Bộ lab cung cấp **cả hai** cùng dùng chung một lớp logic mạng (`client.Client`),

### Tuỳ chọn A — Giao diện dòng lệnh (CLI)

Mở 3 terminal:

```bash
# Terminal 1 — khởi động server
python -m server.server --host 127.0.0.1 --tcp-port 5556 --udp-port 5555

# Terminal 2 — client Alice
python -m client.cli --host 127.0.0.1
> /login alice
> /broadcast hello everyone
> /msg bob hi privately
> /file bob ./examples/demo_file.bin

# Terminal 3 — client Bob
python -m client.cli --host 127.0.0.1
> /login bob
```

### Tuỳ chọn B — Giao diện đồ hoạ Tkinter (GUI)

```bash
# Terminal 1 — khởi động server (như trên)
python -m server.server

# Terminal 2 — Alice GUI
python -m client.gui --host 127.0.0.1

# Terminal 3 — Bob GUI
python -m client.gui --host 127.0.0.1
```

Cửa sổ GUI có:



## Chạy tests

```bash
# Toàn bộ test
python -m unittest discover -s tests -v

# Riêng từng file
python -m unittest tests.test_protocol -v
python -m unittest tests.test_crypto -v
python -m unittest tests.test_file_transfer -v
python -m unittest tests.test_integration -v
```



## Mốc rubric 10 bước

| Bước | Mốc                              | Triển khai trong code                              |
| ---- | -------------------------------- | -------------------------------------------------- |
| 1    | Thiết kế giao thức               | `common/protocol.py` (header 16 byte, 10 msg type)|
| 2    | Handshake Client-Server          | `client/client.py:login()` + `server/server.py:_handle_auth` |
| 3    | Concurrency                      | `server/server.py` thread-per-client + `UserManager` Lock |
| 4    | Xác thực & quản lý trạng thái    | `server/user_manager.py` UserSession              |
| 5    | Định tuyến tin nhắn               | `server/relay.py` relay_broadcast/unicast          |
| 6    | Chuyển tệp đáng tin cậy          | `common/file_transfer.py` send_file/receive_file  |
| 7    | Khả năng chịu lỗi                 | `server/server.py` try/except + cleanup thread    |
| 8    | Lớp bảo mật                       | `common/crypto.py` AES + RSA + HMAC                |
| 9    | Tích hợp UI/CLI                  | `client/cli.py` (CLI) + `client/gui.py` (GUI Tkinter) |
| 10   | Kiểm thử & chất lượng mã         | `tests/` (4 file test)                             |

