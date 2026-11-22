

import argparse
import os
import queue
import socket
import sys
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

# Đảm bảo import được dù chạy trực tiếp (`python client/gui.py`)
# hay chạy dưới dạng module (`python -m client.gui`).
sys.path.insert(
    0, __file__[:__file__.rfind("/client/")] if "/client/" in __file__ else "."
)

from client.client import Client
from common.protocol import (
    MsgType, Flags, send_packet, recv_packet,
    json_payload, parse_json_payload, now_ts,
)
from common.network import DEFAULT_TCP_PORT, DEFAULT_UDP_PORT
from common.crypto import sha256_file


# ── Màu sắc & tag cho Text widget ───────────────────────────────────────────
TAGS = {
    "broadcast": {"foreground": "#1f3a93"},      # xanh đậm
    "private":   {"foreground": "#8e44ad"},       # tím
    "presence":  {"foreground": "#27ae60"},       # xanh lá
    "system":    {"foreground": "#7f8c8d"},       # xám
    "error":     {"foreground": "#c0392b"},       # đỏ
    "file":      {"foreground": "#d35400"},       # cam
    "self":      {"foreground": "#2c3e50"},       # xanh đen (tin mình gửi)
}


class GUIClient(Client):
    """Subclass của Client — override _receiver_loop và _handle_incoming_file
    để đẩy event vào queue thay vì in ra stdout.

    Pattern này bảo toàn nguyên vẹn logic mạng (AUTH, FSM, crypto, file
    transfer) của lớp cha, chỉ thay đổi tầng presentation.
    """

    def __init__(self, event_queue: "queue.Queue", *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._event_queue = event_queue

    # ── Ghi đè receiver loop (đẩy event vào queue) ─────────────────────────
    def _receiver_loop(self) -> None:
        # Important: bắt riêng socket.timeout (subclass của OSError) và loop
        # tiếp. SO_RCVTIMEO=30s chỉ là "không có dữ liệu" chứ không phải mất
        # kết nối. Nếu bắt chung OSError, GUI sẽ tự báo "Mất kết nối" sau 30s
        # im lặng dù server vẫn ổn. Đây là bug #1 đã được sửa (Báo cáo §11.4).
        sock = self.state.tcp_sock
        while not self._stop.is_set():
            try:
                hdr, payload = recv_packet(sock)
            except socket.timeout:
                continue
            except (ConnectionError, OSError):
                if not self._stop.is_set():
                    self._event_queue.put({
                        "type": "system",
                        "text": "⚠️ Mất kết nối đến server (connection closed).",
                    })
                    self._event_queue.put({"type": "disconnected"})
                    self._stop.set()
                break

            try:
                if hdr["flags"] & Flags.ENCRYPTED:
                    payload = self.state.decrypt(payload)

                mtype = hdr["msg_type"]

                if mtype == MsgType.MSG_BROADCAST:
                    env = parse_json_payload(payload)
                    sender = env.get("from", "?")
                    text = env.get("text", "")
                    self._event_queue.put({
                        "type": "broadcast",
                        "sender": sender,
                        "text": text,
                    })

                elif mtype == MsgType.MSG_UNICAST:
                    env = parse_json_payload(payload)
                    sender = env.get("from", "?")
                    text = env.get("text", "")
                    self._event_queue.put({
                        "type": "private",
                        "sender": sender,
                        "text": text,
                    })

                elif mtype == MsgType.PRESENCE:
                    env = parse_json_payload(payload)
                    users = [u["username"] for u in env.get("users", [])]
                    self._event_queue.put({
                        "type": "presence",
                        "users": users,
                    })

                elif mtype == MsgType.FILE_INIT:
                    self._handle_incoming_file(hdr, payload)

                elif mtype == MsgType.ERROR:
                    env = parse_json_payload(payload)
                    self._event_queue.put({
                        "type": "error",
                        "code": env.get("code"),
                        "message": env.get("message", ""),
                    })

                else:
                    self._event_queue.put({
                        "type": "system",
                        "text": f"⚠️ unhandled msg_type 0x{mtype:02X}",
                    })
            except Exception as exc:  # noqa: BLE001
                self._event_queue.put({
                    "type": "error",
                    "text": f"Lỗi receiver: {exc}",
                })

    # ── Ghi đè nhận file — đẩy progress vào queue ─────────────────────────
    def _handle_incoming_file(self, hdr: dict, init_payload: bytes) -> None:
        meta = parse_json_payload(init_payload)
        filename = os.path.basename(meta.get("filename", "received"))
        dest = os.path.join(self.download_dir, filename)
        total = meta.get("chunks", 0)
        size = meta.get("size", 0)

        self._event_queue.put({
            "type": "file_incoming",
            "filename": filename,
            "size": size,
            "chunks": total,
            "sender": meta.get("from", "?"),
        })

        os.makedirs(self.download_dir, exist_ok=True)

        # ACK FILE_INIT, yêu cầu chunk 0
        send_packet(
            self.state.tcp_sock, MsgType.FILE_ACK,
            json_payload({"chunk_id": -1, "ok": True, "want": 0}),
            self.state.session_id,
        )

        received = 0
        with open(dest, "wb") as out:
            while received < total:
                chdr, cpayload = recv_packet(self.state.tcp_sock)
                if chdr["flags"] & Flags.ENCRYPTED:
                    cpayload = self.state.decrypt(cpayload)
                if len(cpayload) < 4:
                    break
                cid = int.from_bytes(cpayload[:4], "big")
                out.write(cpayload[4:])
                received += 1
                self._event_queue.put({
                    "type": "file_progress",
                    "received": received,
                    "total": total,
                    "filename": filename,
                })
                send_packet(
                    self.state.tcp_sock, MsgType.FILE_ACK,
                    json_payload({"chunk_id": cid, "ok": True,
                                  "want": received}),
                    self.state.session_id,
                )

        actual = sha256_file(dest)
        expected = meta.get("sha256")
        ok = (actual == expected) if expected else None
        self._event_queue.put({
            "type": "file_done",
            "filename": filename,
            "dest": dest,
            "ok": ok,
        })


class ChatGUI:
    """Tkinter root window + tất cả widget.

    Vòng đời:
        1. User nhập username + host + port → click [Connect]
        2. Main thread spawn GUIClient.login() trong một worker thread
           (tránh block Tkinter event loop trong lúc AUTH handshake).
        3. Worker thread đẩy kết quả (success/fail) vào queue.
        4. Main thread poll queue, cập nhật trạng thái + enable chat.
    """

    def __init__(self, root: tk.Tk, host: str, tcp_port: int,
                 udp_port: int, download_dir: str):
        self.root = root
        self.host = host
        self.tcp_port = tcp_port
        self.udp_port = udp_port
        self.download_dir = download_dir

        self.event_queue: "queue.Queue" = queue.Queue()
        self.client: GUIClient | None = None
        self._login_thread: threading.Thread | None = None
        self._file_thread: threading.Thread | None = None

        self._build_ui()
        self._poll_queue()  # bắt đầu poll loop

    # ── Xây dựng giao diện ─────────────────────────────────────────────────
    def _build_ui(self) -> None:
        self.root.title("Distributed Collaboration — Assignment 1")
        self.root.geometry("900x620")
        self.root.minsize(720, 480)

        # Style ttk
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("Accent.TButton", foreground="white",
                        background="#2980b9")

        # ── TOP: Connection panel ─────────────────────────────────────────
        top = ttk.LabelFrame(self.root, text="Kết nối", padding=8)
        top.pack(fill="x", padx=8, pady=(8, 4))

        ttk.Label(top, text="Host:").grid(row=0, column=0, sticky="w")
        self.host_var = tk.StringVar(value=self.host)
        ttk.Entry(top, textvariable=self.host_var, width=14).grid(
            row=0, column=1, padx=4)

        ttk.Label(top, text="TCP:").grid(row=0, column=2, sticky="w")
        self.tcp_var = tk.IntVar(value=self.tcp_port)
        ttk.Entry(top, textvariable=self.tcp_var, width=6).grid(
            row=0, column=3, padx=4)

        ttk.Label(top, text="UDP:").grid(row=0, column=4, sticky="w")
        self.udp_var = tk.IntVar(value=self.udp_port)
        ttk.Entry(top, textvariable=self.udp_var, width=6).grid(
            row=0, column=5, padx=4)

        ttk.Label(top, text="Username:").grid(row=0, column=6, sticky="w")
        self.user_var = tk.StringVar()
        ttk.Entry(top, textvariable=self.user_var, width=14).grid(
            row=0, column=7, padx=4)

        self.connect_btn = ttk.Button(top, text="Connect",
                                      command=self.on_connect_click)
        self.connect_btn.grid(row=0, column=8, padx=4)

        self.logout_btn = ttk.Button(top, text="Logout",
                                     command=self.on_logout_click,
                                     state="disabled")
        self.logout_btn.grid(row=0, column=9, padx=4)

        # Status badge
        self.status_var = tk.StringVar(value="● DISCONNECTED")
        self.status_lbl = tk.Label(
            self.root, textvariable=self.status_var,
            fg="white", bg="#c0392b", padx=8, pady=2,
            font=("TkDefaultFont", 10, "bold"))
        self.status_lbl.pack(fill="x", padx=8)

        # ── MAIN: Chat (trái) + Users (phải) ───────────────────────────────
        paned = ttk.Panedwindow(self.root, orient="horizontal")
        paned.pack(fill="both", expand=True, padx=8, pady=4)

        # Bên trái: chat area + input
        left = ttk.Frame(paned)
        paned.add(left, weight=3)

        self.chat = tk.Text(left, wrap="word", state="disabled",
                            font=("Consolas", 10), padx=6, pady=6)
        for tag, cfg in TAGS.items():
            self.chat.tag_config(tag, **cfg)
        self.chat.pack(fill="both", expand=True)

        # Input row
        input_row = ttk.Frame(left)
        input_row.pack(fill="x", pady=(4, 0))

        self.recipient_var = tk.StringVar()
        recip_combo = ttk.Combobox(
            input_row, textvariable=self.recipient_var,
            values=["(broadcast)"], width=16, state="readonly")
        recip_combo.current(0)
        recip_combo.pack(side="left", padx=(0, 4))
        self.recip_combo = recip_combo

        self.msg_var = tk.StringVar()
        self.msg_entry = ttk.Entry(input_row, textvariable=self.msg_var)
        self.msg_entry.pack(side="left", fill="x", expand=True)
        self.msg_entry.bind("<Return>", lambda e: self.on_send_click())

        ttk.Button(input_row, text="Send",
                   command=self.on_send_click).pack(side="left", padx=4)

        # ── File transfer row ─────────────────────────────────────────────
        file_row = ttk.Frame(left)
        file_row.pack(fill="x", pady=(4, 0))

        self.file_path_var = tk.StringVar()
        ttk.Entry(file_row, textvariable=self.file_path_var,
                  state="readonly").pack(side="left", fill="x",
                                         expand=True, padx=(0, 4))
        ttk.Button(file_row, text="Browse…",
                   command=self.on_browse_file).pack(side="left", padx=2)
        self.send_file_btn = ttk.Button(
            file_row, text="Send File", command=self.on_send_file_click,
            state="disabled")
        self.send_file_btn.pack(side="left", padx=2)

        self.progress = ttk.Progressbar(left, mode="determinate")
        self.progress.pack(fill="x", pady=(4, 0))

        # Bên phải: active users list
        right = ttk.Frame(paned, width=220)
        paned.add(right, weight=1)

        ttk.Label(right, text="Active users",
                  font=("TkDefaultFont", 10, "bold")).pack(anchor="w", pady=(0, 4))

        self.users_listbox = tk.Listbox(right, height=20)
        self.users_listbox.pack(fill="both", expand=True)
        self.users_listbox.bind("<<ListboxSelect>>",
                                self.on_user_select)

        ttk.Label(right, text="(Click user → set recipient)",
                  foreground="#7f8c8d").pack(anchor="w", pady=(4, 0))

        # Đóng cửa sổ
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    # ── Poll queue (UI thread, mỗi 100ms) ────────────────────────────────
    def _poll_queue(self) -> None:
        try:
            while True:
                ev = self.event_queue.get_nowait()
                self._handle_event(ev)
        except queue.Empty:
            pass
        self.root.after(100, self._poll_queue)

    def _handle_event(self, ev: dict) -> None:
        kind = ev.get("type")

        if kind == "broadcast":
            self._append_chat(f"[BC] {ev['sender']}: {ev['text']}\n",
                             tag="broadcast")
        elif kind == "private":
            self._append_chat(f"[PM] {ev['sender']}: {ev['text']}\n",
                             tag="private")
        elif kind == "presence":
            self._update_users(ev["users"])
        elif kind == "system":
            self._append_chat(ev["text"] + "\n", tag="system")
        elif kind == "error":
            code = ev.get("code")
            msg = ev.get("message") or ev.get("text", "")
            self._append_chat(f"[ERR] {code}: {msg}\n", tag="error")
        elif kind == "disconnected":
            self._set_status("disconnected")
            self.connect_btn.config(state="normal")
            self.logout_btn.config(state="disabled")
            self.send_file_btn.config(state="disabled")
        elif kind == "login_ok":
            self._set_status("online")
            self._append_chat(
                f"✓ Đăng nhập thành công — session_id={ev['session_id']}\n",
                tag="system")
            self._append_chat(
                f"  K_S đã thiết lập (AES-256 + HMAC-SHA256)\n",
                tag="system")
            self.connect_btn.config(state="disabled")
            self.logout_btn.config(state="normal")
            self.send_file_btn.config(state="normal")
            os.makedirs(self.download_dir, exist_ok=True)
        elif kind == "login_fail":
            self._set_status("disconnected")
            self._append_chat(f"✗ Đăng nhập thất bại: {ev['reason']}\n",
                              tag="error")
            self.connect_btn.config(state="normal")
        elif kind == "file_incoming":
            self._append_chat(
                f"📥 Nhận file: {ev['filename']} "
                f"({ev['size']} bytes, {ev['chunks']} chunks) "
                f"từ {ev.get('sender','?')}\n",
                tag="file")
            self.progress.config(maximum=ev["chunks"], value=0)
        elif kind == "file_progress":
            self.progress.config(value=ev["received"])
            # Cập nhật text nhẹ mà không spam chat
        elif kind == "file_done":
            self.progress.config(value=0)
            ok = ev["ok"]
            ok_txt = "MATCH ✓" if ok is True else (
                "MISMATCH ✗" if ok is False else "n/a")
            self._append_chat(
                f"✓ Lưu file: {ev['dest']} — SHA-256 {ok_txt}\n",
                tag="file")
        elif kind == "file_sent":
            self.progress.config(value=0)
            self._append_chat(
                f"✓ Đã gửi file: {ev['path']} ({ev['chunks']} chunks)\n",
                tag="file")
        elif kind == "file_error":
            self.progress.config(value=0)
            self._append_chat(f"✗ Lỗi gửi file: {ev['reason']}\n",
                              tag="error")

    # ── Helpers UI ────────────────────────────────────────────────────────
    def _append_chat(self, text: str, tag: str = "system") -> None:
        self.chat.config(state="normal")
        self.chat.insert("end", text, tag)
        self.chat.see("end")
        self.chat.config(state="disabled")

    def _set_status(self, state: str) -> None:
        if state == "online":
            self.status_var.set("● ONLINE — authenticated")
            self.status_lbl.config(bg="#27ae60")
        elif state == "authenticating":
            self.status_var.set("● AUTHENTICATING…")
            self.status_lbl.config(bg="#d35400")
        else:
            self.status_var.set("● DISCONNECTED")
            self.status_lbl.config(bg="#c0392b")

    def _update_users(self, users: list) -> None:
        self.users_listbox.delete(0, "end")
        # Giữ "(broadcast)" ở đầu combobox
        new_values = ["(broadcast)"] + list(users)
        self.recip_combo.config(values=new_values)
        # Nếu đang chọn user không còn online → reset về broadcast
        cur = self.recipient_var.get()
        if cur not in new_values:
            self.recipient_var.set("(broadcast)")
            self.recip_combo.current(0)

        for u in users:
            self.users_listbox.insert("end", u)

    # ── Callbacks ─────────────────────────────────────────────────────────
    def on_connect_click(self) -> None:
        username = self.user_var.get().strip()
        if not username:
            messagebox.showwarning("Thiếu thông tin",
                                   "Vui lòng nhập username.")
            return
        try:
            host = self.host_var.get().strip() or "127.0.0.1"
            tcp = int(self.tcp_var.get())
            udp = int(self.udp_var.get())
        except (ValueError, tk.TclError):
            messagebox.showerror("Port không hợp lệ",
                                "TCP/UDP port phải là số nguyên.")
            return

        self.host = host
        self.tcp_port = tcp
        self.udp_port = udp
        self._set_status("authenticating")
        self.connect_btn.config(state="disabled")
        self._append_chat(
            f"→ Đang kết nối {host}:{tcp} (UDP {udp})…\n",
            tag="system")

        # Tạo client mới (mỗi phiên đăng nhập dùng 1 instance mới)
        self.client = GUIClient(
            self.event_queue,
            server_host=host, tcp_port=tcp, udp_port=udp,
            download_dir=self.download_dir,
        )

        def worker():
            try:
                ok = self.client.login(username)
                if ok:
                    self.event_queue.put({
                        "type": "login_ok",
                        "session_id": self.client.state.session_id,
                    })
                else:
                    self.event_queue.put({
                        "type": "login_fail",
                        "reason": "server từ chối AUTH",
                    })
            except Exception as exc:  # noqa: BLE001
                self.event_queue.put({
                    "type": "login_fail",
                    "reason": str(exc),
                })

        self._login_thread = threading.Thread(
            target=worker, daemon=True, name="login")
        self._login_thread.start()

    def on_logout_click(self) -> None:
        if self.client:
            try:
                self.client.logout()
            except Exception:  # noqa: BLE001
                pass
        self._set_status("disconnected")
        self.connect_btn.config(state="normal")
        self.logout_btn.config(state="disabled")
        self.send_file_btn.config(state="disabled")
        self._append_chat("→ Đã đăng xuất.\n", tag="system")

    def on_send_click(self) -> None:
        if not self.client or not self.client.state.tcp_sock:
            messagebox.showinfo("Chưa kết nối",
                                "Hãy Connect trước khi gửi tin nhắn.")
            return
        text = self.msg_var.get().strip()
        if not text:
            return
        recip = self.recipient_var.get()
        try:
            if recip == "(broadcast)":
                self.client.send_broadcast(text)
                self._append_chat(f"[me → BC] {text}\n", tag="self")
            else:
                self.client.send_unicast(recip, text)
                self._append_chat(f"[me → {recip}] {text}\n", tag="self")
        except Exception as exc:  # noqa: BLE001
            self._append_chat(f"[ERR] gửi tin: {exc}\n", tag="error")
        self.msg_var.set("")

    def on_browse_file(self) -> None:
        path = filedialog.askopenfilename(
            title="Chọn file cần gửi",
            initialdir=os.getcwd(),
        )
        if path:
            self.file_path_var.set(path)

    def on_send_file_click(self) -> None:
        if not self.client or not self.client.state.tcp_sock:
            messagebox.showinfo("Chưa kết nối",
                                "Hãy Connect trước khi gửi file.")
            return
        path = self.file_path_var.get().strip()
        if not path or not os.path.isfile(path):
            messagebox.showwarning("File không hợp lệ",
                                   "Chọn file hợp lệ trước khi gửi.")
            return
        recip = self.recipient_var.get()
        if recip == "(broadcast)":
            messagebox.showwarning("Không hỗ trợ",
                                   "Gửi file chỉ hỗ trợ unicast — chọn 1 user.")
            return

        self.send_file_btn.config(state="disabled")

        def progress_cb(done, total):
            self.event_queue.put({
                "type": "file_progress",
                "received": done,
                "total": total,
                "filename": os.path.basename(path),
            })

        def worker():
            try:
                self.client.send_file_to(recip, path,
                                          on_progress=progress_cb)
                self.event_queue.put({
                    "type": "file_sent",
                    "path": path,
                    "chunks": max(1, os.path.getsize(path) // (8 * 1024)),
                })
            except Exception as exc:  # noqa: BLE001
                self.event_queue.put({
                    "type": "file_error",
                    "reason": str(exc),
                })

        self._file_thread = threading.Thread(
            target=worker, daemon=True, name="file_sender")
        self._file_thread.start()
        self._append_chat(
            f"→ Đang gửi {os.path.basename(path)} cho {recip}…\n",
            tag="file")

    def on_user_select(self, _event) -> None:
        sel = self.users_listbox.curselection()
        if not sel:
            return
        username = self.users_listbox.get(sel[0])
        self.recipient_var.set(username)
        # Cập nhật combobox display
        idx = self.recip_combo.cget("values").index(username) \
            if username in self.recip_combo.cget("values") else 0
        self.recip_combo.current(idx)

    def on_close(self) -> None:
        if self.client and self.client.state.tcp_sock:
            try:
                self.client.logout()
            except Exception:  # noqa: BLE001
                pass
        self.root.destroy()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Distributed Collaboration — Tkinter GUI client")
    parser.add_argument("--host", default="127.0.0.1",
                        help="server host (default: 127.0.0.1)")
    parser.add_argument("--tcp-port", type=int, default=DEFAULT_TCP_PORT)
    parser.add_argument("--udp-port", type=int, default=DEFAULT_UDP_PORT)
    parser.add_argument("--download-dir", default="./downloads",
                        help="thư mục lưu file nhận (default: ./downloads)")
    args = parser.parse_args()

    root = tk.Tk()
    ChatGUI(root, host=args.host, tcp_port=args.tcp_port,
            udp_port=args.udp_port, download_dir=args.download_dir)
    root.mainloop()


if __name__ == "__main__":
    main()
