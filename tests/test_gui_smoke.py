

import os
import sys
import unittest

# Thêm thư mục gốc vào sys.path để import được package `client`, `common`
_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

import tkinter as tk  # noqa: E402

from client.gui import ChatGUI  # noqa: E402


class TestGUISmoke(unittest.TestCase):
    """Khởi tạo ChatGUI, đẩy vài event giả lập, kiểm tra widget phản hồi."""

    @classmethod
    def setUpClass(cls):
        """Tạo root window ẩn (tránh nhảy cửa sổ khi chạy test)."""
        cls.root = tk.Tk()
        cls.root.withdraw()

    @classmethod
    def tearDownClass(cls):
        cls.root.destroy()

    def setUp(self):
        self.gui = ChatGUI(
            self.root,
            host="127.0.0.1", tcp_port=5556, udp_port=5555,
            download_dir="/tmp/test_downloads_gui",
        )

    def tearDown(self):
        # Không gọi gui.on_close() ở đây vì nó destroy root — sẽ làm hỏng
        # test kế tiếp. Chỉ đóng client socket nếu có (để tránh leak thread).
        if self.gui.client is not None:
            try:
                self.gui.client.logout()
            except Exception:
                pass
            self.gui.client = None

    # ── Các test case ─────────────────────────────────────────────────────

    def test_initial_state_disconnected(self):
        """Lúc khởi tạo, status phải là DISCONNECTED và client None."""
        self.assertIn("DISCONNECTED", self.gui.status_var.get())
        self.assertIsNone(self.gui.client)

    def test_widgets_created(self):
        """Các widget chính phải tồn tại."""
        for attr in ("chat", "users_listbox", "recip_combo", "msg_entry",
                     "progress", "connect_btn", "logout_btn",
                     "send_file_btn"):
            self.assertTrue(getattr(self.gui, attr), f"thiếu widget {attr}")

    def test_tags_registered(self):
        """Tất cả TAGS phải được đăng ký trên Text widget."""
        widget_tags = self.gui.chat.tag_names()
        for tag in ("broadcast", "private", "presence", "system",
                    "error", "file", "self"):
            self.assertIn(tag, widget_tags, f"thiếu tag {tag}")

    def test_presence_event_updates_users_list(self):
        """PRESENCE event phải cập nhật Listbox users + combobox recipient."""
        self.gui._handle_event({"type": "presence",
                                "users": ["alice", "bob"]})
        self.assertEqual(self.gui.users_listbox.size(), 2)
        combo_values = list(self.gui.recip_combo.cget("values"))
        self.assertIn("(broadcast)", combo_values)
        self.assertIn("alice", combo_values)
        self.assertIn("bob", combo_values)

    def test_broadcast_event_appends_chat(self):
        """Broadcast event phải thêm dòng chat với tag phù hợp."""
        self.gui._handle_event({
            "type": "broadcast",
            "sender": "alice",
            "text": "hello everyone",
        })
        content = self.gui.chat.get("1.0", "end")
        self.assertIn("hello everyone", content)
        self.assertIn("alice", content)

    def test_private_event_appends_chat(self):
        """Private message event phải thêm dòng chat."""
        self.gui._handle_event({
            "type": "private",
            "sender": "bob",
            "text": "hi alice",
        })
        content = self.gui.chat.get("1.0", "end")
        self.assertIn("hi alice", content)

    def test_status_online(self):
        """_set_status('online') phải đặt badge xanh + chữ ONLINE."""
        self.gui._set_status("online")
        self.assertIn("ONLINE", self.gui.status_var.get())

    def test_status_authenticating(self):
        """_set_status('authenticating') phải đặt chữ AUTHENTICATING."""
        self.gui._set_status("authenticating")
        self.assertIn("AUTHENTICATING", self.gui.status_var.get())

    def test_login_ok_event_enables_logout_and_file(self):
        """login_ok event phải enable Logout + Send File, disable Connect."""
        self.gui._handle_event({
            "type": "login_ok",
            "session_id": 1234,
        })
        self.assertIn("ONLINE", self.gui.status_var.get())
        self.assertEqual(str(self.gui.logout_btn.cget("state")), "normal")
        self.assertEqual(str(self.gui.send_file_btn.cget("state")), "normal")
        self.assertEqual(str(self.gui.connect_btn.cget("state")), "disabled")

    def test_disconnected_event_resets_buttons(self):
        """disconnected event phải reset về trạng thái chưa kết nối."""
        self.gui._handle_event({"type": "login_ok", "session_id": 1})
        self.gui._handle_event({"type": "disconnected"})
        self.assertEqual(str(self.gui.connect_btn.cget("state")), "normal")
        self.assertEqual(str(self.gui.logout_btn.cget("state")), "disabled")
        self.assertIn("DISCONNECTED", self.gui.status_var.get())

    def test_recipient_reset_when_user_offline(self):
        """Khi user được chọn bị offline, combobox phải reset về broadcast."""
        self.gui._handle_event({"type": "presence",
                                "users": ["alice", "bob"]})
        self.gui.recipient_var.set("bob")
        # Bob rời đi
        self.gui._handle_event({"type": "presence", "users": ["alice"]})
        self.assertEqual(self.gui.recipient_var.get(), "(broadcast)")


if __name__ == "__main__":
    unittest.main()
