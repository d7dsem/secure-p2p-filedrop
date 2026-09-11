#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Тести логіки стану SecureFileClientApp (не кліків/пікселів — це Рівень 2 з docs/testing.md).
Докладніше: docs/dev-notes.md → "tests/test_appearance.py".
"""

import os
import shutil
import tempfile
import unittest
import zipfile
from unittest import mock

import _pathfix  # noqa: F401  (додає src/ у sys.path перед наступними імпортами)


class AppearanceTestCase(unittest.TestCase):
    """Базовий клас: ізолює HOME/USERPROFILE і піднімає headless
    SecureFileClientApp перед кожним тестом."""

    def setUp(self):
        try:
            import tkinter as tk
        except ImportError as e:
            self.skipTest(f"tkinter недоступний у цьому середовищі: {e}")
            return

        home_dir = tempfile.mkdtemp(prefix="test_appearance_home_")
        self.addCleanup(shutil.rmtree, home_dir, ignore_errors=True)
        self._patch_env("HOME", home_dir)
        self._patch_env("USERPROFILE", home_dir)

        try:
            self.root = tk.Tk()
        except tk.TclError as e:
            self.skipTest(f"Немає доступного дисплея для tkinter: {e}")
            return
        self.root.withdraw()
        self.addCleanup(self.root.destroy)

        self.app = self._create_app()

    def _create_app(self):
        """Гачок для підкласів, яким потрібні інші аргументи конструктора
        (напр. initial_send_dir)."""
        from appearance import SecureFileClientApp
        return SecureFileClientApp(self.root)

    def _patch_env(self, name: str, value: str):
        old = os.environ.get(name)
        os.environ[name] = value
        self.addCleanup(lambda: self._restore_env(name, old))

    @staticmethod
    def _restore_env(name: str, old: str | None):
        if old is None:
            os.environ.pop(name, None)
        else:
            os.environ[name] = old


class RepackAfterCheckboxChangeTests(AppearanceTestCase):
    """Регресія виправленого багу з перезаписом selected_path архівом.
    Докладніше: docs/dev-notes.md → "appearance.py: on_initiate_transfer"."""

    def setUp(self):
        super().setUp()
        self.send_dir = tempfile.mkdtemp(prefix="test_appearance_send_")
        self.addCleanup(shutil.rmtree, self.send_dir, ignore_errors=True)
        with open(os.path.join(self.send_dir, "a.txt"), "w", encoding="utf-8") as f:
            f.write("a")
        with open(os.path.join(self.send_dir, "b.txt"), "w", encoding="utf-8") as f:
            f.write("b")

        self.app.selected_path = self.send_dir
        self.app.selected_is_dir = True
        self.app._file_tree_checked = {}
        self.app._file_tree_meta = {}
        self.app.tree_files.delete(*self.app.tree_files.get_children(""))
        self.app._insert_tree_children("", self.send_dir, "")
        self.app.frame_tree.pack(fill="both", expand=True, before=self.app._transfer_row)
        self.app.btn_transfer.configure(state="normal")
        self.app.var_archive_before_send.set(True)

    def test_selection_survives_first_transfer_init(self):
        self.app.on_initiate_transfer()
        self.assertEqual(self.app.selected_path, self.send_dir)
        self.assertTrue(self.app.selected_is_dir)
        self.assertIsNotNone(self.app.packed_archive_path)
        self.assertEqual(self.app.transfer_payload, [self.app.packed_archive_path])

    def test_second_transfer_init_after_unchecking_a_file_succeeds_and_excludes_it(self):
        self.app.on_initiate_transfer()
        first_archive = self.app.packed_archive_path

        rel_path, abs_path, is_dir = self.app._file_tree_meta["b.txt"]
        self.app._set_checked_recursive(rel_path, abs_path, is_dir, False)

        self.app.on_initiate_transfer()  # раніше падало на "Спочатку оберіть каталог"
        second_archive = self.app.packed_archive_path

        self.assertEqual(first_archive, second_archive)  # той самий шлях, перезаписаний
        with zipfile.ZipFile(second_archive) as zf:
            names = set(zf.namelist())
        self.assertEqual(names, {"a.txt"})


class ArchiveVsAsIsChoiceTests(AppearanceTestCase):
    """Чекбокс "Запакувати в один архів (інакше — передати файли як є)":
    перевіряє обидва режими на тому самому каталозі."""

    def setUp(self):
        super().setUp()
        self.send_dir = tempfile.mkdtemp(prefix="test_appearance_send_")
        self.addCleanup(shutil.rmtree, self.send_dir, ignore_errors=True)
        with open(os.path.join(self.send_dir, "a.txt"), "w", encoding="utf-8") as f:
            f.write("a")
        with open(os.path.join(self.send_dir, "b.txt"), "w", encoding="utf-8") as f:
            f.write("b")

        self.app.selected_path = self.send_dir
        self.app.selected_is_dir = True
        self.app._file_tree_checked = {}
        self.app._file_tree_meta = {}
        self.app.tree_files.delete(*self.app.tree_files.get_children(""))
        self.app._insert_tree_children("", self.send_dir, "")
        self.app.frame_tree.pack(fill="both", expand=True, before=self.app._transfer_row)
        self.app.btn_transfer.configure(state="normal")

    def test_archive_checked_produces_single_zip_payload(self):
        self.app.var_archive_before_send.set(True)
        self.app.on_initiate_transfer()

        self.assertIsNotNone(self.app.packed_archive_path)
        self.assertEqual(self.app.transfer_payload, [self.app.packed_archive_path])
        with zipfile.ZipFile(self.app.packed_archive_path) as zf:
            self.assertEqual(set(zf.namelist()), {"a.txt", "b.txt"})

    def test_archive_unchecked_produces_raw_file_list_payload(self):
        self.app.var_archive_before_send.set(False)
        self.app.on_initiate_transfer()

        self.assertIsNone(self.app.packed_archive_path)  # нічого не заархівовано
        self.assertEqual(
            sorted(os.path.basename(p) for p in self.app.transfer_payload),
            ["a.txt", "b.txt"],
        )

    def test_single_file_selection_needs_no_archive_choice(self):
        file_path = os.path.join(self.send_dir, "a.txt")
        self.app.selected_path = file_path
        self.app.selected_is_dir = False

        self.app.on_initiate_transfer()

        self.assertEqual(self.app.transfer_payload, [file_path])
        self.assertIsNone(self.app.packed_archive_path)


class InitialSendDirTests(AppearanceTestCase):
    """initial_send_dir (--snd-dir у CLI) — одразу обирає каталог, як після
    "Обрати каталог...", без діалогового вікна."""

    def setUp(self):
        self.send_dir = tempfile.mkdtemp(prefix="test_appearance_snd_dir_")
        self.addCleanup(shutil.rmtree, self.send_dir, ignore_errors=True)
        with open(os.path.join(self.send_dir, "a.txt"), "w", encoding="utf-8") as f:
            f.write("a")
        super().setUp()

    def _create_app(self):
        from appearance import SecureFileClientApp
        return SecureFileClientApp(self.root, initial_send_dir=self.send_dir)

    def test_directory_preselected(self):
        self.assertEqual(self.app.selected_path, self.send_dir)
        self.assertTrue(self.app.selected_is_dir)

    def test_tree_populated_with_directory_contents(self):
        self.assertIn("a.txt", self.app.tree_files.get_children(""))

    def test_transfer_button_enabled(self):
        self.assertEqual(str(self.app.btn_transfer["state"]), "normal")


class InvalidSendDirTests(AppearanceTestCase):
    """Неіснуючий шлях у initial_send_dir не має падати — лише запис у лог."""

    def _create_app(self):
        from appearance import SecureFileClientApp
        return SecureFileClientApp(
            self.root, initial_send_dir=os.path.join(tempfile.gettempdir(), "does-not-exist-xyz")
        )

    def test_no_selection_made(self):
        self.assertIsNone(self.app.selected_path)


class GeneratePassphraseTests(AppearanceTestCase):
    """Кнопка "Згенерувати" (парольна фраза) — dev-notes.md → "on_generate_passphrase"."""

    def test_fills_non_empty_passphrase(self):
        self.app.on_generate_passphrase()
        self.assertTrue(self.app.var_passphrase.get())

    def test_two_generations_differ(self):
        self.app.on_generate_passphrase()
        first = self.app.var_passphrase.get()
        self.app.on_generate_passphrase()
        second = self.app.var_passphrase.get()
        self.assertNotEqual(first, second)

    def test_reveals_passphrase_after_generating(self):
        self.app.var_show_pass.set(False)
        self.app._toggle_pass_visibility()
        self.app.on_generate_passphrase()
        self.assertTrue(self.app.var_show_pass.get())
        self.assertEqual(str(self.app.entry_passphrase["show"]), "")


class HandshakeTextCopyableTests(AppearanceTestCase):
    """Регресія реального бага: text_out із state="disabled" блокував і виділення
    мишею, тому ручне копіювання хендшейку мовчки нічого не копіювало.
    Докладніше: docs/dev-notes.md → "appearance.py: text_out"."""

    def test_generated_handshake_is_selectable_via_sel_tag(self):
        self.app.var_passphrase.set("test-pass")
        self.app.on_generate_handshake()
        content = self.app.text_out.get("1.0", "end").strip()
        self.assertTrue(content)

        self.app.text_out.tag_add("sel", "1.0", "end")
        selected = self.app.text_out.get("sel.first", "sel.last").strip()
        self.assertEqual(selected, content)

    def test_typing_into_generated_handshake_is_blocked(self):
        self.app.var_passphrase.set("test-pass")
        self.app.on_generate_handshake()
        before = self.app.text_out.get("1.0", "end")

        self.app.text_out.event_generate("<KeyPress-x>")

        after = self.app.text_out.get("1.0", "end")
        self.assertEqual(before, after)

    def test_copy_works_via_keycode_even_with_foreign_keysym(self):
        """Регресія: Ctrl+C/A прив'язані до keysym у стандартних Tk-біндингах —
        під нелатинською розкладкою клавіатури keysym для фізичної клавіші "C"/"A"
        інший, і копіювання мовчки не спрацьовувало б. keycode=67/65 — фізична
        клавіша, від розкладки не залежить; тут симулюємо саме таку ситуацію
        (Control-Key з правильним keycode, без "рідного" keysym).
        deiconify() — синтетичні keyboard-події потребують реального фокуса
        вікна, withdraw()-вікно (звичайний headless режим тестів) його не дає."""
        self.app.root.deiconify()
        self.app.root.update()
        self.app.var_passphrase.set("test-pass")
        self.app.on_generate_handshake()
        content = self.app.text_out.get("1.0", "end").strip()
        self.app.root.clipboard_clear()

        self.app.text_out.focus_force()
        self.app.root.update()
        self.app.text_out.event_generate("<Control-Key>", keycode=65, state=0x4)  # Ctrl+A
        self.assertTrue(self.app.text_out.tag_ranges("sel"))

        self.app.text_out.event_generate("<Control-Key>", keycode=67, state=0x4)  # Ctrl+C
        self.assertEqual(self.app.root.clipboard_get().strip(), content)


class PasteWorksViaKeycodeTests(AppearanceTestCase):
    """Регресія того самого бага (розкладка клавіатури) для Ctrl+V у text_in.
    Докладніше: docs/dev-notes.md → "_bind_layout_independent_paste"."""

    def test_paste_works_via_keycode_even_with_foreign_keysym(self):
        self.app.root.deiconify()  # синтетичні keyboard-події потребують реального фокуса
        self.app.root.update()
        self.app.root.clipboard_clear()
        self.app.root.clipboard_append("layout-independent-paste-test")
        self.app.text_in.focus_force()
        self.app.root.update()

        self.app.text_in.event_generate("<Control-Key>", keycode=86, state=0x4)  # Ctrl+V

        self.assertEqual(self.app.text_in.get("1.0", "end").strip(), "layout-independent-paste-test")


class InitialPortTests(AppearanceTestCase):
    """--port CLI-параметр — dev-notes.md."""

    def _create_app(self):
        from appearance import SecureFileClientApp
        return SecureFileClientApp(self.root, initial_port=52074)

    def test_port_field_prefilled(self):
        self.assertEqual(self.app.var_port.get(), "52074")

    def test_prefilling_port_does_not_invalidate_anything(self):
        # Виставляється до будь-якого хендшейку — нема чого інвалідовувати.
        self.assertIsNone(self.app.local_key)
        self.assertEqual(self.app._session_epoch, 0)


class PasteHandshakeTests(AppearanceTestCase):
    """on_paste_handshake — обхід Ctrl+V/контекстного меню, симетрично до
    "Скопіювати в буфер". Докладніше: dev-notes.md."""

    def test_pastes_clipboard_content_into_text_in(self):
        self.app.root.clipboard_clear()
        self.app.root.clipboard_append("-----HANDSHAKE-----\nabc\n-----END-----")
        self.app.on_paste_handshake()
        self.assertEqual(
            self.app.text_in.get("1.0", "end").strip(), "-----HANDSHAKE-----\nabc\n-----END-----"
        )

    def test_replaces_existing_text_in_content(self):
        self.app.text_in.insert("1.0", "old stale content")
        self.app.root.clipboard_clear()
        self.app.root.clipboard_append("fresh content")
        self.app.on_paste_handshake()
        self.assertEqual(self.app.text_in.get("1.0", "end").strip(), "fresh content")

    def test_empty_clipboard_warns_without_crashing(self):
        self.app.root.clipboard_clear()
        with mock.patch("appearance.messagebox.showwarning") as mock_warn:
            self.app.on_paste_handshake()
        mock_warn.assert_called_once()


class IsPrivateHostTests(unittest.TestCase):
    """_is_private_host — dev-notes.md → "hairpin NAT попередження"."""

    def test_lan_ranges_are_private(self):
        from appearance import _is_private_host
        for host in ("192.168.1.50", "10.0.0.5", "172.16.5.5", "127.0.0.1"):
            self.assertTrue(_is_private_host(host), host)

    def test_public_ip_is_not_private(self):
        from appearance import _is_private_host
        self.assertFalse(_is_private_host("85.114.203.21"))

    def test_hostname_is_not_private(self):
        """Не голий IP — не спекулюємо, вважаємо непрозорим (не приватним)."""
        from appearance import _is_private_host
        self.assertFalse(_is_private_host("example.com"))


class ChannelWaitDiagnosticsTests(AppearanceTestCase):
    """Hairpin-попередження + тікер очікування — знайдено через скріншот
    користувача (два інстанси на одному ПК, однакова публічна STUN-адреса,
    канал висів без пояснення). Докладніше: docs/dev-notes.md →
    "_maybe_start_channel_establishment — hairpin NAT попередження".

    _maybe_start_channel_establishment одразу стартує фоновий потік із реальним
    establish_connection — мокаємо його, щоб тест не намагався реально
    підключатись по мережі до (фейкових) адрес, які тут використовуються."""

    def setUp(self):
        super().setUp()
        import appearance as appearance_module
        from transport import ConnectionFailed
        patcher = mock.patch.object(
            appearance_module, "establish_connection",
            side_effect=ConnectionFailed("mocked — жодного реального мережевого виклику в тесті"),
        )
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_public_peer_host_logs_hairpin_warning(self):
        self.app.peer_key = b"k" * 32
        self.app.peer_host = "85.114.203.21"
        self.app.peer_port = 33579

        self.app._maybe_start_channel_establishment()

        self.assertIn("85.114.203.21:33579", self.app.var_channel_status.get())
        self.assertIn("hairpin", self.app.text_log.get("1.0", "end"))

    def test_private_peer_host_does_not_log_hairpin_warning(self):
        self.app.peer_key = b"k" * 32
        self.app.peer_host = "192.168.1.50"
        self.app.peer_port = 52075

        self.app._maybe_start_channel_establishment()

        self.assertNotIn("hairpin", self.app.text_log.get("1.0", "end"))

    def test_tick_channel_wait_appends_elapsed_seconds(self):
        self.app.peer_key = b"k" * 32
        self.app.peer_host = "192.168.1.50"
        self.app.peer_port = 52075
        self.app._maybe_start_channel_establishment()
        base_status = self.app.var_channel_status.get()

        self.app._channel_wait_started_at -= 5  # імітуємо 5с очікування без реального sleep
        self.app._tick_channel_wait(self.app._session_epoch)

        self.assertEqual(self.app.var_channel_status.get(), f"{base_status} (5с)")

    def test_tick_stops_after_connection_failed(self):
        self.app.peer_key = b"k" * 32
        self.app.peer_host = "192.168.1.50"
        self.app.peer_port = 52075
        self.app._maybe_start_channel_establishment()
        epoch = self.app._session_epoch

        self.app._handle_channel_event({"epoch": epoch, "kind": "connection_failed", "error": "boom"})
        status_after_failure = self.app.var_channel_status.get()

        self.app._tick_channel_wait(epoch)  # не має нічого дописати -- _channel_pending вже False

        self.assertEqual(self.app.var_channel_status.get(), status_after_failure)

    def test_connection_failed_mentions_hairpin_for_public_peer(self):
        self.app.peer_host = "85.114.203.21"
        self.app._handle_channel_event(
            {"epoch": self.app._session_epoch, "kind": "connection_failed", "error": "timeout"}
        )
        self.assertIn("hairpin", self.app.var_channel_status.get())


class ChannelEventHandlingTests(AppearanceTestCase):
    """_handle_channel_event — регресія знайдених security/code-ревʼю багів:
    канал має явно позначатись розірваним при помилці прийому/закритті, не
    лишатись "Підтверджено" мовчки. Докладніше: docs/dev-notes.md →
    "appearance.py: receive_error / receive_closed"."""

    def _event(self, **fields):
        """Події від фонових потоків несуть epoch (dev-notes.md → "_session_epoch") —
        тут використовуємо поточний, щоб _handle_channel_event їх не ігнорував як застарілі."""
        return {"epoch": self.app._session_epoch, **fields}

    def _mark_connected(self):
        self.app._handle_channel_event(self._event(kind="connected", socket=object(), key=b"k" * 32))

    def test_connected_marks_channel_verified(self):
        self._mark_connected()
        self.assertTrue(self.app.channel_verified)

    def test_receive_error_marks_channel_unverified_and_updates_status(self):
        self._mark_connected()
        self.app._handle_channel_event(self._event(kind="receive_error", error="boom"))
        self.assertFalse(self.app.channel_verified)
        self.assertIn("розірвано", self.app.var_channel_status.get())

    def test_receive_closed_marks_channel_unverified_and_updates_status(self):
        self._mark_connected()
        self.app._handle_channel_event(self._event(kind="receive_closed"))
        self.assertFalse(self.app.channel_verified)
        self.assertIn("закрила з'єднання", self.app.var_channel_status.get())

    def test_receive_error_disables_send_button(self):
        self._mark_connected()
        self.app.transfer_payload = ["dummy.txt"]
        self.app._update_send_button_state()
        self.assertEqual(str(self.app.btn_send["state"]), "normal")

        self.app._handle_channel_event(self._event(kind="receive_error", error="boom"))
        self.assertEqual(str(self.app.btn_send["state"]), "disabled")

    def test_send_error_reenables_send_button(self):
        self.app.btn_send.configure(state="disabled")
        self.app._handle_channel_event(self._event(kind="send_error", error="boom"))
        self.assertEqual(str(self.app.btn_send["state"]), "normal")

    def test_send_done_reenables_send_button(self):
        self.app.btn_send.configure(state="disabled")
        self.app._handle_channel_event(self._event(kind="send_done", count=1))
        self.assertEqual(str(self.app.btn_send["state"]), "normal")

    def test_channel_test_ok_updates_status(self):
        self.app._handle_channel_event(self._event(kind="channel_test_ok"))
        self.assertIn("канал працює", self.app.var_status.get())

    def test_channel_test_failed_updates_status(self):
        self.app._handle_channel_event(self._event(kind="channel_test_failed", error="boom"))
        self.assertIn("boom", self.app.var_status.get())


class TestChannelButtonTests(AppearanceTestCase):
    """on_test_channel — перевірка каналу (ping/pong) без вибору/пакування файлів.
    Докладніше: docs/dev-notes.md → "transport.py: send_ping/receive_files"."""

    def test_warns_if_channel_not_verified(self):
        with mock.patch("appearance.messagebox.showwarning") as mock_warn:
            self.app.on_test_channel()
        mock_warn.assert_called_once()

    def test_sends_ping_when_channel_verified(self):
        import appearance as appearance_module

        self.app.channel_verified = True
        self.app.channel_socket = mock.MagicMock()
        with mock.patch.object(appearance_module, "send_ping") as mock_ping:
            self.app.on_test_channel()
            # _test_channel_worker виконується у фоновому потоці — дочекатись.
            import time
            for _ in range(50):
                if mock_ping.called:
                    break
                time.sleep(0.02)
        mock_ping.assert_called_once_with(self.app.channel_socket)

    def test_send_ping_failure_reports_channel_test_failed(self):
        import appearance as appearance_module

        self.app.channel_verified = True
        self.app.channel_socket = mock.MagicMock()

        with mock.patch.object(appearance_module, "send_ping", side_effect=OSError("broken pipe")):
            self.app._test_channel_worker(self.app._session_epoch)  # напряму, без потоку

        event = self.app._channel_queue.get_nowait()
        self.assertEqual(event["kind"], "channel_test_failed")
        self.assertIn("broken pipe", event["error"])


class WorkerBroadExceptionTests(AppearanceTestCase):
    """Фонові воркери мають репортувати ЛЮБУ помилку в чергу, не лише очікувані
    типи (KeyError/FileNotFoundError/ET.ParseError тощо тихо вбивали потік —
    знайдено code-ревʼю). Докладніше: docs/dev-notes.md → "appearance.py:
    _receive_worker / _send_worker / _channel_establish_worker /
    _connection_setup_worker — широкий except Exception"."""

    def setUp(self):
        super().setUp()
        self.app.channel_socket = object()
        self.app.channel_key = b"k" * 32

    def test_receive_worker_reports_unexpected_exception(self):
        import appearance as appearance_module

        with mock.patch.object(
            appearance_module, "receive_files", side_effect=KeyError("name")
        ):
            self.app._receive_worker(self.app._session_epoch)

        event = self.app._channel_queue.get_nowait()
        self.assertEqual(event["kind"], "receive_error")
        self.assertIn("KeyError", event["error"])
        self.assertEqual(event["epoch"], self.app._session_epoch)

    def test_send_worker_reports_unexpected_exception(self):
        import appearance as appearance_module

        with mock.patch.object(
            appearance_module, "send_files", side_effect=FileNotFoundError("gone.txt")
        ):
            self.app._send_worker("/tmp", ["gone.txt"], self.app._session_epoch)

        event = self.app._channel_queue.get_nowait()
        self.assertEqual(event["kind"], "send_error")
        self.assertIn("FileNotFoundError", event["error"])

    def test_channel_establish_worker_reports_unexpected_connect_exception(self):
        import appearance as appearance_module

        with mock.patch.object(
            appearance_module, "establish_connection", side_effect=RuntimeError("weird")
        ):
            self.app._channel_establish_worker(b"k" * 32, self.app._session_epoch)

        event = self.app._channel_queue.get_nowait()
        self.assertEqual(event["kind"], "connection_failed")
        self.assertIn("RuntimeError", event["error"])

    def test_channel_establish_worker_reports_unexpected_verify_exception(self):
        import appearance as appearance_module

        dummy_socket = mock.MagicMock()
        with mock.patch.object(
            appearance_module, "establish_connection", return_value=dummy_socket
        ), mock.patch.object(
            appearance_module, "verify_channel", side_effect=RuntimeError("weird")
        ):
            self.app._channel_establish_worker(b"k" * 32, self.app._session_epoch)

        event = self.app._channel_queue.get_nowait()
        self.assertEqual(event["kind"], "verification_failed")
        self.assertIn("RuntimeError", event["error"])
        dummy_socket.close.assert_called_once()

    def test_connection_setup_worker_falls_back_on_unexpected_exception(self):
        """Побита XML-відповідь роутера (ET.ParseError) чи будь-яка інша
        неочікувана помилка не має лишити чергу порожньою назавжди."""
        import appearance as appearance_module

        with mock.patch.object(
            appearance_module, "detect_local_address", side_effect=RuntimeError("weird")
        ):
            self.app._connection_setup_worker(52075)

        result = self.app._conn_setup_queue.get_nowait()
        self.assertIsNone(result.get("source"))


class InvalidateSessionOnParamChangeTests(AppearanceTestCase):
    """Регресія реального бага (знайдено користувачем на скріншоті): зміна порту
    ПІСЛЯ генерації хендшейку не впливала на вже запущений канал, лишаючи поле
    вводу й реальний стан застосунку розсинхронізованими. Докладніше:
    docs/dev-notes.md → "_invalidate_session_if_active"."""

    def test_typing_passphrase_before_any_handshake_does_not_invalidate(self):
        self.app.var_passphrase.set("first-try")
        self.assertIsNone(self.app.local_key)
        self.assertEqual(self.app._session_epoch, 0)

    def test_changing_port_after_generate_invalidates_local_key_and_bumps_epoch(self):
        self.app.var_passphrase.set("shared-pass")
        self.app.on_generate_handshake()
        self.assertIsNotNone(self.app.local_key)
        epoch_before = self.app._session_epoch

        self.app.var_port.set("52099")

        self.assertIsNone(self.app.local_key)
        self.assertGreater(self.app._session_epoch, epoch_before)
        self.assertEqual(self.app.text_out.get("1.0", "end").strip(), "")
        self.assertIn("змінено", self.app.var_channel_status.get())

    def test_changing_passphrase_after_generate_invalidates_session(self):
        self.app.var_passphrase.set("shared-pass")
        self.app.on_generate_handshake()

        self.app.var_passphrase.set("different-pass")

        self.assertIsNone(self.app.local_key)

    def test_changing_iterations_after_generate_invalidates_session(self):
        self.app.var_passphrase.set("shared-pass")
        self.app.on_generate_handshake()

        self.app.var_iterations.set("1000")

        self.assertIsNone(self.app.local_key)

    def test_invalidate_closes_open_channel_socket(self):
        self.app.var_passphrase.set("shared-pass")
        self.app.on_generate_handshake()
        dummy_socket = mock.MagicMock()
        self.app.channel_socket = dummy_socket
        self.app.channel_verified = True

        self.app.var_port.set("52099")

        dummy_socket.close.assert_called_once()
        self.assertIsNone(self.app.channel_socket)
        self.assertFalse(self.app.channel_verified)


class OpenIncomingDirTests(AppearanceTestCase):
    """on_open_incoming_dir — dev-notes.md → "on_open_incoming_dir"."""

    def test_nonexistent_dir_shows_info_without_crashing(self):
        self.app.profile.incoming_dir = os.path.join(tempfile.gettempdir(), "does-not-exist-xyz")
        with mock.patch("appearance.messagebox.showinfo") as mock_showinfo:
            self.app.on_open_incoming_dir()
        mock_showinfo.assert_called_once()

    def test_existing_dir_opens_via_platform_command(self):
        real_dir = tempfile.mkdtemp(prefix="test_open_incoming_")
        self.addCleanup(shutil.rmtree, real_dir, ignore_errors=True)
        self.app.profile.incoming_dir = real_dir

        with mock.patch("appearance.sys") as mock_sys, mock.patch(
            "appearance.subprocess.Popen"
        ) as mock_popen, mock.patch("appearance.os.startfile", create=True) as mock_startfile:
            mock_sys.platform = "linux"
            self.app.on_open_incoming_dir()

        mock_popen.assert_called_once_with(["xdg-open", real_dir])
        mock_startfile.assert_not_called()


if __name__ == "__main__":
    unittest.main()
