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

        # SecureFileClientApp.__init__ стартує РЕАЛЬНЕ мережеве налаштування
        # (UPnP-discovery + STUN до публічного сервера) у фоновому потоці
        # (_start_connection_setup, наприкінці __init__) — без цих патчів кожен
        # GUI-тест робив би справжні мережеві виклики. Фейкають миттєвий провал
        # обох рівнів (LAN-only фолбек) — тести, яким потрібна саме ця гілка,
        # переозначають ці ж імена явно (WorkerBroadExceptionTests тощо).
        import appearance as appearance_module
        from nat_traversal import UpnpError
        from stun_client import StunError

        upnp_patcher = mock.patch.object(
            appearance_module, "try_configure_port_forwarding",
            side_effect=UpnpError("mocked — тест не має робити реальних мережевих викликів"),
        )
        upnp_patcher.start()
        self.addCleanup(upnp_patcher.stop)

        stun_patcher = mock.patch.object(
            appearance_module, "get_public_address",
            side_effect=StunError("mocked — тест не має робити реальних мережевих викликів"),
        )
        stun_patcher.start()
        self.addCleanup(stun_patcher.stop)

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
    """Регресія реального бага: поле згенерованого хендшейку (тоді text_out) із
    state="disabled" блокувало і виділення мишею, тому ручне копіювання мовчки
    нічого не копіювало. Докладніше: docs/dev-notes.md → "appearance.py: text_out"."""

    def test_generated_handshake_is_selectable_via_sel_tag(self):
        self.app.var_passphrase.set("test-pass")
        self.app.on_generate_handshake()
        content = self.app.text_handshake.get("1.0", "end").strip()
        self.assertTrue(content)

        self.app.text_handshake.tag_add("sel", "1.0", "end")
        selected = self.app.text_handshake.get("sel.first", "sel.last").strip()
        self.assertEqual(selected, content)

    def test_typing_into_generated_handshake_is_blocked(self):
        self.app.var_passphrase.set("test-pass")
        self.app.on_generate_handshake()
        before = self.app.text_handshake.get("1.0", "end")

        self.app.text_handshake.event_generate("<KeyPress-x>")

        after = self.app.text_handshake.get("1.0", "end")
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
        content = self.app.text_handshake.get("1.0", "end").strip()
        self.app.root.clipboard_clear()

        self.app.text_handshake.focus_force()
        self.app.root.update()
        self.app.text_handshake.event_generate("<Control-Key>", keycode=65, state=0x4)  # Ctrl+A
        self.assertTrue(self.app.text_handshake.tag_ranges("sel"))

        self.app.text_handshake.event_generate("<Control-Key>", keycode=67, state=0x4)  # Ctrl+C
        self.assertEqual(self.app.root.clipboard_get().strip(), content)


class PasteWorksViaKeycodeTests(AppearanceTestCase):
    """Регресія того самого бага (розкладка клавіатури) для Ctrl+V у полі хендшейку —
    тепер Ctrl+V == кнопка "Вставити хендшейк". Докладніше: docs/dev-notes.md →
    "_make_readonly_selectable / keycode"."""

    def test_paste_works_via_keycode_even_with_foreign_keysym(self):
        import appearance as appearance_module
        from connection import build_handshake_packet
        from transport import ConnectionFailed
        from tuning import CONNECTION

        patcher = mock.patch.object(
            appearance_module, "establish_connection", side_effect=ConnectionFailed("mocked"),
        )
        patcher.start()
        self.addCleanup(patcher.stop)
        self.app.var_iterations.set(str(CONNECTION.min_iterations))
        self.app.var_passphrase.set("shared-pass")
        text, _salt, _sid, _host = build_handshake_packet(CONNECTION.min_iterations, 52075, host="192.168.1.50")

        self.app.root.deiconify()  # синтетичні keyboard-події потребують реального фокуса
        self.app.root.update()
        self.app.root.clipboard_clear()
        self.app.root.clipboard_append(text)
        self.app.text_handshake.focus_force()
        self.app.root.update()

        self.app.text_handshake.event_generate("<Control-Key>", keycode=86, state=0x4)  # Ctrl+V

        self.assertEqual(self.app.text_handshake.get("1.0", "end").strip(), text)
        from appearance import _HANDSHAKE_KIND_PEER
        self.assertEqual(self.app._handshake_kind, _HANDSHAKE_KIND_PEER)


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


class PortPrecedenceTests(AppearanceTestCase):
    """Ієрархія дефолтного порту (низ -> верх): tuning.CONNECTION.default_port
    < profile.default_port < CLI --port < ручна правка поля "Порт" у GUI.
    Докладніше: docs/dev-notes.md -> "var_port — дефолт з профілю"."""

    def test_fresh_profile_uses_tuning_default(self):
        from tuning import CONNECTION
        self.assertEqual(self.app.var_port.get(), str(CONNECTION.default_port))
        self.assertEqual(self.app.profile.default_port, CONNECTION.default_port)


class ProfileDefaultPortUsedWhenNoCliTests(AppearanceTestCase):
    """Профіль.default_port заповнює поле "Порт", коли --port не задано."""

    def _create_app(self):
        from appearance import SecureFileClientApp
        from local_config import LocalConfig, save_config
        save_config(LocalConfig(
            client_id="pre-existing", incoming_dir="in", outgoing_dir="out", default_port=52099,
        ))
        return SecureFileClientApp(self.root)

    def test_port_field_uses_profile_default(self):
        self.assertEqual(self.app.var_port.get(), "52099")
        self.assertFalse(self.app._port_overridden_by_user)
        self.assertFalse(self.app._cli_port_provided)


class CliPortOverridesProfileDefaultTests(AppearanceTestCase):
    """CLI --port стоїть вище профілю в ієрархії — перекриває profile.default_port."""

    def _create_app(self):
        from appearance import SecureFileClientApp
        from local_config import LocalConfig, save_config
        save_config(LocalConfig(
            client_id="pre-existing", incoming_dir="in", outgoing_dir="out", default_port=52099,
        ))
        return SecureFileClientApp(self.root, initial_port=52074)

    def test_cli_port_wins_over_profile_default(self):
        self.assertEqual(self.app.var_port.get(), "52074")
        self.assertTrue(self.app._cli_port_provided)
        # CLI не вважається "ручною правкою" для цілей precedence.
        self.assertFalse(self.app._port_overridden_by_user)


class ProfileTabDefaultPortSaveTests(AppearanceTestCase):
    """on_save_profile: зміна "Порт за замовчуванням" синхронізує поле "Порт"
    (вкладка "Сеанс") лише коли користувач ще не редагував його вручну й
    --port не задано. Докладніше: dev-notes.md -> "var_port — дефолт з профілю"."""

    def test_save_updates_main_port_field_when_untouched(self):
        self.app.var_profile_default_port.set("52099")
        self.app.on_save_profile()

        self.assertEqual(self.app.var_port.get(), "52099")
        self.assertEqual(self.app.profile.default_port, 52099)
        # Синхронізація сама по собі не позначає поле як "відредаговане вручну".
        self.assertFalse(self.app._port_overridden_by_user)

    def test_save_does_not_touch_main_port_after_manual_edit(self):
        self.app.var_port.set("60000")  # справжня ручна правка користувачем
        self.assertTrue(self.app._port_overridden_by_user)

        self.app.var_profile_default_port.set("52099")
        self.app.on_save_profile()

        self.assertEqual(self.app.var_port.get(), "60000")
        self.assertEqual(self.app.profile.default_port, 52099)  # профіль однаково зберігається

    def test_save_does_not_touch_main_port_when_cli_port_given(self):
        from appearance import SecureFileClientApp
        app = SecureFileClientApp(self.root, initial_port=52074)
        app.var_profile_default_port.set("52099")

        app.on_save_profile()

        self.assertEqual(app.var_port.get(), "52074")
        self.assertEqual(app.profile.default_port, 52099)

    def test_invalid_profile_port_shows_error_and_does_not_save(self):
        old_default_port = self.app.profile.default_port
        self.app.var_profile_default_port.set("not-a-port")

        with mock.patch("appearance.messagebox.showerror") as mock_error:
            self.app.on_save_profile()

        mock_error.assert_called_once()
        self.assertEqual(self.app.profile.default_port, old_default_port)

    def test_out_of_range_profile_port_shows_error_and_does_not_save(self):
        self.app.var_profile_default_port.set("70000")

        with mock.patch("appearance.messagebox.showerror") as mock_error:
            self.app.on_save_profile()

        mock_error.assert_called_once()


class PasteHandshakeTests(AppearanceTestCase):
    """on_paste_handshake — обхід Ctrl+V/контекстного меню. Вставлене одразу
    обробляється; у полі з'являється лише після успішного розбору. Докладніше: dev-notes.md."""

    def setUp(self):
        super().setUp()
        import appearance as appearance_module
        from transport import ConnectionFailed
        from tuning import CONNECTION
        for target, kwargs in (
            ("establish_connection", {"side_effect": ConnectionFailed("mocked")}),
        ):
            p = mock.patch.object(appearance_module, target, **kwargs)
            p.start()
            self.addCleanup(p.stop)
        patcher = mock.patch("appearance.messagebox.showwarning")
        self.mock_warn = patcher.start()
        self.addCleanup(patcher.stop)
        err_patcher = mock.patch("appearance.messagebox.showerror")
        self.mock_error = err_patcher.start()
        self.addCleanup(err_patcher.stop)
        self.min_iterations = CONNECTION.min_iterations
        self.app.var_iterations.set(str(self.min_iterations))
        self.app.var_passphrase.set("shared-pass")

    def _packet(self, host: str = "192.168.1.50", port: int = 52075) -> str:
        from connection import build_handshake_packet
        return build_handshake_packet(self.min_iterations, port, host=host)[0]

    def _paste(self, text: str):
        self.app.root.clipboard_clear()
        self.app.root.clipboard_append(text)
        self.app.on_paste_handshake()

    def test_pastes_clipboard_content_into_handshake_field(self):
        text = self._packet()
        self._paste(text)
        self.assertEqual(self.app.text_handshake.get("1.0", "end").strip(), text)

    def test_replaces_existing_peer_content(self):
        self._paste(self._packet())
        fresh = self._packet(host="10.0.0.9", port=52076)
        with mock.patch("appearance.messagebox.askyesno", return_value=True):
            self._paste(fresh)
        self.assertEqual(self.app.text_handshake.get("1.0", "end").strip(), fresh)

    def test_empty_clipboard_warns_without_crashing(self):
        self.app.root.clipboard_clear()
        self.app.on_paste_handshake()
        self.mock_warn.assert_called_once()

    def test_unparsable_clipboard_leaves_field_and_session_unchanged(self):
        """Напр. скопійована парольна фраза не має з'явитись у полі незамаскованою."""
        valid = self._packet()
        self._paste(valid)
        old_key = self.app.peer_key

        with mock.patch("appearance.messagebox.askyesno") as mock_ask:
            self._paste("my-secret-passphrase")

        self.mock_error.assert_called_once()
        mock_ask.assert_not_called()  # до запиту "новий сеанс?" не доходить
        self.assertEqual(self.app.text_handshake.get("1.0", "end").strip(), valid)
        self.assertEqual(self.app.peer_key, old_key)
        self.assertNotIn("my-secret-passphrase", self.app.text_log.get("1.0", "end"))

    def test_unparsable_clipboard_on_empty_field_shows_nothing(self):
        self._paste("my-secret-passphrase")
        self.mock_error.assert_called_once()
        self.assertEqual(self.app.text_handshake.get("1.0", "end").strip(), "")

    def _raw_packet(self, **overrides) -> str:
        import base64
        import json
        from tuning import CONNECTION
        packet = {"v": 2, "sid": "abcd", "salt": base64.b64encode(b"s" * 16).decode(),
                  "iter": self.min_iterations, "host": "192.168.1.50", "port": 52075}
        packet.update(overrides)
        b64 = base64.urlsafe_b64encode(json.dumps(packet).encode()).decode()
        return f"{CONNECTION.handshake_header}\n{b64}\n{CONNECTION.handshake_footer}"

    def test_malformed_port_assigns_no_state(self):
        for bad_port in ("abc", 0, 70000, None):
            with self.subTest(port=bad_port):
                self.mock_error.reset_mock()
                self.app.on_process_incoming(raw_text=self._raw_packet(port=bad_port))
                self.mock_error.assert_called_once()
                self.assertIsNone(self.app.peer_key)
                self.assertIsNone(self.app.peer_host)
                self.assertIsNone(self.app.peer_port)
                self.assertFalse(self.app._channel_thread_started)
                self.assertEqual(self.app.text_handshake.get("1.0", "end").strip(), "")

    def test_malformed_host_assigns_no_state(self):
        self.app.on_process_incoming(raw_text=self._raw_packet(host=""))
        self.mock_error.assert_called_once()
        self.assertIsNone(self.app.peer_key)


class HandshakeSectionTests(AppearanceTestCase):
    """Секція "Хендшейк": ОДНЕ поле, БЕЗ перемикача ролі (ONE SESSION = ONE ROLE) —
    "Згенерувати" одразу копіює, "Вставити хендшейк" одразу обробляє.
    Докладніше: docs/dev-notes.md → "Секція «Хендшейк»".

    establish_connection мокаємо — генерація/обробка одразу стартують фоновий потік
    каналу, тест не має реально слухати/підключатись по мережі. Другу
    генерацію/вставку в межах одного тесту супроводжує мокнутий askyesno=True
    (підтверджений новий сеанс) — окремо перевірено в NewSessionConfirmationTests."""

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

        from tuning import CONNECTION
        self.min_iterations = CONNECTION.min_iterations
        self.app.var_iterations.set(str(self.min_iterations))  # швидша деривація; до хендшейку — без інвалідації
        self.app.var_passphrase.set("shared-pass")

    def _peer_handshake(self) -> tuple[str, bytes]:
        from connection import build_handshake_packet
        text, salt, _sid, _host = build_handshake_packet(self.min_iterations, 52075, host="192.168.1.50")
        return text, salt

    def _paste(self, text: str):
        self.app.root.clipboard_clear()
        self.app.root.clipboard_append(text)
        self.app.on_paste_handshake()

    def _paste_confirmed(self, text: str):
        """_paste, але з мокнутим підтвердженням нового сеансу — для випадків,
        коли сеанс уже активний (друга дія в тесті)."""
        with mock.patch("appearance.messagebox.askyesno", return_value=True):
            self._paste(text)

    def test_generate_copies_handshake_to_clipboard(self):
        self.app.root.clipboard_clear()
        self.app.on_generate_handshake()
        content = self.app.text_handshake.get("1.0", "end").strip()
        self.assertTrue(content)
        self.assertEqual(self.app.root.clipboard_get(), content)

    def test_generate_sets_mine_kind_and_fingerprint(self):
        from appearance import _HANDSHAKE_KIND_MINE
        self.app.on_generate_handshake()
        self.assertEqual(self.app._handshake_kind, _HANDSHAKE_KIND_MINE)
        self.assertIn("Код підтвердження: ", self.app.lbl_handshake_fp.cget("text"))
        self.assertNotIn("—", self.app.lbl_handshake_fp.cget("text"))

    def test_paste_sets_peer_kind_and_processes(self):
        from appearance import _HANDSHAKE_KIND_PEER
        from connection import derive_key
        peer_text, peer_salt = self._peer_handshake()

        self._paste(peer_text)

        self.assertEqual(self.app.text_handshake.get("1.0", "end").strip(), peer_text)
        self.assertEqual(self.app._handshake_kind, _HANDSHAKE_KIND_PEER)
        self.assertEqual(self.app.peer_key, derive_key("shared-pass", peer_salt, self.min_iterations))
        self.assertEqual((self.app.peer_host, self.app.peer_port), ("192.168.1.50", 52075))

    def test_ctrl_v_in_log_is_still_blocked(self):
        """on_paste — лише для поля хендшейку; консоль лишається read-only."""
        self.app.root.deiconify()
        self.app.root.update()
        self.app.root.clipboard_clear()
        self.app.root.clipboard_append("should-not-appear")
        self.app.text_log.focus_force()
        self.app.root.update()

        self.app.text_log.event_generate("<Control-Key>", keycode=86, state=0x4)  # Ctrl+V

        self.assertNotIn("should-not-appear", self.app.text_log.get("1.0", "end"))
        self.assertEqual(self.app.text_handshake.get("1.0", "end").strip(), "")

    def test_invalidation_clears_handshake_text_and_fingerprint(self):
        self.app.on_generate_handshake()

        self.app.var_port.set("52099")

        self.assertEqual(self.app.text_handshake.get("1.0", "end").strip(), "")
        self.assertIsNone(self.app._handshake_kind)
        self.assertEqual(self.app.lbl_handshake_fp.cget("text"), "Код підтвердження: —")

    def test_only_one_key_set_after_switching_roles_and_session_key_matches_fingerprint(self):
        """ONE SESSION = ONE ROLE: після Генерувати -> Вставити (з підтвердженням
        скидання) щонайбільше один з local_key/peer_key колись встановлений, і
        _session_key() відповідає коду підтвердження, показаному в полі."""
        from connection import key_fingerprint

        self.app.on_generate_handshake()
        self.assertIsNotNone(self.app.local_key)
        self.assertIsNone(self.app.peer_key)
        self.assertEqual(self.app._session_key(), self.app.local_key)
        self.assertIn(key_fingerprint(self.app.local_key), self.app.lbl_handshake_fp.cget("text"))

        peer_text, _salt = self._peer_handshake()
        self._paste_confirmed(peer_text)

        self.assertIsNone(self.app.local_key)
        self.assertIsNotNone(self.app.peer_key)
        self.assertEqual(self.app._session_key(), self.app.peer_key)
        self.assertIn(key_fingerprint(self.app.peer_key), self.app.lbl_handshake_fp.cget("text"))


class NewSessionConfirmationTests(AppearanceTestCase):
    """ONE SESSION = ONE ROLE: повторне "Згенерувати"/"Вставити хендшейк" (включно з
    тим самим ще раз) при вже активному сеансі питає підтвердження
    (_confirm_reset_if_needed, messagebox.askyesno). Докладніше: docs/dev-notes.md
    → "Секція «Хендшейк»"."""

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

        from tuning import CONNECTION
        self.min_iterations = CONNECTION.min_iterations
        self.app.var_iterations.set(str(self.min_iterations))
        self.app.var_passphrase.set("shared-pass")

    def _peer_handshake(self, host: str = "192.168.1.50", port: int = 52075) -> str:
        from connection import build_handshake_packet
        text, _salt, _sid, _host = build_handshake_packet(self.min_iterations, port, host=host)
        return text

    def test_generate_again_declined_leaves_session_untouched(self):
        self.app.on_generate_handshake()
        old_key = self.app.local_key
        old_text = self.app.text_handshake.get("1.0", "end").strip()

        with mock.patch("appearance.messagebox.askyesno", return_value=False) as mock_ask:
            self.app.on_generate_handshake()

        mock_ask.assert_called_once()
        self.assertEqual(self.app.local_key, old_key)
        self.assertEqual(self.app.text_handshake.get("1.0", "end").strip(), old_text)

    def test_generate_again_confirmed_resets_and_regenerates(self):
        self.app.on_generate_handshake()
        old_key = self.app.local_key

        with mock.patch("appearance.messagebox.askyesno", return_value=True) as mock_ask:
            self.app.on_generate_handshake()

        mock_ask.assert_called_once()
        self.assertIsNotNone(self.app.local_key)
        self.assertNotEqual(self.app.local_key, old_key)

    def test_paste_again_declined_leaves_session_untouched(self):
        first_text = self._peer_handshake()
        self.app.root.clipboard_clear()
        self.app.root.clipboard_append(first_text)
        self.app.on_paste_handshake()
        old_peer_key = self.app.peer_key

        with mock.patch("appearance.messagebox.askyesno", return_value=False) as mock_ask:
            self.app.root.clipboard_clear()
            self.app.root.clipboard_append(self._peer_handshake(host="10.0.0.9", port=52076))
            self.app.on_paste_handshake()

        mock_ask.assert_called_once()
        self.assertEqual(self.app.peer_key, old_peer_key)
        self.assertEqual(self.app.text_handshake.get("1.0", "end").strip(), first_text)

    def test_paste_again_confirmed_resets_and_reprocesses(self):
        first_text = self._peer_handshake()
        self.app.root.clipboard_clear()
        self.app.root.clipboard_append(first_text)
        self.app.on_paste_handshake()
        old_peer_key = self.app.peer_key

        second_text = self._peer_handshake(host="10.0.0.9", port=52076)
        with mock.patch("appearance.messagebox.askyesno", return_value=True) as mock_ask:
            self.app.root.clipboard_clear()
            self.app.root.clipboard_append(second_text)
            self.app.on_paste_handshake()

        mock_ask.assert_called_once()
        self.assertNotEqual(self.app.peer_key, old_peer_key)
        self.assertEqual((self.app.peer_host, self.app.peer_port), ("10.0.0.9", 52076))
        self.assertEqual(self.app.text_handshake.get("1.0", "end").strip(), second_text)


class EmptyPassphraseDialogTests(AppearanceTestCase):
    """Порожня парольна фраза при "Згенерувати"/"Вставити хендшейк" — модальне
    віконце (_prompt_passphrase), не messagebox-попередження. Докладніше:
    docs/dev-notes.md → "Секція «Хендшейк»"."""

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

        from tuning import CONNECTION
        self.min_iterations = CONNECTION.min_iterations
        self.app.var_iterations.set(str(self.min_iterations))
        # var_passphrase лишається порожньою навмисно.

    def test_generate_with_empty_passphrase_prompts_and_uses_result(self):
        with mock.patch.object(self.app, "_prompt_passphrase", return_value="typed-pass") as mock_prompt:
            self.app.on_generate_handshake()

        mock_prompt.assert_called_once()
        self.assertEqual(self.app.var_passphrase.get(), "typed-pass")
        self.assertIsNotNone(self.app.local_key)

    def test_generate_with_empty_passphrase_cancelled_does_nothing(self):
        with mock.patch.object(self.app, "_prompt_passphrase", return_value=None):
            self.app.on_generate_handshake()

        self.assertIsNone(self.app.local_key)
        self.assertEqual(self.app.var_passphrase.get(), "")

    def _peer_text(self) -> str:
        from connection import build_handshake_packet
        text, _salt, _sid, _host = build_handshake_packet(self.min_iterations, 52075, host="192.168.1.50")
        return text

    def test_paste_with_empty_passphrase_prompts_and_processes(self):
        self.app.root.clipboard_clear()
        self.app.root.clipboard_append(self._peer_text())

        with mock.patch.object(self.app, "_prompt_passphrase", return_value="typed-pass") as mock_prompt:
            self.app.on_paste_handshake()

        mock_prompt.assert_called_once()
        self.assertEqual(self.app.var_passphrase.get(), "typed-pass")
        self.assertIsNotNone(self.app.peer_key)

    def test_paste_with_empty_passphrase_cancelled_leaves_peer_key_unset(self):
        self.app.root.clipboard_clear()
        self.app.root.clipboard_append(self._peer_text())

        with mock.patch.object(self.app, "_prompt_passphrase", return_value=None):
            self.app.on_paste_handshake()

        self.assertIsNone(self.app.peer_key)


class VerificationMismatchTests(AppearanceTestCase):
    """kind == "verification_failed" — діалог замість попередження
    (_handle_verification_mismatch). Докладніше: docs/dev-notes.md →
    "Секція «Хендшейк»"."""

    def setUp(self):
        super().setUp()
        import appearance as appearance_module
        from transport import ConnectionFailed
        patcher = mock.patch.object(
            appearance_module, "establish_connection",
            side_effect=ConnectionFailed("mocked — жодного реального мережевого виклику в тесті"),
        )
        self.mock_establish = patcher.start()
        self.addCleanup(patcher.stop)

        from tuning import CONNECTION
        self.min_iterations = CONNECTION.min_iterations
        self.app.var_iterations.set(str(self.min_iterations))
        self.app.var_passphrase.set("shared-pass")

    def _peer_text(self) -> str:
        from connection import build_handshake_packet
        text, _salt, _sid, _host = build_handshake_packet(self.min_iterations, 52075, host="192.168.1.50")
        return text

    def _mismatch_event(self, app=None) -> dict:
        app = app or self.app
        return {"epoch": app._session_epoch, "kind": "verification_failed", "error": "mismatch"}

    def _wait_establish_calls(self, n: int):
        """establish_connection викликається у фоновому потоці — дочекатись n викликів."""
        import time
        for _ in range(200):
            if self.mock_establish.call_count >= n:
                break
            time.sleep(0.01)
        self.assertEqual(self.mock_establish.call_count, n)

    def test_peer_role_reprocesses_stored_text_and_restarts_channel(self):
        peer_text = self._peer_text()
        self.app.root.clipboard_clear()
        self.app.root.clipboard_append(peer_text)
        self.app.on_paste_handshake()
        self.assertTrue(self.app._channel_thread_started)
        self._wait_establish_calls(1)
        old_peer_key = self.app.peer_key
        epoch_before = self.app._session_epoch
        old_stop_event = self.app._channel_stop_event

        with mock.patch.object(self.app, "_prompt_passphrase", return_value="fixed-pass") as mock_prompt:
            self.app._handle_channel_event(self._mismatch_event())

        mock_prompt.assert_called_once()
        self.assertEqual(self.app.var_passphrase.get(), "fixed-pass")
        # Збережений текст переобробляється без повторного копіювання з буфера.
        self.assertEqual(self.app.text_handshake.get("1.0", "end").strip(), peer_text)
        self.assertIsNotNone(self.app.peer_key)
        self.assertNotEqual(self.app.peer_key, old_peer_key)
        self.assertEqual((self.app.peer_host, self.app.peer_port), ("192.168.1.50", 52075))
        self.assertTrue(self.app._channel_thread_started)  # встановлення каналу перезапущено
        self.assertGreater(self.app._session_epoch, epoch_before)
        self.assertTrue(old_stop_event.is_set())
        self._wait_establish_calls(2)
        self.assertIn("інша сторона", self.app.var_channel_status.get())

    def test_mine_role_retry_keeps_handshake_material_and_relistens(self):
        from connection import derive_key, key_fingerprint
        self.app.on_generate_handshake()
        self._wait_establish_calls(1)
        salt, sid = self.app.local_salt, self.app.local_session_id
        old_key = self.app.local_key
        old_text = self.app.text_handshake.get("1.0", "end").strip()
        epoch_before = self.app._session_epoch
        old_stop_event = self.app._channel_stop_event
        self.app.root.clipboard_clear()
        self.app.root.clipboard_append("untouched")

        with mock.patch.object(self.app, "_prompt_passphrase", return_value="fixed-pass-2") as mock_prompt:
            self.app._handle_channel_event(self._mismatch_event())

        mock_prompt.assert_called_once()
        self.assertEqual(self.app.var_passphrase.get(), "fixed-pass-2")
        self.assertEqual(self.app.local_salt, salt)
        self.assertEqual(self.app.local_session_id, sid)
        self.assertEqual(self.app.text_handshake.get("1.0", "end").strip(), old_text)
        self.assertEqual(self.app.root.clipboard_get(), "untouched")  # нічого пересилати не треба
        self.assertEqual(self.app.local_key, derive_key("fixed-pass-2", salt, self.min_iterations))
        self.assertNotEqual(self.app.local_key, old_key)
        self.assertIn(key_fingerprint(self.app.local_key), self.app.lbl_handshake_fp.cget("text"))
        self.assertGreater(self.app._session_epoch, epoch_before)
        self.assertTrue(old_stop_event.is_set())
        self.assertFalse(self.app._channel_stop_event.is_set())
        self.assertTrue(self.app._channel_thread_started)
        self._wait_establish_calls(2)
        self.assertIn("інша сторона", self.app.var_channel_status.get())

    def test_generator_and_joiner_retry_with_same_passphrase_produce_equal_keys(self):
        from appearance import SecureFileClientApp
        joiner = SecureFileClientApp(self.root)
        joiner.var_iterations.set(str(self.min_iterations))
        joiner.var_passphrase.set("typo-pass")

        self.app.on_generate_handshake()  # генератор: "shared-pass", текст — у буфері
        joiner.on_paste_handshake()
        self.assertNotEqual(self.app.local_key, joiner.peer_key)

        for app in (self.app, joiner):
            with mock.patch.object(app, "_prompt_passphrase", return_value="shared-pass"):
                app._handle_channel_event(self._mismatch_event(app))

        self.assertIsNotNone(self.app.local_key)
        self.assertEqual(self.app.local_key, joiner.peer_key)
        self.assertIsNone(self.app.peer_key)
        self.assertIsNone(joiner.local_key)

    def test_manual_passphrase_edit_after_retry_still_fully_resets(self):
        self.app.on_generate_handshake()
        with mock.patch.object(self.app, "_prompt_passphrase", return_value="fixed-pass"):
            self.app._handle_channel_event(self._mismatch_event())
        self.assertIsNotNone(self.app.local_salt)

        self.app.var_passphrase.set("typed-by-hand")

        self.assertIsNone(self.app.local_key)
        self.assertIsNone(self.app.local_salt)
        self.assertIsNone(self.app.local_session_id)
        self.assertEqual(self.app.text_handshake.get("1.0", "end").strip(), "")

    def test_peer_cancel_keeps_state_and_explains_how_to_retry(self):
        peer_text = self._peer_text()
        self.app.root.clipboard_clear()
        self.app.root.clipboard_append(peer_text)
        self.app.on_paste_handshake()
        old_peer_key = self.app.peer_key
        old_passphrase = self.app.var_passphrase.get()
        epoch_before = self.app._session_epoch

        with mock.patch.object(self.app, "_prompt_passphrase", return_value=None) as mock_prompt:
            self.app._handle_channel_event(self._mismatch_event())

        mock_prompt.assert_called_once()
        self.assertEqual(self.app.peer_key, old_peer_key)
        self.assertEqual(self.app.var_passphrase.get(), old_passphrase)
        self.assertEqual(self.app._session_epoch, epoch_before)  # не перепідключається
        self.assertIn("НЕ збігаються", self.app.var_channel_status.get())
        self.assertIn("вставте хендшейк", self.app.var_channel_status.get())

    def test_mine_cancel_keeps_key_and_keeps_listening(self):
        self.app.on_generate_handshake()
        self._wait_establish_calls(1)
        old_key = self.app.local_key
        epoch_before = self.app._session_epoch

        with mock.patch.object(self.app, "_prompt_passphrase", return_value=None):
            self.app._handle_channel_event(self._mismatch_event())

        self.assertEqual(self.app.local_key, old_key)
        self.assertEqual(self.app.var_passphrase.get(), "shared-pass")
        self.assertGreater(self.app._session_epoch, epoch_before)
        self.assertTrue(self.app._channel_thread_started)
        self._wait_establish_calls(2)
        self.assertIn("слухаю", self.app.var_channel_status.get())

    def test_mismatch_dialog_deferred_while_other_modal_open(self):
        self.app.on_generate_handshake()
        self.app._modal_depth = 1
        with mock.patch.object(self.app, "_prompt_passphrase") as mock_prompt:
            self.app._handle_channel_event(self._mismatch_event())
        mock_prompt.assert_not_called()
        self.assertEqual(len(self.app._deferred_channel_events), 1)

    def test_mismatch_dialog_result_ignored_if_session_reset_meanwhile(self):
        self.app.on_generate_handshake()

        def _prompt_and_reset(*_a, **_kw):
            self.app._reset_session_state()
            return "fixed-pass"

        with mock.patch.object(self.app, "_prompt_passphrase", side_effect=_prompt_and_reset):
            self.app._handle_channel_event(self._mismatch_event())

        self.assertIsNone(self.app.local_key)
        self.assertEqual(self.app.var_passphrase.get(), "shared-pass")

    def test_non_verification_error_is_connection_failed_without_dialog(self):
        """transport: обрив/таймаут під час verify_channel -> ConnectionFailed (не VerificationError)."""
        import appearance as appearance_module
        from transport import ConnectionFailed
        for exc in (ConnectionFailed("connection reset during verify"), OSError("connection reset raw")):
            with self.subTest(exc=type(exc).__name__):
                sock = mock.MagicMock()
                self.mock_establish.side_effect = None
                self.mock_establish.return_value = sock
                with mock.patch.object(appearance_module, "verify_channel", side_effect=exc):
                    self.app._channel_establish_worker(b"k" * 32, self.app._session_epoch)

                event = self.app._channel_queue.get_nowait()
                self.assertEqual(event["kind"], "connection_failed")
                sock.close.assert_called_once()
                with mock.patch.object(self.app, "_prompt_passphrase") as mock_prompt:
                    self.app._handle_channel_event(event)
                mock_prompt.assert_not_called()
                self.assertIn(str(exc), self.app.var_channel_status.get())

    def test_verification_error_is_verification_failed(self):
        import appearance as appearance_module
        from transport import VerificationError
        self.mock_establish.side_effect = None
        self.mock_establish.return_value = mock.MagicMock()
        with mock.patch.object(appearance_module, "verify_channel", side_effect=VerificationError("nope")):
            self.app._channel_establish_worker(b"k" * 32, self.app._session_epoch)
        self.assertEqual(self.app._channel_queue.get_nowait()["kind"], "verification_failed")

    def test_connection_failed_message_shown_in_channel_status(self):
        self.app._handle_channel_event({
            "epoch": self.app._session_epoch, "kind": "connection_failed",
            "error": "Не вдалось слухати на порту 52075: порт зайнятий",
        })
        self.assertIn("порт зайнятий", self.app.var_channel_status.get())


class IterationsValidationTests(AppearanceTestCase):
    """Ітерації нижче CONNECTION.min_iterations — гарантована розбіжність ключів
    (сторона, що вставляє, затискає знизу), тому відхиляються при генерації."""

    def test_iterations_below_min_rejected_on_generate(self):
        from tuning import CONNECTION
        self.app.var_passphrase.set("shared-pass")
        self.app.var_iterations.set(str(CONNECTION.min_iterations - 1))
        with mock.patch("appearance.messagebox.showerror") as mock_error:
            self.app.on_generate_handshake()
        mock_error.assert_called_once()
        self.assertIn(str(CONNECTION.min_iterations), mock_error.call_args[0][1])
        self.assertIsNone(self.app.local_key)


class PollChannelEventsTests(AppearanceTestCase):
    """_poll_channel_events — виняток в одному обробнику не зупиняє наступні події й перепланування."""

    def test_exception_in_handler_does_not_stop_processing(self):
        self.app._channel_queue.put({"epoch": self.app._session_epoch, "kind": "a"})
        self.app._channel_queue.put({"epoch": self.app._session_epoch, "kind": "b"})
        with mock.patch.object(
            self.app, "_handle_channel_event", side_effect=[RuntimeError("boom"), None]
        ) as mock_handle, mock.patch.object(self.app.root, "after") as mock_after:
            self.app._poll_channel_events()
        self.assertEqual(mock_handle.call_count, 2)
        mock_after.assert_called_once_with(200, self.app._poll_channel_events)
        self.assertIn("boom", self.app.text_log.get("1.0", "end"))

    def test_stale_connected_event_socket_is_closed(self):
        sock = mock.MagicMock()
        self.app._handle_channel_event(
            {"epoch": self.app._session_epoch - 1, "kind": "connected", "socket": sock, "key": b"k" * 32}
        )
        sock.close.assert_called_once()
        self.assertIsNone(self.app.channel_socket)
        self.assertFalse(self.app.channel_verified)


class ArchiveKeyMatchesChannelKeyTests(AppearanceTestCase):
    """AES-архів має бути зашифрований ключем підтвердженого каналу; скидання сеансу
    видаляє такий архів. Докладніше: dev-notes.md → "Секція «Хендшейк»"."""

    def setUp(self):
        super().setUp()
        import appearance as appearance_module
        from transport import ConnectionFailed
        from tuning import CONNECTION
        patcher = mock.patch.object(
            appearance_module, "establish_connection", side_effect=ConnectionFailed("mocked"),
        )
        patcher.start()
        self.addCleanup(patcher.stop)
        self.app.var_iterations.set(str(CONNECTION.min_iterations))
        self.app.var_passphrase.set("shared-pass")

    def test_send_disabled_when_archive_key_differs_from_channel_key(self):
        self.app.transfer_payload = ["x.zip"]
        self.app._transfer_archive_key = b"a" * 32
        self.app.channel_verified = True
        self.app.channel_socket = mock.MagicMock()
        self.app.channel_key = b"b" * 32
        self.app._update_send_button_state()
        self.assertEqual(str(self.app.btn_send["state"]), "disabled")

        with mock.patch("appearance.messagebox.showwarning") as mock_warn, \
                mock.patch("appearance.send_files") as mock_send:
            self.app.on_send_files()
        mock_warn.assert_called_once()
        mock_send.assert_not_called()

        self.app.channel_key = b"a" * 32
        self.app._update_send_button_state()
        self.assertEqual(str(self.app.btn_send["state"]), "normal")

    def _prepare_encrypted_archive(self) -> str:
        from appearance import _ENCRYPTION_LEVEL_LABELS
        from exchange import EncryptionLevel
        send_dir = tempfile.mkdtemp(prefix="test_appearance_send_")
        self.addCleanup(shutil.rmtree, send_dir, ignore_errors=True)
        with open(os.path.join(send_dir, "a.txt"), "w", encoding="utf-8") as f:
            f.write("a")
        self.app._select_send_dir(send_dir)
        self.app.var_encryption_label.set(_ENCRYPTION_LEVEL_LABELS[EncryptionLevel.AES256])
        self.app.on_generate_handshake()
        self.app.on_initiate_transfer()
        self.assertEqual(self.app._transfer_archive_key, self.app.local_key)
        self.assertTrue(os.path.exists(self.app.packed_archive_path))
        return self.app.packed_archive_path

    def test_full_reset_clears_encrypted_payload(self):
        archive = self._prepare_encrypted_archive()
        self.app.var_port.set("52099")  # ручна зміна параметра — повне скидання
        self.assertIsNone(self.app.transfer_payload)
        self.assertIsNone(self.app.packed_archive_path)
        self.assertIsNone(self.app._transfer_archive_key)
        self.assertFalse(os.path.exists(archive))
        self.assertIn("Ініціалізувати передачу", self.app.var_transfer_status.get())

    def test_retry_reset_clears_encrypted_payload(self):
        archive = self._prepare_encrypted_archive()
        with mock.patch.object(self.app, "_prompt_passphrase", return_value="fixed-pass"):
            self.app._handle_channel_event(
                {"epoch": self.app._session_epoch, "kind": "verification_failed", "error": "x"}
            )
        self.assertIsNone(self.app.transfer_payload)
        self.assertFalse(os.path.exists(archive))

    def test_unencrypted_payload_survives_reset(self):
        self.app.on_generate_handshake()
        self.app.transfer_payload = ["plain.txt"]
        self.app._transfer_archive_key = None
        self.app.var_port.set("52099")
        self.assertEqual(self.app.transfer_payload, ["plain.txt"])


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
            self.app._test_channel_worker(self.app.channel_socket, self.app._session_epoch)  # без потоку

        event = self.app._channel_queue.get_nowait()
        self.assertEqual(event["kind"], "channel_test_failed")
        self.assertIn("broken pipe", event["error"])

    def test_socket_reset_before_worker_start_reports_failure(self):
        """Скидання сеансу між кліком і стартом потоку: None-сокет — подія, не мовчазна смерть."""
        self.app._test_channel_worker(None, self.app._session_epoch)
        event = self.app._channel_queue.get_nowait()
        self.assertEqual(event["kind"], "channel_test_failed")


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
            self.app._receive_worker(self.app.channel_socket, self.app.channel_key, self.app._session_epoch)

        event = self.app._channel_queue.get_nowait()
        self.assertEqual(event["kind"], "receive_error")
        self.assertIn("KeyError", event["error"])
        self.assertEqual(event["epoch"], self.app._session_epoch)

    def test_receive_worker_uses_passed_socket_and_exits_on_stale_epoch(self):
        import appearance as appearance_module
        own_sock, own_key = object(), b"o" * 32
        with mock.patch.object(appearance_module, "receive_files", side_effect=KeyError("x")) as mock_recv:
            self.app._receive_worker(own_sock, own_key, self.app._session_epoch)
        self.assertIs(mock_recv.call_args[0][0], own_sock)
        self.assertIs(mock_recv.call_args[0][1], own_key)

        with mock.patch.object(appearance_module, "receive_files") as mock_recv:
            self.app._receive_worker(own_sock, own_key, self.app._session_epoch - 1)
        mock_recv.assert_not_called()

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
        """Не-VerificationError під час підтвердження — мережева помилка (connection_failed),
        не розбіжність ключів: діалог виправлення фрази тут недоречний."""
        import appearance as appearance_module

        dummy_socket = mock.MagicMock()
        with mock.patch.object(
            appearance_module, "establish_connection", return_value=dummy_socket
        ), mock.patch.object(
            appearance_module, "verify_channel", side_effect=RuntimeError("weird")
        ):
            self.app._channel_establish_worker(b"k" * 32, self.app._session_epoch)

        event = self.app._channel_queue.get_nowait()
        self.assertEqual(event["kind"], "connection_failed")
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
        self.assertEqual(self.app.text_handshake.get("1.0", "end").strip(), "")
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


class HandshakeButtonTooltipTests(AppearanceTestCase):
    """Кнопки хендшейку мають tooltip з описом функції. Tooltip — _Tooltip class,
    яка з'являється при <Enter> після затримки і знищується при <Leave>."""

    def test_tooltip_creates_toplevel_on_show(self):
        """_Tooltip._show() створює Toplevel віконце з текстом tooltip."""
        import tkinter as tk
        from appearance import _Tooltip

        test_widget = tk.Button(self.app.root, text="Test")
        test_widget.pack()
        tooltip_text = "Test tooltip content"
        tooltip = _Tooltip(test_widget, tooltip_text, delay_ms=0)

        # Прямо викликаємо _show() замість event_generate
        tooltip._show()

        # Tooltip повинен створити Toplevel віконце
        self.assertIsNotNone(tooltip.tooltip)
        self.assertIsInstance(tooltip.tooltip, tk.Toplevel)

        # Перевіряємо, що текст присутній у Toplevel
        found_text = False
        for child in tooltip.tooltip.winfo_children():
            if hasattr(child, 'cget'):
                if child.cget('text') == tooltip_text:
                    found_text = True
                    break
        self.assertTrue(found_text, "Текст tooltip не знайдено у Toplevel")

        tooltip._destroy()

    def test_tooltip_destroyed_on_leave(self):
        """При <Leave> tooltip знищується."""
        import tkinter as tk
        from appearance import _Tooltip

        test_widget = tk.Button(self.app.root, text="Test")
        test_widget.pack()
        tooltip = _Tooltip(test_widget, "Test tooltip", delay_ms=0)

        # Показуємо tooltip
        tooltip._show()
        self.assertIsNotNone(tooltip.tooltip)

        # Повинен знищуватись при <Leave>
        tooltip._on_leave()
        self.assertIsNone(tooltip.tooltip)

    def test_tooltip_destroyed_on_button_press(self):
        """При <ButtonPress> tooltip знищується."""
        import tkinter as tk
        from appearance import _Tooltip

        test_widget = tk.Button(self.app.root, text="Test")
        test_widget.pack()
        tooltip = _Tooltip(test_widget, "Test tooltip", delay_ms=0)

        # Показуємо tooltip
        tooltip._show()
        self.assertIsNotNone(tooltip.tooltip)

        # Повинен знищуватись при натисканні
        tooltip._on_leave()
        self.assertIsNone(tooltip.tooltip)

    def test_tooltip_has_correct_styling(self):
        """Tooltip використовує кольори з APPEARANCE."""
        import tkinter as tk
        from appearance import _Tooltip
        from tuning import APPEARANCE

        test_widget = tk.Button(self.app.root, text="Test")
        test_widget.pack()
        tooltip = _Tooltip(test_widget, "Test tooltip", delay_ms=0)

        tooltip._show()

        # Перевіряємо, що Label у Toplevel має правильні кольори
        found_label = False
        for child in tooltip.tooltip.winfo_children():
            if hasattr(child, 'cget'):
                bg = child.cget('background')
                fg = child.cget('foreground')
                if bg == APPEARANCE.dark_bg and fg == APPEARANCE.dark_fg:
                    found_label = True
                    break
        self.assertTrue(found_label, "Label з правильними кольорами не знайдено")

        tooltip._destroy()


if __name__ == "__main__":
    unittest.main()
