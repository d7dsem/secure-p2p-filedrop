#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Шар "зовнішність": tkinter GUI. Крипто — connection.py, дані — exchange.py, тема — tuning.py.
"""

import base64
import hmac
import ipaddress
import os
import queue
import secrets
import socket
import subprocess
import sys
import threading
import time
import tkinter as tk
import tkinter.font as tkfont
from pathlib import Path
from tkinter import ttk, filedialog, messagebox, scrolledtext

from connection import build_handshake_packet, derive_key, detect_local_address, key_fingerprint, parse_handshake_packet
from exchange import EncryptionLevel, build_archive_from_selection, format_size, list_entries
from local_config import LocalConfig, config_path, load_config, save_config
from nat_traversal import UpnpError, try_configure_port_forwarding
from stun_client import StunError, get_public_address
from transport import (
    ConnectionFailed, PeerClosed, TransportError, VerificationError,
    establish_connection, receive_files, send_files, send_ping, verify_channel,
)
from tuning import APPEARANCE, CONNECTION, ENCRYPTION, EXCHANGE, STUN


class _Tooltip:
    """Простий tooltip: Toplevel-віконце з текстом, яке з'являється при <Enter> на віджет.
    На <Leave> або <ButtonPress> — знищується. Позиціюється біля курсора або віджета."""

    def __init__(self, widget, text: str, delay_ms: int = 800, wraplength: int = 300):
        self.widget = widget
        self.text = text
        self.delay_ms = delay_ms
        self.wraplength = wraplength
        self.tooltip = None
        self.after_id = None

        widget.bind("<Enter>", self._on_enter)
        widget.bind("<Leave>", self._on_leave)
        widget.bind("<ButtonPress>", self._on_leave)

    def _on_enter(self, event):
        """Запланувати показ tooltip після затримки."""
        if self.after_id:
            self.widget.after_cancel(self.after_id)
        self.after_id = self.widget.after(self.delay_ms, self._show)

    def _on_leave(self, event=None):
        """Скасувати запланований показ і знищити vidстійучий tooltip."""
        if self.after_id:
            self.widget.after_cancel(self.after_id)
            self.after_id = None
        self._destroy()

    def _show(self):
        """Створити й показати tooltip Toplevel."""
        self._destroy()
        self.tooltip = tk.Toplevel(self.widget)
        self.tooltip.wm_overrideredirect(True)
        self.tooltip.wm_attributes("-topmost", True)

        label = tk.Label(
            self.tooltip,
            text=self.text,
            wraplength=self.wraplength,
            justify="left",
            background=APPEARANCE.dark_bg,
            foreground=APPEARANCE.dark_fg,
            relief="solid",
            borderwidth=1,
            padx=8,
            pady=6,
        )
        label.pack()

        # Позиціюємо біля верхнього лівого кута віджета
        x = self.widget.winfo_rootx()
        y = self.widget.winfo_rooty() + self.widget.winfo_height() + 5
        self.tooltip.wm_geometry(f"+{x}+{y}")

    def _destroy(self):
        """Знищити tooltip Toplevel, якщо існує."""
        if self.tooltip:
            try:
                self.tooltip.destroy()
            except tk.TclError:
                pass
            self.tooltip = None


_TREE_LOADING_SUFFIX = "/__loading__"
_ASSETS_DIR = Path(__file__).resolve().parent.parent / "assets"

_HOST_SOURCE_LABELS = {
    "upnp": "публічна, через UPnP (порт прокинуто на роутері)",
    "stun": "публічна, через STUN (порт НЕ прокинуто, мапінг може бути тимчасовим)",
    None: "локальна, LAN-only",
}


def _is_private_host(host: str) -> bool:
    """True — LAN/loopback-адреса (з'єднання пряме, без роутера). False — виглядає
    публічною: якщо інша сторона за ТИМ САМИМ роутером (напр. тест на одному ПК),
    з'єднання потребує підтримки NAT hairpin/loopback, яку не всі роутери мають —
    dev-notes.md → "_maybe_start_channel_establishment — hairpin NAT попередження"."""
    try:
        return ipaddress.ip_address(host).is_private
    except ValueError:
        return False  # хостнейм (не голий IP) — вважаємо непрозорим, без спекуляцій


def _close_socket(sock) -> None:
    """shutdown(SHUT_RDWR) перед close() — інакше на Linux заблокований recv() у фоновому
    потоці (_receive_worker) не прокидається. None/вже закритий — тихо ігноруємо."""
    if sock is None:
        return
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except (OSError, AttributeError):
        pass
    try:
        sock.close()
    except (OSError, AttributeError):
        pass


def _parse_incoming_handshake(text: str) -> dict:
    """Розбирає й валідує чужий хендшейк ДО будь-якої зміни стану. Кидає Exception
    (ValueError/KeyError/binascii.Error...) на побитому пакеті. Повертає salt/iterations/
    host/port/sid."""
    packet = parse_handshake_packet(text)
    salt = base64.b64decode(packet["salt"])
    # Нижня межа — захист від підробленого/зниженого "iter" у чужому пакеті,
    # що змусило б слабшу деривацію ключа (dev-notes.md).
    iterations = max(int(packet["iter"]), CONNECTION.min_iterations)
    host = packet["host"]
    if not isinstance(host, str) or not host.strip():
        raise ValueError("Некоректна адреса (host) у хендшейку.")
    port = packet["port"]
    if isinstance(port, bool) or not isinstance(port, (int, str)):
        raise ValueError("Некоректний порт у хендшейку.")
    port = int(port)
    if not (CONNECTION.min_port <= port <= CONNECTION.max_port):
        raise ValueError(f"Порт у хендшейку поза межами {CONNECTION.min_port}..{CONNECTION.max_port}: {port}.")
    return {"salt": salt, "iterations": iterations, "host": host.strip(), "port": port, "sid": packet["sid"]}

# Людяні підписи для Combobox шифрування; ключ — те, що реально йде в build_archive_from_selection.
_ENCRYPTION_LEVEL_LABELS = {
    EncryptionLevel.NONE: "Без шифрування (передача у відкриту — нульова безпека)",
    EncryptionLevel.AES128: "AES-128",
    EncryptionLevel.AES256: "AES-256",
}
_ENCRYPTION_LABEL_TO_LEVEL = {label: level for level, label in _ENCRYPTION_LEVEL_LABELS.items()}

# Секція "Хендшейк": одне поле, без перемикача ролі — ОДИН сеанс = ОДНА роль (хто
# генерує, хто вставляє). "Роль" (_HANDSHAKE_KIND_*) — суто внутрішній прапорець,
# який з двох сценаріїв повтору після розбіжності ключів застосувати (знову слухати з
# тими самими salt/sid vs переобробити збережений текст); користувачу не показується
# перемикачем. dev-notes.md → "Секція «Хендшейк»".
_HANDSHAKE_KIND_MINE = "mine"
_HANDSHAKE_KIND_PEER = "peer"
_FINGERPRINT_PLACEHOLDER = "Код підтвердження: —"
_HANDSHAKE_CAPTION_EMPTY = (
    "Немає активного хендшейку. Натисніть «Згенерувати» (якщо ви ініціюєте обмін) "
    "або «Вставити хендшейк» (якщо отримали текст від співрозмовника)."
)
_HANDSHAKE_CAPTION_MINE = "Ваш хендшейк — скопійовано в буфер, надішліть співрозмовнику."
_HANDSHAKE_CAPTION_PEER = "Хендшейк співрозмовника."
_NEW_SESSION_CONFIRM_TITLE = "Новий сеанс?"
_NEW_SESSION_CONFIRM_MESSAGE = "Почати новий сеанс? Поточний хендшейк і канал буде скинуто."

_HELP_TEXT = """Як користуватись

1. Обидві сторони вводять ОДНАКОВУ парольну фразу (не передається мережею) — або одна сторона тисне "Згенерувати" біля пароля й передає готову фразу іншій тим самим каналом, що й хендшейк. Якщо натиснути "Згенерувати"/"Вставити хендшейк" із порожньою фразою — з'явиться віконце для її введення.
2. Сторона A: у секції "Хендшейк" — "Згенерувати" (текст одразу копіюється в буфер обміну) → надсилає стороні B через месенджер (Signal/Telegram тощо).
3. Сторона B: копіює отриманий текст → "Вставити хендшейк" (або Ctrl+V у полі) — хендшейк вставляється й одразу обробляється. Код підтвердження показується під полем.
4. Обидві сторони звіряють короткий код підтвердження (голосом/текстом через той самий месенджер) — мають збігатись. Якщо не збігаються — з'явиться віконце для виправлення фрази й повторної спроби (без ручного копіювання наново).
5. Один сеанс — одна роль: якщо хендшейк уже згенеровано чи оброблено, повторне натискання "Згенерувати"/"Вставити хендшейк" запитає підтвердження — почати новий сеанс (поточний хендшейк і канал буде скинуто).
6. З'єднання встановлюється й підтверджується автоматично (UPnP → STUN → LAN), без додаткових дій.
7. Оберіть файл або каталог, за потреби — архівування/шифрування/стиснення → "Ініціалізувати передачу" → "Надіслати".

Особливості безпеки

- Вміст файлів завжди шифрується (AES-256-CTR); ключ ніколи не передається мережею.
- Без TLS: ім'я файлу, розмір і контрольна сума видно спостерігачу в мережі — прихований лише вміст.
- Немає центрального сервера чи relay: якщо обидві сторони за суворим NAT без UPnP, з'єднання не встановиться.
- Уся безпека тримається на силі парольної фрази — коротку фразу можна підібрати офлайн навіть з коректною деривацією ключа.
- Хендшейк-пакет не містить пароля, лише службові дані (сіль, sid, host/port) — сам собою він не розкриває ключ.

Детальніше: docs/concept.md ("Безпека — обмеження та гарантії") і docs/dev-notes.md у репозиторії проєкту."""


class SecureFileClientApp:
    def __init__(
        self, root: tk.Tk, initial_passphrase: str | None = None, initial_send_dir: str | None = None,
        initial_port: int | None = None,
    ):
        self.root = root
        self.root.title(APPEARANCE.window_title)
        self.root.geometry(APPEARANCE.window_geometry)
        self.root.minsize(*APPEARANCE.window_min_size)
        self._set_window_icon()

        self.local_key: bytes | None = None
        self.local_salt: bytes | None = None
        self.local_session_id: str | None = None
        # Параметри ЗГЕНЕРОВАНОГО хендшейку, потрібні для повтору після розбіжності ключів
        # без нового пакета (_retry_after_mismatch) — dev-notes.md → "Секція «Хендшейк»".
        self.local_iterations: int | None = None
        self._local_handshake_net: str = ""

        self.peer_key: bytes | None = None
        self.peer_host: str | None = None
        self.peer_port: int | None = None

        self.selected_path: str | None = None
        self.selected_is_dir: bool = False
        self.packed_archive_path: str | None = None  # окремо від selected_path — див. dev-notes.md
        self.transfer_payload: list[str] | None = None  # фінальний payload для передачі
        # Ключ, яким зашифровано підготовлений AES-архів (None — payload від ключа не залежить).
        # "Надіслати" дозволено лише якщо він == channel_key — dev-notes.md → "Секція «Хендшейк»".
        self._transfer_archive_key: bytes | None = None

        self.local_port: int | None = None  # локальний порт, на якому реально слухаємо (не public_port)
        self.channel_socket = None  # встановлений і підтверджений сокет (transport.py) або None
        self.channel_key: bytes | None = None  # сесійний ключ, яким верифіковано ЦЕЙ канал — dev-notes.md
        self.channel_verified: bool = False
        self._channel_thread_started: bool = False
        # True поки триває саме встановлення (між стартом і connected/connection_failed/
        # verification_failed) — керує тікером очікування (_tick_channel_wait, dev-notes.md).
        self._channel_pending: bool = False
        self._channel_wait_started_at: float = 0.0
        self._channel_queue: queue.Queue = queue.Queue()
        # Зростає на кожен _invalidate_session_if_active — фонові потоки з попередньої
        # спроби (їх не можна перервати на льоту) позначають свої події старим epoch,
        # і _handle_channel_event їх ігнорує. dev-notes.md.
        self._session_epoch: int = 0
        # Сигналізує ПОТОЧНОМУ _channel_establish_worker зупинитись якнайшвидше (dev-notes.md →
        # "_reset_session_state — звільнення порту"); при скиданні сеансу замінюється на новий
        # екземпляр — старий лишається "сетнутим" для потоку попередньої спроби, що вже його тримає.
        self._channel_stop_event: threading.Event = threading.Event()
        # True лише на час програмної зміни var_passphrase під час повтору після розбіжності —
        # trace не має скидати хендшейк (_invalidate_session_if_active).
        self._suppress_param_invalidation: bool = False
        # Порт: precedence профіль.default_port < CLI --port < ручна правка поля "Порт"
        # (сеансова, у профіль не пишеться) — dev-notes.md → "--port CLI-параметр"/"local_config.py".
        # _port_overridden_by_user — True лише після СПРАВЖНЬОЇ ручної правки поля користувачем;
        # _suppress_port_override_tracking — True на час programmatic set() (initial/CLI/синхронізація
        # з вкладки "Профіль"), щоб такі зміни не позначались як "ручні".
        self._port_overridden_by_user: bool = False
        self._suppress_port_override_tracking: bool = False
        self._cli_port_provided: bool = initial_port is not None
        # >0 поки відкрите модальне віконце (askyesno/_prompt_passphrase) — verification_failed
        # відкладається, щоб діалоги не накладались (_handle_channel_event).
        self._modal_depth: int = 0
        self._deferred_channel_events: list[dict] = []

        # rel_path (POSIX "/") -> чи включено; дефолт — усе включено (запис лише при зміні).
        self._file_tree_checked: dict[str, bool] = {}
        self._file_tree_meta: dict[str, tuple[str, str, bool]] = {}  # iid -> (rel_path, abs_path, is_dir)

        self.public_host: str | None = None
        self.public_port: int | None = None
        self.public_host_source: str | None = None  # "upnp" | "stun" | None
        self._conn_setup_queue: queue.Queue = queue.Queue()

        self.profile: LocalConfig = load_config()

        self._apply_dark_theme()
        self._build_ui()
        self.root.bind("<Escape>", lambda _e: self.root.destroy())
        self._log("Застосунок запущено.")
        self._log(f"Профіль завантажено: client_id={self.profile.client_id} ({config_path()}).")

        if initial_port is not None:
            # CLI --port — не "ручна правка поля" для цілей precedence (dev-notes.md):
            # не позначаємо _port_overridden_by_user, інакше зміна дефолту профілю
            # пізніше вже ніколи не синхронізувала б поле, хоча CLI-порт сам по собі
            # вже вище профілю в ієрархії (_cli_port_provided).
            self._suppress_port_override_tracking = True
            try:
                self.var_port.set(str(initial_port))
            finally:
                self._suppress_port_override_tracking = False

        if initial_passphrase:
            self.var_passphrase.set(initial_passphrase)

        if initial_send_dir:
            if os.path.isdir(initial_send_dir):
                self._select_send_dir(initial_send_dir)
            else:
                self._log(f"--snd-dir: '{initial_send_dir}' не є каталогом — проігноровано.")

        # Автоматично, без кнопки (docs/concept.md); в кінці __init__ — усе вже побудовано.
        self._start_connection_setup()

        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self.root.after(200, self._poll_channel_events)

    def _on_close(self):
        _close_socket(self.channel_socket)
        self.root.destroy()

    def _set_window_icon(self):
        """assets/icon.ico (Windows) + assets/icon.png (крос-платформенно через stdlib
        tkinter.PhotoImage, без Pillow). Відсутня іконка — не критично, просто пропускаємо."""
        try:
            ico_path = _ASSETS_DIR / "icon.ico"
            if os.name == "nt" and ico_path.exists():
                self.root.iconbitmap(default=str(ico_path))
        except tk.TclError:
            pass
        try:
            png_path = _ASSETS_DIR / "icon.png"
            if png_path.exists():
                self._icon_image = tk.PhotoImage(file=str(png_path))  # тримаємо референс — інакше GC забере
                self.root.iconphoto(True, self._icon_image)
        except tk.TclError:
            pass

    # ---- тема ------------------------------------------------------------

    def _apply_dark_theme(self):
        self.root.configure(bg=APPEARANCE.dark_bg)

        # Іменовані шрифти (посилання тримаємо в self, інакше Python їх прибирає — dev-notes.md).
        default_font = tkfont.nametofont("TkDefaultFont")
        default_font.configure(size=default_font.cget("size") + APPEARANCE.base_font_size_delta)
        self._heading_font = default_font.copy()
        self._heading_font.configure(
            size=default_font.cget("size") + APPEARANCE.heading_font_size_delta, weight="bold"
        )
        self._button_font = default_font.copy()  # жирний, без збільшення розміру (heading_font тут завеликий)
        self._button_font.configure(weight="bold")
        self._mono_font = tkfont.nametofont("TkFixedFont")

        style = ttk.Style(self.root)
        if "clam" in style.theme_names():
            style.theme_use("clam")

        style.configure(".", background=APPEARANCE.dark_bg, foreground=APPEARANCE.dark_fg,
                         fieldbackground=APPEARANCE.dark_entry_bg, bordercolor=APPEARANCE.dark_border,
                         lightcolor=APPEARANCE.dark_bg, darkcolor=APPEARANCE.dark_bg)
        style.configure("TFrame", background=APPEARANCE.dark_bg)
        style.configure("TLabelframe", background=APPEARANCE.dark_bg, foreground=APPEARANCE.dark_fg,
                         bordercolor=APPEARANCE.dark_border)
        style.configure("TLabelframe.Label", background=APPEARANCE.dark_bg, foreground=APPEARANCE.dark_fg,
                         font=self._heading_font)
        style.configure("TLabel", background=APPEARANCE.dark_bg, foreground=APPEARANCE.dark_fg_muted)
        # TCheckbutton не стилізуємо — усі чекбокси тепер plain tk.Checkbutton (_make_checkbutton).
        style.configure("TEntry", fieldbackground=APPEARANCE.dark_entry_bg, foreground=APPEARANCE.dark_fg,
                         insertcolor=APPEARANCE.dark_fg, bordercolor=APPEARANCE.dark_border)
        style.configure("TButton", background=APPEARANCE.dark_entry_bg, foreground=APPEARANCE.dark_fg,
                         bordercolor=APPEARANCE.dark_border, padding=(8, 4))
        style.map("TButton",
                  background=[("active", APPEARANCE.dark_accent)],
                  foreground=[("active", APPEARANCE.dark_fg)])
        # Акцентні CTA-кнопки, візуально відділені від звичайних (tuning.py: accent_button_bg).
        style.configure("Accent.TButton", background=APPEARANCE.accent_button_bg,
                         foreground=APPEARANCE.accent_button_fg, bordercolor=APPEARANCE.dark_border,
                         font=self._button_font, padding=(8, 4))
        style.map("Accent.TButton",
                  background=[("active", APPEARANCE.dark_accent)],
                  foreground=[("active", APPEARANCE.accent_button_fg)])
        style.configure("TNotebook", background=APPEARANCE.dark_bg, bordercolor=APPEARANCE.dark_border)
        style.configure("TNotebook.Tab", background=APPEARANCE.dark_entry_bg, foreground=APPEARANCE.dark_fg,
                         padding=(12, 4))
        style.map("TNotebook.Tab",
                  background=[("selected", APPEARANCE.dark_accent)],
                  foreground=[("selected", APPEARANCE.dark_fg)])
        style.configure("Treeview", background=APPEARANCE.dark_entry_bg, foreground=APPEARANCE.dark_fg,
                         fieldbackground=APPEARANCE.dark_entry_bg, bordercolor=APPEARANCE.dark_border)
        style.map("Treeview",
                  background=[("selected", APPEARANCE.dark_accent)],
                  foreground=[("selected", APPEARANCE.dark_fg)])
        style.configure("Treeview.Heading", background=APPEARANCE.dark_bg_panel, foreground=APPEARANCE.dark_fg,
                         bordercolor=APPEARANCE.dark_border)
        # Без цього "clam" на hover заголовка колонки падає на світлий дефолт (знайдений баг).
        style.map("Treeview.Heading",
                  background=[("active", APPEARANCE.dark_bg_panel), ("pressed", APPEARANCE.dark_entry_bg)],
                  foreground=[("active", APPEARANCE.dark_fg), ("pressed", APPEARANCE.dark_fg)])
        style.configure("TCombobox", fieldbackground=APPEARANCE.dark_entry_bg, foreground=APPEARANCE.dark_fg,
                         background=APPEARANCE.dark_entry_bg, bordercolor=APPEARANCE.dark_border,
                         arrowcolor=APPEARANCE.dark_fg)
        style.map("TCombobox",
                  fieldbackground=[("readonly", APPEARANCE.dark_entry_bg)],
                  foreground=[("readonly", APPEARANCE.dark_fg)])
        # Випадний список Combobox — окремий Tk-Listbox, стилем ttk не керується.
        self.root.option_add("*TCombobox*Listbox.background", APPEARANCE.dark_entry_bg)
        self.root.option_add("*TCombobox*Listbox.foreground", APPEARANCE.dark_fg)
        self.root.option_add("*TCombobox*Listbox.selectBackground", APPEARANCE.dark_accent)
        self.root.option_add("*TCombobox*Listbox.selectForeground", APPEARANCE.dark_fg)

    def _style_text_widget(self, widget):
        widget.configure(
            bg=APPEARANCE.dark_entry_bg, fg=APPEARANCE.dark_fg,
            insertbackground=APPEARANCE.dark_fg,
            selectbackground=APPEARANCE.dark_accent, selectforeground=APPEARANCE.dark_fg,
            relief="flat", borderwidth=1,
        )

    def _make_checkbutton(self, parent, text: str, variable: tk.BooleanVar, command=None) -> tk.Checkbutton:
        """Plain tk.Checkbutton, не ttk — "clam" малює позначений стан як хрестик, не галочку.
        Докладніше: docs/dev-notes.md → "appearance.py: _make_checkbutton"."""
        return tk.Checkbutton(
            parent, text=text, variable=variable, command=command,
            bg=APPEARANCE.dark_bg, fg=APPEARANCE.dark_fg,
            selectcolor=APPEARANCE.dark_entry_bg,
            activebackground=APPEARANCE.dark_bg, activeforeground=APPEARANCE.dark_fg,
            highlightthickness=0, borderwidth=0,
        )

    # Windows/Tk: стандартні біндинги Ctrl+C/V/A прив'язані до keysym (символу), який
    # ОС перекладає за поточною розкладкою клавіатури — під нелатинською розкладкою
    # фізична клавіша "V" дає інший keysym (кириличну літеру), і Control-v мовчки не
    # спрацьовує. event.keycode — фізична клавіша, від розкладки не залежить.
    # Докладніше: docs/dev-notes.md → "_make_readonly_selectable / keycode".
    _KEYCODE_A = 65
    _KEYCODE_C = 67
    _KEYCODE_V = 86
    _KEYCODE_INSERT = 45

    def _make_readonly_selectable(self, text_widget, on_paste=None) -> None:
        """Текст лишається виділюваним/копійованим (Ctrl+C, виділення мишею), але без
        редагування — на відміну від state="disabled", який у Tk блокує й виділення теж.
        Ctrl+C/Ctrl+A виконуються ЯВНО (event_generate/tag_add), а не просто "пропускаються"
        далі — інакше довелось би покладатись на штатний Tk-біндинг, який має ту саму
        проблему з розкладкою, що й вирішуємо тут. on_paste — якщо задано, Ctrl+V (теж за
        keycode) викликає його замість вставки в сам віджет (поле хендшейку: Ctrl+V ==
        кнопка "Вставити хендшейк"). Докладніше: docs/dev-notes.md →
        "appearance.py: _make_readonly_selectable"."""
        navigation_keys = {"Left", "Right", "Up", "Down", "Prior", "Next", "Home", "End", "Tab"}

        def _block_edit(event):
            if event.keysym in navigation_keys:
                return None
            if event.state & 0x4:
                if event.keycode in (self._KEYCODE_C, self._KEYCODE_INSERT):
                    text_widget.event_generate("<<Copy>>")
                    return "break"
                if event.keycode == self._KEYCODE_A:
                    text_widget.tag_add("sel", "1.0", "end")
                    return "break"
                if on_paste is not None and event.keycode == self._KEYCODE_V:
                    on_paste()
                    return "break"
            return "break"

        text_widget.bind("<Key>", _block_edit)

    def _make_reserved_label(self, parent, text: str, wraplength: int, height: int, **pack_kwargs) -> ttk.Label:
        """Label у Frame фіксованої висоти — щоб ріст тексту (1->N рядків) не двигав вікно.
        Докладніше: docs/dev-notes.md → "appearance.py: _make_reserved_label"."""
        holder = ttk.Frame(parent, height=height)
        holder.pack(fill="x", **pack_kwargs)
        holder.pack_propagate(False)
        label = ttk.Label(holder, text=text, wraplength=wraplength, justify="left")
        label.pack(anchor="nw", fill="both")
        return label

    # ---- побудова інтерфейсу -----------------------------------------

    def _build_ui(self):
        pad = {"padx": 10, "pady": 6}

        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True)

        tab_session = ttk.Frame(self.notebook)
        tab_profile = ttk.Frame(self.notebook)
        tab_log = ttk.Frame(self.notebook)
        tab_help = ttk.Frame(self.notebook)
        self.notebook.add(tab_session, text="Сеанс")
        self.notebook.add(tab_profile, text="Профіль")
        self.notebook.add(tab_log, text="Консоль / Лог")
        self.notebook.add(tab_help, text="Довідка")

        self._build_session_tab(tab_session)
        self._build_profile_tab(tab_profile, pad)
        self._build_log_tab(tab_log, pad)
        self._build_help_tab(tab_help, pad)

        # --- Статус (спільний для всіх вкладок) ---
        self.var_status = tk.StringVar(value="Готово.")
        status_bar = ttk.Label(self.root, textvariable=self.var_status, relief="sunken", anchor="w")
        status_bar.pack(fill="x", side="bottom")

    def _make_scrollable(self, parent: ttk.Frame) -> ttk.Frame:
        """Внутрішній ttk.Frame, що прокручується колесом миші/скролбаром.
        Докладніше: docs/dev-notes.md → "appearance.py: _make_scrollable"."""
        canvas = tk.Canvas(parent, bg=APPEARANCE.dark_bg, highlightthickness=0)
        vscroll = ttk.Scrollbar(parent, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=vscroll.set)
        canvas.pack(side="left", fill="both", expand=True)
        vscroll.pack(side="right", fill="y")

        inner = ttk.Frame(canvas)
        window_id = canvas.create_window((0, 0), window=inner, anchor="nw")

        def _on_inner_configure(_event=None):
            canvas.configure(scrollregion=canvas.bbox("all"))

        def _on_canvas_configure(event):
            canvas.itemconfigure(window_id, width=event.width)

        inner.bind("<Configure>", _on_inner_configure)
        canvas.bind("<Configure>", _on_canvas_configure)

        def _on_mousewheel(event):
            canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

        canvas.bind("<Enter>", lambda _e: canvas.bind_all("<MouseWheel>", _on_mousewheel))
        canvas.bind("<Leave>", lambda _e: canvas.unbind_all("<MouseWheel>"))

        return inner

    def _build_session_tab(self, parent: ttk.Frame):
        """Двоколонковий layout: зліва сеанс/з'єднання (прокручується), справа дерево файлів.
        Чому: docs/dev-notes.md → "appearance.py: _build_session_tab"."""
        paned = ttk.PanedWindow(parent, orient="horizontal")
        paned.pack(fill="both", expand=True)

        left_outer = ttk.Frame(paned)
        right_outer = ttk.Frame(paned)
        paned.add(left_outer, weight=2)
        paned.add(right_outer, weight=3)

        left = self._make_scrollable(left_outer)
        self._build_session_left(left)
        self._build_session_right(right_outer)

    def _build_session_left(self, parent: ttk.Frame):
        pad = {"padx": 10, "pady": 6}

        # Пароль — теж параметр хендшейку, окремої секції не потребує; ітерації й порт в один рядок.
        frame_params = ttk.LabelFrame(parent, text="Параметри хендшейку")
        frame_params.pack(fill="x", **pad)
        frame_params.columnconfigure(1, weight=1)

        ttk.Label(frame_params, text="Парольна фраза:").grid(
            row=0, column=0, sticky="w", padx=8, pady=(8, 4)
        )
        self.var_passphrase = tk.StringVar()
        self.entry_passphrase = ttk.Entry(frame_params, textvariable=self.var_passphrase, show="*")
        self.entry_passphrase.grid(row=0, column=1, columnspan=3, sticky="ew", padx=(0, 4), pady=(8, 4))
        self.var_show_pass = tk.BooleanVar(value=False)
        self._make_checkbutton(
            frame_params, "Показати", self.var_show_pass, self._toggle_pass_visibility
        ).grid(row=0, column=4, sticky="w", padx=(0, 8), pady=(8, 4))
        ttk.Button(frame_params, text="Згенерувати", command=self.on_generate_passphrase).grid(
            row=0, column=5, sticky="w", padx=(0, 8), pady=(8, 4)
        )

        ttk.Label(frame_params, text="Ітерацій:").grid(
            row=1, column=0, sticky="w", padx=8, pady=(0, 8)
        )
        self.var_iterations = tk.StringVar(value=str(CONNECTION.default_iterations))
        ttk.Entry(frame_params, textvariable=self.var_iterations, width=10).grid(
            row=1, column=1, sticky="w", padx=(0, 12), pady=(0, 8)
        )
        ttk.Label(frame_params, text="Порт:").grid(
            row=1, column=2, sticky="w", padx=(0, 4), pady=(0, 8)
        )
        # Дефолт поля — профіль.default_port (CLI --port, якщо заданий, підставляється
        # пізніше в __init__, ПІСЛЯ _build_ui). tuning.CONNECTION.default_port тут не
        # використовується напряму — profile.default_port сам fallback-иться на нього
        # при завантаженні профілю (local_config.py), якщо в файлі профілю його нема.
        self.var_port = tk.StringVar(value=str(self.profile.default_port))
        ttk.Entry(frame_params, textvariable=self.var_port, width=8).grid(
            row=1, column=3, sticky="w", padx=(0, 8), pady=(0, 8)
        )

        # Зміна будь-якого з трьох параметрів хендшейку ПІСЛЯ того, як хендшейк уже
        # згенеровано/оброблено, робить поточний ключ/канал недійсним — інша сторона
        # деривувала ключ зі старим значенням. dev-notes.md → "_invalidate_session_if_active".
        self.var_passphrase.trace_add("write", self._invalidate_session_if_active)
        self.var_iterations.trace_add("write", self._invalidate_session_if_active)
        self.var_port.trace_add("write", self._invalidate_session_if_active)
        # Окремий trace (не пов'язаний з інвалідацією сеансу) — відстежує лише факт
        # СПРАВЖНЬОЇ ручної правки поля користувачем, для precedence з профілем
        # (dev-notes.md → "local_config.py").
        self.var_port.trace_add("write", self._mark_port_overridden)

        # БЕЗ кнопки: перевірка запускається автоматично (_start_connection_setup), лише звіт тут.
        frame_conn = ttk.LabelFrame(parent, text="Мережеві налаштування")
        frame_conn.pack(fill="x", **pad)
        # Фіксована висота (1 vs 2 рядки тексту) — інакше вікно "стрибало" по висоті; dev-notes.md.
        status_holder = ttk.Frame(frame_conn, height=40)
        status_holder.pack(fill="x", padx=8, pady=8)
        status_holder.pack_propagate(False)
        self.var_conn_status = tk.StringVar(value="Очікування автоматичної перевірки (UPnP → STUN)...")
        ttk.Label(status_holder, textvariable=self.var_conn_status, wraplength=340, justify="left").pack(
            anchor="nw", fill="both"
        )

        # --- Секція: хендшейк — ОДНЕ поле, БЕЗ перемикача ролі: один сеанс = одна
        # роль (dev-notes.md → "Секція «Хендшейк»"). "Згенерувати" й "Вставити
        # хендшейк" — обидві дії, що можуть почати новий сеанс (з підтвердженням,
        # якщо старий ще активний, _confirm_reset_if_needed). Кожна кнопка має
        # tooltip з описом функції.
        frame_handshake = ttk.LabelFrame(parent, text="Хендшейк")
        frame_handshake.pack(fill="x", **pad)

        self._handshake_kind: str | None = None  # _HANDSHAKE_KIND_MINE/_PEER — лише внутрішній стан
        self._handshake_text: str = ""
        self._handshake_fingerprint: str = _FINGERPRINT_PLACEHOLDER

        btns_handshake = ttk.Frame(frame_handshake)
        btns_handshake.pack(fill="x", padx=8, pady=(8, 4))

        btn_generate = ttk.Button(
            btns_handshake, text="Згенерувати", style="Accent.TButton",
            command=self.on_generate_handshake,
        )
        btn_generate.pack(side="left")
        _Tooltip(
            btn_generate,
            "Згенерувати свій хендшейк — одразу копіюється в буфер. Надішліть його співрозмовнику через месенджер; застосунок чекатиме на з'єднання.",
            delay_ms=APPEARANCE.tooltip_delay_ms,
            wraplength=APPEARANCE.tooltip_wraplength,
        )

        btn_paste = ttk.Button(
            btns_handshake, text="Вставити хендшейк", style="Accent.TButton",
            command=self.on_paste_handshake,
        )
        btn_paste.pack(side="left", padx=8)
        _Tooltip(
            btn_paste,
            "Вставити хендшейк, отриманий від співрозмовника (з буфера обміну) — застосунок одразу підключиться.",
            delay_ms=APPEARANCE.tooltip_delay_ms,
            wraplength=APPEARANCE.tooltip_wraplength,
        )

        self.text_handshake = scrolledtext.ScrolledText(
            frame_handshake, height=APPEARANCE.text_widget_height, wrap="char", font=self._mono_font
        )
        self.text_handshake.pack(fill="x", padx=8, pady=(0, 4))
        self._style_text_widget(self.text_handshake)
        # Не state="disabled" — блокує й виділення мишею (dev-notes.md), а згенерований
        # хендшейк звідси треба й вручну виділяти/копіювати. Ctrl+V (за keycode, незалежно
        # від розкладки) == "Вставити хендшейк" — вставка йде лише через on_paste_handshake.
        self._make_readonly_selectable(self.text_handshake, on_paste=self.on_paste_handshake)

        self.lbl_handshake_fp = self._make_reserved_label(
            frame_handshake, _FINGERPRINT_PLACEHOLDER, wraplength=340, height=40, padx=8, pady=(0, 8)
        )

        # --- Секція: канал передачі — автоматично, щойно відомі local_key і
        # адреса іншої сторони (після generate + process incoming, у будь-якому
        # порядку). Сервісна функція з docs/concept.md: establish + HMAC-звірка.
        frame_channel = ttk.LabelFrame(parent, text="Канал передачі")
        frame_channel.pack(fill="x", **pad)
        self.var_channel_status = tk.StringVar(value="Очікування хендшейку з обох сторін...")
        # 80px — статус може містити текст помилки з transport (напр. "порт зайнятий"), не лише 1-2 рядки.
        channel_label = self._make_reserved_label(
            frame_channel, "", wraplength=340, height=80, padx=8, pady=8,
        )
        channel_label.configure(textvariable=self.var_channel_status)
        ttk.Button(frame_channel, text="Перевірити канал", command=self.on_test_channel).pack(
            anchor="w", padx=8, pady=(0, 8)
        )

    def _build_session_right(self, parent: ttk.Frame):
        pad = {"padx": 10, "pady": 6}

        # --- Секція: вибір файлу/каталогу — права колонка на всю висоту ---
        frame_file = ttk.LabelFrame(parent, text="Що передати")
        frame_file.pack(fill="both", expand=True, **pad)

        btns_file = ttk.Frame(frame_file)
        btns_file.pack(fill="x", padx=8, pady=8)
        ttk.Button(btns_file, text="Обрати файл...", command=self.on_choose_file).pack(
            side="left"
        )
        ttk.Button(
            btns_file, text="Обрати каталог...", command=self.on_choose_dir
        ).pack(side="left", padx=8)

        self.lbl_selected = self._make_reserved_label(
            frame_file, "Нічого не обрано", wraplength=520, height=60, padx=8, pady=(0, 4)
        )

        # Дерево з'являється лише для каталогу; кнопка передачі — нижче, поза деревом
        # (потрібна і для одиночного файлу). Підкаталоги — лінивим довантаженням.
        self.frame_tree = ttk.Frame(frame_file)

        tree_toolbar = ttk.Frame(self.frame_tree)
        tree_toolbar.pack(fill="x", padx=8, pady=(0, 4))
        ttk.Button(
            tree_toolbar, text="Позначити все", command=lambda: self._set_all_checked(True)
        ).pack(side="left")
        ttk.Button(
            tree_toolbar, text="Зняти все", command=lambda: self._set_all_checked(False)
        ).pack(side="left", padx=8)

        tree_container = ttk.Frame(self.frame_tree)
        tree_container.pack(fill="both", expand=True, padx=8)
        self.tree_files = ttk.Treeview(
            tree_container, columns=("chk", "size"), show="tree headings", selectmode="none",
        )
        self.tree_files.heading("#0", text="Ім'я")
        self.tree_files.heading("chk", text="✓")
        self.tree_files.heading("size", text="Розмір")
        self.tree_files.column("#0", width=340, stretch=True)
        self.tree_files.column("chk", width=32, anchor="center", stretch=False)
        self.tree_files.column("size", width=90, anchor="e", stretch=False)
        tree_scroll = ttk.Scrollbar(tree_container, orient="vertical", command=self.tree_files.yview)
        self.tree_files.configure(yscrollcommand=tree_scroll.set)
        self.tree_files.pack(side="left", fill="both", expand=True)
        tree_scroll.pack(side="left", fill="y")
        self.tree_files.bind("<Button-1>", self._on_tree_click)
        self.tree_files.bind("<<TreeviewOpen>>", self._on_tree_open)

        # Архів vs "як є" — лише для каталогу (одиночний файл нема що архівувати).
        self.var_archive_before_send = tk.BooleanVar(value=True)
        self._make_checkbutton(
            self.frame_tree, "Запакувати в один архів (інакше — передати файли як є)",
            self.var_archive_before_send,
        ).pack(anchor="w", padx=8, pady=(4, 0))

        # Стиснення й шифрування архіву — стосуються лише режиму "запакувати в архів".
        # Вибір AES128/256 автоматично вмикає архівування (шифрування без архіву не має сенсу).
        options_row = ttk.Frame(self.frame_tree)
        options_row.pack(fill="x", padx=8, pady=(4, 0))

        self.var_compress = tk.BooleanVar(value=ENCRYPTION.default_compress)
        self._make_checkbutton(options_row, "Стиснення", self.var_compress).pack(side="left")

        ttk.Label(options_row, text="Шифрування:").pack(side="left", padx=(16, 4))
        default_label = _ENCRYPTION_LEVEL_LABELS[EncryptionLevel(ENCRYPTION.default_level)]
        self.var_encryption_label = tk.StringVar(value=default_label)
        encryption_combo = ttk.Combobox(
            options_row, textvariable=self.var_encryption_label,
            values=list(_ENCRYPTION_LEVEL_LABELS.values()), state="readonly", width=32,
        )
        encryption_combo.pack(side="left")
        self.var_encryption_label.trace_add("write", self._on_encryption_level_change)

        btns_transfer = ttk.Frame(frame_file)
        btns_transfer.pack(fill="x", padx=8, pady=8)
        self._transfer_row = btns_transfer  # опорна точка для pack(..., before=...) у on_choose_dir
        self.btn_transfer = ttk.Button(
            btns_transfer, text="Ініціалізувати передачу", style="Accent.TButton",
            command=self.on_initiate_transfer, state="disabled",
        )
        self.btn_transfer.pack(side="left")
        # "Надіслати" — активна лише коли і payload готовий (Ініціалізувати передачу),
        # і канал підтверджений (transport.verify_channel) — див. _update_send_button_state.
        self.btn_send = ttk.Button(
            btns_transfer, text="Надіслати", style="Accent.TButton",
            command=self.on_send_files, state="disabled",
        )
        self.btn_send.pack(side="left", padx=8)
        self.var_transfer_status = tk.StringVar(value="")
        ttk.Label(btns_transfer, textvariable=self.var_transfer_status, wraplength=340).pack(
            side="left", padx=8
        )

        # Прогрес поточної передачі (send_progress/receive_progress з transport.py через чергу).
        progress_row = ttk.Frame(frame_file)
        progress_row.pack(fill="x", padx=8, pady=(0, 8))
        self.var_progress_text = tk.StringVar(value="")
        ttk.Label(progress_row, textvariable=self.var_progress_text, wraplength=520).pack(anchor="w")
        self.progress_bar = ttk.Progressbar(progress_row, orient="horizontal", mode="determinate", maximum=100)
        self.progress_bar.pack(fill="x", pady=(2, 0))

    def _build_profile_tab(self, parent: ttk.Frame, pad: dict):
        """local_config.py: client_id + дефолтні каталоги + дефолтний порт. На диск —
        лише по кнопці "Зберегти профіль". Дефолтний порт — dev-notes.md → "local_config.py"."""
        frame_id = ttk.LabelFrame(parent, text="Ідентифікатор клієнта")
        frame_id.pack(fill="x", **pad)
        self.var_client_id = tk.StringVar(value=self.profile.client_id)
        ttk.Entry(frame_id, textvariable=self.var_client_id).pack(fill="x", padx=8, pady=8)

        frame_dirs = ttk.LabelFrame(parent, text="Каталоги за замовчуванням")
        frame_dirs.pack(fill="x", **pad)
        frame_dirs.columnconfigure(0, weight=1)

        ttk.Label(frame_dirs, text="Вхідні файли (куди зберігати отримане):").grid(
            row=0, column=0, columnspan=2, sticky="w", padx=8, pady=(8, 2)
        )
        self.var_incoming_dir = tk.StringVar(value=self.profile.incoming_dir)
        ttk.Entry(frame_dirs, textvariable=self.var_incoming_dir).grid(
            row=1, column=0, sticky="ew", padx=(8, 4)
        )
        ttk.Button(frame_dirs, text="Обрати...", command=self.on_choose_incoming_dir).grid(
            row=1, column=1, padx=(0, 8)
        )
        ttk.Button(frame_dirs, text="Відкрити", command=self.on_open_incoming_dir).grid(
            row=1, column=2, padx=(0, 8)
        )

        ttk.Label(frame_dirs, text="Вихідні файли (звідки типово брати для передачі):").grid(
            row=2, column=0, columnspan=2, sticky="w", padx=8, pady=(10, 2)
        )
        self.var_outgoing_dir = tk.StringVar(value=self.profile.outgoing_dir)
        ttk.Entry(frame_dirs, textvariable=self.var_outgoing_dir).grid(
            row=3, column=0, sticky="ew", padx=(8, 4), pady=(0, 8)
        )
        ttk.Button(frame_dirs, text="Обрати...", command=self.on_choose_outgoing_dir).grid(
            row=3, column=1, padx=(0, 8), pady=(0, 8)
        )

        # Дефолтний порт профілю — низ ієрархії precedence (профіль < CLI --port < ручна
        # правка поля "Порт" на вкладці "Сеанс"). dev-notes.md → "local_config.py".
        frame_port = ttk.LabelFrame(parent, text="Порт за замовчуванням")
        frame_port.pack(fill="x", **pad)
        ttk.Label(frame_port, text="Порт:").grid(row=0, column=0, sticky="w", padx=8, pady=8)
        self.var_profile_default_port = tk.StringVar(value=str(self.profile.default_port))
        entry_profile_port = ttk.Entry(frame_port, textvariable=self.var_profile_default_port, width=8)
        entry_profile_port.grid(row=0, column=1, sticky="w", padx=(0, 8), pady=8)
        _Tooltip(
            entry_profile_port,
            "Порт, яким одразу заповнюється поле «Порт» на вкладці «Сеанс» при наступному "
            "запуску. При збереженні тут одразу оновлює й поточне поле «Порт» — але лише "
            "якщо ви ще не редагували те поле вручну цього сеансу і не задали --port у CLI "
            "(hierarchy: профіль < CLI < ручна правка).",
            delay_ms=APPEARANCE.tooltip_delay_ms,
            wraplength=APPEARANCE.tooltip_wraplength,
        )

        frame_save = ttk.Frame(parent)
        frame_save.pack(fill="x", **pad)
        ttk.Button(
            frame_save, text="Зберегти профіль", style="Accent.TButton", command=self.on_save_profile
        ).pack(side="left")
        self.var_profile_status = tk.StringVar(value=f"Конфіг: {config_path()}")
        ttk.Label(frame_save, textvariable=self.var_profile_status, wraplength=440).pack(
            side="left", padx=8
        )

    def _build_log_tab(self, parent: ttk.Frame, pad: dict):
        """Діагностична вкладка (UPnP/хендшейк), щоб не засмічувати основний екран."""
        btns_log = ttk.Frame(parent)
        btns_log.pack(fill="x", **pad)
        ttk.Button(btns_log, text="Очистити", command=self._clear_log).pack(side="left")

        self.text_log = scrolledtext.ScrolledText(parent, wrap="word")
        self.text_log.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        self._style_text_widget(self.text_log)
        # Не state="disabled" — це в Tk блокує й виділення мишею, не лише редагування.
        self._make_readonly_selectable(self.text_log)

    def _log(self, message: str):
        timestamp = time.strftime("%H:%M:%S")
        self.text_log.insert("end", f"[{timestamp}] {message}\n")
        self.text_log.see("end")

    def _clear_log(self):
        self.text_log.delete("1.0", "end")

    def _build_help_tab(self, parent: ttk.Frame, pad: dict):
        """Лаконічна довідка: кроки використання + ключові особливості безпеки.
        Докладніше: docs/concept.md, docs/dev-notes.md."""
        text = scrolledtext.ScrolledText(parent, wrap="word")
        text.pack(fill="both", expand=True, padx=10, pady=10)
        self._style_text_widget(text)
        text.insert("end", _HELP_TEXT)
        self._make_readonly_selectable(text)

    def _toggle_pass_visibility(self):
        self.entry_passphrase.configure(show="" if self.var_show_pass.get() else "*")

    def on_generate_passphrase(self):
        """Замінює поле парольної фрази криптографічно випадковою (secrets, не random) —
        передати іншій стороні тим самим захищеним каналом, що й хендшейк."""
        self.var_passphrase.set(secrets.token_urlsafe(CONNECTION.generated_passphrase_bytes))
        self.var_show_pass.set(True)
        self._toggle_pass_visibility()
        self._set_status("Парольну фразу згенеровано — скопіюйте й передайте іншій стороні.")
        self._log("Згенеровано нову парольну фразу.")

    def _on_encryption_level_change(self, *_args):
        """AES128/256 без архіву не має сенсу — авто-вмикаємо архівування при виборі AES."""
        level = _ENCRYPTION_LABEL_TO_LEVEL[self.var_encryption_label.get()]
        if level != EncryptionLevel.NONE:
            self.var_archive_before_send.set(True)

    # ---- допоміжне ------------------------------------------------------

    def _get_iterations(self) -> int | None:
        """Нижче CONNECTION.min_iterations відхиляємо: сторона, що вставляє, затискає "iter"
        знизу до min_iterations (_parse_incoming_handshake) — ключі гарантовано розійшлися б."""
        try:
            n = int(self.var_iterations.get())
            if n < CONNECTION.min_iterations:
                raise ValueError
            return n
        except ValueError:
            messagebox.showerror(
                "Помилка",
                f"Кількість ітерацій має бути цілим числом не менше {CONNECTION.min_iterations}.",
            )
            return None

    def _get_port(self) -> int | None:
        try:
            n = int(self.var_port.get())
            if not (CONNECTION.min_port <= n <= CONNECTION.max_port):
                raise ValueError
            return n
        except ValueError:
            messagebox.showerror(
                "Помилка",
                f"Порт має бути цілим числом від {CONNECTION.min_port} до {CONNECTION.max_port}.",
            )
            return None

    def _get_profile_default_port(self) -> int | None:
        """Валідація поля "Порт за замовчуванням" на вкладці "Профіль" — той самий діапазон,
        що й _get_port, окрема помилка (не плутати з полем "Порт" на вкладці "Сеанс")."""
        try:
            n = int(self.var_profile_default_port.get())
            if not (CONNECTION.min_port <= n <= CONNECTION.max_port):
                raise ValueError
            return n
        except ValueError:
            messagebox.showerror(
                "Помилка",
                f"Порт за замовчуванням має бути цілим числом від {CONNECTION.min_port} "
                f"до {CONNECTION.max_port}.",
            )
            return None

    def _set_status(self, text: str):
        self.var_status.set(text)

    # ---- обробники подій -------------------------------------------------

    def _prompt_passphrase(self, title: str, message: str, initial: str = "") -> str | None:
        """Модальне віконце введення парольної фрази — заміна messagebox-попередження
        при порожній фразі (Генерувати/Вставити) і засіб виправити фразу після
        розбіжності кодів підтвердження (verification_failed). Маскування узгоджене
        з entry_passphrase (чекбокс "Показати"); Enter=OK, Esc=Cancel. Повертає
        непорожній введений текст або None (Cancel/порожньо/закрито хрестиком).
        Докладніше: docs/dev-notes.md → "_prompt_passphrase"."""
        dialog = tk.Toplevel(self.root)
        dialog.title(title)
        dialog.transient(self.root)
        dialog.resizable(False, False)
        dialog.configure(bg=APPEARANCE.dark_bg)

        result: dict = {"value": None}

        ttk.Label(dialog, text=message, wraplength=360, justify="left").pack(
            padx=12, pady=(12, 6), anchor="w"
        )

        var_value = tk.StringVar(value=initial)
        row = ttk.Frame(dialog)
        row.pack(fill="x", padx=12, pady=(0, 6))
        entry = ttk.Entry(row, textvariable=var_value, show="*")
        entry.pack(side="left", fill="x", expand=True)
        var_show = tk.BooleanVar(value=False)
        self._make_checkbutton(
            row, "Показати", var_show,
            lambda: entry.configure(show="" if var_show.get() else "*"),
        ).pack(side="left", padx=(6, 0))

        btns = ttk.Frame(dialog)
        btns.pack(fill="x", padx=12, pady=(0, 12))

        def _ok(_event=None):
            result["value"] = var_value.get()
            dialog.destroy()

        def _cancel(_event=None):
            dialog.destroy()

        ttk.Button(btns, text="OK", style="Accent.TButton", command=_ok).pack(side="left")
        ttk.Button(btns, text="Скасувати", command=_cancel).pack(side="left", padx=8)

        dialog.bind("<Return>", _ok)
        dialog.bind("<Escape>", _cancel)
        dialog.protocol("WM_DELETE_WINDOW", _cancel)
        entry.focus_set()

        self._modal_depth += 1
        try:
            dialog.grab_set()
            self.root.wait_window(dialog)
        finally:
            self._modal_depth -= 1

        return result["value"] or None

    def _session_active(self) -> bool:
        """Чи вже стартовано сеанс (ключ дериновано і/або канал уже встановлюється/
        встановлено) — визначає, чи потрібне підтвердження перед новим
        Генерувати/Вставити (ONE SESSION = ONE ROLE, dev-notes.md)."""
        return (
            self.local_key is not None or self.peer_key is not None
            or self.channel_socket is not None or self._channel_thread_started
        )

    def _confirm_reset_if_needed(self) -> bool:
        """Якщо сеанс уже активний — питає підтвердження й, у разі згоди, скидає
        стан. Повертає True, якщо викликач може продовжувати дію (сеансу не було
        АБО скидання підтверджено); False — користувач відмовився, дію потрібно
        перервати без жодних змін стану."""
        if not self._session_active():
            return True
        self._modal_depth += 1  # verification_failed під час askyesno відкладається (_handle_channel_event)
        try:
            confirmed = messagebox.askyesno(_NEW_SESSION_CONFIRM_TITLE, _NEW_SESSION_CONFIRM_MESSAGE)
        finally:
            self._modal_depth -= 1
        if not confirmed:
            return False
        self._reset_session_state()
        self._log("Новий сеанс підтверджено користувачем — попередній хендшейк і канал скинуто.")
        return True

    def _reset_session_state(self):
        """Повністю скидає стан сеансу: епоху (застарілі фонові потоки більше не
        мають ефекту — dev-notes.md → "_session_epoch"), ключі, адресу іншої
        сторони, канал, текст/код хендшейку. Спільна логіка для
        _invalidate_session_if_active (зміна параметра хендшейку) і
        _confirm_reset_if_needed (свідомий новий сеанс). Після скидання щонайбільше
        один із local_key/peer_key колись знову буде встановлений — _session_key()."""
        self._reset_channel_attempt()

        self.local_key = None
        self.local_salt = None
        self.local_session_id = None
        self.local_iterations = None
        self._local_handshake_net = ""
        self.peer_key = None
        self.peer_host = None
        self.peer_port = None
        self.local_port = None

        self._handshake_kind = None
        self._handshake_text = ""
        self._handshake_fingerprint = _FINGERPRINT_PLACEHOLDER
        self._render_handshake_field()
        self._update_send_button_state()

    def _reset_channel_attempt(self):
        """Скидає лише СПРОБУ каналу, не хендшейк: епоха, stop_event, сокет, channel_key,
        прапорці, зашифрований payload. Спільна частина повного скидання
        (_reset_session_state) і повтору після розбіжності ключів (_retry_after_mismatch),
        де salt/sid/текст хендшейку мають лишитись."""
        self._session_epoch += 1  # застарілі фонові потоки з попередньої спроби більше не мають ефекту

        # Сигналізує ПОТОЧНОМУ _channel_establish_worker (якщо ще працює) зупинитись
        # якнайшвидше — інакше його listening-сокет тримає local_port ще до
        # TRANSPORT.connect_timeout_seconds (300с). Новий Event — для НАСТУПНОЇ спроби;
        # establish_connection реагує на stop_event у межах accept_poll_timeout_seconds
        # (0.5с) — port звільняється швидко, хоч сам застарілий потік ще донесе (і
        # _handle_channel_event проігнорує за epoch) свою подію пізніше.
        # Докладніше: docs/dev-notes.md → "_reset_session_state — звільнення порту".
        self._channel_stop_event.set()
        self._channel_stop_event = threading.Event()

        _close_socket(self.channel_socket)
        self.channel_socket = None
        self.channel_key = None
        self.channel_verified = False
        self._channel_thread_started = False
        self._channel_pending = False
        self._discard_key_bound_payload()
        self._update_send_button_state()

    def _discard_key_bound_payload(self):
        """AES-архів зашифровано ключем попередньої спроби — після скидання він не
        відповідатиме новому channel_key. Видаляємо (файл створює сам застосунок у
        EXCHANGE.pack_subdir_name) і просимо ініціалізувати передачу заново."""
        if self._transfer_archive_key is None:
            return
        archive = self.packed_archive_path
        if archive and os.path.basename(os.path.dirname(archive)) == EXCHANGE.pack_subdir_name:
            try:
                os.remove(archive)
            except OSError:
                pass
        self._transfer_archive_key = None
        self.packed_archive_path = None
        self.transfer_payload = None
        if self.selected_path and self.selected_is_dir:
            self.lbl_selected.configure(text=f"Каталог: {self.selected_path}")
        self.var_transfer_status.set(
            "Сеанс змінено — зашифрований архів скинуто. Натисніть «Ініціалізувати передачу» ще раз."
        )
        self._log("Зашифрований архів скинуто (ключ сеансу змінився) — потрібна повторна ініціалізація передачі.")

    def on_generate_handshake(self):
        if not self._confirm_reset_if_needed():
            return

        passphrase = self.var_passphrase.get()
        if not passphrase:
            passphrase = self._prompt_passphrase(
                "Парольна фраза", "Введіть парольну фразу, щоб згенерувати хендшейк.",
            )
            if passphrase is None:
                return
            self.var_passphrase.set(passphrase)  # сеанс ще неактивний — trace нічого не скине

        iterations = self._get_iterations()
        if iterations is None:
            return
        port = self._get_port()
        if port is None:
            return

        # public_port — реально спостережений зовнішній порт (може відрізнятись від
        # локального при STUN — dev-notes.md); None, якщо з'єднання не налаштовувалось.
        effective_port = self.public_port if self.public_port is not None else port

        text, salt, session_id, host = build_handshake_packet(
            iterations, effective_port, host=self.public_host
        )
        self.local_salt = salt
        self.local_session_id = session_id
        self.local_iterations = iterations
        self._local_handshake_net = f"{host}:{effective_port}"
        self.local_key = derive_key(passphrase, salt, iterations)
        self.local_port = port  # порт, на якому РЕАЛЬНО слухатимемо (не effective_port — dev-notes.md)

        self._show_handshake(_HANDSHAKE_KIND_MINE, text, self._local_fingerprint_text())
        # Одразу в буфер — окремої кнопки "Скопіювати" нема; ручне виділення в полі теж працює.
        self.root.clipboard_clear()
        self.root.clipboard_append(text)

        host_kind = _HOST_SOURCE_LABELS[self.public_host_source]
        self._set_status("Хендшейк згенеровано й скопійовано в буфер обміну. Надішліть його через месенджер.")
        self._log(
            f"Хендшейк згенеровано: sid={session_id}, net={host}:{effective_port} ({host_kind}), "
            f"iter={iterations}."
        )
        self._maybe_start_channel_establishment()

    def _local_fingerprint_text(self) -> str:
        return (
            f"Код підтвердження: {key_fingerprint(self.local_key)}  "
            f"(sid={self.local_session_id}, net={self._local_handshake_net})"
        )

    def _render_handshake_field(self):
        """Показує в полі поточний текст/код й код підтвердження."""
        self.text_handshake.delete("1.0", "end")
        self.text_handshake.insert("1.0", self._handshake_text)
        self.lbl_handshake_fp.configure(text=self._handshake_fingerprint)

    def _show_handshake(self, kind: str, text: str, fingerprint: str):
        """Записує поточний вміст/код і його "роль" (лише внутрішній прапорець —
        генерація → MINE, вставка → PEER) і перемальовує поле/підпис."""
        self._handshake_kind = kind
        self._handshake_text = text
        self._handshake_fingerprint = fingerprint
        self._render_handshake_field()

    def on_paste_handshake(self):
        """Вставляє вміст буфера обміну напряму (root.clipboard_get()), в обхід
        Ctrl+V/контекстного меню — Tk-віджети Text не мають штатного контекстного
        меню "Вставити", а надійність самого Ctrl+V залежить від фокусу. Одразу
        обробляє вставлене (окремої кнопки "Обробити" нема) — симетрично до
        "Згенерувати", що одразу копіює. Спочатку читає буфер (щоб порожній буфер
        не запускав дарма запит підтвердження нового сеансу), потім, якщо сеанс уже
        активний, питає підтвердження (_confirm_reset_if_needed). Вміст буфера показується
        в полі лише після успішного розбору — інакше випадково скопійована, напр., фраза
        з'явилась би в полі незамаскованою. Докладніше: dev-notes.md."""
        try:
            content = self.root.clipboard_get()
        except tk.TclError:
            messagebox.showwarning("Увага", "Буфер обміну порожній або не містить тексту.")
            return
        try:
            _parse_incoming_handshake(content)
        except Exception as e:
            # Текст буфера в лог/діалог не пишемо — там може бути секрет (напр. фраза).
            messagebox.showerror(
                "Помилка розбору хендшейку",
                f"Буфер обміну не містить коректного хендшейку ({type(e).__name__}).",
            )
            self._log(f"Вставка хендшейку — ПОМИЛКА розбору: {type(e).__name__}.")
            return
        if not self._confirm_reset_if_needed():
            return
        self.on_process_incoming(raw_text=content)

    def on_process_incoming(self, raw_text: str | None = None):
        """Обробляє raw_text (вставка з буфера або збережений текст при повторі після
        розбіжності ключів — _retry_after_mismatch), за замовчуванням self._handshake_text.
        Розбір і валідація (host/port) — ДО будь-якої зміни стану; текст з'являється в
        полі лише після успіху."""
        passphrase = self.var_passphrase.get()
        if not passphrase:
            passphrase = self._prompt_passphrase(
                "Парольна фраза", "Введіть парольну фразу, щоб обробити вставлений хендшейк.",
            )
            if passphrase is None:
                return
            self.var_passphrase.set(passphrase)  # peer_key ще не виставлено -> trace тут безпечний

        text = raw_text if raw_text is not None else self._handshake_text
        try:
            parsed = _parse_incoming_handshake(text)  # увесь розбір/валідація — ДО зміни стану
        except Exception as e:
            messagebox.showerror("Помилка розбору хендшейку", str(e))
            self._log(f"Обробка вхідного хендшейку — ПОМИЛКА: {type(e).__name__}: {e}")
            return

        iterations = parsed["iterations"]
        self.peer_key = derive_key(passphrase, parsed["salt"], iterations)
        self.peer_host = parsed["host"]
        self.peer_port = parsed["port"]
        self._show_handshake(
            _HANDSHAKE_KIND_PEER, text,
            f"Код підтвердження: {key_fingerprint(self.peer_key)}  "
            f"(sid={parsed['sid']}, net={self.peer_host}:{self.peer_port})",
        )
        self._set_status(
            "Ключ з вхідного хендшейку отримано. "
            "Звірте коди підтвердження з обох сторін через голос/месенджер — "
            "вони мають збігатися."
        )
        self._log(
            f"Вхідний хендшейк оброблено: sid={parsed['sid']}, "
            f"net={self.peer_host}:{self.peer_port}, iter={iterations}."
        )
        self._maybe_start_channel_establishment()

    def _handle_verification_mismatch(self):
        """kind == "verification_failed": замість попередження — віконце з поясненням
        і полем для виправленої фрази. Повтор — на ТОМУ САМОМУ хендшейку, нічого
        пересилати не треба (dev-notes.md → "Секція «Хендшейк»"). OK:
        - роль PEER (ця сторона вставляла) — переобробляє ЗБЕРЕЖЕНИЙ текст з новою
          фразою і знову підключається (connect-цикл чекає, поки інша сторона слухатиме);
        - роль MINE (ця сторона генерувала) — ті самі salt/sid/iterations/текст, local_key
          переводиться з нової фрази, знову слухає.
        Cancel: MINE — слухає далі з ПОТОЧНОЮ фразою (помилка могла бути в іншої сторони,
        її виправлений повтор має до кого підключитись); PEER — не підключається, статус
        пояснює, як повторити."""
        epoch = self._session_epoch
        new_passphrase = self._prompt_passphrase(
            "Ключі не збігаються",
            "Коди підтвердження відрізняються — ймовірно, одруківка в парольній фразі. "
            "Звірте короткі коди підтвердження з іншою стороною (голосом/текстом через "
            "месенджер). Введіть виправлену фразу, щоб спробувати ще раз — хендшейк "
            "пересилати не треба, інша сторона теж має натиснути OK.",
            initial=self.var_passphrase.get(),
        )
        if epoch != self._session_epoch:
            return  # поки діалог був відкритий, сеанс скинуто/змінено — повтор уже неактуальний
        if new_passphrase is None:
            if self._handshake_kind == _HANDSHAKE_KIND_MINE and self.local_key is not None:
                self._retry_after_mismatch(None)
                self.var_channel_status.set(
                    f"Ключі НЕ збігаються — слухаю на порту {self.local_port} з поточною фразою"
                )
                self._set_status(
                    "Ключі не збігаються. Слухаю далі з поточною фразою — якщо помилка у вас, "
                    "змініть фразу (скине хендшейк) або дочекайтесь повтору іншої сторони."
                )
            else:
                self.var_channel_status.set(
                    "Ключі НЕ збігаються — повторне з'єднання не виконується. "
                    "Щоб повторити, вставте хендшейк ще раз."
                )
            return
        self._retry_after_mismatch(new_passphrase)

    def _retry_after_mismatch(self, new_passphrase: str | None):
        """Повтор після verification_failed БЕЗ нового хендшейку. new_passphrase=None —
        лише перезапуск слухання (MINE, Cancel). var_passphrase змінюється з вимкненим
        trace (_suppress_param_invalidation) — повне скидання стерло б salt/sid/текст;
        скидається лише спроба каналу (_reset_channel_attempt)."""
        kind = self._handshake_kind
        stored_text = self._handshake_text
        self._reset_channel_attempt()
        if new_passphrase is not None:
            self._suppress_param_invalidation = True
            try:
                self.var_passphrase.set(new_passphrase)
            finally:
                self._suppress_param_invalidation = False

        if kind == _HANDSHAKE_KIND_PEER:
            self.peer_key = None
            self.on_process_incoming(raw_text=stored_text)
            if self._channel_pending:
                self.var_channel_status.set(
                    f"Повтор: з'єднуюсь з {self.peer_host}:{self.peer_port} — "
                    f"чекаю, поки інша сторона теж натисне OK"
                )
            return

        if kind != _HANDSHAKE_KIND_MINE or self.local_salt is None or self.local_iterations is None:
            return
        if new_passphrase is not None:
            self.local_key = derive_key(new_passphrase, self.local_salt, self.local_iterations)
            self._show_handshake(_HANDSHAKE_KIND_MINE, stored_text, self._local_fingerprint_text())
            self._log(f"Повтор після розбіжності ключів: sid={self.local_session_id}, ключ переведено з нової фрази.")
        self._maybe_start_channel_establishment()
        if new_passphrase is not None and self._channel_pending:
            self.var_channel_status.set(
                f"Повтор: слухаю на порту {self.local_port} — чекаю, поки інша сторона теж натисне OK"
            )
            self._set_status("Повтор з тим самим хендшейком — пересилати його не треба.")

    # ---- канал передачі (сервісна функція + Фаза 3, transport.py) --------

    def _session_key(self) -> bytes | None:
        """Спільний сесійний ключ ЦІЄЇ сторони. ONE SESSION = ONE ROLE (dev-notes.md):
        щонайбільше одне з local_key/peer_key будь-коли встановлене (гарантія —
        _reset_session_state/_confirm_reset_if_needed), тому пріоритет не потрібен —
        просто повертаємо те, що є."""
        return self.local_key if self.local_key is not None else self.peer_key

    def _invalidate_session_if_active(self, *_trace_args):
        """trace на var_passphrase/var_iterations/var_port — будь-яка зміна одного з них
        ПІСЛЯ того, як хендшейк уже згенеровано/оброблено, робить поточний ключ/канал
        недійсним (інша сторона деривувала ключ зі старим значенням, чи слухає застарілий
        порт — саме так знайдено реальний баг). Скидає стан і повідомляє про потребу
        повторного обміну хендшейком, замість мовчки лишати застарілий канал.
        Докладніше: docs/dev-notes.md → "_invalidate_session_if_active"."""
        if self._suppress_param_invalidation:
            return  # програмна зміна фрази під час повтору (_retry_after_mismatch) — хендшейк лишається
        if not self._session_active():
            return  # нічого ще не було згенеровано/оброблено — звичайне введення пароля

        self._reset_session_state()
        self.var_channel_status.set("Параметри змінено — попередній хендшейк і канал недійсні.")
        self._set_status(
            "Параметри хендшейку змінено — згенеруйте/обробіть хендшейк заново й "
            "надішліть його іншій стороні повторно."
        )
        self._log("Параметри хендшейку змінено — попередній сеанс і канал скинуто.")

    def _mark_port_overridden(self, *_trace_args):
        """trace на var_port: позначає, що користувач ВРУЧНУ відредагував поле "Порт"
        цього сеансу — після цього зміна дефолтного порту в профілі (вкладка "Профіль")
        більше не підмінює поле автоматично (precedence: профіль < CLI < ручна правка,
        dev-notes.md → "local_config.py"). Ігнорується під час programmatic set()
        (initial/CLI/синхронізація з профілю) через _suppress_port_override_tracking."""
        if self._suppress_port_override_tracking:
            return
        self._port_overridden_by_user = True

    def _maybe_start_channel_establishment(self):
        """Стартує встановлення каналу, щойно відомий сесійний ключ. peer_host/
        peer_port — опційні: за протоколом docs/concept.md хендшейк ділиться лише
        в один бік, тому сторона, яка його ЗГЕНЕРУВАЛА, зазвичай не знає адреси
        іншої сторони — вона просто слухає (establish_connection у режимі
        "лише слухати"); сторона, яка ОБРОБИЛА вхідний хендшейк, знає адресу
        (peer_host/peer_port) і підключається сама. Один раз за сеанс."""
        if self._channel_thread_started:
            return
        session_key = self._session_key()
        if session_key is None:
            return
        local_port = self._get_port()
        if local_port is None:
            return
        self.local_port = local_port

        self._channel_thread_started = True
        self._channel_pending = True
        self._channel_wait_started_at = time.monotonic()
        if self.peer_host is not None and self.peer_port is not None:
            self.var_channel_status.set(f"Встановлюю з'єднання з {self.peer_host}:{self.peer_port}...")
            self._log(
                f"Канал передачі: встановлюю з'єднання з {self.peer_host}:{self.peer_port} "
                f"(локальний порт {self.local_port})..."
            )
            if not _is_private_host(self.peer_host):
                self._log(
                    f"Канал передачі: адреса іншої сторони ({self.peer_host}) публічна — якщо "
                    f"обидві сторони за одним роутером (напр. тест на одному ПК), з'єднання може "
                    f"не пройти без підтримки NAT hairpin/loopback на роутері."
                )
        else:
            self.var_channel_status.set(f"Слухаю на порту {self.local_port} — чекаю на іншу сторону...")
            self._log(f"Канал передачі: слухаю на порту {self.local_port}, чекаю підключення.")
        epoch = self._session_epoch
        # Знімок self._channel_stop_event ЗАРАЗ — щоб наступний _reset_session_state (новий
        # Event) сигналізував СААМЕ цій спробі зупинитись, не майбутній (dev-notes.md).
        stop_event = self._channel_stop_event
        threading.Thread(
            target=self._channel_establish_worker, args=(session_key, epoch, stop_event), daemon=True
        ).start()
        self.root.after(1000, self._tick_channel_wait, epoch)

    def _tick_channel_wait(self, epoch: int):
        """Раз/с дописує до статусу скільки часу вже триває встановлення каналу —
        інакше 300с очікування виглядають як зависання, не активна спроба (dev-notes.md)."""
        if epoch != self._session_epoch or not self._channel_pending:
            return
        elapsed = int(time.monotonic() - self._channel_wait_started_at)
        base = self.var_channel_status.get().split(" (")[0]
        self.var_channel_status.set(f"{base} ({elapsed}с)")
        self.root.after(1000, self._tick_channel_wait, epoch)

    def _put_channel_event(self, epoch: int, event: dict) -> None:
        """Тегує подію її epoch — _handle_channel_event ігнорує застарілі (dev-notes.md)."""
        event["epoch"] = epoch
        self._channel_queue.put(event)

    def _channel_establish_worker(
        self, session_key: bytes, epoch: int, stop_event: threading.Event | None = None
    ):
        """Фоновий потік — жодних звернень до self.root/tkinter, лише мережа й запис у чергу.
        Широкі except Exception — щоб неочікувана помилка не вбила потік мовчки (dev-notes.md).
        epoch — знімок self._session_epoch на момент старту; якщо параметри хендшейку
        зміняться, поки цей потік ще працює (перервати сокет-виклики на льоту не можна),
        _handle_channel_event ігнорує його події як застарілі. stop_event — знімок
        self._channel_stop_event на момент старту (див. _maybe_start_channel_establishment) —
        establish_connection перевіряє його під час очікування й звільняє listening-сокет
        (порт) протягом accept_poll_timeout_seconds після скидання сеансу, а не аж до
        connect_timeout_seconds; параметр опційний (за замовчуванням — поточний
        self._channel_stop_event) лише для сумісності з прямими викликами з тестів."""
        if stop_event is None:
            stop_event = self._channel_stop_event
        try:
            sock = establish_connection(self.local_port, self.peer_host, self.peer_port, stop_event=stop_event)
        except ConnectionFailed as e:
            self._put_channel_event(epoch, {"kind": "connection_failed", "error": str(e)})
            return
        except Exception as e:
            self._put_channel_event(epoch, {"kind": "connection_failed", "error": f"{type(e).__name__}: {e}"})
            return
        try:
            verify_channel(sock, session_key)
        except Exception as e:
            _close_socket(sock)
            # Лише VerificationError = справжня розбіжність ключів (діалог виправлення фрази).
            # Обрив/таймаут/будь-що інше під час підтвердження — мережева помилка, не одруківка.
            if isinstance(e, VerificationError):
                self._put_channel_event(epoch, {"kind": "verification_failed", "error": str(e)})
            else:
                self._put_channel_event(epoch, {"kind": "connection_failed", "error": f"{type(e).__name__}: {e}"})
            return
        self._put_channel_event(epoch, {"kind": "connected", "socket": sock, "key": session_key})

    def _poll_channel_events(self):
        """Персистентний опитувач self._channel_queue — стартує в __init__ і
        працює весь час роботи застосунку (безпечно, черга здебільшого порожня).
        Виняток в одному обробнику логуються й не зупиняє наступні події/перепланування."""
        try:
            while True:
                try:
                    event = self._channel_queue.get_nowait()
                except queue.Empty:
                    break
                try:
                    self._handle_channel_event(event)
                except Exception as e:
                    # Лише тип події й виняток — сама подія може містити ключ/сокет.
                    self._log(f"Помилка обробки події каналу '{event.get('kind')}': {type(e).__name__}: {e}")
        finally:
            deferred, self._deferred_channel_events = self._deferred_channel_events, []
            for event in deferred:
                self._channel_queue.put(event)
            self.root.after(200, self._poll_channel_events)

    def _handle_channel_event(self, event: dict):
        if event.get("epoch") != self._session_epoch:
            # Застаріла подія з потоку попереднього сеансу (dev-notes.md) — ігноруємо, але
            # сокет, який вона несе, закриваємо: інакше з'єднання висить до кінця роботи.
            _close_socket(event.get("socket"))
            return
        kind = event["kind"]

        if kind == "verification_failed" and self._modal_depth > 0:
            # Відкрите інше модальне віконце (напр. "Почати новий сеанс?") — не накладаємо
            # діалог; _poll_channel_events поверне подію в чергу, після скидання вона застаріє.
            self._deferred_channel_events.append(event)
            return

        if kind == "connection_failed":
            self._channel_pending = False
            hint = ""
            if self.peer_host is not None and not _is_private_host(self.peer_host):
                hint = (
                    f" Адреса {self.peer_host} публічна — ймовірна причина: NAT hairpin/loopback "
                    f"не підтримується роутером (типово при тестуванні двох сторін за одним роутером)."
                )
            self.var_channel_status.set(f"Не вдалось встановити з'єднання: {event['error']}{hint}")
            self._log(f"Канал передачі: {event['error']}{hint}")

        elif kind == "verification_failed":
            self._channel_pending = False
            self._log(f"Канал передачі: {event['error']}")
            self._handle_verification_mismatch()

        elif kind == "connected":
            self._channel_pending = False
            self.channel_socket = event["socket"]
            self.channel_key = event["key"]
            self.channel_verified = True
            self.var_channel_status.set("Підтверджено — канал готовий до передачі.")
            self._log("Канал передачі: ключі підтверджено, з'єднання готове.")
            self._update_send_button_state()
            threading.Thread(
                target=self._receive_worker, args=(event["socket"], event["key"], event["epoch"]), daemon=True
            ).start()

        elif kind == "receive_progress":
            self.progress_bar["value"] = event["pct"]
            self.var_progress_text.set(f"Приймаю: {event['name']} — {event['pct']}%")

        elif kind == "receive_done":
            names = ", ".join(os.path.basename(p) for p in event["files"])
            self._set_status(f"Отримано {len(event['files'])} файл(и/ів): {names}")
            self._log(
                f"Канал передачі: отримано {len(event['files'])} файл(и/ів) у "
                f"{self.profile.incoming_dir}: {names}."
            )
            self.progress_bar["value"] = 100
            self.var_progress_text.set(f"Отримано {len(event['files'])} файл(и/ів).")

        elif kind == "receive_error":
            # Прийом на цій стороні зупинено назавжди (dev-notes.md) — канал більше
            # не робочий в обох напрямках, це має бути видно користувачу, не лише в лозі.
            self.channel_verified = False
            self.var_channel_status.set("Канал розірвано (помилка прийому) — передача файлів неможлива.")
            self._log(f"Канал передачі: помилка прийому — {event['error']}")
            self._update_send_button_state()

        elif kind == "receive_closed":
            self.channel_verified = False
            self.var_channel_status.set("Інша сторона закрила з'єднання — канал більше не активний.")
            self._log("Канал передачі: інша сторона закрила з'єднання.")
            self._update_send_button_state()

        elif kind == "send_progress":
            self.progress_bar["value"] = event["pct"]
            self.var_progress_text.set(f"Надсилаю: {event['name']} — {event['pct']}%")

        elif kind == "send_done":
            self.var_transfer_status.set(f"Надіслано {event['count']} файл(и/ів).")
            self._set_status(f"Надіслано {event['count']} файл(и/ів).")
            self._log(f"Канал передачі: надіслано {event['count']} файл(и/ів).")
            self.progress_bar["value"] = 100
            self.var_progress_text.set(f"Надіслано {event['count']} файл(и/ів).")
            self.btn_send.configure(state="normal")

        elif kind == "send_error":
            self.var_transfer_status.set(f"Помилка надсилання: {event['error']}")
            self._log(f"Канал передачі: помилка надсилання — {event['error']}")
            self.progress_bar["value"] = 0
            self.var_progress_text.set("")
            self.btn_send.configure(state="normal")

        elif kind == "channel_test_ok":
            self._set_status("Перевірка каналу: отримано відповідь — канал працює.")
            self._log("Перевірка каналу: pong отримано, канал живий.")

        elif kind == "channel_test_failed":
            self._set_status(f"Перевірка каналу: не вдалось надіслати ping — {event['error']}")
            self._log(f"Перевірка каналу: помилка — {event['error']}")

    def _receive_worker(self, sock, key: bytes, epoch: int):
        """Фоновий потік: приймає файли в profile.incoming_dir, доки інша сторона
        не закриє з'єднання. Цикл — щоб приймати кілька послідовних передач за сеанс.
        sock/key — знімок ЦЬОГО каналу (не self.channel_socket/channel_key — ті вже можуть
        належати новому сеансу); виходить, щойно epoch змінився."""
        # Без агрегованого прогресу (на відміну від send) — receive_files не знає
        # загальної кількості/розміру файлів наперед, лише поточний.
        last_pct = {"value": -1}

        def on_progress(rel_path: str, done: int, total: int):
            pct = int(done * 100 / total) if total else 100
            if pct != last_pct["value"]:
                last_pct["value"] = pct
                self._put_channel_event(epoch, {"kind": "receive_progress", "name": rel_path, "pct": pct})

        def on_control(_header: dict):
            # Наразі єдиний тип — {"type":"pong"}, відповідь на наш send_ping (on_test_channel).
            self._put_channel_event(epoch, {"kind": "channel_test_ok"})

        while epoch == self._session_epoch:
            try:
                received = receive_files(
                    sock, key, self.profile.incoming_dir,
                    on_progress=on_progress, on_control=on_control,
                )
                self._put_channel_event(epoch, {"kind": "receive_done", "files": received})
            except PeerClosed:
                self._put_channel_event(epoch, {"kind": "receive_closed"})
                return
            except TransportError as e:
                self._put_channel_event(epoch, {"kind": "receive_error", "error": str(e)})
                return
            except Exception as e:
                # Побитий/ворожий кадр чи зникнення диска — теж має зупинити цикл із
                # видимою помилкою, а не тихо вбити потік (dev-notes.md).
                self._put_channel_event(epoch, {"kind": "receive_error", "error": f"{type(e).__name__}: {e}"})
                return

    def _payload_matches_channel_key(self) -> bool:
        """AES-архів має бути зашифрований САМЕ ключем підтвердженого каналу — інакше
        отримувач не розпакує (після повтору/нового сеансу ключ міг змінитись)."""
        if self._transfer_archive_key is None:
            return True  # payload не залежить від ключа
        return self.channel_key is not None and hmac.compare_digest(self._transfer_archive_key, self.channel_key)

    def _update_send_button_state(self):
        ready = self.channel_verified and bool(self.transfer_payload) and self._payload_matches_channel_key()
        self.btn_send.configure(state="normal" if ready else "disabled")

    def on_test_channel(self):
        """Перевіряє, що канал реально живий (ping/pong), без вибору/пакування файлів —
        відповідь приходить через той самий _receive_worker, що вже читає сокет (dev-notes.md)."""
        if not self.channel_verified or self.channel_socket is None:
            messagebox.showwarning("Увага", "Канал ще не готовий — зачекайте на підтвердження з'єднання.")
            return
        self._set_status("Перевірка каналу: надсилаю ping...")
        self._log("Перевірка каналу: надсилаю ping.")
        # Знімок сокета ЗАРАЗ — скидання сеансу між кліком і стартом потоку занулить self.channel_socket.
        threading.Thread(
            target=self._test_channel_worker, args=(self.channel_socket, self._session_epoch), daemon=True
        ).start()

    def _test_channel_worker(self, sock, epoch: int):
        try:
            if sock is None:
                raise TransportError("канал закрито")
            send_ping(sock)
        except Exception as e:
            self._put_channel_event(epoch, {"kind": "channel_test_failed", "error": f"{type(e).__name__}: {e}"})

    def _transfer_root_dir(self) -> str:
        if self.packed_archive_path:
            return os.path.dirname(self.packed_archive_path)
        if self.selected_is_dir:
            return self.selected_path
        return os.path.dirname(self.selected_path)

    def on_send_files(self):
        if not self.channel_verified or self.channel_socket is None:
            messagebox.showwarning("Увага", "Канал ще не готовий — зачекайте на підтвердження з'єднання.")
            return
        if not self.transfer_payload:
            messagebox.showwarning("Увага", "Спочатку натисніть «Ініціалізувати передачу».")
            return
        if not self._payload_matches_channel_key():
            messagebox.showwarning(
                "Увага",
                "Архів зашифровано іншим ключем, ніж ключ підтвердженого каналу — "
                "натисніть «Ініціалізувати передачу» ще раз.",
            )
            self._update_send_button_state()
            return

        self.btn_send.configure(state="disabled")
        self.progress_bar["value"] = 0
        self.var_progress_text.set("")
        self.var_transfer_status.set(f"Надсилаю {len(self.transfer_payload)} файл(и/ів)...")
        self._set_status("Надсилаю файли...")
        self._log(f"Надсилання {len(self.transfer_payload)} файл(и/ів)...")
        threading.Thread(
            target=self._send_worker,
            args=(
                self._transfer_root_dir(), list(self.transfer_payload), self._session_epoch,
                self.channel_socket, self.channel_key,
            ),
            daemon=True,
        ).start()

    def _send_worker(self, root_dir: str, files: list, epoch: int, sock=None, key: bytes | None = None):
        """sock/key — знімок каналу на момент кліку (див. _receive_worker)."""
        # Агрегований прогрес по всіх файлах разом (розмір відомий заздалегідь — на
        # відміну від прийому, де файли йдуть потоком без наперед відомого підсумку).
        progress = {"prev_name": None, "bytes_before_current": 0, "prev_total": 0, "last_pct": -1}

        def on_progress(rel_path: str, done: int, total: int):
            if rel_path != progress["prev_name"]:
                progress["bytes_before_current"] += progress["prev_total"]
                progress["prev_name"] = rel_path
                progress["prev_total"] = total
            pct = int((progress["bytes_before_current"] + done) * 100 / total_bytes)
            if pct != progress["last_pct"]:
                progress["last_pct"] = pct
                self._put_channel_event(epoch, {"kind": "send_progress", "name": rel_path, "pct": pct})

        try:
            total_bytes = sum(os.path.getsize(f) for f in files) or 1
            send_files(sock, key, root_dir, files, on_progress=on_progress)
            self._put_channel_event(epoch, {"kind": "send_done", "count": len(files)})
        except TransportError as e:
            self._put_channel_event(epoch, {"kind": "send_error", "error": str(e)})
        except Exception as e:
            # Напр. файл зник/заблокований між "Ініціалізувати" й "Надіслати" —
            # має розблокувати кнопку з видимою помилкою, а не тихо вбити потік.
            self._put_channel_event(epoch, {"kind": "send_error", "error": f"{type(e).__name__}: {e}"})

    def _start_connection_setup(self):
        """Триетапна модель UPnP → STUN → LAN-only, автоматично й у фоновому потоці.
        Докладніше: docs/dev-notes.md → "appearance.py: _start_connection_setup"."""
        port = self._get_port()
        if port is None:
            return
        self.var_conn_status.set("Перевіряю (UPnP → STUN)...")
        self._log(f"Мережеві налаштування: автоматична перевірка UPnP → STUN (порт {port})...")

        thread = threading.Thread(target=self._connection_setup_worker, args=(port,), daemon=True)
        thread.start()
        self.root.after(150, self._poll_connection_setup)

    def _connection_setup_worker(self, port: int):
        """Фоновий потік — жодних звернень до self.root/tkinter, лише мережа й запис у чергу.
        Зовнішній try/except Exception — щоб неочікувана помилка (напр. побита XML-відповідь
        роутера, ET.ParseError) не лишила чергу порожньою назавжди; фолбек на LAN-only."""
        result: dict = {"port": port}
        try:
            try:
                local_ip = detect_local_address()
                external_ip = try_configure_port_forwarding(local_ip, port)
            except UpnpError as e:
                result["upnp_error"] = str(e)
            else:
                result["source"] = "upnp"
                result["host"] = external_ip
                result["port_used"] = port  # UPnP мапить зовнішній порт == внутрішньому
                self._conn_setup_queue.put(result)
                return

            try:
                stun_ip, stun_port = get_public_address(port)
            except StunError as e:
                result["stun_error"] = str(e)
                result["source"] = None
            else:
                result["source"] = "stun"
                result["host"] = stun_ip
                result["port_used"] = stun_port  # НЕ port: NAT сам обирає зовнішній (dev-notes.md)
        except Exception as e:
            result.setdefault("upnp_error", f"неочікувана помилка: {type(e).__name__}: {e}")
            result["source"] = None

        self._conn_setup_queue.put(result)

    def _poll_connection_setup(self):
        try:
            result = self._conn_setup_queue.get_nowait()
        except queue.Empty:
            self.root.after(150, self._poll_connection_setup)
            return
        self._apply_connection_setup_result(result)

    def _apply_connection_setup_result(self, result: dict):
        if "upnp_error" in result:
            self._log(f"Мережеві налаштування (рівень 1, UPnP) — невдача: {result['upnp_error']}")

        if result.get("source") == "upnp":
            self.public_host = result["host"]
            self.public_port = result["port_used"]
            self.public_host_source = "upnp"
            self.var_conn_status.set(f"UPnP: успіх — {self.public_host}:{self.public_port}")
            self._log(
                f"Мережеві налаштування (рівень 1, UPnP) — успіх: зовнішня IP "
                f"{self.public_host}, порт {self.public_port} прокинуто."
            )
            return

        if "stun_error" in result:
            self._log(f"Мережеві налаштування (рівень 2, STUN) — невдача: {result['stun_error']}")

        if result.get("source") == "stun":
            self.public_host = result["host"]
            self.public_port = result["port_used"]
            self.public_host_source = "stun"
            self.var_conn_status.set(
                f"STUN: успіх — {self.public_host}:{self.public_port} (порт не прокинуто автоматично)"
            )
            self._log(
                f"Мережеві налаштування (рівень 2, STUN) — успіх: {self.public_host}:{self.public_port} "
                f"(порт не прокинуто)."
            )
            return

        self.public_host = None
        self.public_port = None
        self.public_host_source = None
        self.var_conn_status.set(
            "UPnP і STUN не спрацювали — буде використано локальну адресу (LAN-only)."
        )
        self._log("Мережеві налаштування: UPnP і STUN не спрацювали — LAN-only.")

    def on_choose_file(self):
        path = filedialog.askopenfilename(
            title="Оберіть файл", initialdir=self.var_outgoing_dir.get() or None
        )
        if path:
            self.selected_path = path
            self.selected_is_dir = False
            self.lbl_selected.configure(text=f"Файл: {path}")
            self.frame_tree.pack_forget()  # дерево/чекбокс архівування — лише для каталогу
            self.btn_transfer.configure(state="normal")  # одиночний файл — передача "як є", без вибору
            self.var_transfer_status.set("")
            self.packed_archive_path = None
            self.transfer_payload = None
            self._transfer_archive_key = None
            self._update_send_button_state()

    def on_choose_dir(self):
        path = filedialog.askdirectory(
            title="Оберіть каталог", initialdir=self.var_outgoing_dir.get() or None
        )
        if path:
            self._select_send_dir(path)

    def _select_send_dir(self, path: str):
        """Спільна логіка для on_choose_dir і --snd-dir: те, що відбувається після
        того, як каталог для передачі вже обрано (діалогом чи параметром CLI)."""
        self.selected_path = path
        self.selected_is_dir = True
        self.packed_archive_path = None
        self.transfer_payload = None
        self._transfer_archive_key = None
        self._update_send_button_state()
        self.lbl_selected.configure(text=f"Каталог: {path}")

        self._file_tree_checked = {}
        self._file_tree_meta = {}
        self.tree_files.delete(*self.tree_files.get_children(""))
        self._insert_tree_children("", path, "")
        self.frame_tree.pack(fill="both", expand=True, before=self._transfer_row)
        self.btn_transfer.configure(state="normal")
        self.var_transfer_status.set("")
        self._set_status(
            "Позначте чекбоксами, що включити (усе включено за замовчуванням), оберіть "
            "архівувати чи передати як є, і натисніть «Ініціалізувати передачу»."
        )
        self._log(f"Обрано каталог для передачі: {path}")

    # ---- дерево вмісту каталогу (чекбокси) --------------------------------

    def _insert_tree_children(self, parent_iid: str, abs_dir: str, rel_prefix: str):
        entries = list_entries(abs_dir, exclude_names=frozenset({EXCHANGE.pack_subdir_name}))
        for entry in entries:
            rel_path = f"{rel_prefix}/{entry.name}" if rel_prefix else entry.name
            checked = self._file_tree_checked.get(rel_path, True)
            iid = rel_path
            self.tree_files.insert(
                parent_iid, "end", iid=iid,
                text=entry.name,
                values=("☑" if checked else "☐", format_size(entry.size_bytes)),
            )
            self._file_tree_meta[iid] = (rel_path, entry.abs_path, entry.is_dir)
            if entry.is_dir:
                # Заглушка-дитина для стрілки розгортання; реальний вміст — лінивo в _on_tree_open.
                self.tree_files.insert(iid, "end", iid=f"{iid}{_TREE_LOADING_SUFFIX}", text="…")

    def _on_tree_open(self, _event=None):
        item = self.tree_files.focus()
        if not item or item not in self._file_tree_meta:
            return
        children = self.tree_files.get_children(item)
        if len(children) == 1 and children[0] == f"{item}{_TREE_LOADING_SUFFIX}":
            self.tree_files.delete(children[0])
            rel_path, abs_path, _is_dir = self._file_tree_meta[item]
            self._insert_tree_children(item, abs_path, rel_path)

    def _on_tree_click(self, event):
        if self.tree_files.identify_region(event.x, event.y) != "cell":
            return
        if self.tree_files.identify_column(event.x) != "#1":  # "#1" = колонка "chk"
            return
        item = self.tree_files.identify_row(event.y)
        if not item or item not in self._file_tree_meta:
            return

        rel_path, abs_path, is_dir = self._file_tree_meta[item]
        new_state = not self._file_tree_checked.get(rel_path, True)
        self._set_checked_recursive(rel_path, abs_path, is_dir, new_state)
        self._refresh_visible_checkmarks()

    def _set_checked_recursive(self, rel_path: str, abs_path: str, is_dir: bool, checked: bool):
        """Пише стан у _file_tree_checked для rel_path і (якщо каталог) для всіх нащадків,
        навіть ще не довантажених у дерево."""
        self._file_tree_checked[rel_path] = checked
        if not is_dir:
            return
        for root, dirs, files in os.walk(abs_path):
            dirs[:] = [d for d in dirs if d != EXCHANGE.pack_subdir_name]
            for name in dirs + files:
                full = os.path.join(root, name)
                rel = os.path.relpath(full, self.selected_path).replace(os.sep, "/")
                self._file_tree_checked[rel] = checked

    def _set_all_checked(self, checked: bool):
        """"Позначити все"/"Зняти все". Рахує через os.walk, тому працює і для
        ще не розгорнутих підкаталогів дерева."""
        if not self.selected_path or not self.selected_is_dir:
            return
        for root, dirs, files in os.walk(self.selected_path):
            dirs[:] = [d for d in dirs if d != EXCHANGE.pack_subdir_name]
            for name in dirs + files:
                full = os.path.join(root, name)
                rel = os.path.relpath(full, self.selected_path).replace(os.sep, "/")
                self._file_tree_checked[rel] = checked
        self._refresh_visible_checkmarks()

    def _refresh_visible_checkmarks(self):
        for iid, (rel_path, _abs_path, _is_dir) in self._file_tree_meta.items():
            if not self.tree_files.exists(iid):
                continue
            checked = self._file_tree_checked.get(rel_path, True)
            self.tree_files.set(iid, "chk", "☑" if checked else "☐")

    def on_initiate_transfer(self):
        """Фіналізує self.transfer_payload — готує, що саме піде через send_files()
        по кнопці «Надіслати». Каталог: архів чи "як є" за var_archive_before_send."""
        if not self.selected_path:
            messagebox.showwarning("Увага", "Спочатку оберіть файл або каталог.")
            return

        if not self.selected_is_dir:
            self.transfer_payload = [self.selected_path]
            self.packed_archive_path = None
            self._transfer_archive_key = None
            self.var_transfer_status.set("Готово до передачі: 1 файл (як є).")
            self._set_status(f"Готово до передачі: {os.path.basename(self.selected_path)}.")
            self._log(f"Ініціалізація передачі: 1 файл як є — {self.selected_path}.")
            self._update_send_button_state()
            return

        # selected_path/selected_is_dir НЕ змінюємо (виправлений баг) — dev-notes.md.
        included_files = []
        for root, dirs, files in os.walk(self.selected_path):
            dirs[:] = [d for d in dirs if d != EXCHANGE.pack_subdir_name]
            for fname in files:
                full = os.path.join(root, fname)
                rel = os.path.relpath(full, self.selected_path).replace(os.sep, "/")
                if self._file_tree_checked.get(rel, True):
                    included_files.append(full)

        if not included_files:
            messagebox.showwarning(
                "Увага", "Не обрано жодного файлу — зніміть менше позначок і спробуйте ще раз."
            )
            return

        encryption_level = _ENCRYPTION_LABEL_TO_LEVEL[self.var_encryption_label.get()]
        # AES без архіву не має сенсу (шифрується сам ZIP-контейнер) — форсуємо архівування.
        should_archive = self.var_archive_before_send.get() or encryption_level != EncryptionLevel.NONE

        if should_archive:
            password = None
            if encryption_level != EncryptionLevel.NONE:
                password = self._session_key()
                if password is None:
                    messagebox.showwarning(
                        "Увага",
                        "Спочатку виконайте хендшейк (згенеруйте свій або вставте отриманий) — "
                        "сесійний ключ використовується як пароль AES-шифрування архіву.",
                    )
                    return

            try:
                archive_path = build_archive_from_selection(
                    self.selected_path, included_files,
                    encryption=encryption_level, compress=self.var_compress.get(), password=password,
                )
            except ValueError as e:
                messagebox.showerror("Помилка пакування", str(e))
                return

            self.packed_archive_path = archive_path
            self.transfer_payload = [archive_path]
            # Ключ, яким РЕАЛЬНО зашифровано архів — "Надіслати" звіряє його з channel_key.
            self._transfer_archive_key = password
            self.lbl_selected.configure(
                text=f"Каталог: {self.selected_path}  →  запаковано: {archive_path}"
            )
            compress_kind = "зі стисненням" if self.var_compress.get() else "без стиснення"
            encryption_kind = _ENCRYPTION_LEVEL_LABELS[encryption_level]
            self.var_transfer_status.set(
                f"Готово до передачі: 1 архів ({len(included_files)} файл(и/ів) усередині, "
                f"{compress_kind}, {encryption_kind})."
            )
            self._set_status(f"Готово до передачі: архів з {len(included_files)} файл(и/ів).")
            self._log(
                f"Ініціалізація передачі: запаковано {len(included_files)} файл(и/ів) у {archive_path} "
                f"({compress_kind}, {encryption_kind})."
            )
        else:
            self.packed_archive_path = None
            self.transfer_payload = included_files
            self._transfer_archive_key = None
            self.var_transfer_status.set(
                f"Готово до передачі: {len(included_files)} файл(и/ів) як є (без архівування)."
            )
            self._set_status(f"Готово до передачі: {len(included_files)} файл(и/ів) як є.")
            self._log(
                f"Ініціалізація передачі: {len(included_files)} файл(и/ів) як є (без архівування)."
            )

        self._update_send_button_state()

    def on_choose_incoming_dir(self):
        path = filedialog.askdirectory(
            title="Оберіть каталог для вхідних файлів",
            initialdir=self.var_incoming_dir.get() or None,
        )
        if path:
            self.var_incoming_dir.set(path)

    def on_open_incoming_dir(self):
        """Відкриває поточний (уже збережений у профілі) каталог вхідних файлів
        у файловому менеджері ОС — перегляд прийнятого без пошуку вручну."""
        path = self.profile.incoming_dir
        if not os.path.isdir(path):
            messagebox.showinfo("Каталог порожній", f"Каталог ще не створено (нічого не отримано): {path}")
            return
        try:
            if sys.platform == "win32":
                os.startfile(path)
            elif sys.platform == "darwin":
                subprocess.Popen(["open", path])
            else:
                subprocess.Popen(["xdg-open", path])
        except OSError as e:
            messagebox.showerror("Помилка", f"Не вдалось відкрити каталог: {e}")

    def on_choose_outgoing_dir(self):
        path = filedialog.askdirectory(
            title="Оберіть каталог для вихідних файлів",
            initialdir=self.var_outgoing_dir.get() or None,
        )
        if path:
            self.var_outgoing_dir.set(path)

    def on_save_profile(self):
        client_id = self.var_client_id.get().strip()
        if not client_id:
            messagebox.showwarning("Увага", "Ідентифікатор клієнта не може бути порожнім.")
            return

        new_default_port = self._get_profile_default_port()
        if new_default_port is None:
            return  # помилку вже показано (_get_profile_default_port)
        port_changed = new_default_port != self.profile.default_port

        self.profile = LocalConfig(
            client_id=client_id,
            incoming_dir=self.var_incoming_dir.get().strip() or self.profile.incoming_dir,
            outgoing_dir=self.var_outgoing_dir.get().strip() or self.profile.outgoing_dir,
            default_port=new_default_port,
        )
        save_config(self.profile)

        # Синхронізація поля "Порт" (вкладка "Сеанс") — лише якщо користувач ще не
        # редагував його вручну цього сеансу і порт не заданий явно через --port
        # (hierarchy: профіль < CLI < ручна правка, dev-notes.md → "local_config.py").
        # Просто і передбачувано: інші комбінації (CLI заданий, чи вже редагували
        # вручну) НЕ підмінюються — вищий пріоритет у ієрархії не чіпаємо.
        if port_changed and not self._port_overridden_by_user and not self._cli_port_provided:
            self._suppress_port_override_tracking = True
            try:
                self.var_port.set(str(new_default_port))
            finally:
                self._suppress_port_override_tracking = False

        self.var_profile_status.set(f"Збережено ({config_path()}).")
        self._set_status("Профіль збережено.")
        self._log(
            f"Профіль збережено: client_id={self.profile.client_id}, "
            f"incoming={self.profile.incoming_dir}, outgoing={self.profile.outgoing_dir}, "
            f"default_port={self.profile.default_port}."
        )

