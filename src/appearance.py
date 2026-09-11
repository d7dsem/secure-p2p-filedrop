#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Шар "зовнішність": tkinter GUI застосунку. Крипто-логіка — у
connection.py, підготовка даних до передачі — у exchange.py,
конфігурація вікна/теми — у tuning.py (AppearanceTuning).
"""

import base64
import os
import time
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext

from connection import build_handshake_packet, derive_key, detect_local_address, key_fingerprint, parse_handshake_packet
from exchange import build_archive_from_selection, format_size, list_entries, prepare_archive
from local_config import LocalConfig, config_path, load_config, save_config
from nat_traversal import UpnpError, try_configure_port_forwarding
from stun_client import StunError, get_public_address
from tuning import APPEARANCE, CONNECTION, EXCHANGE, STUN

_TREE_LOADING_SUFFIX = "/__loading__"

_HOST_SOURCE_LABELS = {
    "upnp": "публічна, через UPnP (порт прокинуто на роутері)",
    "stun": "публічна, через STUN (порт НЕ прокинуто, мапінг може бути тимчасовим)",
    None: "локальна, LAN-only",
}


class SecureFileClientApp:
    def __init__(self, root: tk.Tk, initial_passphrase: str | None = None):
        self.root = root
        self.root.title(APPEARANCE.window_title)
        self.root.geometry(APPEARANCE.window_geometry)
        self.root.minsize(*APPEARANCE.window_min_size)

        self.local_key: bytes | None = None
        self.local_salt: bytes | None = None
        self.local_session_id: str | None = None

        self.peer_key: bytes | None = None
        self.peer_host: str | None = None
        self.peer_port: int | None = None

        self.selected_path: str | None = None
        self.selected_is_dir: bool = False
        self.packed_archive_path: str | None = None  # окремо від selected_path — щоб дерево
                                                       # й каталог лишались доступні для повторного
                                                       # пакування після зміни чекбоксів (знайдений баг)

        # Стан дерева вмісту каталогу (appearance.py -> "Що передати"):
        # rel_path (POSIX "/"-шляхи від обраного кореня) -> чи включено.
        # Дефолт — усе включено; запис у словнику потрібен лише для
        # того, що користувач явно зняв/повернув позначку.
        self._file_tree_checked: dict[str, bool] = {}
        self._file_tree_meta: dict[str, tuple[str, str, bool]] = {}  # iid -> (rel_path, abs_path, is_dir)

        self.public_host: str | None = None
        self.public_port: int | None = None
        self.public_host_source: str | None = None  # "upnp" | "stun" | None

        self.profile: LocalConfig = load_config()

        self._apply_dark_theme()
        self._build_ui()
        self._log("Застосунок запущено.")
        self._log(f"Профіль завантажено: client_id={self.profile.client_id} ({config_path()}).")

        if initial_passphrase:
            self.var_passphrase.set(initial_passphrase)

    # ---- тема ------------------------------------------------------------

    def _apply_dark_theme(self):
        self.root.configure(bg=APPEARANCE.dark_bg)

        style = ttk.Style(self.root)
        if "clam" in style.theme_names():
            style.theme_use("clam")

        style.configure(".", background=APPEARANCE.dark_bg, foreground=APPEARANCE.dark_fg,
                         fieldbackground=APPEARANCE.dark_entry_bg, bordercolor=APPEARANCE.dark_border,
                         lightcolor=APPEARANCE.dark_bg, darkcolor=APPEARANCE.dark_bg)
        style.configure("TFrame", background=APPEARANCE.dark_bg)
        style.configure("TLabelframe", background=APPEARANCE.dark_bg, foreground=APPEARANCE.dark_fg,
                         bordercolor=APPEARANCE.dark_border)
        style.configure("TLabelframe.Label", background=APPEARANCE.dark_bg, foreground=APPEARANCE.dark_fg)
        style.configure("TLabel", background=APPEARANCE.dark_bg, foreground=APPEARANCE.dark_fg_muted)
        style.configure("TCheckbutton", background=APPEARANCE.dark_bg, foreground=APPEARANCE.dark_fg)
        style.map("TCheckbutton",
                  background=[("active", APPEARANCE.dark_bg)],
                  foreground=[("active", APPEARANCE.dark_fg)])
        style.configure("TEntry", fieldbackground=APPEARANCE.dark_entry_bg, foreground=APPEARANCE.dark_fg,
                         insertcolor=APPEARANCE.dark_fg, bordercolor=APPEARANCE.dark_border)
        style.configure("TButton", background=APPEARANCE.dark_entry_bg, foreground=APPEARANCE.dark_fg,
                         bordercolor=APPEARANCE.dark_border)
        style.map("TButton",
                  background=[("active", APPEARANCE.dark_accent)],
                  foreground=[("active", APPEARANCE.dark_fg)])
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

    def _style_text_widget(self, widget):
        widget.configure(
            bg=APPEARANCE.dark_entry_bg, fg=APPEARANCE.dark_fg,
            insertbackground=APPEARANCE.dark_fg,
            selectbackground=APPEARANCE.dark_accent, selectforeground=APPEARANCE.dark_fg,
            relief="flat", borderwidth=1,
        )

    # ---- побудова інтерфейсу -----------------------------------------

    def _build_ui(self):
        pad = {"padx": 10, "pady": 6}

        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True)

        tab_session = ttk.Frame(self.notebook)
        tab_profile = ttk.Frame(self.notebook)
        tab_log = ttk.Frame(self.notebook)
        self.notebook.add(tab_session, text="Сеанс")
        self.notebook.add(tab_profile, text="Профіль")
        self.notebook.add(tab_log, text="Консоль / Лог")

        self._build_session_tab(tab_session, pad)
        self._build_profile_tab(tab_profile, pad)
        self._build_log_tab(tab_log, pad)

        # --- Статус (спільний для всіх вкладок) ---
        self.var_status = tk.StringVar(value="Готово.")
        status_bar = ttk.Label(self.root, textvariable=self.var_status, relief="sunken", anchor="w")
        status_bar.pack(fill="x", side="bottom")

    def _build_session_tab(self, parent: ttk.Frame, pad: dict):
        # --- Секція: парольна фраза ---
        frame_pass = ttk.LabelFrame(parent, text="Парольна фраза")
        frame_pass.pack(fill="x", **pad)

        self.var_passphrase = tk.StringVar()
        self.entry_passphrase = ttk.Entry(
            frame_pass, textvariable=self.var_passphrase, show="*"
        )
        self.entry_passphrase.pack(side="left", fill="x", expand=True, padx=(8, 4), pady=8)

        self.var_show_pass = tk.BooleanVar(value=False)
        chk_show = ttk.Checkbutton(
            frame_pass, text="Показати", variable=self.var_show_pass,
            command=self._toggle_pass_visibility
        )
        chk_show.pack(side="left", padx=(0, 8))

        # --- Секція: кількість ітерацій + порт для з'єднання ---
        frame_iter = ttk.Frame(parent)
        frame_iter.pack(fill="x", **pad)
        ttk.Label(frame_iter, text="Кількість ітерацій хешування:").pack(side="left")
        self.var_iterations = tk.StringVar(value=str(CONNECTION.default_iterations))
        ttk.Entry(frame_iter, textvariable=self.var_iterations, width=12).pack(
            side="left", padx=8
        )
        ttk.Label(frame_iter, text="Порт для з'єднання:").pack(side="left", padx=(16, 0))
        self.var_port = tk.StringVar(value=str(CONNECTION.default_port))
        ttk.Entry(frame_iter, textvariable=self.var_port, width=8).pack(
            side="left", padx=8
        )

        # --- Секція: налаштування з'єднання (рівень 1 UPnP -> рівень 2 STUN) ---
        frame_conn = ttk.Frame(parent)
        frame_conn.pack(fill="x", **pad)
        ttk.Button(
            frame_conn, text="Налаштувати з'єднання (UPnP → STUN)", command=self.on_setup_connection
        ).pack(side="left")
        self.var_conn_status = tk.StringVar(
            value="Не запускалось (буде використано локальну адресу, LAN-only)."
        )
        ttk.Label(frame_conn, textvariable=self.var_conn_status, wraplength=420).pack(
            side="left", padx=8
        )

        # --- Секція: вихідний хендшейк ---
        frame_out = ttk.LabelFrame(parent, text="Мій хендшейк (надіслати через месенджер)")
        frame_out.pack(fill="both", expand=True, **pad)

        btns_out = ttk.Frame(frame_out)
        btns_out.pack(fill="x", padx=8, pady=(8, 4))
        ttk.Button(
            btns_out, text="Згенерувати хендшейк", command=self.on_generate_handshake
        ).pack(side="left")
        ttk.Button(
            btns_out, text="Скопіювати в буфер", command=self.on_copy_handshake
        ).pack(side="left", padx=8)

        self.text_out = scrolledtext.ScrolledText(frame_out, height=APPEARANCE.text_widget_height, wrap="char")
        self.text_out.pack(fill="both", expand=True, padx=8, pady=(0, 4))
        self._style_text_widget(self.text_out)
        self.text_out.configure(state="disabled")

        self.lbl_local_fp = ttk.Label(frame_out, text="Код підтвердження: —")
        self.lbl_local_fp.pack(anchor="w", padx=8, pady=(0, 8))

        # --- Секція: вхідний хендшейк ---
        frame_in = ttk.LabelFrame(parent, text="Хендшейк співрозмовника (вставити з месенджера)")
        frame_in.pack(fill="both", expand=True, **pad)

        self.text_in = scrolledtext.ScrolledText(frame_in, height=APPEARANCE.text_widget_height, wrap="char")
        self.text_in.pack(fill="both", expand=True, padx=8, pady=8)
        self._style_text_widget(self.text_in)

        btns_in = ttk.Frame(frame_in)
        btns_in.pack(fill="x", padx=8, pady=(0, 8))
        ttk.Button(
            btns_in, text="Обробити вхідний хендшейк", command=self.on_process_incoming
        ).pack(side="left")

        self.lbl_peer_fp = ttk.Label(frame_in, text="Код підтвердження ключа: —")
        self.lbl_peer_fp.pack(anchor="w", padx=8, pady=(0, 4))

        # --- Секція: вибір файлу/каталогу ---
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

        self.lbl_selected = ttk.Label(frame_file, text="Нічого не обрано", wraplength=580)
        self.lbl_selected.pack(anchor="w", padx=8, pady=(0, 4))

        # Дерево вмісту обраного каталогу — з'являється лише після
        # "Обрати каталог..."; кожен рядок має колонку-чекбокс, підкаталоги
        # розкриваються лінивим довантаженням (<<TreeviewOpen>>).
        self.frame_tree = ttk.Frame(frame_file)

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

        btns_pack = ttk.Frame(self.frame_tree)
        btns_pack.pack(fill="x", padx=8, pady=8)
        self.btn_pack = ttk.Button(
            btns_pack, text="Запакувати обране", command=self.on_pack_selected, state="disabled"
        )
        self.btn_pack.pack(side="left")
        self.var_pack_status = tk.StringVar(value="")
        ttk.Label(btns_pack, textvariable=self.var_pack_status, wraplength=420).pack(
            side="left", padx=8
        )

    def _build_profile_tab(self, parent: ttk.Frame, pad: dict):
        """Локальний профіль користувача (local_config.py): ідентифікатор
        клієнта + дефолтні каталоги вхідних/вихідних файлів. Поля тут —
        це поточні (рантайм) значення; на диск вони йдуть лише по кнопці
        "Зберегти профіль", не автоматично."""
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

        frame_save = ttk.Frame(parent)
        frame_save.pack(fill="x", **pad)
        ttk.Button(frame_save, text="Зберегти профіль", command=self.on_save_profile).pack(side="left")
        self.var_profile_status = tk.StringVar(value=f"Конфіг: {config_path()}")
        ttk.Label(frame_save, textvariable=self.var_profile_status, wraplength=440).pack(
            side="left", padx=8
        )

    def _build_log_tab(self, parent: ttk.Frame, pad: dict):
        """Окрема вкладка для діагностичної інформації (UPnP-спроби,
        результати хендшейку тощо) — щоб не засмічувати основний екран,
        але мати куди дивитись, коли щось пішло не так."""
        btns_log = ttk.Frame(parent)
        btns_log.pack(fill="x", **pad)
        ttk.Button(btns_log, text="Очистити", command=self._clear_log).pack(side="left")

        self.text_log = scrolledtext.ScrolledText(parent, wrap="word", state="disabled")
        self.text_log.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        self._style_text_widget(self.text_log)

    def _log(self, message: str):
        timestamp = time.strftime("%H:%M:%S")
        self.text_log.configure(state="normal")
        self.text_log.insert("end", f"[{timestamp}] {message}\n")
        self.text_log.see("end")
        self.text_log.configure(state="disabled")

    def _clear_log(self):
        self.text_log.configure(state="normal")
        self.text_log.delete("1.0", "end")
        self.text_log.configure(state="disabled")

    def _toggle_pass_visibility(self):
        self.entry_passphrase.configure(show="" if self.var_show_pass.get() else "*")

    # ---- допоміжне ------------------------------------------------------

    def _get_iterations(self) -> int | None:
        try:
            n = int(self.var_iterations.get())
            if n <= 0:
                raise ValueError
            return n
        except ValueError:
            messagebox.showerror("Помилка", "Кількість ітерацій має бути додатним цілим числом.")
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

    def _set_status(self, text: str):
        self.var_status.set(text)

    # ---- обробники подій -------------------------------------------------

    def on_generate_handshake(self):
        passphrase = self.var_passphrase.get()
        if not passphrase:
            messagebox.showwarning("Увага", "Спочатку введіть парольну фразу.")
            return
        iterations = self._get_iterations()
        if iterations is None:
            return
        port = self._get_port()
        if port is None:
            return

        # self.public_port — реально спостережений зовнішній порт (UPnP:
        # той самий, що й локальний, бо мапили точно його; STUN: НАТ міг
        # підмінити на інший — перевірено наживо). Якщо з'єднання взагалі
        # не налаштовувалось (LAN-only), public_port лишається None —
        # тоді в пакет іде локально введений порт, як і раніше.
        effective_port = self.public_port if self.public_port is not None else port

        text, salt, session_id, host = build_handshake_packet(
            iterations, effective_port, host=self.public_host
        )
        self.local_salt = salt
        self.local_session_id = session_id
        self.local_key = derive_key(passphrase, salt, iterations)

        self.text_out.configure(state="normal")
        self.text_out.delete("1.0", "end")
        self.text_out.insert("1.0", text)
        self.text_out.configure(state="disabled")

        host_kind = _HOST_SOURCE_LABELS[self.public_host_source]
        self.lbl_local_fp.configure(
            text=f"Код підтвердження: {key_fingerprint(self.local_key)}  "
                 f"(sid={session_id}, net={host}:{effective_port})"
        )
        self._set_status("Хендшейк згенеровано. Надішліть його через месенджер.")
        self._log(
            f"Хендшейк згенеровано: sid={session_id}, net={host}:{effective_port} ({host_kind}), "
            f"iter={iterations}."
        )

    def on_copy_handshake(self):
        content = self.text_out.get("1.0", "end").strip()
        if not content:
            messagebox.showwarning("Увага", "Спочатку згенеруйте хендшейк.")
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(content)
        self._set_status("Хендшейк скопійовано в буфер обміну.")

    def on_process_incoming(self):
        passphrase = self.var_passphrase.get()
        if not passphrase:
            messagebox.showwarning("Увага", "Спочатку введіть парольну фразу.")
            return

        raw_text = self.text_in.get("1.0", "end")
        try:
            packet = parse_handshake_packet(raw_text)
            salt = base64.b64decode(packet["salt"])
            iterations = int(packet["iter"])
        except Exception as e:
            messagebox.showerror("Помилка розбору хендшейку", str(e))
            self._log(f"Обробка вхідного хендшейку — ПОМИЛКА: {e}")
            return

        self.peer_key = derive_key(passphrase, salt, iterations)
        self.peer_host = packet["host"]
        self.peer_port = int(packet["port"])
        self.lbl_peer_fp.configure(
            text=f"Код підтвердження ключа: {key_fingerprint(self.peer_key)}  "
                 f"(sid={packet['sid']}, net={self.peer_host}:{self.peer_port})"
        )
        self._set_status(
            "Ключ з вхідного хендшейку отримано. "
            "Звірте коди підтвердження з обох сторін через голос/месенджер — "
            "вони мають збігатися."
        )
        self._log(
            f"Вхідний хендшейк оброблено: sid={packet['sid']}, "
            f"net={self.peer_host}:{self.peer_port}, iter={iterations}."
        )

    def on_setup_connection(self):
        """
        Триетапна модель встановлення з'єднання з docs/concept.md
        ("Принципове архітектурне обмеження"):
          1. Локально, без третіх сторін — UPnP-запит до власного роутера.
          2. Якщо не вдалось — публічний STUN (лише дізнатись адресу,
             не хостинг).
          3. Якщо і це не вдалось — лишається локальна LAN-адреса;
             жодного relay/TURN-фолбеку немає навмисно.
        """
        port = self._get_port()
        if port is None:
            return

        # --- Рівень 1: UPnP (власний роутер) ---
        self._set_status("Рівень 1/2: UPnP (власний роутер)...")
        self.var_conn_status.set("Рівень 1/2: UPnP...")
        self._log(f"Рівень 1 — UPnP: пошук IGD-роутера в локальній мережі (порт {port})...")
        self.root.update_idletasks()

        try:
            local_ip = detect_local_address()
            external_ip = try_configure_port_forwarding(local_ip, port)
        except UpnpError as e:
            self._log(f"Рівень 1 (UPnP) — невдача: {e}")
        else:
            self.public_host = external_ip
            self.public_port = port  # UPnP мапить зовнішній порт == внутрішньому (сам про це просили)
            self.public_host_source = "upnp"
            self.var_conn_status.set(f"UPnP: успіх — {external_ip}:{port}")
            self._set_status(f"З'єднання налаштовано через UPnP: {external_ip}:{port}")
            self._log(f"Рівень 1 (UPnP) — успіх: зовнішня IP {external_ip}, порт {port} прокинуто.")
            return

        # --- Рівень 2: публічний STUN (лише дізнатись адресу) ---
        self._set_status("Рівень 2/2: публічний STUN...")
        self.var_conn_status.set("Рівень 2/2: STUN...")
        self._log(
            f"Рівень 2 — STUN: запит до {STUN.server_host}:{STUN.server_port} "
            f"(разовий, без хостингу з нашого боку; docs/concept.md)..."
        )
        self.root.update_idletasks()

        try:
            stun_ip, stun_port = get_public_address(port)
        except StunError as e:
            self._log(f"Рівень 2 (STUN) — невдача: {e}")
            self.public_host = None
            self.public_port = None
            self.public_host_source = None
            self.var_conn_status.set(
                "UPnP і STUN не спрацювали — буде використано локальну адресу (LAN-only)."
            )
            self._set_status("Автоналаштування з'єднання не вдалось — LAN-only.")
            messagebox.showwarning(
                "Автоналаштування з'єднання не вдалось",
                "Ні UPnP, ні публічний STUN не змогли визначити доступну ззовні адресу — "
                "типово це означає symmetric NAT/CGNAT або суворий фаєрвол. Пряме "
                "P2P-з'єднання через інтернет у такому випадку технічно неможливе без "
                "relay, який цей застосунок принципово не використовує (docs/concept.md).\n\n"
                "Хендшейк усе одно можна згенерувати — з локальною адресою він "
                "працюватиме в межах однієї LAN/VPN.",
            )
            return

        self.public_host = stun_ip
        # НЕ self._get_port(): NAT сам обирає зовнішній порт незалежно від
        # локального (переконались наживо — 52075 локально мапнувся на
        # зовсім інший зовнішній порт) — беремо лише те, що реально
        # повернув STUN, інакше хендшейк вкаже порт, на якому нас
        # насправді не видно ззовні.
        self.public_port = stun_port
        self.public_host_source = "stun"
        self.var_conn_status.set(f"STUN: успіх — {stun_ip}:{stun_port} (порт не прокинуто автоматично)")
        self._set_status(f"З'єднання налаштовано через STUN: {stun_ip}:{stun_port}")
        self._log(
            f"Рівень 2 (STUN) — успіх: публічна адреса {stun_ip}:{stun_port}. "
            f"УВАГА: на відміну від UPnP, порт тут НЕ прокинуто — це працює, лише поки "
            f"живий NAT-мапінг від цього запиту (типово секунди-хвилини), без гарантії."
        )

    def on_choose_file(self):
        path = filedialog.askopenfilename(
            title="Оберіть файл", initialdir=self.var_outgoing_dir.get() or None
        )
        if path:
            self.selected_path = path
            self.selected_is_dir = False
            self.lbl_selected.configure(text=f"Файл: {path}")
            self.frame_tree.pack_forget()
            self.btn_pack.configure(state="disabled")
            self.var_pack_status.set("")
            self.packed_archive_path = None

    def on_choose_dir(self):
        path = filedialog.askdirectory(
            title="Оберіть каталог", initialdir=self.var_outgoing_dir.get() or None
        )
        if not path:
            return

        self.selected_path = path
        self.selected_is_dir = True
        self.packed_archive_path = None
        self.lbl_selected.configure(text=f"Каталог: {path}")

        self._file_tree_checked = {}
        self._file_tree_meta = {}
        self.tree_files.delete(*self.tree_files.get_children(""))
        self._insert_tree_children("", path, "")
        self.frame_tree.pack(fill="both", expand=True)
        self.btn_pack.configure(state="normal")
        self.var_pack_status.set("")
        self._set_status(
            "Позначте чекбоксами, що включити в архів (усе включено за замовчуванням), "
            "і натисніть «Запакувати обране»."
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
                # Порожня "дитина"-заглушка — щоб з'явилась стрілка
                # розгортання; реальні діти довантажуються лінивo при
                # відкритті вузла (_on_tree_open), а не одразу для всього
                # дерева (може бути дорого для великих каталогів).
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
        """Записує стан у модель (_file_tree_checked) для rel_path і,
        якщо це каталог, для геть усіх його нащадків — навіть ще не
        довантажених у дерево (щоб коректний чекбокс з'явився одразу,
        коли вузол буде розгорнуто пізніше)."""
        self._file_tree_checked[rel_path] = checked
        if not is_dir:
            return
        for root, dirs, files in os.walk(abs_path):
            dirs[:] = [d for d in dirs if d != EXCHANGE.pack_subdir_name]
            for name in dirs + files:
                full = os.path.join(root, name)
                rel = os.path.relpath(full, self.selected_path).replace(os.sep, "/")
                self._file_tree_checked[rel] = checked

    def _refresh_visible_checkmarks(self):
        for iid, (rel_path, _abs_path, _is_dir) in self._file_tree_meta.items():
            if not self.tree_files.exists(iid):
                continue
            checked = self._file_tree_checked.get(rel_path, True)
            self.tree_files.set(iid, "chk", "☑" if checked else "☐")

    def on_pack_selected(self):
        if not self.selected_path or not self.selected_is_dir:
            messagebox.showwarning("Увага", "Спочатку оберіть каталог.")
            return

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

        try:
            archive_path = build_archive_from_selection(self.selected_path, included_files)
        except ValueError as e:
            messagebox.showerror("Помилка пакування", str(e))
            return

        # ВАЖЛИВО: selected_path/selected_is_dir НЕ змінюємо (залишається
        # обраний каталог, не архів) — інакше повторне пакування після
        # зміни чекбоксів одразу впаде на guard-перевірці вище (знайдений
        # і виправлений баг: раніше сюди писався шлях архіву, і другий
        # клік "Запакувати обране" бачив selected_is_dir=False й відмовляв
        # з "Спочатку оберіть каталог", хоча дерево й далі було на екрані).
        self.packed_archive_path = archive_path
        self.lbl_selected.configure(text=f"Каталог: {self.selected_path}  →  запаковано: {archive_path}")
        self.var_pack_status.set(f"Запаковано {len(included_files)} файл(и/ів) у {archive_path}.")
        self._set_status(f"Запаковано {len(included_files)} файл(и/ів). Передача (Фаза 3) ще не реалізована.")
        self._log(
            f"Запаковано {len(included_files)} файл(и/ів) у {archive_path} "
            f"(технічна підпапка {EXCHANGE.pack_subdir_name}, не входить у вибір)."
        )

    def on_choose_incoming_dir(self):
        path = filedialog.askdirectory(
            title="Оберіть каталог для вхідних файлів",
            initialdir=self.var_incoming_dir.get() or None,
        )
        if path:
            self.var_incoming_dir.set(path)

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

        self.profile = LocalConfig(
            client_id=client_id,
            incoming_dir=self.var_incoming_dir.get().strip() or self.profile.incoming_dir,
            outgoing_dir=self.var_outgoing_dir.get().strip() or self.profile.outgoing_dir,
        )
        save_config(self.profile)

        self.var_profile_status.set(f"Збережено ({config_path()}).")
        self._set_status("Профіль збережено.")
        self._log(
            f"Профіль збережено: client_id={self.profile.client_id}, "
            f"incoming={self.profile.incoming_dir}, outgoing={self.profile.outgoing_dir}."
        )

    def prepare_archive(self) -> str:
        """Делегує підготовку архіву в шар "обмін" (exchange.py)."""
        return prepare_archive(self.selected_path, self.selected_is_dir)
