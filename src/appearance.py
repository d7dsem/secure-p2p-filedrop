#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Шар "зовнішність": tkinter GUI. Крипто — connection.py, дані — exchange.py, тема — tuning.py.
"""

import base64
import os
import queue
import threading
import time
import tkinter as tk
import tkinter.font as tkfont
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
        self.packed_archive_path: str | None = None  # окремо від selected_path — див. dev-notes.md
        self.transfer_payload: list[str] | None = None  # фінальний payload для майбутньої Фази 3

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

        if initial_passphrase:
            self.var_passphrase.set(initial_passphrase)

        # Автоматично, без кнопки (docs/concept.md); в кінці __init__ — усе вже побудовано.
        self._start_connection_setup()

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

        self._build_session_tab(tab_session)
        self._build_profile_tab(tab_profile, pad)
        self._build_log_tab(tab_log, pad)

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
        self.var_port = tk.StringVar(value=str(CONNECTION.default_port))
        ttk.Entry(frame_params, textvariable=self.var_port, width=8).grid(
            row=1, column=3, sticky="w", padx=(0, 8), pady=(0, 8)
        )

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

        # --- Секція: вихідний хендшейк ---
        frame_out = ttk.LabelFrame(parent, text="Мій хендшейк (надіслати через месенджер)")
        frame_out.pack(fill="x", **pad)

        btns_out = ttk.Frame(frame_out)
        btns_out.pack(fill="x", padx=8, pady=(8, 4))
        ttk.Button(
            btns_out, text="Згенерувати хендшейк", style="Accent.TButton",
            command=self.on_generate_handshake,
        ).pack(side="left")
        ttk.Button(
            btns_out, text="Скопіювати в буфер", command=self.on_copy_handshake
        ).pack(side="left", padx=8)

        self.text_out = scrolledtext.ScrolledText(
            frame_out, height=APPEARANCE.text_widget_height, wrap="char", font=self._mono_font
        )
        self.text_out.pack(fill="x", padx=8, pady=(0, 4))
        self._style_text_widget(self.text_out)
        self.text_out.configure(state="disabled")

        self.lbl_local_fp = ttk.Label(frame_out, text="Код підтвердження: —", wraplength=340)
        self.lbl_local_fp.pack(anchor="w", padx=8, pady=(0, 8))

        # --- Секція: вхідний хендшейк ---
        frame_in = ttk.LabelFrame(parent, text="Хендшейк співрозмовника (вставити з месенджера)")
        frame_in.pack(fill="x", **pad)

        self.text_in = scrolledtext.ScrolledText(
            frame_in, height=APPEARANCE.text_widget_height, wrap="char", font=self._mono_font
        )
        self.text_in.pack(fill="x", padx=8, pady=8)
        self._style_text_widget(self.text_in)

        btns_in = ttk.Frame(frame_in)
        btns_in.pack(fill="x", padx=8, pady=(0, 8))
        ttk.Button(
            btns_in, text="Обробити вхідний хендшейк", command=self.on_process_incoming
        ).pack(side="left")

        self.lbl_peer_fp = ttk.Label(frame_in, text="Код підтвердження ключа: —", wraplength=340)
        self.lbl_peer_fp.pack(anchor="w", padx=8, pady=(0, 4))

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

        self.lbl_selected = ttk.Label(frame_file, text="Нічого не обрано", wraplength=520)
        self.lbl_selected.pack(anchor="w", padx=8, pady=(0, 4))

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

        btns_transfer = ttk.Frame(frame_file)
        btns_transfer.pack(fill="x", padx=8, pady=8)
        self._transfer_row = btns_transfer  # опорна точка для pack(..., before=...) у on_choose_dir
        self.btn_transfer = ttk.Button(
            btns_transfer, text="Ініціалізувати передачу", style="Accent.TButton",
            command=self.on_initiate_transfer, state="disabled",
        )
        self.btn_transfer.pack(side="left")
        self.var_transfer_status = tk.StringVar(value="")
        ttk.Label(btns_transfer, textvariable=self.var_transfer_status, wraplength=420).pack(
            side="left", padx=8
        )

    def _build_profile_tab(self, parent: ttk.Frame, pad: dict):
        """local_config.py: client_id + дефолтні каталоги. На диск — лише по кнопці "Зберегти профіль"."""
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

        # public_port — реально спостережений зовнішній порт (може відрізнятись від
        # локального при STUN — dev-notes.md); None, якщо з'єднання не налаштовувалось.
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
        """Фоновий потік — жодних звернень до self.root/tkinter, лише мережа й запис у чергу."""
        result: dict = {"port": port}
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
                f"Мережеві налаштування (рівень 2, STUN) — успіх: публічна адреса "
                f"{self.public_host}:{self.public_port}. УВАГА: на відміну від UPnP, порт тут НЕ "
                f"прокинуто — це працює, лише поки живий NAT-мапінг від цього запиту "
                f"(типово секунди-хвилини), без гарантії."
            )
            return

        self.public_host = None
        self.public_port = None
        self.public_host_source = None
        self.var_conn_status.set(
            "UPnP і STUN не спрацювали — буде використано локальну адресу (LAN-only)."
        )
        self._log(
            "Мережеві налаштування: обидва рівні не спрацювали (типово symmetric NAT/CGNAT або "
            "суворий фаєрвол) — хендшейк генеруватиметься з локальною LAN-адресою."
        )

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

    def on_choose_dir(self):
        path = filedialog.askdirectory(
            title="Оберіть каталог", initialdir=self.var_outgoing_dir.get() or None
        )
        if not path:
            return

        self.selected_path = path
        self.selected_is_dir = True
        self.packed_archive_path = None
        self.transfer_payload = None
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
        """Фіналізує self.transfer_payload (Фаза 3-транспорт ще не реалізований — лише
        готуємо й звітуємо). Каталог: архів чи "як є" за var_archive_before_send."""
        if not self.selected_path:
            messagebox.showwarning("Увага", "Спочатку оберіть файл або каталог.")
            return

        if not self.selected_is_dir:
            self.transfer_payload = [self.selected_path]
            self.packed_archive_path = None
            self.var_transfer_status.set("Готово до передачі: 1 файл (як є).")
            self._set_status(
                f"Готово до передачі: {os.path.basename(self.selected_path)}. "
                f"Передача (Фаза 3) ще не реалізована."
            )
            self._log(f"Ініціалізація передачі: 1 файл як є — {self.selected_path}. Фаза 3 ще не реалізована.")
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

        if self.var_archive_before_send.get():
            try:
                archive_path = build_archive_from_selection(self.selected_path, included_files)
            except ValueError as e:
                messagebox.showerror("Помилка пакування", str(e))
                return

            self.packed_archive_path = archive_path
            self.transfer_payload = [archive_path]
            self.lbl_selected.configure(
                text=f"Каталог: {self.selected_path}  →  запаковано: {archive_path}"
            )
            self.var_transfer_status.set(
                f"Готово до передачі: 1 архів ({len(included_files)} файл(и/ів) усередині)."
            )
            self._set_status(
                f"Готово до передачі: архів з {len(included_files)} файл(и/ів). "
                f"Передача (Фаза 3) ще не реалізована."
            )
            self._log(
                f"Ініціалізація передачі: запаковано {len(included_files)} файл(и/ів) у {archive_path} "
                f"(технічна підпапка {EXCHANGE.pack_subdir_name}, не входить у вибір). "
                f"Фаза 3 ще не реалізована."
            )
        else:
            self.packed_archive_path = None
            self.transfer_payload = included_files
            self.var_transfer_status.set(
                f"Готово до передачі: {len(included_files)} файл(и/ів) як є (без архівування)."
            )
            self._set_status(
                f"Готово до передачі: {len(included_files)} файл(и/ів) як є. "
                f"Передача (Фаза 3) ще не реалізована."
            )
            self._log(
                f"Ініціалізація передачі: {len(included_files)} файл(и/ів) як є (без архівування). "
                f"Фаза 3 ще не реалізована."
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
