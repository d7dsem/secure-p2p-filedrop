#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Каркас клієнта для обміну файлами між ПК без статичної адреси.
Ця частина відповідає лише за:
  1) деривацію ключа з парольної фрази (ітеративний SHA-256, як задано);
  2) підготовку "хендшейку" (пакет для передачі через захищений месенджер);
  3) обробку вхідного хендшейку від співрозмовника;
  4) вибір файлу або каталогу для подальшого архівування.

Залежності: лише стандартна бібліотека Python (tkinter, hashlib, json,
base64, secrets, zipfile, os, tempfile). Кросплатформенно (Windows/macOS/Linux),
за умови що Python зібраний з Tk (стандартно для офіційних дистрибутивів).
"""

import base64
import hashlib
import json
import os
import secrets
import tempfile
import zipfile
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext

DEFAULT_ITERATIONS = 200_000
HANDSHAKE_HEADER = "-----HANDSHAKE-----"
HANDSHAKE_FOOTER = "-----END-----"

# Палітра темної теми. Ttk не має вбудованої темної теми "з коробки" —
# кольори задаються вручну через ttk.Style (для ttk-віджетів) і напряму
# через configure() для класичних Tk-віджетів (Text/ScrolledText не є
# ttk-віджетами й стилем не керуються).
DARK_BG = "#1e1e1e"
DARK_BG_PANEL = "#252526"
DARK_FG = "#e6e6e6"
DARK_FG_MUTED = "#9aa0a6"
DARK_ENTRY_BG = "#2d2d30"
DARK_ACCENT = "#3a7afe"
DARK_BORDER = "#3c3c3c"


# --------------------------------------------------------------------------
# Криптографічна частина
# --------------------------------------------------------------------------

def derive_key(passphrase: str, salt: bytes, iterations: int) -> bytes:
    """
    Деривація ключа так, як описано в запиті: ітеративне хешування SHA-256.

    ПРИМІТКА (явно позначено, бо це відхилення від того, що буквально
    просили, продиктоване питаннями безпеки):
    Сіль домішується лише один раз на старті. Це працює, але є слабшим
    за стандартний PBKDF2-HMAC: у "голому" ланцюжку SHA-256(SHA-256(...))
    немає HMAC-конструкції, тому теоретично можливі атаки, яких PBKDF2
    уникає. Стандартна бібліотека Python вже містить готову й сильнішу
    реалізацію без жодної додаткової залежності:

        hashlib.pbkdf2_hmac('sha256', passphrase.encode(), salt, iterations)

    Тобто перехід на неї НЕ додає залежностей і рекомендується. Нижче
    лишив саме той варіант, який ви описали (ручний ланцюжок), як
    базовий каркас — заміна на pbkdf2_hmac буде однорядковою.
    """
    data = salt + passphrase.encode("utf-8")
    digest = hashlib.sha256(data).digest()
    for _ in range(iterations - 1):
        digest = hashlib.sha256(digest).digest()
    return digest


def key_fingerprint(key: bytes) -> str:
    """Короткий 'код підтвердження' ключа — щоб озвучити й звірити
    з іншою стороною через месенджер/голосом, не передаючи сам ключ.
    Це додано понад те, що прямо просили, бо без нього немає способу
    переконатись, що обидві сторони отримали однаковий ключ."""
    return hashlib.sha256(key).hexdigest()[:8].upper()


# --------------------------------------------------------------------------
# Хендшейк (пакет для передачі через месенджер)
# --------------------------------------------------------------------------

def build_handshake_packet(iterations: int) -> tuple[str, bytes, str]:
    """
    Формує пакет, який НЕ містить парольної фрази — лише сіль,
    ідентифікатор сесії та кількість ітерацій. Ключ з цього пакету
    відновити неможливо без знання самої парольної фрази.
    Повертає (текст_для_копіювання, salt, session_id).
    """
    salt = secrets.token_bytes(16)
    session_id = secrets.token_hex(8)
    packet = {
        "v": 1,
        "sid": session_id,
        "salt": base64.b64encode(salt).decode("ascii"),
        "iter": iterations,
    }
    raw = json.dumps(packet, separators=(",", ":")).encode("utf-8")
    b64 = base64.urlsafe_b64encode(raw).decode("ascii")
    text = f"{HANDSHAKE_HEADER}\n{b64}\n{HANDSHAKE_FOOTER}"
    return text, salt, session_id


def parse_handshake_packet(text: str) -> dict:
    """Розбирає вхідний хендшейк, знятий копіюванням з месенджера."""
    cleaned = text.strip()
    cleaned = cleaned.replace(HANDSHAKE_HEADER, "").replace(HANDSHAKE_FOOTER, "")
    cleaned = cleaned.strip()
    if not cleaned:
        raise ValueError("Порожній хендшейк")
    raw = base64.urlsafe_b64decode(cleaned.encode("ascii"))
    packet = json.loads(raw.decode("utf-8"))
    for field in ("v", "sid", "salt", "iter"):
        if field not in packet:
            raise ValueError(f"У хендшейку відсутнє поле '{field}'")
    return packet


# --------------------------------------------------------------------------
# GUI
# --------------------------------------------------------------------------

class SecureFileClientApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Обмін файлами — підготовка сеансу")
        self.root.geometry("640x720")
        self.root.minsize(560, 640)

        self.local_key: bytes | None = None
        self.local_salt: bytes | None = None
        self.local_session_id: str | None = None

        self.peer_key: bytes | None = None

        self.selected_path: str | None = None
        self.selected_is_dir: bool = False

        self._apply_dark_theme()
        self._build_ui()

    # ---- побудова інтерфейсу -----------------------------------------

    def _build_ui(self):
        pad = {"padx": 10, "pady": 6}

        # --- Секція: парольна фраза ---
        frame_pass = ttk.LabelFrame(self.root, text="Парольна фраза")
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

        # --- Секція: кількість ітерацій ---
        frame_iter = ttk.Frame(self.root)
        frame_iter.pack(fill="x", **pad)
        ttk.Label(frame_iter, text="Кількість ітерацій хешування:").pack(side="left")
        self.var_iterations = tk.StringVar(value=str(DEFAULT_ITERATIONS))
        ttk.Entry(frame_iter, textvariable=self.var_iterations, width=12).pack(
            side="left", padx=8
        )

        # --- Секція: вихідний хендшейк ---
        frame_out = ttk.LabelFrame(self.root, text="Мій хендшейк (надіслати через месенджер)")
        frame_out.pack(fill="both", expand=True, **pad)

        btns_out = ttk.Frame(frame_out)
        btns_out.pack(fill="x", padx=8, pady=(8, 4))
        ttk.Button(
            btns_out, text="Згенерувати хендшейк", command=self.on_generate_handshake
        ).pack(side="left")
        ttk.Button(
            btns_out, text="Скопіювати в буфер", command=self.on_copy_handshake
        ).pack(side="left", padx=8)

        self.text_out = scrolledtext.ScrolledText(frame_out, height=6, wrap="char")
        self.text_out.pack(fill="both", expand=True, padx=8, pady=(0, 4))
        self.text_out.configure(state="disabled")

        self.lbl_local_fp = ttk.Label(frame_out, text="Код підтвердження: —")
        self.lbl_local_fp.pack(anchor="w", padx=8, pady=(0, 8))

        # --- Секція: вхідний хендшейк ---
        frame_in = ttk.LabelFrame(self.root, text="Хендшейк співрозмовника (вставити з месенджера)")
        frame_in.pack(fill="both", expand=True, **pad)

        self.text_in = scrolledtext.ScrolledText(frame_in, height=6, wrap="char")
        self.text_in.pack(fill="both", expand=True, padx=8, pady=8)

        btns_in = ttk.Frame(frame_in)
        btns_in.pack(fill="x", padx=8, pady=(0, 8))
        ttk.Button(
            btns_in, text="Обробити вхідний хендшейк", command=self.on_process_incoming
        ).pack(side="left")

        self.lbl_peer_fp = ttk.Label(frame_in, text="Код підтвердження ключа: —")
        self.lbl_peer_fp.pack(anchor="w", padx=8, pady=(0, 4))

        # --- Секція: вибір файлу/каталогу ---
        frame_file = ttk.LabelFrame(self.root, text="Що передати")
        frame_file.pack(fill="x", **pad)

        btns_file = ttk.Frame(frame_file)
        btns_file.pack(fill="x", padx=8, pady=8)
        ttk.Button(btns_file, text="Обрати файл...", command=self.on_choose_file).pack(
            side="left"
        )
        ttk.Button(
            btns_file, text="Обрати каталог...", command=self.on_choose_dir
        ).pack(side="left", padx=8)

        self.lbl_selected = ttk.Label(frame_file, text="Нічого не обрано", wraplength=580)
        self.lbl_selected.pack(anchor="w", padx=8, pady=(0, 8))

        # --- Статус ---
        self.var_status = tk.StringVar(value="Готово.")
        status_bar = ttk.Label(self.root, textvariable=self.var_status, relief="sunken", anchor="w")
        status_bar.pack(fill="x", side="bottom")

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

        text, salt, session_id = build_handshake_packet(iterations)
        self.local_salt = salt
        self.local_session_id = session_id
        self.local_key = derive_key(passphrase, salt, iterations)

        self.text_out.configure(state="normal")
        self.text_out.delete("1.0", "end")
        self.text_out.insert("1.0", text)
        self.text_out.configure(state="disabled")

        self.lbl_local_fp.configure(
            text=f"Код підтвердження: {key_fingerprint(self.local_key)}  "
                 f"(sid={session_id})"
        )
        self._set_status("Хендшейк згенеровано. Надішліть його через месенджер.")

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
            return

        self.peer_key = derive_key(passphrase, salt, iterations)
        self.lbl_peer_fp.configure(
            text=f"Код підтвердження ключа: {key_fingerprint(self.peer_key)}  "
                 f"(sid={packet['sid']})"
        )
        self._set_status(
            "Ключ з вхідного хендшейку отримано. "
            "Звірте коди підтвердження з обох сторін через голос/месенджер — "
            "вони мають збігатися."
        )

    def on_choose_file(self):
        path = filedialog.askopenfilename(title="Оберіть файл")
        if path:
            self.selected_path = path
            self.selected_is_dir = False
            self.lbl_selected.configure(text=f"Файл: {path}")

    def on_choose_dir(self):
        path = filedialog.askdirectory(title="Оберіть каталог")
        if path:
            self.selected_path = path
            self.selected_is_dir = True
            self.lbl_selected.configure(text=f"Каталог (буде заархівовано): {path}")

    # ---- заготовка під наступний крок (архівування) ----------------------

    def prepare_archive(self) -> str:
        """
        Стаб: якщо обрано каталог — пакує його в ZIP у тимчасовій директорії
        й повертає шлях до архіву; якщо файл — повертає шлях без змін.

        ВАЖЛИВО (явно позначено — це не було в запиті, але критично для
        наступного кроку "запаролені архіви"):
        Стандартний модуль zipfile у Python НЕ вміє створювати архіви
        з сучасним AES-шифруванням — лише читати legacy ZipCrypto
        (слабке, не рекомендується для реального захисту). Щоб
        отримати справді захищений архів, є два шляхи:
          1) додати одну зовнішню залежність (наприклад, pyzipper —
             підтримує AES-256 для ZIP);
          2) не шифрувати сам архів, а шифрувати вже встановлений канал
             (як і обговорювалось раніше) — тоді архів можна лишити
             без пароля, бо захист забезпечує транспортний рівень.
        Це прямий наслідок вимоги "мінімум залежностей": варіант (2)
        її не порушує, варіант (1) — порушує на одну бібліотеку.
        """
        if not self.selected_path:
            raise ValueError("Спочатку оберіть файл або каталог.")

        if not self.selected_is_dir:
            return self.selected_path

        tmp_dir = tempfile.mkdtemp(prefix="secure_transfer_")
        archive_path = os.path.join(tmp_dir, "payload.zip")
        base = self.selected_path
        with zipfile.ZipFile(archive_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for root, _dirs, files in os.walk(base):
                for fname in files:
                    full = os.path.join(root, fname)
                    arcname = os.path.relpath(full, os.path.dirname(base))
                    zf.write(full, arcname)
        return archive_path


def main():
    root = tk.Tk()
    try:
        style = ttk.Style()
        if "clam" in style.theme_names():
            style.theme_use("clam")
    except Exception:
        pass
    app = SecureFileClientApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
