#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Шар "транспорт": сервісна функція (встановлення й підтвердження з'єднання) і Фаза 3
(передача файлів) з docs/concept.md. Без GUI-залежностей — appearance.py лише викликає ці
функції у фонових потоках. Протокол і причини рішень: docs/dev-notes.md → "transport.py".
"""

import hashlib
import hmac
import json
import os
import secrets
import socket
import struct
import threading
import time

from Cryptodome.Cipher import AES

from tuning import TRANSPORT


class TransportError(Exception):
    """Базовий клас помилок транспортного шару."""


class ConnectionFailed(TransportError):
    """Не вдалось встановити TCP-з'єднання з іншою стороною (ні прийняти, ні підключитись)."""


class VerificationError(TransportError):
    """З'єднання встановлено, але HMAC-підтвердження ключа не пройшло — ключі не збігаються."""


class PeerClosed(TransportError):
    """Інша сторона закрила з'єднання (нормальне завершення передачі або обрив)."""


# --------------------------------------------------------------------------
# Кадрування: кожне повідомлення — 4-байтний big-endian префікс довжини + тіло.
# --------------------------------------------------------------------------

def send_frame(sock: socket.socket, data: bytes) -> None:
    sock.sendall(struct.pack("!I", len(data)) + data)


def recv_exact(sock: socket.socket, n: int) -> bytes:
    chunks = []
    remaining = n
    while remaining > 0:
        chunk = sock.recv(min(remaining, TRANSPORT.chunk_size_bytes))
        if not chunk:
            raise PeerClosed("З'єднання закрито іншою стороною під час читання.")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def recv_frame(sock: socket.socket) -> bytes:
    header = recv_exact(sock, TRANSPORT.frame_length_bytes)
    (length,) = struct.unpack("!I", header)
    if length > TRANSPORT.max_frame_bytes:
        raise TransportError(f"Кадр завеликий ({length} байт) — обрив з'єднання.")
    return recv_exact(sock, length)


def send_json(sock: socket.socket, obj: dict) -> None:
    send_frame(sock, json.dumps(obj, separators=(",", ":")).encode("utf-8"))


def recv_json(sock: socket.socket) -> dict:
    return json.loads(recv_frame(sock).decode("utf-8"))


# --------------------------------------------------------------------------
# Встановлення з'єднання: слухаємо на local_port І одночасно пробуємо
# підключитись до peer_host:peer_port — що спрацює першим, те й перемагає.
# Не потребує NAT hole-punching трюків: досить, щоб ХОЧ ОДИН бік був
# досяжний (UPnP/STUN підготували адресу заздалегідь) — Docker/dev-notes.
# --------------------------------------------------------------------------

def establish_connection(
    local_port: int,
    peer_host: str | None,
    peer_port: int | None,
    stop_event: threading.Event | None = None,
    timeout: float | None = None,
) -> socket.socket:
    """Повертає перший встановлений сокет (прийнятий або підключений).

    peer_host/peer_port можуть бути None — це нормально для сторони, яка
    ЗГЕНЕРУВАЛА хендшейк і ще не знає адреси іншої сторони (за протоколом
    docs/concept.md хендшейк ділиться лише в один бік): тоді працюємо в
    режимі "лише слухати", інша сторона підключається сама, дізнавшись наш
    host/port із хендшейку. Докладніше: docs/dev-notes.md → "transport.py".

    Кидає ConnectionFailed, якщо нічого не вдалось за timeout."""
    stop_event = stop_event or threading.Event()
    timeout = TRANSPORT.connect_timeout_seconds if timeout is None else timeout
    result: dict = {}
    result_lock = threading.Lock()
    done = threading.Event()

    def _set_result(sock: socket.socket) -> bool:
        with result_lock:
            if "sock" in result:
                return False  # хтось інший уже переміг — цей сокет зайвий
            result["sock"] = sock
            done.set()
            return True

    def _accept_worker():
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            listener.bind(("0.0.0.0", local_port))
            listener.listen(TRANSPORT.listen_backlog)
            listener.settimeout(TRANSPORT.accept_poll_timeout_seconds)
            while not done.is_set() and not stop_event.is_set():
                try:
                    conn, _addr = listener.accept()
                except socket.timeout:
                    continue
                except OSError:
                    return
                conn.settimeout(None)  # знімаємо poll-таймаут листенера — далі сокет блокуючий
                if not _set_result(conn):
                    conn.close()
                return
        finally:
            listener.close()

    def _connect_worker():
        start = time.monotonic()
        while not done.is_set() and not stop_event.is_set():
            if time.monotonic() - start > timeout:
                return
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(TRANSPORT.connect_retry_interval_seconds * 4)
            try:
                sock.connect((peer_host, peer_port))
            except OSError:
                sock.close()
                time.sleep(TRANSPORT.connect_retry_interval_seconds)
                continue
            sock.settimeout(None)  # знімаємо короткий connect-таймаут — далі сокет блокуючий
            if not _set_result(sock):
                sock.close()
            return

    threads = [threading.Thread(target=_accept_worker, daemon=True)]
    if peer_host is not None and peer_port is not None:
        threads.append(threading.Thread(target=_connect_worker, daemon=True))
    for t in threads:
        t.start()
    done.wait(timeout=timeout)
    stop_event.set()  # сигналізуємо іншому воркеру зупинитись, навіть якщо ми виграли

    with result_lock:
        sock = result.get("sock")
    if sock is None:
        target = f"{peer_host}:{peer_port}" if peer_host is not None else "(адреса іншої сторони невідома)"
        raise ConnectionFailed(
            f"Не вдалось встановити з'єднання з {target} за {timeout}с "
            f"(ні прийняти вхідне на порту {local_port}, ні підключитись)."
        )
    return sock


# --------------------------------------------------------------------------
# Підтвердження ключа: взаємний HMAC challenge-response, ключ ніколи не
# передається по мережі. Симетричний протокол — не важливо, хто прийняв,
# а хто підключився.
# --------------------------------------------------------------------------

def verify_channel(sock: socket.socket, key: bytes, timeout: float | None = None) -> None:
    """Кидає VerificationError, якщо ключі не збігаються (або таймаут/обрив)."""
    old_timeout = sock.gettimeout()
    sock.settimeout(TRANSPORT.verify_timeout_seconds if timeout is None else timeout)
    try:
        my_nonce = secrets.token_bytes(TRANSPORT.nonce_size_bytes)
        send_frame(sock, my_nonce)
        peer_nonce = recv_frame(sock)

        my_proof = hmac.new(key, peer_nonce, hashlib.sha256).digest()
        send_frame(sock, my_proof)
        peer_proof = recv_frame(sock)

        expected = hmac.new(key, my_nonce, hashlib.sha256).digest()
        if not hmac.compare_digest(peer_proof, expected):
            raise VerificationError("Код підтвердження ключа не збігається з іншою стороною.")
    except (TransportError, OSError, socket.timeout) as e:
        if isinstance(e, VerificationError):
            raise
        raise VerificationError(f"Не вдалось підтвердити ключ: {e}") from e
    finally:
        sock.settimeout(old_timeout)


# --------------------------------------------------------------------------
# Передача файлів: AES-256-CTR поверх кадрів. Один потік кадрів на файл:
# JSON-заголовок {"name","size"} -> N зашифрованих байт -> SHA-256 оригіналу.
# Завершення передачі — кадр {"type":"done"}.
# --------------------------------------------------------------------------

def _aes_cipher(key: bytes, nonce: bytes):
    return AES.new(key, AES.MODE_CTR, nonce=nonce[:8], initial_value=int.from_bytes(nonce[8:], "big"))


def send_files(sock: socket.socket, key: bytes, root_dir: str, file_paths: list, on_progress=None) -> None:
    """file_paths — абсолютні шляхи під root_dir (як у exchange.build_archive_from_selection)."""
    for full_path in file_paths:
        rel_path = os.path.relpath(full_path, root_dir).replace(os.sep, "/")
        size = os.path.getsize(full_path)
        nonce = secrets.token_bytes(TRANSPORT.aes_nonce_bytes)
        cipher = _aes_cipher(key, nonce)
        digest = hashlib.sha256()

        send_json(sock, {"type": "file", "name": rel_path, "size": size, "nonce": nonce.hex()})

        sent = 0
        with open(full_path, "rb") as f:
            while True:
                chunk = f.read(TRANSPORT.chunk_size_bytes)
                if not chunk:
                    break
                digest.update(chunk)
                send_frame(sock, cipher.encrypt(chunk))
                sent += len(chunk)
                if on_progress:
                    on_progress(rel_path, sent, size)
        send_json(sock, {"type": "checksum", "sha256": digest.hexdigest()})

    send_json(sock, {"type": "done"})


def receive_files(sock: socket.socket, key: bytes, dest_dir: str, on_progress=None) -> list:
    """Приймає файли, доки не прийде {"type":"done"} або з'єднання не закриється.
    Повертає список абсолютних шляхів записаних файлів. Перевіряє SHA-256 кожного —
    невідповідність -> TransportError, файл не лишається напівзаписаним без попередження."""
    received: list = []
    os.makedirs(dest_dir, exist_ok=True)

    while True:
        header = recv_json(sock)
        if header.get("type") == "done":
            break
        if header.get("type") != "file":
            raise TransportError(f"Неочікуваний тип кадру: {header.get('type')!r}")

        rel_path = header["name"]
        size = int(header["size"])
        nonce = bytes.fromhex(header["nonce"])
        cipher = _aes_cipher(key, nonce)
        digest = hashlib.sha256()

        # Захист від path traversal: rel_path не має виходити за межі dest_dir.
        dest_path = os.path.normpath(os.path.join(dest_dir, rel_path))
        if not dest_path.startswith(os.path.normpath(dest_dir) + os.sep) and dest_path != os.path.normpath(dest_dir):
            raise TransportError(f"Небезпечний шлях у заголовку файлу: {rel_path!r}")
        os.makedirs(os.path.dirname(dest_path), exist_ok=True)

        remaining = size
        with open(dest_path, "wb") as f:
            while remaining > 0:
                encrypted = recv_frame(sock)
                plain = cipher.decrypt(encrypted)
                digest.update(plain)
                f.write(plain)
                remaining -= len(plain)
                if on_progress:
                    on_progress(rel_path, size - remaining, size)

        checksum_msg = recv_json(sock)
        if checksum_msg.get("type") != "checksum":
            raise TransportError("Очікувався кадр контрольної суми після файлу.")
        if digest.hexdigest() != checksum_msg.get("sha256"):
            os.remove(dest_path)
            raise TransportError(f"Контрольна сума не збіглась для '{rel_path}' — файл видалено.")

        received.append(dest_path)

    return received
