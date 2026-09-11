#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Шар "підключення": деривація ключа з парольної фрази, формування й розбір хендшейк-пакета.
Обмін пакетом — через окремий месенджер поза застосунком (docs/concept.md, Фаза 1).
"""

import base64
import hashlib
import json
import secrets
import socket

from tuning import CONNECTION


def derive_key(passphrase: str, salt: bytes, iterations: int) -> bytes:
    """PBKDF2-HMAC-SHA256, стандартна бібліотека.
    Докладніше: docs/dev-notes.md → "connection.py: derive_key"."""
    return hashlib.pbkdf2_hmac("sha256", passphrase.encode("utf-8"), salt, iterations)


def key_fingerprint(key: bytes) -> str:
    """"Код підтвердження" ключа для звірки голосом/текстом без передачі самого ключа.
    Докладніше: docs/dev-notes.md → "connection.py: key_fingerprint"."""
    return hashlib.sha256(key).hexdigest()[:CONNECTION.fingerprint_hex_length].upper()


def detect_local_address() -> str:
    """Best-effort локальна IP-адреса (LAN-only, не публічна ззовні).
    Докладніше: docs/dev-notes.md → "connection.py: detect_local_address"."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(0.2)
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except OSError:
        pass
    try:
        return socket.gethostbyname(socket.gethostname())
    except OSError:
        return "127.0.0.1"


def build_handshake_packet(iterations: int, port: int, host: str | None = None) -> tuple[str, bytes, str, str]:
    """Пакет без парольної фрази. host=None -> автовизначення локальної адреси, інакше передане
    значення (UPnP/STUN). Повертає (текст, salt, session_id, host_у_пакеті)."""
    salt = secrets.token_bytes(CONNECTION.salt_size_bytes)
    session_id = secrets.token_hex(CONNECTION.session_id_size_bytes)
    if host is None:
        host = detect_local_address()
    packet = {
        "v": CONNECTION.packet_version,
        "sid": session_id,
        "salt": base64.b64encode(salt).decode("ascii"),
        "iter": iterations,
        "host": host,
        "port": port,
    }
    raw = json.dumps(packet, separators=(",", ":")).encode("utf-8")
    b64 = base64.urlsafe_b64encode(raw).decode("ascii")
    text = f"{CONNECTION.handshake_header}\n{b64}\n{CONNECTION.handshake_footer}"
    return text, salt, session_id, host


def parse_handshake_packet(text: str) -> dict:
    """Розбирає вхідний хендшейк, знятий копіюванням з месенджера."""
    cleaned = text.strip()
    cleaned = cleaned.replace(CONNECTION.handshake_header, "")
    cleaned = cleaned.replace(CONNECTION.handshake_footer, "")
    cleaned = cleaned.strip()
    if not cleaned:
        raise ValueError("Порожній хендшейк")
    raw = base64.urlsafe_b64decode(cleaned.encode("ascii"))
    packet = json.loads(raw.decode("utf-8"))
    for field_name in ("v", "sid", "salt", "iter", "host", "port"):
        if field_name not in packet:
            raise ValueError(f"У хендшейку відсутнє поле '{field_name}'")
    return packet
