#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Шар "підключення": деривація сесійного ключа з парольної фрази та
формування/розбір хендшейк-пакета, яким користувачі обмінюються через
окремий захищений месенджер (сам застосунок участі в цій передачі не
бере — див. docs/concept.md, Фаза 1).
"""

import base64
import hashlib
import json
import secrets
import socket

from tuning import CONNECTION


def derive_key(passphrase: str, salt: bytes, iterations: int) -> bytes:
    """
    Деривація сесійного ключа через PBKDF2-HMAC-SHA256 (стандартна
    бібліотека, без додаткових залежностей). Раніше тут був ручний
    ланцюжок SHA-256(SHA-256(...)) без HMAC-конструкції — слабший
    варіант, залишений як компроміс на старті проєкту; замінено на
    цю реалізацію.
    """
    return hashlib.pbkdf2_hmac("sha256", passphrase.encode("utf-8"), salt, iterations)


def key_fingerprint(key: bytes) -> str:
    """Короткий 'код підтвердження' ключа — щоб озвучити й звірити
    з іншою стороною через месенджер/голосом, не передаючи сам ключ.
    Це додано понад те, що прямо просили, бо без нього немає способу
    переконатись, що обидві сторони отримали однаковий ключ."""
    return hashlib.sha256(key).hexdigest()[:CONNECTION.fingerprint_hex_length].upper()


def detect_local_address() -> str:
    """
    Найкраще наближення (best-effort) локальної IP-адреси хоста — другий,
    мережевий компонент хендшейку (див. docs/concept.md, Фаза 1, п.1):
    "інформація, потрібна для встановлення з'єднання".

    ПРИМІТКА: це адреса локального мережевого інтерфейсу, а не публічна
    адреса ззовні. Придатна для з'єднання в межах однієї LAN/VPN.
    З'єднання через інтернет (за NAT) потребує додаткових кроків
    (переадресація порту, STUN тощо) — це вже за межами цього кроку
    розробки й не реалізовано.
    """
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
    """
    Формує пакет, який НЕ містить парольної фрази — лише сіль,
    ідентифікатор сесії, кількість ітерацій і мережеву інформацію
    (адреса + порт), потрібну іншій стороні для P2P-з'єднання.
    Ключ з цього пакету відновити неможливо без знання самої парольної
    фрази.

    host=None (типово) — автовизначення адреси локального інтерфейсу
    (LAN-only). Якщо викликач уже отримав публічну IP іншим шляхом
    (наприклад, через UPnP — nat_traversal.try_configure_port_forwarding),
    її можна передати напряму, і вона піде в пакет замість локальної.

    Повертає (текст_для_копіювання, salt, session_id, host_що_потрапив_у_пакет).
    """
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
