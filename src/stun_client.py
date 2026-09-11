#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Шар "підключення": мінімальний STUN-клієнт (RFC 5389) — рівень 2 моделі з'єднання.
Чим відрізняється від UPnP (nat_traversal.py): docs/dev-notes.md → "stun_client.py".
"""

import os
import socket
import struct

from tuning import STUN

_MAGIC_COOKIE = 0x2112A442
_BINDING_REQUEST = 0x0001
_BINDING_SUCCESS_RESPONSE = 0x0101
_ATTR_MAPPED_ADDRESS = 0x0001
_ATTR_XOR_MAPPED_ADDRESS = 0x0020
_FAMILY_IPV4 = 0x01


class StunError(Exception):
    """Не вдалось дізнатись публічну адресу через STUN (таймаут, немає
    мережі, сервер повернув щось нерозпізнаване тощо)."""


# --------------------------------------------------------------------------
# Чисті функції кодування/декодування STUN-повідомлень — без мережевого I/O,
# легко тестувати окремо.
# --------------------------------------------------------------------------

def build_binding_request(transaction_id: bytes) -> bytes:
    if len(transaction_id) != 12:
        raise ValueError("transaction_id має бути рівно 12 байт (вимога RFC 5389)")
    return struct.pack("!HHI12s", _BINDING_REQUEST, 0, _MAGIC_COOKIE, transaction_id)


def _parse_xor_mapped_address(value: bytes) -> tuple[str, int] | None:
    if len(value) < 8 or value[1] != _FAMILY_IPV4:
        return None
    xport = struct.unpack("!H", value[2:4])[0]
    port = xport ^ (_MAGIC_COOKIE >> 16)
    xaddr = struct.unpack("!I", value[4:8])[0]
    addr = xaddr ^ _MAGIC_COOKIE
    ip = socket.inet_ntoa(struct.pack("!I", addr))
    return ip, port


def _parse_mapped_address(value: bytes) -> tuple[str, int] | None:
    if len(value) < 8 or value[1] != _FAMILY_IPV4:
        return None
    port = struct.unpack("!H", value[2:4])[0]
    ip = socket.inet_ntoa(value[4:8])
    return ip, port


def parse_binding_response(data: bytes, transaction_id: bytes) -> tuple[str, int]:
    """Розбирає STUN Binding Success Response і повертає (ip, port) з
    XOR-MAPPED-ADDRESS (пріоритетно) або legacy MAPPED-ADDRESS."""
    if len(data) < 20:
        raise StunError("Закоротка відповідь від STUN-сервера (менше 20 байт заголовка)")

    msg_type, msg_len, magic_cookie, resp_txn_id = struct.unpack("!HHI12s", data[:20])
    if magic_cookie != _MAGIC_COOKIE:
        raise StunError("Відповідь без коректного STUN magic cookie — не STUN-сервер?")
    if msg_type != _BINDING_SUCCESS_RESPONSE:
        raise StunError(f"STUN-сервер повернув неочікуваний тип повідомлення: 0x{msg_type:04x}")
    if resp_txn_id != transaction_id:
        raise StunError("STUN-відповідь з іншим transaction ID (збій мережі або підміна)")

    body = data[20:20 + msg_len]
    mapped: tuple[str, int] | None = None
    offset = 0
    while offset + 4 <= len(body):
        attr_type, attr_len = struct.unpack("!HH", body[offset:offset + 4])
        value = body[offset + 4:offset + 4 + attr_len]
        if len(value) < attr_len:
            break  # обрізане повідомлення — далі парсити нема сенсу
        if attr_type == _ATTR_XOR_MAPPED_ADDRESS:
            parsed = _parse_xor_mapped_address(value)
            if parsed:
                return parsed
        elif attr_type == _ATTR_MAPPED_ADDRESS and mapped is None:
            mapped = _parse_mapped_address(value)
        padded_len = attr_len + ((4 - attr_len % 4) % 4)
        offset += 4 + padded_len

    if mapped:
        return mapped
    raise StunError(
        "У відповіді STUN-сервера немає адресного атрибута "
        "(XOR-MAPPED-ADDRESS/MAPPED-ADDRESS)"
    )


# --------------------------------------------------------------------------
# Мережевий виклик
# --------------------------------------------------------------------------

def get_public_address(
    local_port: int,
    server_host: str | None = None,
    server_port: int | None = None,
    timeout: float | None = None,
) -> tuple[str, int]:
    """Прив'язується до local_port, питає STUN-сервер публічну IP:port для цього сокета.
    Кидає StunError при невдачі — виклик з appearance.py переходить до наступного рівня."""
    host = server_host or STUN.server_host
    port = server_port or STUN.server_port
    timeout = STUN.timeout_seconds if timeout is None else timeout

    transaction_id = os.urandom(12)
    request = build_binding_request(transaction_id)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        try:
            sock.bind(("0.0.0.0", local_port))
        except OSError as e:
            raise StunError(f"Не вдалось прив'язатись до локального порту {local_port}: {e}") from e

        sock.settimeout(timeout)
        try:
            sock.sendto(request, (host, port))
            data, _addr = sock.recvfrom(2048)
        except socket.timeout as e:
            raise StunError(f"STUN-сервер {host}:{port} не відповів за {timeout}с") from e
        except OSError as e:
            raise StunError(f"Не вдалось звернутись до STUN-сервера {host}:{port}: {e}") from e
    finally:
        sock.close()

    return parse_binding_response(data, transaction_id)
