#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Тести чистої логіки stun_client.py — Рівень 1 з docs/testing.md.

Реальний UDP-обмін зі справжнім публічним STUN-сервером тут НЕ
тестується (мережева залежність, зовнішній сервіс) — лише кодування
Binding Request і розбір (синтетичного) Binding Response, включно з
XOR-MAPPED-ADDRESS/MAPPED-ADDRESS і помилковими відповідями.
"""

import os
import socket
import struct
import unittest

import _pathfix  # noqa: F401  (додає src/ у sys.path перед наступними імпортами)

from stun_client import (
    StunError,
    _MAGIC_COOKIE,
    build_binding_request,
    parse_binding_response,
)

_BINDING_SUCCESS_RESPONSE = 0x0101
_ATTR_MAPPED_ADDRESS = 0x0001
_ATTR_XOR_MAPPED_ADDRESS = 0x0020


def _xor_mapped_address_attr(ip: str, port: int) -> bytes:
    ip_int = struct.unpack("!I", socket.inet_aton(ip))[0]
    xport = port ^ (_MAGIC_COOKIE >> 16)
    xaddr = ip_int ^ _MAGIC_COOKIE
    value = struct.pack("!BBHI", 0, 1, xport, xaddr)
    return struct.pack("!HH", _ATTR_XOR_MAPPED_ADDRESS, len(value)) + value


def _mapped_address_attr(ip: str, port: int) -> bytes:
    value = struct.pack("!BBH4s", 0, 1, port, socket.inet_aton(ip))
    return struct.pack("!HH", _ATTR_MAPPED_ADDRESS, len(value)) + value


def _binding_response(body: bytes, transaction_id: bytes, msg_type: int = _BINDING_SUCCESS_RESPONSE) -> bytes:
    header = struct.pack("!HHI12s", msg_type, len(body), _MAGIC_COOKIE, transaction_id)
    return header + body


class BuildBindingRequestTests(unittest.TestCase):
    def test_request_is_20_bytes_header_only(self):
        txn = os.urandom(12)
        req = build_binding_request(txn)
        self.assertEqual(len(req), 20)

    def test_request_contains_magic_cookie_and_transaction_id(self):
        txn = os.urandom(12)
        req = build_binding_request(txn)
        msg_type, msg_len, magic_cookie, embedded_txn = struct.unpack("!HHI12s", req)
        self.assertEqual(msg_type, 0x0001)
        self.assertEqual(msg_len, 0)
        self.assertEqual(magic_cookie, _MAGIC_COOKIE)
        self.assertEqual(embedded_txn, txn)

    def test_wrong_transaction_id_length_raises(self):
        with self.assertRaises(ValueError):
            build_binding_request(b"too-short")


class ParseBindingResponseTests(unittest.TestCase):
    def setUp(self):
        self.txn = os.urandom(12)

    def test_xor_mapped_address_round_trip(self):
        body = _xor_mapped_address_attr("203.0.113.42", 54321)
        resp = _binding_response(body, self.txn)
        ip, port = parse_binding_response(resp, self.txn)
        self.assertEqual((ip, port), ("203.0.113.42", 54321))

    def test_legacy_mapped_address_used_as_fallback(self):
        body = _mapped_address_attr("198.51.100.7", 1234)
        resp = _binding_response(body, self.txn)
        ip, port = parse_binding_response(resp, self.txn)
        self.assertEqual((ip, port), ("198.51.100.7", 1234))

    def test_xor_mapped_address_preferred_over_mapped_address(self):
        body = _mapped_address_attr("198.51.100.7", 1111) + _xor_mapped_address_attr("203.0.113.42", 2222)
        resp = _binding_response(body, self.txn)
        ip, port = parse_binding_response(resp, self.txn)
        self.assertEqual((ip, port), ("203.0.113.42", 2222))

    def test_too_short_response_raises(self):
        with self.assertRaises(StunError):
            parse_binding_response(b"\x00" * 10, self.txn)

    def test_wrong_message_type_raises(self):
        resp = _binding_response(b"", self.txn, msg_type=0x0111)  # Binding Error Response
        with self.assertRaises(StunError):
            parse_binding_response(resp, self.txn)

    def test_mismatched_transaction_id_raises(self):
        body = _xor_mapped_address_attr("203.0.113.42", 54321)
        resp = _binding_response(body, self.txn)
        other_txn = os.urandom(12)
        with self.assertRaises(StunError):
            parse_binding_response(resp, other_txn)

    def test_missing_address_attribute_raises(self):
        resp = _binding_response(b"", self.txn)  # без жодного адресного атрибута
        with self.assertRaises(StunError):
            parse_binding_response(resp, self.txn)

    def test_bad_magic_cookie_raises(self):
        header = struct.pack("!HHI12s", _BINDING_SUCCESS_RESPONSE, 0, 0xDEADBEEF, self.txn)
        with self.assertRaises(StunError):
            parse_binding_response(header, self.txn)


if __name__ == "__main__":
    unittest.main()
