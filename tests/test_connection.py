#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Модульні тести шару "підключення" (`connection.py`) — Рівень 1 з
docs/testing.md. Без GUI, без мережі, без участі користувача.

Запуск: python -m unittest discover -s tests -v
"""

import base64
import hashlib
import json
import unittest

import _pathfix  # noqa: F401  (додає src/ у sys.path перед наступними імпортами)

from connection import (
    build_handshake_packet,
    derive_key,
    key_fingerprint,
    parse_handshake_packet,
)
from tuning import CONNECTION

TEST_PORT = 52075  # довільний, лише для передачі в build_handshake_packet у тестах


class DeriveKeyTests(unittest.TestCase):
    def setUp(self):
        self.salt = b"\x01" * 16
        self.iterations = 1000  # менше, ніж дефолт, щоб тести лишались швидкими

    def test_deterministic_same_inputs(self):
        key1 = derive_key("passphrase", self.salt, self.iterations)
        key2 = derive_key("passphrase", self.salt, self.iterations)
        self.assertEqual(key1, key2)

    def test_different_passphrase_gives_different_key(self):
        key1 = derive_key("passphrase-a", self.salt, self.iterations)
        key2 = derive_key("passphrase-b", self.salt, self.iterations)
        self.assertNotEqual(key1, key2)

    def test_single_character_change_gives_different_key(self):
        # непряма перевірка лавинного ефекту: навіть одруківка на одну
        # літеру мусить давати цілком інший ключ, а не "майже такий самий"
        key1 = derive_key("correct-passphrase", self.salt, self.iterations)
        key2 = derive_key("correct-passphrasee", self.salt, self.iterations)
        self.assertNotEqual(key1, key2)

    def test_different_salt_gives_different_key(self):
        key1 = derive_key("passphrase", b"\x01" * 16, self.iterations)
        key2 = derive_key("passphrase", b"\x02" * 16, self.iterations)
        self.assertNotEqual(key1, key2)

    def test_different_iterations_gives_different_key(self):
        key1 = derive_key("passphrase", self.salt, 1000)
        key2 = derive_key("passphrase", self.salt, 1001)
        self.assertNotEqual(key1, key2)

    def test_key_length_is_sha256_digest_size(self):
        key = derive_key("passphrase", self.salt, self.iterations)
        self.assertEqual(len(key), 32)

    def test_matches_stdlib_pbkdf2_hmac_directly(self):
        # Регресійний тест: якщо колись хтось повернеться до ручного
        # ланцюжка SHA-256(SHA-256(...)) замість PBKDF2-HMAC (див.
        # docs/concept.md, "Відомі технічні компроміси"), цей тест
        # це одразу зловить.
        key = derive_key("passphrase", self.salt, self.iterations)
        expected = hashlib.pbkdf2_hmac(
            "sha256", b"passphrase", self.salt, self.iterations
        )
        self.assertEqual(key, expected)


class KeyFingerprintTests(unittest.TestCase):
    def test_length_matches_tuning(self):
        fp = key_fingerprint(b"\x00" * 32)
        self.assertEqual(len(fp), CONNECTION.fingerprint_hex_length)

    def test_is_uppercase_hex(self):
        fp = key_fingerprint(b"\x00" * 32)
        self.assertTrue(all(c in "0123456789ABCDEF" for c in fp))
        self.assertEqual(fp, fp.upper())

    def test_deterministic_same_key(self):
        key = b"\xab" * 32
        self.assertEqual(key_fingerprint(key), key_fingerprint(key))

    def test_different_keys_give_different_fingerprints(self):
        fp1 = key_fingerprint(b"\x01" * 32)
        fp2 = key_fingerprint(b"\x02" * 32)
        self.assertNotEqual(fp1, fp2)


class HandshakePacketRoundTripTests(unittest.TestCase):
    def test_round_trip_fields_match(self):
        text, salt, session_id, host = build_handshake_packet(iterations=12345, port=TEST_PORT)
        packet = parse_handshake_packet(text)

        self.assertEqual(packet["sid"], session_id)
        self.assertEqual(packet["iter"], 12345)
        self.assertEqual(base64.b64decode(packet["salt"]), salt)
        self.assertEqual(packet["v"], CONNECTION.packet_version)
        # Мережевий компонент хендшейку (docs/concept.md, Фаза 1, п.1):
        # адреса й порт, потрібні іншій стороні для P2P-з'єднання.
        self.assertEqual(packet["host"], host)
        self.assertEqual(packet["port"], TEST_PORT)

    def test_derived_key_matches_on_both_sides(self):
        # Симулює обидві сторони хендшейку: та сама passphrase + пакет із
        # build_handshake_packet мають давати той самий сесійний ключ.
        text, salt, _sid, _host = build_handshake_packet(iterations=1000, port=TEST_PORT)
        packet = parse_handshake_packet(text)
        peer_salt = base64.b64decode(packet["salt"])
        peer_iterations = int(packet["iter"])

        key_a = derive_key("shared-secret", salt, 1000)
        key_b = derive_key("shared-secret", peer_salt, peer_iterations)
        self.assertEqual(key_a, key_b)

    def test_salt_and_session_id_are_random_each_call(self):
        _, salt1, sid1, _host1 = build_handshake_packet(iterations=1000, port=TEST_PORT)
        _, salt2, sid2, _host2 = build_handshake_packet(iterations=1000, port=TEST_PORT)
        self.assertNotEqual(salt1, salt2)
        self.assertNotEqual(sid1, sid2)

    def test_text_contains_header_and_footer(self):
        text, _, _, _host = build_handshake_packet(iterations=1000, port=TEST_PORT)
        self.assertIn(CONNECTION.handshake_header, text)
        self.assertIn(CONNECTION.handshake_footer, text)

    def test_empty_text_raises_value_error(self):
        with self.assertRaises(ValueError):
            parse_handshake_packet("")

    def test_whitespace_only_text_raises_value_error(self):
        with self.assertRaises(ValueError):
            parse_handshake_packet("   \n  ")

    def test_truncated_text_raises_value_error(self):
        # Короткий, а не "половинний" префікс — щоб тест не залежав від
        # випадкового збігу довжин base64, що могло б дати валідний,
        # хоч і безглуздий, JSON.
        text, _, _, _host = build_handshake_packet(iterations=1000, port=TEST_PORT)
        truncated = text[:30]
        with self.assertRaises(ValueError):
            parse_handshake_packet(truncated)

    def test_missing_iter_field_raises_value_error(self):
        incomplete = {
            "v": CONNECTION.packet_version, "sid": "abc", "salt": "AAAA==",
            "host": "127.0.0.1", "port": TEST_PORT,
        }  # без "iter"
        raw = json.dumps(incomplete, separators=(",", ":")).encode("utf-8")
        b64 = base64.urlsafe_b64encode(raw).decode("ascii")
        text = f"{CONNECTION.handshake_header}\n{b64}\n{CONNECTION.handshake_footer}"

        with self.assertRaises(ValueError):
            parse_handshake_packet(text)

    def test_missing_network_info_raises_value_error(self):
        # Без "host"/"port" пакет вважається неповним — це навмисно
        # (наступна сторона не зможе спробувати P2P-з'єднання).
        incomplete = {
            "v": CONNECTION.packet_version, "sid": "abc", "salt": "AAAA==", "iter": 1000,
        }  # без "host"/"port"
        raw = json.dumps(incomplete, separators=(",", ":")).encode("utf-8")
        b64 = base64.urlsafe_b64encode(raw).decode("ascii")
        text = f"{CONNECTION.handshake_header}\n{b64}\n{CONNECTION.handshake_footer}"

        with self.assertRaises(ValueError):
            parse_handshake_packet(text)

    def test_garbage_text_raises_value_error(self):
        with self.assertRaises(ValueError):
            parse_handshake_packet("зовсім не хендшейк, а випадковий текст")


if __name__ == "__main__":
    unittest.main()
