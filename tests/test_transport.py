#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Рівень 3 з docs/testing.md: реальний мережевий P2P-транспорт через loopback
(127.0.0.1, два різні порти) в одному тестовому процесі — без другого фізичного ПК,
без tkinter. Повільніше за Рівень 1 (реальні сокети/потоки), але не мокнуте.
"""

import hashlib
import os
import shutil
import socket
import tempfile
import threading
import unittest

import _pathfix  # noqa: F401  (додає src/ у sys.path перед наступними імпортами)

from transport import (
    ConnectionFailed,
    TransportError,
    VerificationError,
    establish_connection,
    receive_files,
    send_files,
    verify_channel,
)

_KEY_A = hashlib.sha256(b"test-session-key-material").digest()  # 32 байти, детерміновано


def _free_port_pair() -> tuple:
    """Дві вільні (наразі) порти на 127.0.0.1 — беремо ОС-виданий ефемерний порт
    двома окремими сокетами, щоб уникнути конфлікту паралельних тестів."""
    s1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s1.bind(("127.0.0.1", 0))
    s2.bind(("127.0.0.1", 0))
    port_a = s1.getsockname()[1]
    port_b = s2.getsockname()[1]
    s1.close()
    s2.close()
    return port_a, port_b


class EstablishConnectionTests(unittest.TestCase):
    def test_both_sides_connect_over_loopback(self):
        port_a, port_b = _free_port_pair()
        results = {}

        def side_a():
            sock = establish_connection(port_a, "127.0.0.1", port_b, timeout=10)
            results["a"] = sock

        def side_b():
            sock = establish_connection(port_b, "127.0.0.1", port_a, timeout=10)
            results["b"] = sock

        ta, tb = threading.Thread(target=side_a), threading.Thread(target=side_b)
        ta.start(); tb.start()
        ta.join(timeout=15); tb.join(timeout=15)

        self.assertIn("a", results)
        self.assertIn("b", results)
        results["a"].close()
        results["b"].close()

    def test_no_peer_raises_connection_failed(self):
        port_a, port_b = _free_port_pair()
        with self.assertRaises(ConnectionFailed):
            establish_connection(port_a, "127.0.0.1", port_b, timeout=1.0)

    def test_listen_only_mode_when_peer_unknown(self):
        """Сторона, що згенерувала хендшейк, ще не знає адреси іншої сторони
        (docs/concept.md: хендшейк ділиться лише в один бік) — establish_connection
        з peer_host=None має просто слухати, доки інша сторона не підключиться сама."""
        port_a, port_b = _free_port_pair()
        results = {}

        def side_a_listen_only():
            results["a"] = establish_connection(port_a, None, None, timeout=10)

        def side_b_connects():
            results["b"] = establish_connection(port_b, "127.0.0.1", port_a, timeout=10)

        ta, tb = threading.Thread(target=side_a_listen_only), threading.Thread(target=side_b_connects)
        ta.start(); tb.start()
        ta.join(timeout=15); tb.join(timeout=15)

        self.assertIn("a", results)
        self.assertIn("b", results)
        results["a"].close()
        results["b"].close()

    def test_listen_only_mode_times_out_if_nobody_connects(self):
        port_a, _port_b = _free_port_pair()
        with self.assertRaises(ConnectionFailed):
            establish_connection(port_a, None, None, timeout=1.0)


class VerifyChannelTests(unittest.TestCase):
    def _connected_pair(self):
        port_a, port_b = _free_port_pair()
        results = {}

        def side_a():
            results["a"] = establish_connection(port_a, "127.0.0.1", port_b, timeout=10)

        def side_b():
            results["b"] = establish_connection(port_b, "127.0.0.1", port_a, timeout=10)

        ta, tb = threading.Thread(target=side_a), threading.Thread(target=side_b)
        ta.start(); tb.start()
        ta.join(timeout=15); tb.join(timeout=15)
        return results["a"], results["b"]

    def test_matching_keys_verify_successfully_on_both_sides(self):
        sock_a, sock_b = self._connected_pair()
        outcomes = {}

        def verify_a():
            try:
                verify_channel(sock_a, _KEY_A)
                outcomes["a"] = "ok"
            except VerificationError as e:
                outcomes["a"] = str(e)

        def verify_b():
            try:
                verify_channel(sock_b, _KEY_A)
                outcomes["b"] = "ok"
            except VerificationError as e:
                outcomes["b"] = str(e)

        ta, tb = threading.Thread(target=verify_a), threading.Thread(target=verify_b)
        ta.start(); tb.start()
        ta.join(timeout=10); tb.join(timeout=10)

        self.assertEqual(outcomes.get("a"), "ok")
        self.assertEqual(outcomes.get("b"), "ok")
        sock_a.close()
        sock_b.close()

    def test_mismatched_keys_fail_verification_on_both_sides(self):
        sock_a, sock_b = self._connected_pair()
        outcomes = {}

        def verify_a():
            try:
                verify_channel(sock_a, b"A" * 32)
                outcomes["a"] = "ok"
            except VerificationError:
                outcomes["a"] = "mismatch"

        def verify_b():
            try:
                verify_channel(sock_b, b"B" * 32)
                outcomes["b"] = "ok"
            except VerificationError:
                outcomes["b"] = "mismatch"

        ta, tb = threading.Thread(target=verify_a), threading.Thread(target=verify_b)
        ta.start(); tb.start()
        ta.join(timeout=10); tb.join(timeout=10)

        self.assertEqual(outcomes.get("a"), "mismatch")
        self.assertEqual(outcomes.get("b"), "mismatch")
        sock_a.close()
        sock_b.close()


class SendReceiveFilesTests(unittest.TestCase):
    def setUp(self):
        self.send_root = tempfile.mkdtemp(prefix="test_transport_send_")
        self.recv_root = tempfile.mkdtemp(prefix="test_transport_recv_")
        self.addCleanup(shutil.rmtree, self.send_root, ignore_errors=True)
        self.addCleanup(shutil.rmtree, self.recv_root, ignore_errors=True)

        os.makedirs(os.path.join(self.send_root, "sub"))
        self.a_path = os.path.join(self.send_root, "a.txt")
        self.b_path = os.path.join(self.send_root, "sub", "b.bin")
        with open(self.a_path, "w", encoding="utf-8") as f:
            f.write("hello world " * 5000)  # достатньо велике для кількох chunk_size
        with open(self.b_path, "wb") as f:
            f.write(os.urandom(200_000))

    def _connected_verified_pair(self):
        port_a, port_b = _free_port_pair()
        results = {}

        def side_a():
            sock = establish_connection(port_a, "127.0.0.1", port_b, timeout=10)
            verify_channel(sock, _KEY_A)
            results["a"] = sock

        def side_b():
            sock = establish_connection(port_b, "127.0.0.1", port_a, timeout=10)
            verify_channel(sock, _KEY_A)
            results["b"] = sock

        ta, tb = threading.Thread(target=side_a), threading.Thread(target=side_b)
        ta.start(); tb.start()
        ta.join(timeout=15); tb.join(timeout=15)
        return results["a"], results["b"]

    def test_files_round_trip_with_subdirectories(self):
        sock_a, sock_b = self._connected_verified_pair()
        outcomes = {}

        def sender():
            send_files(sock_a, _KEY_A, self.send_root, [self.a_path, self.b_path])

        def receiver():
            outcomes["received"] = receive_files(sock_b, _KEY_A, self.recv_root)

        ts, tr = threading.Thread(target=sender), threading.Thread(target=receiver)
        ts.start(); tr.start()
        ts.join(timeout=20); tr.join(timeout=20)
        sock_a.close(); sock_b.close()

        received = outcomes.get("received", [])
        self.assertEqual(len(received), 2)

        with open(self.a_path, "rb") as f_orig, open(os.path.join(self.recv_root, "a.txt"), "rb") as f_recv:
            self.assertEqual(f_orig.read(), f_recv.read())
        with open(self.b_path, "rb") as f_orig, open(os.path.join(self.recv_root, "sub", "b.bin"), "rb") as f_recv:
            self.assertEqual(f_orig.read(), f_recv.read())

    def test_progress_callback_reaches_full_size(self):
        sock_a, sock_b = self._connected_verified_pair()
        progress_calls = []

        def sender():
            send_files(sock_a, _KEY_A, self.send_root, [self.a_path])

        def receiver():
            receive_files(sock_b, _KEY_A, self.recv_root, on_progress=lambda *args: progress_calls.append(args))

        ts, tr = threading.Thread(target=sender), threading.Thread(target=receiver)
        ts.start(); tr.start()
        ts.join(timeout=20); tr.join(timeout=20)
        sock_a.close(); sock_b.close()

        self.assertTrue(progress_calls)
        last_name, last_done, last_total = progress_calls[-1]
        self.assertEqual(last_done, last_total)

    def test_path_traversal_in_filename_is_rejected(self):
        """receive_files не повинен писати за межі dest_dir, навіть якщо заголовок
        (гіпотетично зіпсований/ворожий) містить '../'."""
        sock_a, sock_b = self._connected_verified_pair()
        outcomes = {}

        def sender():
            # Імітуємо ворожий/побитий заголовок напряму, в обхід send_files.
            from transport import send_frame, send_json
            data = b"malicious"
            send_json(sock_a, {"type": "file", "name": "../escape.txt", "size": len(data), "nonce": "00" * 16})
            from transport import _aes_cipher
            cipher = _aes_cipher(_KEY_A, bytes(16))
            send_frame(sock_a, cipher.encrypt(data))
            digest = hashlib.sha256(data).hexdigest()
            send_json(sock_a, {"type": "checksum", "sha256": digest})
            send_json(sock_a, {"type": "done"})

        def receiver():
            try:
                receive_files(sock_b, _KEY_A, self.recv_root)
                outcomes["error"] = None
            except TransportError as e:
                outcomes["error"] = str(e)

        ts, tr = threading.Thread(target=sender), threading.Thread(target=receiver)
        ts.start(); tr.start()
        ts.join(timeout=15); tr.join(timeout=15)
        sock_a.close(); sock_b.close()

        self.assertIsNotNone(outcomes.get("error"))
        escaped_path = os.path.join(os.path.dirname(self.recv_root), "escape.txt")
        self.assertFalse(os.path.exists(escaped_path))


if __name__ == "__main__":
    unittest.main()
