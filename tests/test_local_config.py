#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Модульні тести шару "профіль" (local_config.py) — Рівень 1 з docs/testing.md.
Явний `path` замість ~/config.json — див. docs/dev-notes.md → "tests/test_local_config.py".
"""

import json
import shutil
import tempfile
import unittest
from pathlib import Path

import _pathfix  # noqa: F401  (додає src/ у sys.path перед наступними імпортами)

from local_config import LocalConfig, load_config, save_config
from tuning import CONNECTION


class LoadConfigTests(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="test_local_config_")
        self.addCleanup(shutil.rmtree, self.tmp_dir, ignore_errors=True)
        self.path = Path(self.tmp_dir) / "profile" / "config.json"

    def test_missing_file_returns_generated_defaults_and_creates_file(self):
        self.assertFalse(self.path.exists())
        config = load_config(self.path)

        self.assertTrue(config.client_id)
        self.assertTrue(config.incoming_dir)
        self.assertTrue(config.outgoing_dir)
        self.assertTrue(self.path.exists())  # дефолти одразу зберігаються

    def test_two_generated_client_ids_differ(self):
        config1 = load_config(self.path)
        (Path(self.tmp_dir) / "profile2").mkdir()
        config2 = load_config(Path(self.tmp_dir) / "profile2" / "config.json")
        self.assertNotEqual(config1.client_id, config2.client_id)

    def test_corrupted_json_falls_back_to_defaults(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text("це не json {{{", encoding="utf-8")

        config = load_config(self.path)
        self.assertTrue(config.client_id)  # не впало, підставило дефолт

    def test_partial_json_fills_missing_fields_with_defaults(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps({"client_id": "manually-set-id"}), encoding="utf-8")

        config = load_config(self.path)
        self.assertEqual(config.client_id, "manually-set-id")
        self.assertTrue(config.incoming_dir)
        self.assertTrue(config.outgoing_dir)

    def test_missing_file_default_port_is_tuning_default(self):
        config = load_config(self.path)
        self.assertEqual(config.default_port, CONNECTION.default_port)

    def test_profile_without_port_field_falls_back_to_tuning_default(self):
        """Профіль, збережений ДО появи default_port (зворотна сумісність)."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(
            json.dumps({"client_id": "old-profile", "incoming_dir": "in", "outgoing_dir": "out"}),
            encoding="utf-8",
        )

        config = load_config(self.path)
        self.assertEqual(config.default_port, CONNECTION.default_port)

    def test_valid_port_in_file_is_used(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps({"default_port": 52074}), encoding="utf-8")

        config = load_config(self.path)
        self.assertEqual(config.default_port, 52074)

    def test_invalid_port_values_fall_back_without_crashing(self):
        for bad_port in ("not-a-number", 0, 70000, -1, None, True, [52074]):
            with self.subTest(port=bad_port):
                path = Path(self.tmp_dir) / f"config_{repr(bad_port)}.json"
                path.write_text(json.dumps({"default_port": bad_port}), encoding="utf-8")

                config = load_config(path)
                self.assertEqual(config.default_port, CONNECTION.default_port)


class SaveConfigTests(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="test_local_config_save_")
        self.addCleanup(shutil.rmtree, self.tmp_dir, ignore_errors=True)
        self.path = Path(self.tmp_dir) / "nested" / "dir" / "config.json"

    def test_creates_parent_directories(self):
        self.assertFalse(self.path.parent.exists())
        save_config(LocalConfig(client_id="c1", incoming_dir="in", outgoing_dir="out"), self.path)
        self.assertTrue(self.path.exists())

    def test_round_trip_save_then_load(self):
        original = LocalConfig(
            client_id="round-trip-id", incoming_dir="/tmp/in", outgoing_dir="/tmp/out", default_port=52074,
        )
        save_config(original, self.path)

        loaded = load_config(self.path)
        self.assertEqual(loaded, original)
        self.assertEqual(loaded.default_port, 52074)

    def test_save_overwrites_previous_content(self):
        save_config(LocalConfig(client_id="first", incoming_dir="a", outgoing_dir="b"), self.path)
        save_config(LocalConfig(client_id="second", incoming_dir="c", outgoing_dir="d"), self.path)

        loaded = load_config(self.path)
        self.assertEqual(loaded.client_id, "second")

    def test_written_file_is_readable_json_with_expected_keys(self):
        save_config(LocalConfig(client_id="c1", incoming_dir="in", outgoing_dir="out"), self.path)
        data = json.loads(self.path.read_text(encoding="utf-8"))
        self.assertEqual(set(data.keys()), {"client_id", "incoming_dir", "outgoing_dir", "default_port"})

    def test_written_file_includes_explicit_default_port(self):
        save_config(
            LocalConfig(client_id="c1", incoming_dir="in", outgoing_dir="out", default_port=52074), self.path,
        )
        data = json.loads(self.path.read_text(encoding="utf-8"))
        self.assertEqual(data["default_port"], 52074)


if __name__ == "__main__":
    unittest.main()
