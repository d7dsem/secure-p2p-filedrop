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
        original = LocalConfig(client_id="round-trip-id", incoming_dir="/tmp/in", outgoing_dir="/tmp/out")
        save_config(original, self.path)

        loaded = load_config(self.path)
        self.assertEqual(loaded, original)

    def test_save_overwrites_previous_content(self):
        save_config(LocalConfig(client_id="first", incoming_dir="a", outgoing_dir="b"), self.path)
        save_config(LocalConfig(client_id="second", incoming_dir="c", outgoing_dir="d"), self.path)

        loaded = load_config(self.path)
        self.assertEqual(loaded.client_id, "second")

    def test_written_file_is_readable_json_with_expected_keys(self):
        save_config(LocalConfig(client_id="c1", incoming_dir="in", outgoing_dir="out"), self.path)
        data = json.loads(self.path.read_text(encoding="utf-8"))
        self.assertEqual(set(data.keys()), {"client_id", "incoming_dir", "outgoing_dir"})


if __name__ == "__main__":
    unittest.main()
