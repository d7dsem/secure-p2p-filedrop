#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Тести CLI-аргументів (--pswd/-p, --snd-dir) — Рівень 1 з docs/testing.md, чисте argparse без GUI.
"""

import unittest

import _pathfix  # noqa: F401  (додає src/ у sys.path перед наступними імпортами)

from secure_file_drop_entry import parse_args


class ParseArgsTests(unittest.TestCase):
    def test_no_args_passphrase_is_none(self):
        args = parse_args([])
        self.assertIsNone(args.passphrase)

    def test_long_flag_sets_passphrase(self):
        args = parse_args(["--pswd", "hunter2"])
        self.assertEqual(args.passphrase, "hunter2")

    def test_short_flag_sets_passphrase(self):
        args = parse_args(["-p", "hunter2"])
        self.assertEqual(args.passphrase, "hunter2")

    def test_no_args_send_dir_is_none(self):
        args = parse_args([])
        self.assertIsNone(args.send_dir)

    def test_snd_dir_flag_sets_send_dir(self):
        args = parse_args(["--snd-dir", "/tmp/payload"])
        self.assertEqual(args.send_dir, "/tmp/payload")

    def test_both_flags_together(self):
        args = parse_args(["--pswd", "hunter2", "--snd-dir", "/tmp/payload"])
        self.assertEqual(args.passphrase, "hunter2")
        self.assertEqual(args.send_dir, "/tmp/payload")


if __name__ == "__main__":
    unittest.main()
