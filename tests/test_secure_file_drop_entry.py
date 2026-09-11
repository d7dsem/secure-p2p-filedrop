#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Тести CLI-аргументів (--pswd/-p) — Рівень 1 з docs/testing.md, чисте argparse без GUI.
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


if __name__ == "__main__":
    unittest.main()
