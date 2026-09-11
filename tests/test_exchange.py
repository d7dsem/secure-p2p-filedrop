#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Модульні тести шару "обмін" (exchange.py) — Рівень 1 з docs/testing.md, без GUI/мережі.
"""

import os
import shutil
import tempfile
import unittest
import zipfile

import _pathfix  # noqa: F401  (додає src/ у sys.path перед наступними імпортами)

from exchange import build_archive_from_selection, format_size, list_entries, prepare_archive
from tuning import EXCHANGE


class PrepareArchiveFileTests(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="test_exchange_file_")
        self.file_path = os.path.join(self.tmp_dir, "payload.txt")
        with open(self.file_path, "w", encoding="utf-8") as f:
            f.write("вміст тестового файлу")

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_file_path_returned_unchanged(self):
        result = prepare_archive(self.file_path, is_dir=False)
        self.assertEqual(result, self.file_path)

    def test_file_is_not_touched(self):
        prepare_archive(self.file_path, is_dir=False)
        with open(self.file_path, encoding="utf-8") as f:
            self.assertEqual(f.read(), "вміст тестового файлу")


class PrepareArchiveDirTests(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="test_exchange_dir_")
        self.src_dir = os.path.join(self.tmp_dir, "payload_dir")
        os.makedirs(os.path.join(self.src_dir, "subdir"))
        with open(os.path.join(self.src_dir, "a.txt"), "w", encoding="utf-8") as f:
            f.write("a")
        with open(os.path.join(self.src_dir, "subdir", "b.txt"), "w", encoding="utf-8") as f:
            f.write("b")

        self._archives_to_clean = []

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)
        for archive_path in self._archives_to_clean:
            shutil.rmtree(os.path.dirname(archive_path), ignore_errors=True)

    def _prepare(self):
        result = prepare_archive(self.src_dir, is_dir=True)
        self._archives_to_clean.append(result)
        return result

    def test_returns_path_to_zip_that_exists(self):
        archive_path = self._prepare()
        self.assertTrue(os.path.isfile(archive_path))

    def test_archive_file_name_matches_tuning(self):
        archive_path = self._prepare()
        self.assertEqual(os.path.basename(archive_path), EXCHANGE.archive_file_name)

    def test_archive_dir_uses_configured_prefix(self):
        archive_path = self._prepare()
        archive_dir_name = os.path.basename(os.path.dirname(archive_path))
        self.assertTrue(archive_dir_name.startswith(EXCHANGE.temp_dir_prefix))

    def test_archive_contains_expected_relative_paths(self):
        archive_path = self._prepare()

        expected = set()
        for root, _dirs, files in os.walk(self.src_dir):
            for fname in files:
                full = os.path.join(root, fname)
                rel = os.path.relpath(full, os.path.dirname(self.src_dir))
                expected.add(rel.replace(os.sep, "/"))

        with zipfile.ZipFile(archive_path) as zf:
            actual = set(name.replace(os.sep, "/") for name in zf.namelist())

        self.assertEqual(actual, expected)

    def test_archive_content_matches_original(self):
        archive_path = self._prepare()
        with zipfile.ZipFile(archive_path) as zf:
            names = zf.namelist()
            a_entry = next(n for n in names if n.endswith("a.txt"))
            self.assertEqual(zf.read(a_entry).decode("utf-8"), "a")


class PrepareArchiveErrorTests(unittest.TestCase):
    def test_empty_path_raises_value_error(self):
        with self.assertRaises(ValueError):
            prepare_archive("", is_dir=False)

    def test_none_path_raises_value_error(self):
        with self.assertRaises(ValueError):
            prepare_archive(None, is_dir=False)


class FormatSizeTests(unittest.TestCase):
    def test_bytes_shown_as_integer(self):
        self.assertEqual(format_size(500), "500 Б")

    def test_kilobytes_one_decimal(self):
        self.assertEqual(format_size(2048), "2.0 КБ")

    def test_gigabytes(self):
        self.assertEqual(format_size(5 * 1024 ** 3), "5.0 ГБ")

    def test_zero_bytes(self):
        self.assertEqual(format_size(0), "0 Б")


class ListEntriesTests(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="test_list_entries_")
        self.addCleanup(shutil.rmtree, self.tmp_dir, ignore_errors=True)

        os.makedirs(os.path.join(self.tmp_dir, "sub"))
        with open(os.path.join(self.tmp_dir, "a.txt"), "w", encoding="utf-8") as f:
            f.write("x" * 10)
        with open(os.path.join(self.tmp_dir, "sub", "b.txt"), "w", encoding="utf-8") as f:
            f.write("y" * 20)
        with open(os.path.join(self.tmp_dir, "sub", "c.txt"), "w", encoding="utf-8") as f:
            f.write("z" * 5)

    def test_lists_one_level_only(self):
        entries = list_entries(self.tmp_dir)
        names = {e.name for e in entries}
        self.assertEqual(names, {"a.txt", "sub"})  # без вкладених b.txt/c.txt

    def test_dirs_come_before_files_alphabetically(self):
        entries = list_entries(self.tmp_dir)
        self.assertEqual([e.name for e in entries], ["sub", "a.txt"])

    def test_file_size_is_exact(self):
        entries = list_entries(self.tmp_dir)
        a = next(e for e in entries if e.name == "a.txt")
        self.assertEqual(a.size_bytes, 10)
        self.assertFalse(a.is_dir)

    def test_dir_size_is_aggregate_of_contents(self):
        entries = list_entries(self.tmp_dir)
        sub = next(e for e in entries if e.name == "sub")
        self.assertEqual(sub.size_bytes, 20 + 5)
        self.assertTrue(sub.is_dir)

    def test_excluded_name_is_skipped(self):
        os.makedirs(os.path.join(self.tmp_dir, "technical"))
        entries = list_entries(self.tmp_dir, exclude_names=frozenset({"technical"}))
        names = {e.name for e in entries}
        self.assertNotIn("technical", names)

    def test_excluded_name_skipped_at_nested_level_too(self):
        # Технічна підпапка виключається на будь-якому рівні обходу, не
        # лише на верхньому — інакше агрегований розмір каталогу міг би
        # її врахувати.
        os.makedirs(os.path.join(self.tmp_dir, "sub", "technical"))
        with open(os.path.join(self.tmp_dir, "sub", "technical", "junk.bin"), "wb") as f:
            f.write(b"0" * 1000)
        entries = list_entries(self.tmp_dir, exclude_names=frozenset({"technical"}))
        sub = next(e for e in entries if e.name == "sub")
        self.assertEqual(sub.size_bytes, 20 + 5)  # без junk.bin з technical/


class BuildArchiveFromSelectionTests(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="test_build_archive_")
        self.addCleanup(shutil.rmtree, self.tmp_dir, ignore_errors=True)

        os.makedirs(os.path.join(self.tmp_dir, "sub"))
        self.a_path = os.path.join(self.tmp_dir, "a.txt")
        self.b_path = os.path.join(self.tmp_dir, "sub", "b.txt")
        self.c_path = os.path.join(self.tmp_dir, "sub", "c.txt")
        with open(self.a_path, "w", encoding="utf-8") as f:
            f.write("a")
        with open(self.b_path, "w", encoding="utf-8") as f:
            f.write("b")
        with open(self.c_path, "w", encoding="utf-8") as f:
            f.write("c")

    def test_archive_created_in_technical_subdir_of_root(self):
        archive_path = build_archive_from_selection(self.tmp_dir, [self.a_path])
        expected_dir = os.path.join(self.tmp_dir, EXCHANGE.pack_subdir_name)
        self.assertEqual(os.path.dirname(archive_path), expected_dir)
        self.assertTrue(os.path.isfile(archive_path))

    def test_archive_contains_only_included_files(self):
        archive_path = build_archive_from_selection(self.tmp_dir, [self.a_path, self.b_path])
        with zipfile.ZipFile(archive_path) as zf:
            names = set(n.replace(os.sep, "/") for n in zf.namelist())
        self.assertEqual(names, {"a.txt", "sub/b.txt"})
        self.assertNotIn("sub/c.txt", names)

    def test_no_included_files_raises_value_error(self):
        with self.assertRaises(ValueError):
            build_archive_from_selection(self.tmp_dir, [])

    def test_technical_subdir_excluded_from_subsequent_listing(self):
        build_archive_from_selection(self.tmp_dir, [self.a_path])
        entries = list_entries(self.tmp_dir, exclude_names=frozenset({EXCHANGE.pack_subdir_name}))
        names = {e.name for e in entries}
        self.assertNotIn(EXCHANGE.pack_subdir_name, names)


if __name__ == "__main__":
    unittest.main()
