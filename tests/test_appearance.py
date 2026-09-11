#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Тести логіки стану SecureFileClientApp (не кліків/пікселів — це Рівень 2 з docs/testing.md).
Докладніше: docs/dev-notes.md → "tests/test_appearance.py".
"""

import os
import shutil
import tempfile
import unittest
import zipfile

import _pathfix  # noqa: F401  (додає src/ у sys.path перед наступними імпортами)


class AppearanceTestCase(unittest.TestCase):
    """Базовий клас: ізолює HOME/USERPROFILE і піднімає headless
    SecureFileClientApp перед кожним тестом."""

    def setUp(self):
        try:
            import tkinter as tk
        except ImportError as e:
            self.skipTest(f"tkinter недоступний у цьому середовищі: {e}")
            return

        home_dir = tempfile.mkdtemp(prefix="test_appearance_home_")
        self.addCleanup(shutil.rmtree, home_dir, ignore_errors=True)
        self._patch_env("HOME", home_dir)
        self._patch_env("USERPROFILE", home_dir)

        try:
            self.root = tk.Tk()
        except tk.TclError as e:
            self.skipTest(f"Немає доступного дисплея для tkinter: {e}")
            return
        self.root.withdraw()
        self.addCleanup(self.root.destroy)

        from appearance import SecureFileClientApp
        self.app = SecureFileClientApp(self.root)

    def _patch_env(self, name: str, value: str):
        old = os.environ.get(name)
        os.environ[name] = value
        self.addCleanup(lambda: self._restore_env(name, old))

    @staticmethod
    def _restore_env(name: str, old: str | None):
        if old is None:
            os.environ.pop(name, None)
        else:
            os.environ[name] = old


class RepackAfterCheckboxChangeTests(AppearanceTestCase):
    """Регресія виправленого багу з перезаписом selected_path архівом.
    Докладніше: docs/dev-notes.md → "appearance.py: on_initiate_transfer"."""

    def setUp(self):
        super().setUp()
        self.send_dir = tempfile.mkdtemp(prefix="test_appearance_send_")
        self.addCleanup(shutil.rmtree, self.send_dir, ignore_errors=True)
        with open(os.path.join(self.send_dir, "a.txt"), "w", encoding="utf-8") as f:
            f.write("a")
        with open(os.path.join(self.send_dir, "b.txt"), "w", encoding="utf-8") as f:
            f.write("b")

        self.app.selected_path = self.send_dir
        self.app.selected_is_dir = True
        self.app._file_tree_checked = {}
        self.app._file_tree_meta = {}
        self.app.tree_files.delete(*self.app.tree_files.get_children(""))
        self.app._insert_tree_children("", self.send_dir, "")
        self.app.frame_tree.pack(fill="both", expand=True, before=self.app._transfer_row)
        self.app.btn_transfer.configure(state="normal")
        self.app.var_archive_before_send.set(True)

    def test_selection_survives_first_transfer_init(self):
        self.app.on_initiate_transfer()
        self.assertEqual(self.app.selected_path, self.send_dir)
        self.assertTrue(self.app.selected_is_dir)
        self.assertIsNotNone(self.app.packed_archive_path)
        self.assertEqual(self.app.transfer_payload, [self.app.packed_archive_path])

    def test_second_transfer_init_after_unchecking_a_file_succeeds_and_excludes_it(self):
        self.app.on_initiate_transfer()
        first_archive = self.app.packed_archive_path

        rel_path, abs_path, is_dir = self.app._file_tree_meta["b.txt"]
        self.app._set_checked_recursive(rel_path, abs_path, is_dir, False)

        self.app.on_initiate_transfer()  # раніше падало на "Спочатку оберіть каталог"
        second_archive = self.app.packed_archive_path

        self.assertEqual(first_archive, second_archive)  # той самий шлях, перезаписаний
        with zipfile.ZipFile(second_archive) as zf:
            names = set(zf.namelist())
        self.assertEqual(names, {"a.txt"})


class ArchiveVsAsIsChoiceTests(AppearanceTestCase):
    """Чекбокс "Запакувати в один архів (інакше — передати файли як є)":
    перевіряє обидва режими на тому самому каталозі."""

    def setUp(self):
        super().setUp()
        self.send_dir = tempfile.mkdtemp(prefix="test_appearance_send_")
        self.addCleanup(shutil.rmtree, self.send_dir, ignore_errors=True)
        with open(os.path.join(self.send_dir, "a.txt"), "w", encoding="utf-8") as f:
            f.write("a")
        with open(os.path.join(self.send_dir, "b.txt"), "w", encoding="utf-8") as f:
            f.write("b")

        self.app.selected_path = self.send_dir
        self.app.selected_is_dir = True
        self.app._file_tree_checked = {}
        self.app._file_tree_meta = {}
        self.app.tree_files.delete(*self.app.tree_files.get_children(""))
        self.app._insert_tree_children("", self.send_dir, "")
        self.app.frame_tree.pack(fill="both", expand=True, before=self.app._transfer_row)
        self.app.btn_transfer.configure(state="normal")

    def test_archive_checked_produces_single_zip_payload(self):
        self.app.var_archive_before_send.set(True)
        self.app.on_initiate_transfer()

        self.assertIsNotNone(self.app.packed_archive_path)
        self.assertEqual(self.app.transfer_payload, [self.app.packed_archive_path])
        with zipfile.ZipFile(self.app.packed_archive_path) as zf:
            self.assertEqual(set(zf.namelist()), {"a.txt", "b.txt"})

    def test_archive_unchecked_produces_raw_file_list_payload(self):
        self.app.var_archive_before_send.set(False)
        self.app.on_initiate_transfer()

        self.assertIsNone(self.app.packed_archive_path)  # нічого не заархівовано
        self.assertEqual(
            sorted(os.path.basename(p) for p in self.app.transfer_payload),
            ["a.txt", "b.txt"],
        )

    def test_single_file_selection_needs_no_archive_choice(self):
        file_path = os.path.join(self.send_dir, "a.txt")
        self.app.selected_path = file_path
        self.app.selected_is_dir = False

        self.app.on_initiate_transfer()

        self.assertEqual(self.app.transfer_payload, [file_path])
        self.assertIsNone(self.app.packed_archive_path)


if __name__ == "__main__":
    unittest.main()
