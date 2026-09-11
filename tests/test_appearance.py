#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Тести шару "зовнішність" (appearance.py) — НЕ взаємодія з пікселями чи
кліками (це й далі Рівень 2, ручний чекліст docs/testing.md), а логіка
стану класу SecureFileClientApp, яку можна викликати напряму на
прихованому (withdraw()) tkinter-віджеті без участі користувача. Якщо
tkinter або дисплей недоступні (headless Linux CI без Xvfb) — тест
пропускається, а не падає.

Ізольовано від справжнього профілю користувача підміною HOME/USERPROFILE
на тимчасову директорію (як у tests/test_local_config.py).
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
    """Регресія: after 1-е пакування метод раніше перезаписував
    selected_path/selected_is_dir шляхом архіву, через що 2-й клік
    "Запакувати обране" одразу впадав на guard-перевірці ("Спочатку
    оберіть каталог"), хоча дерево й далі було на екрані."""

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
        self.app.frame_tree.pack(fill="both", expand=True)
        self.app.btn_pack.configure(state="normal")

    def test_selection_survives_first_pack(self):
        self.app.on_pack_selected()
        self.assertEqual(self.app.selected_path, self.send_dir)
        self.assertTrue(self.app.selected_is_dir)
        self.assertIsNotNone(self.app.packed_archive_path)

    def test_second_pack_after_unchecking_a_file_succeeds_and_excludes_it(self):
        self.app.on_pack_selected()
        first_archive = self.app.packed_archive_path

        rel_path, abs_path, is_dir = self.app._file_tree_meta["b.txt"]
        self.app._set_checked_recursive(rel_path, abs_path, is_dir, False)

        self.app.on_pack_selected()  # раніше падало на "Спочатку оберіть каталог"
        second_archive = self.app.packed_archive_path

        self.assertEqual(first_archive, second_archive)  # той самий шлях, перезаписаний
        with zipfile.ZipFile(second_archive) as zf:
            names = set(zf.namelist())
        self.assertEqual(names, {"a.txt"})


if __name__ == "__main__":
    unittest.main()
