#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Шар "обмін": підготовка вже обраних даних (файл/каталог) до передачі.
Сам транспорт файлів (Фаза 3, docs/concept.md) сюди ще не входить.

Два способи підготовки каталогу:
  - prepare_archive() — старий, "усе одразу": пакує весь каталог у ZIP
    у системній тимчасовій директорії, без вибору вмісту.
  - list_entries() + build_archive_from_selection() — новий: дозволяє
    показати вміст каталогу (appearance.py, дерево з чекбоксами),
    обрати підмножину файлів і запакувати лише її в технічну підпапку
    в корені самого обраного каталогу (EXCHANGE.pack_subdir_name).
"""

import os
import tempfile
import zipfile
from dataclasses import dataclass

from tuning import EXCHANGE


def prepare_archive(path: str, is_dir: bool) -> str:
    """
    Якщо обрано каталог — пакує його в ZIP у тимчасовій директорії й
    повертає шлях до архіву; якщо файл — повертає шлях без змін.

    ВАЖЛИВО (явно позначено — це не було в запиті, але критично для
    наступного кроку "запаролені архіви"):
    Стандартний модуль zipfile у Python НЕ вміє створювати архіви
    з сучасним AES-шифруванням — лише читати legacy ZipCrypto
    (слабке, не рекомендується для реального захисту). Щоб
    отримати справді захищений архів, є два шляхи:
      1) додати одну зовнішню залежність (наприклад, pyzipper —
         підтримує AES-256 для ZIP);
      2) не шифрувати сам архів, а шифрувати вже встановлений канал
         (як і обговорювалось раніше) — тоді архів можна лишити
         без пароля, бо захист забезпечує транспортний рівень.
    Це прямий наслідок вимоги "мінімум залежностей": варіант (2)
    її не порушує, варіант (1) — порушує на одну бібліотеку.
    """
    if not path:
        raise ValueError("Спочатку оберіть файл або каталог.")

    if not is_dir:
        return path

    tmp_dir = tempfile.mkdtemp(prefix=EXCHANGE.temp_dir_prefix)
    archive_path = os.path.join(tmp_dir, EXCHANGE.archive_file_name)
    with zipfile.ZipFile(archive_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, _dirs, files in os.walk(path):
            for fname in files:
                full = os.path.join(root, fname)
                arcname = os.path.relpath(full, os.path.dirname(path))
                zf.write(full, arcname)
    return archive_path


# --------------------------------------------------------------------------
# Перегляд вмісту каталогу з можливістю обрати підмножину (чекбокси в GUI)
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class DirEntry:
    name: str
    abs_path: str
    is_dir: bool
    size_bytes: int


def format_size(size_bytes: int) -> str:
    """Людяний розмір (Б/КБ/МБ/...), одиниці — з tuning.EXCHANGE.size_units."""
    size = float(size_bytes)
    units = EXCHANGE.size_units
    for unit in units[:-1]:
        if size < 1024:
            return f"{int(size)} {unit}" if unit == units[0] else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} {units[-1]}"


def _dir_size(path: str, exclude_names: frozenset[str]) -> int:
    total = 0
    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in exclude_names]
        for fname in files:
            try:
                total += os.path.getsize(os.path.join(root, fname))
            except OSError:
                pass  # файл зник/недоступний між scandir і getsize — пропускаємо, не падаємо
    return total


def list_entries(dir_path: str, exclude_names: frozenset[str] = frozenset()) -> list[DirEntry]:
    """
    Один рівень вмісту dir_path (для лінивого розгортання дерева в GUI):
    підкаталоги й файли, відсортовані — спершу каталоги, потім файли, за
    іменем без урахування регістру. Розмір підкаталогу — агрегований
    (рекурсивний обхід, виключаючи exclude_names на будь-якому рівні —
    зокрема технічну підпапку під архів, щоб вона ніде не потрапляла у
    вибір і не намагалась запакувати сама себе).
    """
    entries = []
    with os.scandir(dir_path) as it:
        for de in it:
            if de.name in exclude_names:
                continue
            is_dir = de.is_dir(follow_symlinks=False)
            try:
                size = _dir_size(de.path, exclude_names) if is_dir else de.stat().st_size
            except OSError:
                size = 0
            entries.append(DirEntry(name=de.name, abs_path=de.path, is_dir=is_dir, size_bytes=size))
    entries.sort(key=lambda e: (not e.is_dir, e.name.lower()))
    return entries


def build_archive_from_selection(root_dir: str, included_files: list[str]) -> str:
    """
    Пакує обрані файли (included_files — абсолютні шляхи, усі під
    root_dir) у ZIP, складений у технічну підпапку в корені root_dir
    (EXCHANGE.pack_subdir_name/EXCHANGE.archive_file_name) — саме тому
    ця підпапка виключається зі сканування в list_entries(), інакше
    архів міг би спробувати запакувати сам себе за повторного пакування.
    """
    if not included_files:
        raise ValueError("Не обрано жодного файлу для архівування.")

    pack_dir = os.path.join(root_dir, EXCHANGE.pack_subdir_name)
    os.makedirs(pack_dir, exist_ok=True)
    archive_path = os.path.join(pack_dir, EXCHANGE.archive_file_name)

    with zipfile.ZipFile(archive_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for full_path in included_files:
            arcname = os.path.relpath(full_path, root_dir)
            zf.write(full_path, arcname)
    return archive_path
