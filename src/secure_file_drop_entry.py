#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Точка входу застосунку. Мапа шарів і залежностей: docs/dev-notes.md → "secure_file_drop_entry.py".
"""

import argparse
import tkinter as tk
from tkinter import ttk

from appearance import SecureFileClientApp


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """argv=None означає "взяти з sys.argv" (звичайний запуск); явний список
    зручний для тестів — не потребує підміни sys.argv."""
    parser = argparse.ArgumentParser(description="Secure P2P FileDrop — GUI-клієнт")
    parser.add_argument(
        "--pswd", "-p", dest="passphrase", type=str, default=None,
        help="Парольна фраза, якою одразу заповнити поле в GUI (зручно для дебагу; "
             "у звичайному використанні пароль краще вводити вручну).",
    )
    return parser.parse_args(argv)


def main():
    args = parse_args()
    root = tk.Tk()
    try:
        style = ttk.Style()
        if "clam" in style.theme_names():
            style.theme_use("clam")
    except Exception:
        pass
    app = SecureFileClientApp(root, initial_passphrase=args.passphrase)
    root.mainloop()


if __name__ == "__main__":
    main()
