#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Точка входу застосунку. Мапа шарів і залежностей: docs/architecture.md.
"""

import argparse


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """argv=None означає "взяти з sys.argv" (звичайний запуск); явний список
    зручний для тестів — не потребує підміни sys.argv."""
    parser = argparse.ArgumentParser(description="Secure P2P FileDrop — GUI-клієнт")
    parser.add_argument(
        "--pswd", "-p", dest="passphrase", type=str, default=None,
        help="Парольна фраза, якою одразу заповнити поле в GUI (зручно для дебагу; "
             "у звичайному використанні пароль краще вводити вручну).",
    )
    parser.add_argument(
        "--snd-dir", dest="send_dir", type=str, default=None,
        help="Каталог, який одразу обрати для передачі (як після 'Обрати каталог...').",
    )
    parser.add_argument(
        "--port", dest="port", type=int, default=None,
        help="Порт, яким одразу заповнити поле в GUI (зручно для двох інстансів на "
             "одному ПК — кожному свій порт без ручного редагування поля). Не вказано — "
             "поле заповнюється дефолтним портом з профілю (local_config.py).",
    )
    return parser.parse_args(argv)


def main():
    # tkinter/appearance імпортуються тут, не на рівні модуля, — щоб тести `cli`-групи
    # (лише parse_args) не вантажили увесь GUI-стек.
    import tkinter as tk
    from tkinter import ttk

    from appearance import SecureFileClientApp

    args = parse_args()
    root = tk.Tk()
    try:
        style = ttk.Style()
        if "clam" in style.theme_names():
            style.theme_use("clam")
    except Exception:
        pass
    app = SecureFileClientApp(
        root, initial_passphrase=args.passphrase, initial_send_dir=args.send_dir, initial_port=args.port,
    )
    root.mainloop()


if __name__ == "__main__":
    main()
