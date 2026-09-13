#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Групи тестів по шарах коду (докладніше — docs/architecture.md).
Запуск: `python tests/_groups.py <група...> [unittest-прапорці]`.
Без аргументів — усі групи (`all`). `--list` друкує групи й алiаси.

Скрипт (не пакет): запускаючи його напряму (`python tests/_groups.py ...`),
Python кладе директорію скрипта (tests/) першою в sys.path — тому
`import _pathfix` у кожному тестовому модулі й далі знаходить _pathfix.py
поруч і додає src/ у sys.path, як і при `python -m unittest discover`.
"""

import sys
import unittest

GROUPS = {
    "handshake": ["test_connection"],
    "data": ["test_exchange"],
    "profile": ["test_local_config"],
    "nat": ["test_nat_traversal", "test_stun_client"],
    "transport": ["test_transport"],
    "gui": ["test_appearance"],
    "cli": ["test_secure_file_drop_entry"],
}

ALIASES = {
    "fast": ["handshake", "data", "profile", "nat", "cli"],
    "all": list(GROUPS),
}

# unittest-прапорці, після яких наступний токен — значення прапорця (не назва
# групи чи тесту), напр. `-k derive`. Тримаємо тут, а не вгадуємо за формою.
_FLAGS_WITH_VALUE = {"-k", "--pattern"}


def _print_list():
    print("Групи:")
    for name, modules in GROUPS.items():
        print(f"  {name}: {', '.join(modules)}")
    print("Алiаси:")
    for name, members in ALIASES.items():
        print(f"  {name}: {', '.join(members)}")


def _expand(args):
    """Розбирає argv на (unittest-прапорці+їхні значення, назви модулів, прямі імена тестів)."""
    flags = []
    modules = []
    names = []
    it = iter(args)
    for arg in it:
        if arg in GROUPS:
            modules.extend(GROUPS[arg])
        elif arg in ALIASES:
            for group in ALIASES[arg]:
                modules.extend(GROUPS[group])
        elif arg.startswith("-"):
            flags.append(arg)
            if arg in _FLAGS_WITH_VALUE:
                try:
                    flags.append(next(it))
                except StopIteration:
                    pass
        else:
            # Не назва групи/алiасу — пряме ім'я тесту (напр.
            # test_appearance.IsPrivateHostTests) чи назва модуля,
            # передається в unittest як є.
            names.append(arg)

    if not modules and not names:
        # Без жодного явного вибору групи/тесту — усі групи.
        for group in ALIASES["all"]:
            modules.extend(GROUPS[group])

    return flags, list(dict.fromkeys(modules)), names


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv

    if "--list" in argv:
        _print_list()
        return 0

    flags, modules, names = _expand(argv)
    test_argv = [sys.argv[0], *flags, *modules, *names]
    # exit=True (типово) — unittest.main сам викликає sys.exit() з тим самим
    # кодом, що й звичайний `python -m unittest ...` (0/1/5 тощо), без
    # потреби переізобретати цю логіку тут.
    unittest.main(module=None, argv=test_argv)


if __name__ == "__main__":
    main()
