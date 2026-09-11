#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Шар "профіль": персистентний локальний конфіг користувача —
ідентифікатор клієнта (client_id) і дефолтні каталоги вхідних/вихідних
файлів. Зберігається окремим JSON-файлом у домашній директорії
користувача (крос-платформенно, без сторонніх залежностей).

На відміну від tuning.py (жорсткі дефолти застосунку, задані в коді й
незмінні в рантаймі), значення тут користувач сам редагує під час
роботи застосунку і свідомо зберігає окремою дією (кнопка "Зберегти
профіль" в appearance.py) — доти зміни лишаються лише в пам'яті сеансу.
"""

import json
import secrets
from dataclasses import asdict, dataclass
from pathlib import Path

from tuning import PROFILE


@dataclass
class LocalConfig:
    client_id: str
    incoming_dir: str
    outgoing_dir: str


def config_path() -> Path:
    return Path.home() / PROFILE.config_dir_name / PROFILE.config_file_name


def _generate_client_id() -> str:
    return f"{PROFILE.client_id_prefix}{secrets.token_hex(PROFILE.client_id_random_hex_bytes)}"


def _default_config() -> LocalConfig:
    return LocalConfig(
        client_id=_generate_client_id(),
        incoming_dir=str(Path.home() / PROFILE.default_incoming_subdir),
        outgoing_dir=str(Path.home() / PROFILE.default_outgoing_subdir),
    )


def load_config(path: Path | None = None) -> LocalConfig:
    """
    Читає локальний конфіг з диска. Якщо файлу немає або він пошкоджений
    (побитий JSON, не той тип тощо) — підставляє дефолти й одразу зберігає
    їх на диск, щоб client_id закріпився за цим ПК з першого запуску, а не
    генерувався щоразу заново.
    """
    path = path or config_path()
    defaults = _default_config()

    if path.exists():
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            return LocalConfig(
                client_id=str(data.get("client_id") or defaults.client_id),
                incoming_dir=str(data.get("incoming_dir") or defaults.incoming_dir),
                outgoing_dir=str(data.get("outgoing_dir") or defaults.outgoing_dir),
            )
        except (json.JSONDecodeError, OSError, TypeError, AttributeError):
            pass

    save_config(defaults, path)
    return defaults


def save_config(config: LocalConfig, path: Path | None = None) -> None:
    path = path or config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(asdict(config), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
