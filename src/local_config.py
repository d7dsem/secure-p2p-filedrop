#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Шар "профіль": персистентний локальний конфіг користувача (client_id, дефолтні каталоги,
дефолтний порт) у JSON-файлі домашньої директорії. Чим відрізняється від tuning.py: docs/dev-notes.md → "local_config.py".
"""

import json
import secrets
from dataclasses import asdict, dataclass
from pathlib import Path

from tuning import CONNECTION, PROFILE


@dataclass
class LocalConfig:
    client_id: str
    incoming_dir: str
    outgoing_dir: str
    # Дефолтний порт профілю — низ ієрархії precedence: tuning.CONNECTION.default_port
    # (лише коли в профілі його взагалі нема/пошкоджений) < цей default_port < CLI --port <
    # ручна правка поля "Порт" в GUI (сеансова, у профіль не пишеться). Докладніше:
    # docs/dev-notes.md → "local_config.py".
    default_port: int = CONNECTION.default_port


def config_path() -> Path:
    return Path.home() / PROFILE.config_dir_name / PROFILE.config_file_name


def _generate_client_id() -> str:
    return f"{PROFILE.client_id_prefix}{secrets.token_hex(PROFILE.client_id_random_hex_bytes)}"


def _default_config() -> LocalConfig:
    return LocalConfig(
        client_id=_generate_client_id(),
        incoming_dir=str(Path.home() / PROFILE.default_incoming_subdir),
        outgoing_dir=str(Path.home() / PROFILE.default_outgoing_subdir),
        default_port=CONNECTION.default_port,
    )


def _parse_port(value, fallback: int) -> int:
    """Валідує default_port із файлу профілю: ціле 1..65535. Відсутнє/биту-типу/поза
    межами значення (старий профіль без поля, ручне псування файлу) — тихий fallback
    на tuning.CONNECTION.default_port, без падіння застосунку."""
    if isinstance(value, bool):
        return fallback
    try:
        port = int(value)
    except (TypeError, ValueError):
        return fallback
    if not (CONNECTION.min_port <= port <= CONNECTION.max_port):
        return fallback
    return port


def load_config(path: Path | None = None) -> LocalConfig:
    """Читає конфіг з диска; якщо немає/пошкоджений — підставляє дефолти й одразу зберігає
    (щоб client_id закріпився з першого запуску, а не генерувався щоразу заново).
    Профіль без default_port (файл, збережений до появи цього поля) — сумісний,
    fallback на tuning.CONNECTION.default_port (_parse_port)."""
    path = path or config_path()
    defaults = _default_config()

    if path.exists():
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            return LocalConfig(
                client_id=str(data.get("client_id") or defaults.client_id),
                incoming_dir=str(data.get("incoming_dir") or defaults.incoming_dir),
                outgoing_dir=str(data.get("outgoing_dir") or defaults.outgoing_dir),
                default_port=_parse_port(data.get("default_port"), CONNECTION.default_port),
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
