#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Єдине місце зберігання конфігураційних параметрів, щоб уникнути магічних констант у решті коду.
Кожен датаклас = один шар застосунку (назва вказує на шар); мапа шарів — docs/architecture.md.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class ConnectionTuning:
    # OWASP-рекомендація для PBKDF2-HMAC-SHA256 (>=600_000); докладніше: dev-notes.md.
    default_iterations: int = 600_000
    # Нижня межа для iterations, отриманих ІЗ ЧУЖОГО пакета (parse_handshake_packet) —
    # захист від підробленого/зниженого значення, що змусило б слабшу деривацію.
    min_iterations: int = 200_000
    # secrets.token_urlsafe(n) з n байт сирої ентропії — ~192 біти, з великим запасом
    # над рекомендаціями (напр. EFF diceware 6 слів ~77 біт).
    generated_passphrase_bytes: int = 24
    salt_size_bytes: int = 16
    session_id_size_bytes: int = 8
    fingerprint_hex_length: int = 8
    packet_version: int = 2  # v2: до пакету додано host/port (мережевий компонент хендшейку)
    handshake_header: str = "-----HANDSHAKE-----"
    handshake_footer: str = "-----END-----"
    default_port: int = 52075
    min_port: int = 1
    max_port: int = 65535


@dataclass(frozen=True)
class NatTuning:
    """UPnP IGD: лише власний роутер користувача, жодного зовнішнього сервера. Див. docs/concept.md."""
    ssdp_address: str = "239.255.255.250"
    ssdp_port: int = 1900
    ssdp_search_target: str = "urn:schemas-upnp-org:device:InternetGatewayDevice:1"
    discovery_timeout_seconds: float = 2.0
    soap_timeout_seconds: float = 3.0
    port_mapping_description: str = "secure-p2p-filedrop"
    port_mapping_lease_seconds: int = 0  # 0 = без обмеження (до видалення/ребута роутера)


@dataclass(frozen=True)
class StunTuning:
    """Публічний STUN-сервер, рівень 2 моделі з'єднання — не власна інфраструктура,
    разовий stateless-запит. Див. docs/concept.md, "Принципове архітектурне обмеження"."""
    server_host: str = "stun.l.google.com"
    server_port: int = 19302
    timeout_seconds: float = 2.0


@dataclass(frozen=True)
class ProfileTuning:
    """Шар "профіль": лише ДЕ шукати конфіг і дефолти для першого запуску —
    поточні значення живуть у local_config.py. Докладніше: docs/dev-notes.md."""
    config_dir_name: str = ".secure_p2p_filedrop"
    config_file_name: str = "config.json"
    default_incoming_subdir: str = "SecureFileDrop/incoming"
    default_outgoing_subdir: str = "SecureFileDrop/outgoing"
    client_id_prefix: str = "client-"
    client_id_random_hex_bytes: int = 4


@dataclass(frozen=True)
class AppearanceTuning:
    window_title: str = "Обмін файлами — підготовка сеансу"
    # Ширший дефолт під двоколонковий layout — старий 640x720 не вміщав дерево файлів.
    window_geometry: str = "900x825"
    window_min_size: tuple[int, int] = (760, 520)
    text_widget_height: int = 6
    base_font_size_delta: int = 1  # наскільки збільшити системний дефолт (дрібний за замовчуванням)
    heading_font_size_delta: int = 1  # наскільки заголовки секцій більші за (вже збільшений) базовий шрифт

    # Палітра темної теми (ttk не має її "з коробки"). Докладніше: docs/dev-notes.md.
    dark_bg: str = "#1e1e1e"
    dark_bg_panel: str = "#252526"
    dark_fg: str = "#e6e6e6"
    dark_fg_muted: str = "#9aa0a6"
    dark_entry_bg: str = "#2d2d30"
    dark_accent: str = "#3a7afe"
    dark_border: str = "#3c3c3c"

    # Темніший за dark_accent фон CTA-кнопок — контраст з текстом ~6.3:1 проти ~3.1:1
    # (нижче WCAG AA). Докладніше: docs/dev-notes.md → "tuning.py: AppearanceTuning.accent_button_bg".
    accent_button_bg: str = "#2f5fac"
    accent_button_fg: str = "#ffffff"


@dataclass(frozen=True)
class ExchangeTuning:
    archive_file_name: str = "payload.zip"
    temp_dir_prefix: str = "secure_transfer_"
    # Технічна підпапка під архів у корені обраного каталогу — виключається зі сканування
    # (appearance.py), щоб сама не потрапила у вибір. Докладніше: docs/dev-notes.md.
    pack_subdir_name: str = ".secure_p2p_filedrop_pack"
    size_units: tuple[str, ...] = ("Б", "КБ", "МБ", "ГБ", "ТБ")


@dataclass(frozen=True)
class EncryptionTuning:
    """Шифрування архіву через pyzipper (AES) — єдина зовнішня залежність проєкту,
    свідомий виняток із "мінімум залежностей". Докладніше: docs/concept.md."""
    default_level: str = "none"
    default_compress: bool = True
    aes128_bits: int = 128
    aes256_bits: int = 256


@dataclass(frozen=True)
class TransportTuning:
    """Шар "транспорт" (Фаза 3 + сервісна функція, docs/concept.md): сокети,
    протокол підтвердження ключа (HMAC challenge-response), передача файлів."""
    connect_retry_interval_seconds: float = 0.5
    # Реалістично велике: сторона, що згенерувала хендшейк, чекає, поки людина
    # скопіює його, надішле іншому месенджером, а той вставить і обробить —
    # це хвилини, не секунди. Тести самі передають короткий timeout явно.
    connect_timeout_seconds: float = 300.0
    listen_backlog: int = 1
    accept_poll_timeout_seconds: float = 0.5  # для періодичної перевірки stop_event
    verify_timeout_seconds: float = 5.0
    nonce_size_bytes: int = 16
    chunk_size_bytes: int = 65536
    frame_length_bytes: int = 4  # big-endian префікс довжини кадру
    max_frame_bytes: int = 64 * 1024 * 1024  # запобіжник від OOM на побитому/ворожому кадрі
    aes_nonce_bytes: int = 16


CONNECTION = ConnectionTuning()
NAT = NatTuning()
STUN = StunTuning()
PROFILE = ProfileTuning()
APPEARANCE = AppearanceTuning()
EXCHANGE = ExchangeTuning()
ENCRYPTION = EncryptionTuning()
TRANSPORT = TransportTuning()
