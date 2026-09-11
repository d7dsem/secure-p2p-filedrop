#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Єдине місце зберігання конфігураційних параметрів і значень, щоб уникнути
магічних констант у решті коду.

Кожен датаклас відповідає окремому шару застосунку — назва датакласу
вказує, до якого компонента системи належать його параметри:
  - ConnectionTuning — деривація ключа й хендшейк (шар "підключення");
  - NatTuning — UPnP-проброс порту, теж шар "підключення";
  - StunTuning — публічний STUN-сервер (рівень 2 моделі встановлення
    з'єднання, теж шар "підключення" — див. docs/concept.md);
  - ProfileTuning — де шукати персистентний локальний конфіг користувача
    (client_id, дефолтні каталоги) — шар "профіль";
  - AppearanceTuning — вікно, тема, розміри (шар "зовнішність");
  - ExchangeTuning — підготовка даних до передачі (шар "обмін").
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class ConnectionTuning:
    default_iterations: int = 200_000
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
    """UPnP IGD: спілкування лише з власним роутером користувача (SSDP у
    локальному сегменті мережі + SOAP на control URL, знайдений через
    SSDP) — жодного зовнішнього/третього сервера. Див. docs/concept.md."""
    ssdp_address: str = "239.255.255.250"
    ssdp_port: int = 1900
    ssdp_search_target: str = "urn:schemas-upnp-org:device:InternetGatewayDevice:1"
    discovery_timeout_seconds: float = 2.0
    soap_timeout_seconds: float = 3.0
    port_mapping_description: str = "secure-p2p-filedrop"
    port_mapping_lease_seconds: int = 0  # 0 = без обмеження (до видалення/ребута роутера)


@dataclass(frozen=True)
class StunTuning:
    """Публічний STUN-сервер — рівень 2 моделі встановлення з'єднання
    (docs/concept.md, "Принципове архітектурне обмеження"): НЕ власна
    інфраструктура, а разовий stateless-запит до вже готового чужого
    сервісу лише для того, щоб дізнатись свою публічну IP:port — жодних
    файлових даних чи сесійного ключа туди не йде."""
    server_host: str = "stun.l.google.com"
    server_port: int = 19302
    timeout_seconds: float = 2.0


@dataclass(frozen=True)
class ProfileTuning:
    """Шар "профіль": ЦІ значення лише задають, ДЕ шукати персистентний
    локальний конфіг користувача (client_id, дефолтні каталоги
    вхідних/вихідних файлів) і які дефолти підставити при першому
    запуску. Самі поточні користувацькі значення живуть у
    local_config.py / файлі конфігу на диску, не тут — на відміну від
    решти tuning.py, це не незмінні дефолти застосунку, а лише "звідки
    старт", далі користувач їх редагує й зберігає сам."""
    config_dir_name: str = ".secure_p2p_filedrop"
    config_file_name: str = "config.json"
    default_incoming_subdir: str = "SecureFileDrop/incoming"
    default_outgoing_subdir: str = "SecureFileDrop/outgoing"
    client_id_prefix: str = "client-"
    client_id_random_hex_bytes: int = 4


@dataclass(frozen=True)
class AppearanceTuning:
    window_title: str = "Обмін файлами — підготовка сеансу"
    window_geometry: str = "640x720"
    window_min_size: tuple[int, int] = (560, 640)
    text_widget_height: int = 6

    # Палітра темної теми. Ttk не має вбудованої темної теми "з коробки" —
    # кольори задаються вручну через ttk.Style (для ttk-віджетів) і напряму
    # через configure() для класичних Tk-віджетів (Text/ScrolledText не є
    # ttk-віджетами й стилем не керуються).
    dark_bg: str = "#1e1e1e"
    dark_bg_panel: str = "#252526"
    dark_fg: str = "#e6e6e6"
    dark_fg_muted: str = "#9aa0a6"
    dark_entry_bg: str = "#2d2d30"
    dark_accent: str = "#3a7afe"
    dark_border: str = "#3c3c3c"


@dataclass(frozen=True)
class ExchangeTuning:
    archive_file_name: str = "payload.zip"
    temp_dir_prefix: str = "secure_transfer_"
    # Технічна підпапка в корені обраного каталогу передачі, куди
    # складається архів вибраних елементів (appearance.py, вкладка
    # "Сеанс" -> дерево з чекбоксами). Виключається зі сканування/показу
    # дерева, щоб сама не потрапила у вибір і не запакувала сама себе.
    pack_subdir_name: str = ".secure_p2p_filedrop_pack"
    size_units: tuple[str, ...] = ("Б", "КБ", "МБ", "ГБ", "ТБ")


CONNECTION = ConnectionTuning()
NAT = NatTuning()
STUN = StunTuning()
PROFILE = ProfileTuning()
APPEARANCE = AppearanceTuning()
EXCHANGE = ExchangeTuning()
