#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Шар "підключення": UPnP IGD-клієнт для проходження NAT.

ПРИНЦИПОВО (зафіксовано за вимогою користувача — жодних третіх сторін
в архітектурі): цей модуль говорить ЛИШЕ з роутером у власній локальній
мережі користувача — SSDP-пошук (UDP-multicast у межах LAN) і SOAP-запити
на control URL, отриманий із XML-опису самого роутера. Жодного зовнішнього
сервера (ні STUN, ні relay, ні "what's my ip"-подібних сервісів) тут немає
і бути не повинно.

Якщо роутер не підтримує UPnP (вимкнено, немає підтримки, CGNAT у
провайдера тощо) — це фіксується як UpnpUnavailable/UpnpActionError, і
виклик з appearance.py має впасти назад на ручний ввід публічної IP та
ручний проброс порту користувачем (докладніше — docs/concept.md).
"""

import socket
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from xml.sax.saxutils import escape as _xml_escape

from tuning import NAT


class UpnpError(Exception):
    """Базовий клас помилок UPnP-клієнта."""


class UpnpUnavailable(UpnpError):
    """У локальній мережі не знайдено UPnP IGD-роутера (вимкнено/не підтримується)."""


class UpnpActionError(UpnpError):
    """Роутер знайдено, але конкретна SOAP-дія (GetExternalIPAddress,
    AddPortMapping тощо) повернула помилку."""


_WAN_SERVICE_TYPES = (
    "urn:schemas-upnp-org:service:WANIPConnection:1",
    "urn:schemas-upnp-org:service:WANPPPConnection:1",
)

_DEVICE_DESC_NS = "urn:schemas-upnp-org:device-1-0"


# --------------------------------------------------------------------------
# Допоміжне: розбір XML без зав'язки на конкретний namespace-префікс
# --------------------------------------------------------------------------

def _local_name(tag: str) -> str:
    return tag.split("}", 1)[-1] if "}" in tag else tag


def _find_text(root: ET.Element, tag_name: str) -> str | None:
    for el in root.iter():
        if _local_name(el.tag) == tag_name:
            return (el.text or "").strip()
    return None


def _parse_header(raw_response: str, header_name: str) -> str | None:
    for line in raw_response.split("\r\n"):
        if ":" not in line:
            continue
        name, _, value = line.partition(":")
        if name.strip().lower() == header_name.lower():
            return value.strip()
    return None


# --------------------------------------------------------------------------
# SSDP-пошук роутера в локальній мережі
# --------------------------------------------------------------------------

def _ssdp_discover(search_target: str, timeout: float) -> list[str]:
    """Надсилає SSDP M-SEARCH у локальний мультикаст-сегмент і збирає
    заголовки LOCATION з відповідей. Працює тільки в межах LAN — це не
    звернення до жодного зовнішнього хоста."""
    message = "\r\n".join([
        "M-SEARCH * HTTP/1.1",
        f"HOST: {NAT.ssdp_address}:{NAT.ssdp_port}",
        'MAN: "ssdp:discover"',
        "MX: 2",
        f"ST: {search_target}",
        "", "",
    ]).encode("utf-8")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.settimeout(timeout)
    locations: list[str] = []
    try:
        sock.sendto(message, (NAT.ssdp_address, NAT.ssdp_port))
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                data, _addr = sock.recvfrom(8192)
            except socket.timeout:
                break
            except OSError:
                break
            location = _parse_header(data.decode("utf-8", errors="ignore"), "LOCATION")
            if location:
                locations.append(location)
    finally:
        sock.close()
    return locations


def _fetch_device_description(location_url: str, timeout: float) -> ET.Element:
    with urllib.request.urlopen(location_url, timeout=timeout) as resp:  # noqa: S310 (LAN-only URL з SSDP)
        data = resp.read()
    return ET.fromstring(data)


def _find_wan_service(root: ET.Element, base_url: str) -> tuple[str, str] | None:
    """Шукає в XML-описі роутера сервіс WANIPConnection/WANPPPConnection і
    повертає (control_url, service_type), або None, якщо не знайдено."""
    for service in root.iter(f"{{{_DEVICE_DESC_NS}}}service"):
        service_type = service.findtext(f"{{{_DEVICE_DESC_NS}}}serviceType", "")
        if service_type in _WAN_SERVICE_TYPES:
            control_url = service.findtext(f"{{{_DEVICE_DESC_NS}}}controlURL", "")
            if control_url:
                return urllib.parse.urljoin(base_url, control_url), service_type
    return None


def discover_igd_control_url(timeout: float | None = None) -> tuple[str, str]:
    """Знаходить у локальній мережі UPnP IGD-роутер і повертає
    (control_url, service_type) для подальших SOAP-запитів.
    Кидає UpnpUnavailable, якщо жодного придатного роутера не знайдено."""
    timeout = NAT.discovery_timeout_seconds if timeout is None else timeout
    locations = _ssdp_discover(NAT.ssdp_search_target, timeout)

    errors: list[str] = []
    for location in dict.fromkeys(locations):  # de-dup зі збереженням порядку
        try:
            root = _fetch_device_description(location, timeout)
        except (urllib.error.URLError, ET.ParseError, OSError) as e:
            errors.append(f"{location}: {e}")
            continue
        found = _find_wan_service(root, location)
        if found:
            return found

    detail = f" ({'; '.join(errors)})" if errors else ""
    raise UpnpUnavailable(
        "Не знайдено UPnP IGD-роутер у локальній мережі — можливо, UPnP "
        "вимкнено на роутері або він його не підтримує." + detail
    )


# --------------------------------------------------------------------------
# SOAP-запити до знайденого control URL
# --------------------------------------------------------------------------

def _build_soap_envelope(service_type: str, action: str, params: dict[str, str]) -> bytes:
    """Чиста функція без мережевого I/O — легко тестувати окремо."""
    args_xml = "".join(
        f"<{name}>{_xml_escape(str(value))}</{name}>" for name, value in params.items()
    )
    envelope = (
        '<?xml version="1.0"?>'
        '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
        's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">'
        "<s:Body>"
        f'<u:{action} xmlns:u="{service_type}">{args_xml}</u:{action}>'
        "</s:Body></s:Envelope>"
    )
    return envelope.encode("utf-8")


def _extract_soap_fault(root: ET.Element) -> str | None:
    code = _find_text(root, "errorCode")
    desc = _find_text(root, "errorDescription")
    if code or desc:
        return f"UPnP error {code}: {desc}"
    fault_string = _find_text(root, "faultstring")
    return fault_string


def _soap_request(
    control_url: str, service_type: str, action: str,
    params: dict[str, str], timeout: float,
) -> ET.Element:
    body = _build_soap_envelope(service_type, action, params)
    request = urllib.request.Request(
        control_url,
        data=body,
        method="POST",
        headers={
            "Content-Type": 'text/xml; charset="utf-8"',
            "SOAPAction": f'"{service_type}#{action}"',
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as resp:  # noqa: S310 (LAN-only)
            data = resp.read()
    except urllib.error.HTTPError as e:
        data = e.read()
        try:
            fault_root = ET.fromstring(data)
            message = _extract_soap_fault(fault_root) or f"HTTP {e.code}"
        except ET.ParseError:
            message = f"HTTP {e.code}"
        raise UpnpActionError(f"Роутер відхилив дію '{action}': {message}") from e
    except urllib.error.URLError as e:
        raise UpnpActionError(f"Не вдалось звернутись до роутера для дії '{action}': {e}") from e

    return ET.fromstring(data)


def get_external_ip(control_url: str, service_type: str, timeout: float | None = None) -> str:
    """Публічна IP-адреса, яку роутер бачить на своєму WAN-інтерфейсі."""
    timeout = NAT.soap_timeout_seconds if timeout is None else timeout
    root = _soap_request(control_url, service_type, "GetExternalIPAddress", {}, timeout)
    ip = _find_text(root, "NewExternalIPAddress")
    if not ip:
        raise UpnpActionError("Роутер не повернув зовнішню IP-адресу")
    return ip


def add_port_mapping(
    control_url: str, service_type: str,
    external_port: int, internal_port: int, internal_client_ip: str,
    protocol: str = "TCP", timeout: float | None = None,
) -> None:
    """Просить роутер прокинути external_port -> internal_client_ip:internal_port."""
    timeout = NAT.soap_timeout_seconds if timeout is None else timeout
    params = {
        "NewRemoteHost": "",
        "NewExternalPort": str(external_port),
        "NewProtocol": protocol.upper(),
        "NewInternalPort": str(internal_port),
        "NewInternalClient": internal_client_ip,
        "NewEnabled": "1",
        "NewPortMappingDescription": NAT.port_mapping_description,
        "NewLeaseDuration": str(NAT.port_mapping_lease_seconds),
    }
    _soap_request(control_url, service_type, "AddPortMapping", params, timeout)


# --------------------------------------------------------------------------
# Високорівнева точка входу для appearance.py
# --------------------------------------------------------------------------

def try_configure_port_forwarding(local_ip: str, local_port: int, protocol: str = "TCP") -> str:
    """
    Одна функція для GUI: (1) знаходить UPnP IGD у своїй LAN, (2) дізнається
    зовнішню IP, (3) просить прокинути зовнішній порт на local_ip:local_port.
    Повертає зовнішню IP при успіху.

    Кидає UpnpError (UpnpUnavailable/UpnpActionError) при будь-якій
    невдачі — виклик з appearance.py має це ловити й пропонувати
    користувачу ручний fallback (самостійний проброс порту + ручний ввід
    публічної IP), а не намагатись достукатись кудись іще.
    """
    control_url, service_type = discover_igd_control_url()
    external_ip = get_external_ip(control_url, service_type)
    add_port_mapping(
        control_url, service_type,
        external_port=local_port, internal_port=local_port,
        internal_client_ip=local_ip, protocol=protocol,
    )
    return external_ip
