#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Тести чистої логіки nat_traversal.py — Рівень 1 з docs/testing.md.

Реальна SSDP-мультикаст-розсилка і SOAP-запити до справжнього роутера тут
НЕ тестуються (потребують живого UPnP-пристрою в локальній мережі — це
ручний/інтеграційний тест, не модульний). Тут перевіряється лише те, що не
залежить від мережі: парсинг XML-відповідей роутера, побудова SOAP-тіла,
розбір заголовків SSDP-відповіді.
"""

import unittest
import xml.etree.ElementTree as ET

import _pathfix  # noqa: F401  (додає src/ у sys.path перед наступними імпортами)

from nat_traversal import (
    UpnpUnavailable,
    _build_soap_envelope,
    _extract_soap_fault,
    _find_text,
    _find_wan_service,
    _local_name,
    _parse_header,
    discover_igd_control_url,
)

# Скорочений, але структурно типовий приклад XML-опису UPnP IGD-роутера
# (schema urn:schemas-upnp-org:device-1-0), як його реально віддають
# домашні роутери на LOCATION-URL із SSDP-відповіді.
_DEVICE_DESCRIPTION_XML = """<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
  <device>
    <deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
    <friendlyName>Home Router</friendlyName>
    <deviceList>
      <device>
        <deviceType>urn:schemas-upnp-org:device:WANDevice:1</deviceType>
        <deviceList>
          <device>
            <deviceType>urn:schemas-upnp-org:device:WANConnectionDevice:1</deviceType>
            <serviceList>
              <service>
                <serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
                <serviceId>urn:upnp-org:serviceId:WANIPConn1</serviceId>
                <controlURL>/ctl/IPConn</controlURL>
                <eventSubURL>/evt/IPConn</eventSubURL>
                <SCPDURL>/IPConn.xml</SCPDURL>
              </service>
            </serviceList>
          </device>
        </deviceList>
      </device>
    </deviceList>
  </device>
</root>
"""

_DEVICE_DESCRIPTION_NO_WAN_XML = """<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
  <device>
    <deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
    <friendlyName>Router Without WAN Service In This Branch</friendlyName>
  </device>
</root>
"""

_SOAP_FAULT_XML = """<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
  <s:Body>
    <s:Fault>
      <faultcode>s:Client</faultcode>
      <faultstring>UPnPError</faultstring>
      <detail>
        <UPnPError xmlns="urn:schemas-upnp-org:control-1-0">
          <errorCode>718</errorCode>
          <errorDescription>ConflictInMappingEntry</errorDescription>
        </UPnPError>
      </detail>
    </s:Fault>
  </s:Body>
</s:Envelope>
"""

_SOAP_EXTERNAL_IP_RESPONSE_XML = """<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
  <s:Body>
    <u:GetExternalIPAddressResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">
      <NewExternalIPAddress>203.0.113.42</NewExternalIPAddress>
    </u:GetExternalIPAddressResponse>
  </s:Body>
</s:Envelope>
"""


class LocalNameAndFindTextTests(unittest.TestCase):
    def test_local_name_strips_namespace(self):
        self.assertEqual(_local_name("{urn:schemas-upnp-org:device-1-0}service"), "service")

    def test_local_name_without_namespace_unchanged(self):
        self.assertEqual(_local_name("service"), "service")

    def test_find_text_locates_nested_element_ignoring_namespace(self):
        root = ET.fromstring(_SOAP_EXTERNAL_IP_RESPONSE_XML)
        self.assertEqual(_find_text(root, "NewExternalIPAddress"), "203.0.113.42")

    def test_find_text_returns_none_when_absent(self):
        root = ET.fromstring(_SOAP_EXTERNAL_IP_RESPONSE_XML)
        self.assertIsNone(_find_text(root, "NoSuchTag"))


class ParseSsdpHeaderTests(unittest.TestCase):
    def test_extracts_location_case_insensitively(self):
        raw = "HTTP/1.1 200 OK\r\nlocation: http://192.168.1.1:1900/desc.xml\r\nST: upnp:rootdevice\r\n"
        self.assertEqual(_parse_header(raw, "LOCATION"), "http://192.168.1.1:1900/desc.xml")

    def test_missing_header_returns_none(self):
        raw = "HTTP/1.1 200 OK\r\nST: upnp:rootdevice\r\n"
        self.assertIsNone(_parse_header(raw, "LOCATION"))


class FindWanServiceTests(unittest.TestCase):
    def test_finds_control_url_and_resolves_relative_to_base(self):
        root = ET.fromstring(_DEVICE_DESCRIPTION_XML)
        result = _find_wan_service(root, "http://192.168.1.1:1900/desc.xml")
        self.assertIsNotNone(result)
        control_url, service_type = result
        self.assertEqual(control_url, "http://192.168.1.1:1900/ctl/IPConn")
        self.assertEqual(service_type, "urn:schemas-upnp-org:service:WANIPConnection:1")

    def test_returns_none_when_no_wan_service_present(self):
        root = ET.fromstring(_DEVICE_DESCRIPTION_NO_WAN_XML)
        self.assertIsNone(_find_wan_service(root, "http://192.168.1.1:1900/desc.xml"))


class SoapEnvelopeTests(unittest.TestCase):
    def test_envelope_contains_action_and_service_type(self):
        body = _build_soap_envelope(
            "urn:schemas-upnp-org:service:WANIPConnection:1",
            "GetExternalIPAddress",
            {},
        ).decode("utf-8")
        self.assertIn("<u:GetExternalIPAddress ", body)
        self.assertIn("urn:schemas-upnp-org:service:WANIPConnection:1", body)

    def test_envelope_includes_params_and_escapes_special_chars(self):
        body = _build_soap_envelope(
            "urn:schemas-upnp-org:service:WANIPConnection:1",
            "AddPortMapping",
            {"NewPortMappingDescription": "a & b < c"},
        ).decode("utf-8")
        self.assertIn("<NewPortMappingDescription>a &amp; b &lt; c</NewPortMappingDescription>", body)


class SoapFaultExtractionTests(unittest.TestCase):
    def test_extracts_upnp_error_code_and_description(self):
        root = ET.fromstring(_SOAP_FAULT_XML)
        message = _extract_soap_fault(root)
        self.assertIn("718", message)
        self.assertIn("ConflictInMappingEntry", message)


class DiscoverIgdNoResponseTests(unittest.TestCase):
    def test_raises_upnp_unavailable_when_no_router_answers(self):
        # Дуже короткий timeout у мережі без реального UPnP-роутера
        # (наприклад, у CI/пісочниці) — SSDP не отримає жодної відповіді,
        # і функція має впасти з керованою помилкою, а не зависнути/впасти
        # з нечитабельним traceback.
        with self.assertRaises(UpnpUnavailable):
            discover_igd_control_url(timeout=0.2)


if __name__ == "__main__":
    unittest.main()
