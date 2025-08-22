# tests/test_whois_helpers.py

import pytest
from batman_do_cerrado.modules.whois import _detect_target_type, _parse_whois_kv, _parse_domain_whois, _parse_ip_whois

def test_detect_target_type_com_ipv4_validos():
    """Verifica se IPs IPv4 válidos são corretamente identificados."""
    assert _detect_target_type("8.8.8.8") == "ip"
    assert _detect_target_type("192.168.0.1") == "ip"
    assert _detect_target_type("0.0.0.0") == "ip"
    assert _detect_target_type("255.255.255.255") == "ip"

def test_detect_target_type_com_dominios_validos():
    """Verifica se domínios válidos são corretamente identificados."""
    assert _detect_target_type("google.com") == "domain"
    assert _detect_target_type("github.com.br") == "domain"
    assert _detect_target_type("meu-site-com-hifen.net") == "domain"
    assert _detect_target_type("a.b.c.d.e.f.co") == "domain"

def test_detect_target_type_com_entradas_invalidas():
    """Verifica se entradas inválidas retornam None."""
    assert _detect_target_type("nao-e-um-dominio") is None
    assert _detect_target_type("12345") is None
    assert _detect_target_type("8.8.8") is None
    assert _detect_target_type("google.com/") is None
    assert _detect_target_type("") is None

def test_parse_whois_kv_com_dados_validos():
    """Testa o parser de chave-valor com uma amostra de texto WHOIS."""
    raw_text = """
% This is a comment
# Another comment
Domain Name: google.com
Registrar: MarkMonitor Inc.
Name Server: ns1.google.com
Name Server: ns2.google.com
    """
    parsed_data = _parse_whois_kv(raw_text)
    assert "domain_name" in parsed_data
    assert parsed_data["registrar"] == ["MarkMonitor Inc."]
    assert parsed_data["name_server"] == ["ns1.google.com", "ns2.google.com"]

def test_parse_domain_whois_com_dados_comuns():
    """Testa o parser de WHOIS de domínio com uma amostra de texto comum."""
    raw_text = """
Registrar: MarkMonitor Inc.
Creation Date: 1997-09-15T04:00:00Z
Registry Expiry Date: 2028-09-13T04:00:00Z
Name Server: ns1.google.com
    """
    parsed_data = _parse_domain_whois(raw_text)
    assert parsed_data["registrar"] == "MarkMonitor Inc."
    assert parsed_data["creation_date"] == "1997-09-15T04:00:00Z"
    assert parsed_data["expiration_date"] == "2028-09-13T04:00:00Z"
    assert "ns1.google.com" in parsed_data["nameservers"]

def test_parse_ip_whois_com_dados_comuns():
    """Testa o parser de WHOIS de IP com uma amostra de texto comum."""
    raw_text = """
OrgName:        Google LLC
Organization:   Google LLC
OriginAS:       AS15169
AS-Name:        GOOGLE
    """
    parsed_data = _parse_ip_whois(raw_text)
    assert parsed_data["isp"] == "Google LLC"
    assert parsed_data["asn_number"] == 15169
    assert parsed_data["asn_name"] == "GOOGLE"
    assert parsed_data["raw"] == raw_text
