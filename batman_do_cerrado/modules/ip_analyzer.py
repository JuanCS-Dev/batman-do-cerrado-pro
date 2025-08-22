# batman-do-cerrado-pro/batman_do_cerrado/modules/ip_analyzer.py

"""
Módulo IP Analyzer (Refatorado e Unificado) - Batman do Cerrado

Este módulo é o centro de inteligência para investigações de IP. Ele unifica
funcionalidades de GeoIP, WHOIS, DNS Reverso e Reputação, utilizando a biblioteca
core e reutilizando outros módulos do framework.
"""

import argparse
import sys
from typing import Optional, Dict, Any

import requests
from ipwhois import IPWhois
from ipwhois.exceptions import IPDefinedError

from batman_do_cerrado.core import ui, utils
from batman_do_cerrado.core.config import config
from batman_do_cerrado.core.models import IPAddressInfo
from . import whois

# --- Lógica de Análise de IP ---

def _query_geoip(ip: str, session: requests.Session) -> Dict[str, Any]:
    """
    Consulta GeoIP em múltiplos provedores com fallback.
    Retorna o dicionário de dados brutos do primeiro provedor bem-sucedido.
    """
    # Provedor 1: IPWhois
    try:
        obj = IPWhois(ip)
        results = obj.lookup_whois()
        if results and results.get("asn"):
            return {"source": "ipwhois", "data": results}
    except IPDefinedError:
         return {"source": "ipwhois", "data": {"error": "IP Privado"}}
    except Exception:
        pass

    # Provedor 2: ip-api.com
    try:
        resp = session.get(f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,regionName,city,lat,lon,timezone,isp,org,as,query")
        if resp.ok and resp.json().get("status") == "success":
            return {"source": "ip-api.com", "data": resp.json()}
    except requests.RequestException:
        pass

    # Provedor 3: ipinfo.io
    ipinfo_token = config.get_secret("ipinfo_token")
    if ipinfo_token:
        try:
            resp = session.get(f"https://ipinfo.io/{ip}", headers={"Authorization": f"Bearer {ipinfo_token}"})
            if resp.ok:
                return {"source": "ipinfo.io", "data": resp.json()}
        except requests.RequestException:
            pass
    
    return {"source": "none", "data": {}}

def _query_reputation(ip: str, session: requests.Session) -> Dict[str, Any]:
    """Consulta a reputação de um IP usando a API do AbuseIPDB."""
    api_key = config.get_secret("abuseipdb_key")
    if not api_key:
        return {"error": "Chave de API do AbuseIPDB não configurada."}

    try:
        resp = session.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={'ipAddress': ip, 'maxAgeInDays': '90'},
            headers={'Accept': 'application/json', 'Key': api_key}
        )
        resp.raise_for_status()
        return resp.json().get("data", {})
    except requests.RequestException as e:
        return {"error": f"Falha na API: {e.response.status_code if e.response else str(e)}"}


def _normalize_and_merge(info: IPAddressInfo, geo_result: Dict, whois_result: IPAddressInfo):
    """Normaliza e funde os dados de GeoIP e WHOIS no nosso modelo de dados."""
    info.ptr = whois_result.ptr
    info.isp = info.isp or whois_result.isp
    info.asn_number = info.asn_number or whois_result.asn_number
    info.asn_name = info.asn_name or whois_result.asn_name
    info.raw_data["whois"] = whois_result.raw_data.get("whois")
    
    source = geo_result.get("source", "none")
    data = geo_result.get("data", {})
    info.source_api = source
    info.raw_data["geoip"] = data

    if source == "ipwhois":
        info.country_code = data.get("asn_country_code")
        info.city = next((net.get('city') for net in data.get('nets', []) if net.get('city')), None)
        info.region = next((net.get('state') for net in data.get('nets', []) if net.get('state')), None)
        info.latitude = data.get("latitude")
        info.longitude = data.get("longitude")
    elif source == "ip-api.com":
        info.country_code = data.get("countryCode")
        info.city = data.get("city")
        info.region = data.get("regionName")
        info.isp = info.isp or data.get("isp")
        info.latitude = data.get("lat")
        info.longitude = data.get("lon")
    elif source == "ipinfo.io":
        info.country_code = data.get("country")
        info.city = data.get("city")
        info.region = data.get("region")
        info.isp = info.isp or data.get("org")
        if loc := data.get("loc"):
            try:
                lat, lon = loc.split(',')
                info.latitude = float(lat)
                info.longitude = float(lon)
            except (ValueError, IndexError):
                pass

def analyze(target: str) -> Optional[IPAddressInfo]:
    """
    Orquestra a análise completa de um IP, unificando todas as fontes de dados.
    """
    print(ui.color("\nExecutando análise de Rede (WHOIS & DNS)...", ui.GRAY))
    whois_result = whois.analyze(target)
    if not isinstance(whois_result, IPAddressInfo):
        print(ui.color("Análise de WHOIS falhou ou o alvo não é um IP.", ui.RED))
        return None
    
    final_info = whois_result

    print(ui.color("Executando análise de Geolocalização (GeoIP)...", ui.GRAY))
    session = requests.Session()
    session.headers.update({"User-Agent": "Batman-do-Cerrado-PRO/2.0"})
    geo_result = _query_geoip(target, session)
    _normalize_and_merge(final_info, geo_result, whois_result)

    print(ui.color("Executando análise de Reputação (AbuseIPDB)...", ui.GRAY))
    reputation_data = _query_reputation(target, session)
    final_info.raw_data["reputation"] = reputation_data

    return final_info

# ... (main e _print_results podem ser mantidos para testes diretos, mas o CLI principal usará o _print_ip_dossier do cli.py)
