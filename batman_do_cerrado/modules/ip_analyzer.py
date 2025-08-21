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
# Reutilização de código em ação! Importamos nosso próprio módulo refatorado.
from . import whois

# --- Lógica de Análise de IP ---

def _query_geoip(ip: str, session: requests.Session) -> Dict[str, Any]:
    """
    Consulta GeoIP em múltiplos provedores com fallback, inspirado no seu ip_searcher.
    Retorna o dicionário de dados brutos do primeiro provedor bem-sucedido.
    """
    # Provedor 1: IPWhois (usando a biblioteca)
    try:
        obj = IPWhois(ip)
        results = obj.lookup_whois()
        # A biblioteca ipwhois retorna uma estrutura que podemos normalizar
        if results and results.get("asn"):
            return {"source": "ipwhois", "data": results}
    except IPDefinedError:
         # Ignora IPs privados, que não podem ser consultados
         return {"source": "ipwhois", "data": {"error": "IP Privado"}}
    except Exception:
        pass # Falha, tenta o próximo

    # Provedor 2: ip-api.com (fallback)
    try:
        resp = session.get(f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,regionName,city,lat,lon,timezone,isp,org,as,query")
        if resp.ok and resp.json().get("status") == "success":
            return {"source": "ip-api.com", "data": resp.json()}
    except requests.RequestException:
        pass # Falha, tenta o próximo

    # Provedor 3: ipinfo.io (se a chave de API estiver configurada)
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
    # Funde dados do WHOIS (que já vem no formato certo)
    info.ptr = whois_result.ptr
    info.isp = info.isp or whois_result.isp
    info.asn_number = info.asn_number or whois_result.asn_number
    info.asn_name = info.asn_name or whois_result.asn_name
    info.raw_data["whois"] = whois_result.raw_data.get("whois")
    
    # Normaliza e funde dados do GeoIP
    source = geo_result.get("source", "none")
    data = geo_result.get("data", {})
    info.source_api = source
    info.raw_data["geoip"] = data

    if source == "ipwhois":
        info.country_code = data.get("asn_country_code")
        info.city = next((net.get('city') for net in data.get('nets', []) if net.get('city')), None)
        info.region = next((net.get('state') for net in data.get('nets', []) if net.get('state')), None)
    elif source == "ip-api.com":
        info.country_code = data.get("countryCode")
        info.city = data.get("city")
        info.region = data.get("regionName")
        info.isp = info.isp or data.get("isp")
    elif source == "ipinfo.io":
        info.country_code = data.get("country")
        info.city = data.get("city")
        info.region = data.get("region")
        info.isp = info.isp or data.get("org")

def analyze(target: str) -> Optional[IPAddressInfo]:
    """
    Orquestra a análise completa de um IP, unificando todas as fontes de dados.
    """
    # 1. Análise de WHOIS e DNS Reverso (reutilizando nosso módulo)
    print(ui.color("\nExecutando análise de Rede (WHOIS & DNS)...", ui.GRAY))
    whois_result = whois.analyze(target)
    if not isinstance(whois_result, IPAddressInfo):
        print(ui.color("Análise de WHOIS falhou ou o alvo não é um IP.", ui.RED))
        return None
    
    # Nosso objeto final começa com os dados do WHOIS
    final_info = whois_result

    # 2. Análise de Geolocalização (com múltiplos provedores)
    print(ui.color("Executando análise de Geolocalização (GeoIP)...", ui.GRAY))
    session = requests.Session()
    session.headers.update({"User-Agent": "Batman-do-Cerrado-PRO/2.0"})
    geo_result = _query_geoip(target, session)
    _normalize_and_merge(final_info, geo_result, whois_result)

    # 3. Análise de Reputação
    print(ui.color("Executando análise de Reputação (AbuseIPDB)...", ui.GRAY))
    reputation_data = _query_reputation(target, session)
    final_info.raw_data["reputation"] = reputation_data

    return final_info


def _print_results(info: IPAddressInfo):
    """Imprime o dossiê completo do IP de forma organizada."""
    ui.print_banner()
    print(ui.color(f"--- Dossiê do IP: {info.ip} ---", ui.BOLD + ui.CYAN))

    # Seção de Rede e DNS
    print(ui.color("\n[ DADOS DE REDE E DNS ]", ui.BLUE))
    print(f"  {'ISP/Organização:':<20} {info.isp or 'N/A'}")
    asn = f"AS{info.asn_number}" if info.asn_number else "N/A"
    print(f"  {'ASN:':<20} {asn} ({info.asn_name or 'N/A'})")
    print(f"  {'DNS Reverso (PTR):':<20} {info.ptr or 'Nenhum'}")

    # Seção de Geolocalização
    print(ui.color("\n[ GEOLOCALIZAÇÃO ]", ui.BLUE))
    print(f"  {'Cidade:':<20} {info.city or 'N/A'}")
    print(f"  {'Região/Estado:':<20} {info.region or 'N/A'}")
    print(f"  {'País:':<20} {info.country_code or 'N/A'}")
    print(f"  {'Fonte dos Dados:':<20} {info.source_api or 'Nenhuma'}")

    # Seção de Reputação
    print(ui.color("\n[ REPUTAÇÃO (ABUSEIPDB) ]", ui.BLUE))
    rep = info.raw_data.get("reputation", {})
    if "error" in rep:
        print(ui.color(f"  Erro: {rep['error']}", ui.YELLOW))
    else:
        score = rep.get('abuseConfidenceScore', 0)
        score_color = ui.GREEN if score < 25 else (ui.YELLOW if score < 75 else ui.RED)
        print(f"  {'Pontuação de Abuso:':<20} {ui.color(str(score), ui.BOLD + score_color)} / 100")
        print(f"  {'Total de Denúncias:':<20} {rep.get('totalReports', 0)}")
        print(f"  {'É IP Público:':<20} {'Sim' if rep.get('isPublic') else 'Não'}")
        print(f"  {'Domínio:':<20} {rep.get('domain', 'N/A')}")
        
    print()


def main():
    """Ponto de entrada para execução interativa."""
    parser = argparse.ArgumentParser(description="Módulo IP Analyzer - Batman do Cerrado")
    parser.add_argument("target", nargs="?", help="IP alvo para análise.")
    args = parser.parse_args()

    ui.print_banner()
    print(ui.color("Módulo de Análise de IP (Unificado)", ui.CYAN))
    
    target = args.target
    if not target:
        try:
            target = input(ui.color("Alvo (IP): ", ui.GREEN)).strip()
        except KeyboardInterrupt:
            print(ui.color("\nOperação cancelada.", ui.YELLOW)); return
            
    if not target:
        print(ui.color("Nenhum alvo fornecido.", ui.RED)); return

    result = analyze(target)
    if result:
        _print_results(result)
    else:
        print(ui.color(f"\nA análise falhou para o alvo {target}.", ui.RED))

if __name__ == "__main__":
    main()
