# batman-do-cerrado-pro/batman_do_cerrado/modules/ip_analyzer.py

"""
Módulo IP Analyzer (Refatorado e Robusto) - Batman do Cerrado

Este módulo centraliza a inteligência para análise de IPs, unificando GeoIP, WHOIS,
DNS Reverso e Reputação. Agora mais robusto, resiliente a falhas, com saídas padronizadas
e feedbacks claros para o usuário.
"""

import argparse
import sys
from typing import Optional, Dict, Any

import requests

# Importação opcional do ipwhois
try:
    from ipwhois import IPWhois  # type: ignore
    from ipwhois.exceptions import IPDefinedError  # type: ignore
except Exception:
    IPWhois = None
    class IPDefinedError(Exception): pass

from batman_do_cerrado.core import ui, utils
from batman_do_cerrado.core.config import config
from batman_do_cerrado.core.models import IPAddressInfo
from . import whois

# --- Funções Utilitárias ---

def _safe_json(resp: requests.Response) -> Dict:
    """Retorna o JSON da resposta ou um dicionário vazio."""
    try:
        return resp.json()
    except Exception:
        return {}

def _query_geoip(ip: str, session: requests.Session) -> Dict[str, Any]:
    """
    Consulta GeoIP em múltiplos provedores com fallback.
    Retorna dados padronizados: {'source': ..., 'data': {...}}
    """
    # Provedor 1: IPWhois
    if IPWhois is not None:
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
        resp = session.get(
            f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,regionName,city,lat,lon,timezone,isp,org,as,query"
        )
        data = _safe_json(resp)
        if resp.ok and data.get("status") == "success":
            return {"source": "ip-api.com", "data": data}
    except requests.RequestException:
        pass

    # Provedor 3: ipinfo.io
    ipinfo_token = config.get_secret("ipinfo_token")
    if ipinfo_token:
        try:
            resp = session.get(
                f"https://ipinfo.io/{ip}",
                headers={"Authorization": f"Bearer {ipinfo_token}"}
            )
            if resp.ok:
                return {"source": "ipinfo.io", "data": _safe_json(resp)}
        except requests.RequestException:
            pass

    return {"source": "none", "data": {"error": "Nenhum provedor disponível"}}

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
        code = getattr(e.response, 'status_code', None)
        return {"error": f"Falha na API AbuseIPDB. Código: {code or str(e)}"}

def _normalize_and_merge(info: IPAddressInfo, geo_result: Dict, whois_result: IPAddressInfo):
    """Normaliza e funde os dados de GeoIP e WHOIS no modelo de dados."""
    # WHOIS
    info.ptr = whois_result.ptr
    info.isp = info.isp or whois_result.isp
    info.asn_number = info.asn_number or whois_result.asn_number
    info.asn_name = info.asn_name or whois_result.asn_name
    info.raw_data["whois"] = whois_result.raw_data.get("whois", {})

    # GeoIP
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
    Saídas robustas e tratadas.
    """
    print(ui.color("\nExecutando análise de Rede (WHOIS & DNS)...", ui.GRAY))
    whois_result = whois.analyze(target)
    if not isinstance(whois_result, IPAddressInfo):
        print(ui.color("Análise de WHOIS falhou ou o alvo não é um IP.", ui.RED))
        return None

    final_info = whois_result

    # GeoIP
    print(ui.color("Executando análise de Geolocalização (GeoIP)...", ui.GRAY))
    session = requests.Session()
    session.headers.update({"User-Agent": "Batman-do-Cerrado-PRO/2.0"})
    geo_result = _query_geoip(target, session)
    _normalize_and_merge(final_info, geo_result, whois_result)

    # Reputação
    print(ui.color("Executando análise de Reputação (AbuseIPDB)...", ui.GRAY))
    reputation_data = _query_reputation(target, session)
    final_info.raw_data["reputation"] = reputation_data

    return final_info

def _format_dict(d: Dict, level=1, prefix="  ") -> str:
    """Formata dicionários aninhados para saída legível."""
    lines = []
    for k, v in d.items():
        if isinstance(v, dict):
            lines.append(f"{prefix*level}{k}:")
            lines.append(_format_dict(v, level+1, prefix))
        else:
            lines.append(f"{prefix*level}{k}: {v}")
    return "\n".join(lines)

def _print_results(info: IPAddressInfo):
    """Imprime o dossiê completo do IP de forma organizada e tratada."""
    ui.print_banner()
    print(ui.color(f"--- Dossiê do IP: {info.ip} ---", ui.BOLD + ui.CYAN))

    # Rede e DNS
    print(ui.color("\n[ DADOS DE REDE E DNS ]", ui.BLUE))
    print(f"  {'ISP/Organização:':<20} {info.isp or 'N/A'}")
    asn = f"AS{info.asn_number}" if info.asn_number else "N/A"
    print(f"  {'ASN:':<20} {asn} ({info.asn_name or 'N/A'})")
    print(f"  {'DNS Reverso (PTR):':<20} {info.ptr or 'Nenhum'}")

    # GeoIP
    print(ui.color("\n[ GEOLOCALIZAÇÃO ]", ui.BLUE))
    print(f"  {'Cidade:':<20} {info.city or 'N/A'}")
    print(f"  {'Região/Estado:':<20} {info.region or 'N/A'}")
    print(f"  {'País:':<20} {info.country_code or 'N/A'}")
    print(f"  {'Fonte dos Dados:':<20} {info.source_api or 'Nenhuma'}")

    # Reputação
    print(ui.color("\n[ REPUTAÇÃO (ABUSEIPDB) ]", ui.BLUE))
    rep = info.raw_data.get("reputation", {})
    if "error" in rep:
        print(ui.color(f"  Erro: {rep['error']}", ui.YELLOW))
    elif not rep:
        print(ui.color("  Nenhum dado de reputação encontrado.", ui.YELLOW))
    else:
        score = rep.get('abuseConfidenceScore', 0)
        score_color = ui.GREEN if score < 25 else (ui.YELLOW if score < 75 else ui.RED)
        print(f"  {'Pontuação de Abuso:':<20} {ui.color(str(score), ui.BOLD + score_color)} / 100")
        print(f"  {'Total de Denúncias:':<20} {rep.get('totalReports', 0)}")
        print(f"  {'É IP Público:':<20} {'Sim' if rep.get('isPublic', True) else 'Não'}")
        print(f"  {'Domínio:':<20} {rep.get('domain', 'N/A')}")
        if rep.get('usageType'):
            print(f"  {'Uso:':<20} {rep['usageType']}")

    # Extra (raw data)
    print(ui.color("\n[ DADOS BRUTOS ]", ui.BLUE))
    for section in ('whois', 'geoip'):
        if info.raw_data.get(section):
            print(f"\n{section.upper()}:")
            print(_format_dict(info.raw_data[section], level=2, prefix="    "))

    print()

def main():
    """Execução interativa com tratamento de erros e saídas padronizadas."""
    parser = argparse.ArgumentParser(description="Módulo IP Analyzer - Batman do Cerrado")
    parser.add_argument("target", nargs="?", help="IP alvo para análise.")
    args = parser.parse_args()

    ui.print_banner()
    print(ui.color("Módulo de Análise de IP (Robusto e Unificado)", ui.CYAN))

    target = args.target
    if not target:
        try:
            target = input(ui.color("Alvo (IP): ", ui.GREEN)).strip()
        except KeyboardInterrupt:
            print(ui.color("\nOperação cancelada.", ui.YELLOW)); return
    
    if not target:
        print(ui.color("Nenhum alvo fornecido.", ui.RED)); return

    try:
        result = analyze(target)
        if result:
            _print_results(result)
        else:
            print(ui.color(f"\nA análise falhou para o alvo {target}.", ui.RED))
    except Exception as e:
        print(ui.color(f"Erro inesperado durante análise: {e}", ui.RED))
        if config.get("debug", False):
            import traceback; traceback.print_exc()

if __name__ == "__main__":
    main()
