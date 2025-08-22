# batman-do-cerrado-pro/batman_do_cerrado/modules/domain_analyzer.py

"""
Módulo Domain Analyzer (Refatorado e Robusto) - Batman do Cerrado

Realiza uma análise OSINT profunda em um domínio, unificando consultas
DNS, análise de e-mail, fingerprinting HTTP/TLS e busca por subdomínios.
Agora com robustez, tratamento de exceções e saídas formatadas.
"""

import argparse
import json
import socket
import ssl
import sys
import concurrent.futures
from html.parser import HTMLParser
from typing import List, Optional, Dict, Any, Tuple

import requests

from batman_do_cerrado.core import ui, utils
from batman_do_cerrado.core.config import config
from batman_do_cerrado.core.models import DomainInfo

# --- Parsers e Helpers Específicos do Módulo ---

class _TitleParser(HTMLParser):
    """Um parser HTML minimalista para extrair o título de uma página."""
    def __init__(self):
        super().__init__()
        self.in_title = False
        self.title = ""
    def handle_starttag(self, tag, attrs):
        if tag.lower() == "title": self.in_title = True
    def handle_endtag(self, tag):
        if tag.lower() == "title": self.in_title = False
    def handle_data(self, data):
        if self.in_title: self.title += data

def _parse_spf(txt_records: List[str]) -> Optional[Dict[str, Any]]:
    """Encontra e parseia o registro SPF a partir de uma lista de registros TXT."""
    for record in txt_records:
        if record.lower().startswith('"v=spf1'):
            # Limpa as aspas que o dig às vezes retorna
            clean_record = record.strip('"')
            mechanisms = [part for part in clean_record.split() if not part.startswith("exp=")]
            return {"raw": clean_record, "mechanisms": mechanisms}
    return None

def _parse_dmarc(dmarc_records: List[str]) -> Optional[Dict[str, Any]]:
    """Parseia o registro DMARC."""
    if not dmarc_records: return None
    record = dmarc_records[0].strip('"') # Pega o primeiro e limpa
    
    parsed = {"raw": record}
    for part in record.split(';'):
        if '=' in part:
            key, value = part.split('=', 1)
            parsed[key.strip()] = value.strip()
    return parsed

# --- Funções de Coleta de Dados ---

def _query_dns(domain: str) -> Dict[str, List[str]]:
    """Coleta os principais registros DNS para um domínio, com tratamento de erros."""
    print(ui.color("  -> Coletando registros DNS...", ui.GRAY))
    records = {}
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CAA", "DS"]
    for rec_type in record_types:
        try:
            result = utils.run_command(["dig", "+short", domain, rec_type])
            if result.success:
                records[rec_type] = result.stdout.splitlines()
        except Exception as e:
            print(ui.color(f"    [!] Falha ao consultar tipo {rec_type}: {e}", ui.YELLOW))
    
    # Consulta DMARC separadamente
    try:
        dmarc_result = utils.run_command(["dig", "+short", f"_dmarc.{domain}", "TXT"])
        if dmarc_result.success:
            records["_DMARC"] = dmarc_result.stdout.splitlines()
    except Exception as e:
        print(ui.color(f"    [!] Falha ao consultar DMARC: {e}", ui.YELLOW))
        
    return records

def _test_axfr(domain: str, ns_records: List[str]) -> bool:
    """Testa transferência de zona (AXFR) em todos os servidores NS."""
    print(ui.color("  -> Testando Transferência de Zona (AXFR)...", ui.GRAY))
    if not ns_records: return False
    
    for ns in ns_records:
        try:
            result = utils.run_command(["dig", f"@{ns.rstrip('.')}", domain, "AXFR"])
            if result.success and "Transfer failed." not in result.stdout and "XFR size" in result.stdout:
                # Sucesso! A transferência de zona está aberta em pelo menos um NS.
                return True
        except Exception as e:
            print(ui.color(f"    [!] Falha ao testar AXFR em {ns}: {e}", ui.YELLOW))
    return False

def _fetch_http_headers(url: str, session: requests.Session) -> Dict[str, Any]:
    """Busca o cabeçalho de uma URL e informações básicas."""
    try:
        resp = session.get(url, timeout=8, allow_redirects=False)
        title_parser = _TitleParser()
        # Parseia apenas um pedaço do corpo para performance
        title_parser.feed(resp.text[:4096])
        
        return {
            "status_code": resp.status_code,
            "headers": dict(resp.headers),
            "title": title_parser.title.strip(),
            "redirect_location": resp.headers.get("Location")
        }
    except requests.RequestException as e:
        return {"error": f"Falha na conexão: {e}"}

def _get_cert_info(domain: str) -> Optional[Dict[str, Any]]:
    """Obtém informações do certificado TLS de um domínio."""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                
                subject = dict(x[0] for x in cert.get("subject", []))
                issuer = dict(x[0] for x in cert.get("issuer", []))
                sans = [item[1] for item in cert.get("subjectAltName", [])]
                
                return {
                    "subject_cn": subject.get("commonName"),
                    "issuer_cn": issuer.get("commonName"),
                    "sans": sans,
                    "not_before": cert.get("notBefore"),
                    "not_after": cert.get("notAfter"),
                }
    except (socket.gaierror, ssl.SSLError, socket.timeout) as e:
        print(ui.color(f"    [!] Falha ao obter certificado TLS: {e}", ui.YELLOW))
        return None # Erros esperados se o host não resolver ou não tiver TLS
    except Exception as e:
        print(ui.color(f"    [!] Erro inesperado ao buscar TLS: {e}", ui.RED))
        return None

# --- Orquestrador Principal ---

def analyze(target: str) -> Optional[DomainInfo]:
    """
    Orquestra a análise completa de um domínio. Saídas tratadas e robustas.
    """
    print(ui.color(f"\nIniciando análise completa para o domínio: {target}", ui.CYAN))

    # --- DNS e Análise de E-mail ---
    dns_data = _query_dns(target)
    
    info = DomainInfo(
        domain_name=target,
        a_records=dns_data.get("A", []),
        aaaa_records=dns_data.get("AAAA", []),
        mx_records=[{"raw": r} for r in dns_data.get("MX", [])], # Simplificado
        ns_records=dns_data.get("NS", []),
        txt_records=dns_data.get("TXT", []),
        spf=_parse_spf(dns_data.get("TXT", [])) or {},
        dmarc=_parse_dmarc(dns_data.get("_DMARC", [])) or {},
        is_axfr_open=_test_axfr(target, dns_data.get("NS", []))
    )

    # --- Análise HTTP/TLS ---
    session = requests.Session()
    session.headers.update({"User-Agent": "Batman-do-Cerrado-PRO/2.0"})
    
    print(ui.color("  -> Realizando fingerprint HTTP/HTTPS...", ui.GRAY))
    info.raw_data["http"] = _fetch_http_headers(f"http://{target}", session)
    info.raw_data["https.pre-redirect"] = _fetch_http_headers(f"https://{target}", session)

    print(ui.color("  -> Analisando certificado TLS...", ui.GRAY))
    info.raw_data["tls"] = _get_cert_info(target)

    return info

def _format_dict(d: Dict, level=1, prefix="  ") -> str:
    """Formata dicionários aninhados para saída legível."""
    lines = []
    for k, v in d.items():
        if isinstance(v, dict):
            lines.append(f"{prefix*level}{k}:")
            lines.append(_format_dict(v, level+1, prefix))
        elif isinstance(v, list):
            lines.append(f"{prefix*level}{k}: {', '.join(str(x) for x in v)}")
        else:
            lines.append(f"{prefix*level}{k}: {v}")
    return "\n".join(lines)

def _print_results(info: DomainInfo):
    """Imprime o dossiê completo do Domínio de forma organizada e tratada."""
    ui.print_banner()
    print(ui.color(f"--- Dossiê do Domínio: {info.domain_name} ---", ui.BOLD + ui.CYAN))

    # Seção DNS
    print(ui.color("\n[ REGISTROS DNS PRINCIPAIS ]", ui.BLUE))
    print(f"  {'A (IPv4):':<15} {', '.join(info.a_records) or 'Nenhum'}")
    print(f"  {'AAAA (IPv6):':<15} {', '.join(info.aaaa_records) or 'Nenhum'}")
    print(f"  {'NS (Serv. Nomes):':<15} {', '.join(info.ns_records) or 'Nenhum'}")

    # Seção E-mail
    print(ui.color("\n[ ANÁLISE DE E-MAIL ]", ui.BLUE))
    print(f"  {'MX (Mail Exchanger):':<15} {', '.join(r['raw'] for r in info.mx_records) or 'Nenhum'}")
    print(f"  {'SPF:':<15} {info.spf.get('raw', 'Não encontrado')}")
    print(f"  {'DMARC:':<15} {info.dmarc.get('raw', 'Não encontrado')}")

    # Seção Segurança DNS
    print(ui.color("\n[ SEGURANÇA DNS ]", ui.BLUE))
    axfr_status = ui.color("ABERTA (VULNERÁVEL!)", ui.RED + ui.BOLD) if info.is_axfr_open else ui.color("Fechada", ui.GREEN)
    print(f"  {'Transferência de Zona (AXFR):':<35} {axfr_status}")

    # Seção Web
    print(ui.color("\n[ FINGERPRINT WEB (HTTP/HTTPS) ]", ui.BLUE))
    http = info.raw_data.get("http", {})
    https = info.raw_data.get("https.pre-redirect", {})
    tls = info.raw_data.get("tls", {})
    if "error" in http:
        print(f"  {'HTTP (porta 80):':<25} Erro: {http['error']}")
    else:
        print(f"  {'HTTP (porta 80):':<25} Status {http.get('status_code', '-')}, Redireciona para -> {http.get('redirect_location', 'N/A')}")
    if "error" in https:
        print(f"  {'HTTPS (porta 443):':<25} Erro: {https['error']}")
    else:
        print(f"  {'HTTPS (porta 443):':<25} Status {https.get('status_code', '-')}, Título: '{https.get('title', 'N/A')}'")
    if tls:
        print(f"  {'Certificado TLS Issuer:':<25} {tls.get('issuer_cn', 'N/A')}")
        print(f"  {'Certificado TLS Expira em:':<25} {tls.get('not_after', 'N/A')}")
    else:
        print(f"  {'Certificado TLS:':<25} Não foi possível obter informações.")

    # Extra (raw data)
    print(ui.color("\n[ RAW DATA (DEBUG) ]", ui.GRAY))
    print(_format_dict(info.raw_data, level=2, prefix="    "))
    print()

def main():
    """Ponto de entrada para execução interativa do módulo."""
    if not utils.find_binary("dig"):
        print(ui.color("ERRO: O binário 'dig' é essencial para este módulo.", ui.RED))
        print("Instale-o com 'sudo apt install dnsutils' ou equivalente.")
        sys.exit(1)
        
    parser = argparse.ArgumentParser(description="Módulo Domain Analyzer - Batman do Cerrado")
    parser.add_argument("target", nargs="?", help="Domínio alvo para análise.")
    args = parser.parse_args()

    ui.print_banner()
    print(ui.color("Módulo de Análise de Domínios (Robusto)", ui.CYAN))
    
    target = args.target
    if not target:
        try:
            target = input(ui.color("Alvo (domínio): ", ui.GREEN)).strip()
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
