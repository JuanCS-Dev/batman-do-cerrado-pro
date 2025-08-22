"""
Módulo WHOIS (Robusto, Moderno e Enriquecido) - Batman do Cerrado

Consulta WHOIS, RDAP e DNS usando múltiplas fontes e heurísticas modernas,
retornando objetos padronizados e enriquecidos. Saída tratada, integração
com core, detecção de domínio internacionalizado, fallback para RDAP, e
suporte a detecção de domínios expiring/expired.
"""

import re
import json
import socket
from typing import Dict, List, Optional, Union, Any

from batman_do_cerrado.core import ui, utils
from batman_do_cerrado.core.models import DomainInfo, IPAddressInfo
from batman_do_cerrado.core.config import config

try:
    import requests
except ImportError:
    requests = None

# --- Regex e Constantes Modernas ---
IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}$")
WHOIS_KV_RE = re.compile(r"^\s*([^:]+?)\s*:\s*(.+?)\s*$")

def _parse_whois_kv(text: str) -> Dict[str, List[str]]:
    """Transforma saída WHOIS em dicionário chave-valor (multi-valor)."""
    data: Dict[str, List[str]] = {}
    for line in text.splitlines():
        if not line or line.startswith(("%", "#")):
            continue
        match = WHOIS_KV_RE.match(line)
        if match:
            key = match.group(1).strip().lower().replace(" ", "_")
            value = match.group(2).strip()
            data.setdefault(key, []).append(value)
    return data

def _parse_domain_whois(text: str) -> Dict[str, Any]:
    """Extrai campos comuns de resposta WHOIS de domínio."""
    kv = _parse_whois_kv(text)
    def get_first(keys: List[str]) -> Optional[str]:
        for key in keys:
            if key in kv:
                return kv[key][0]
        return None

    # Detecta status de expiração
    status = (kv.get("domain_status", []) + kv.get("status", []))
    expired = any("redemption" in s.lower() or "expired" in s.lower() for s in status)
    expiring = any("pendingdelete" in s.lower() or "pending delete" in s.lower() for s in status)

    return {
        "registrar": get_first(["registrar", "sponsoring_registrar", "registrar_name"]),
        "creation_date": get_first(["creation_date", "registered_on", "created"]),
        "expiration_date": get_first(["registry_expiry_date", "expiration_date", "expires_on"]),
        "status": status,
        "nameservers": kv.get("name_server", []) + kv.get("nserver", []),
        "raw": text,
        "expired": expired,
        "expiring": expiring,
    }

def _parse_ip_whois(text: str) -> Dict[str, Any]:
    """Extrai campos comuns de resposta WHOIS de IP."""
    kv = _parse_whois_kv(text)
    def get_first(keys: List[str]) -> Optional[str]:
        for key in keys:
            if key in kv:
                return kv[key][0]
        return None

    asn_str = get_first(["origin", "originas", "origin-as", "originating_as"])
    asn_num = None
    if asn_str:
        asn_match = re.search(r'\d+', asn_str)
        if asn_match:
            asn_num = int(asn_match.group(0))

    return {
        "isp": get_first(["orgname", "org-name", "organization", "owner", "descr"]),
        "asn_number": asn_num,
        "asn_name": get_first(["asn-name", "as-name"]),
        "raw": text,
    }

def _detect_target_type(target: str) -> Optional[str]:
    """Detecta se o alvo é IPv4 ou domínio (inclui IDN)."""
    if IPV4_RE.match(target):
        return "ip"
    try:
        ascii_dom = target.encode("idna").decode("ascii")
        if DOMAIN_RE.match(ascii_dom):
            return "domain"
    except Exception:
        pass
    return None

def _query_dns(domain: str) -> Dict[str, List[str]]:
    """Executa consultas DNS básicas usando 'dig'."""
    records = {}
    if not utils.find_binary("dig"):
        print(ui.color("AVISO: Binário 'dig' não encontrado para consulta DNS.", ui.YELLOW))
        return records
    for rec_type in ["A", "AAAA", "MX", "NS", "TXT"]:
        result = utils.run_command(["dig", "+short", domain, rec_type])
        if result.success:
            records[rec_type] = result.stdout.splitlines()
    return records

def _rdap_lookup(target: str) -> Optional[dict]:
    """
    Consulta RDAP para IP ou domínio — alternativa moderna ao WHOIS.
    Requer requests.
    """
    if not requests:
        return None
    rdap_url = None
    if IPV4_RE.match(target):
        rdap_url = f"https://rdap.arin.net/registry/ip/{target}"
    else:
        ascii_dom = target.encode("idna").decode("ascii")
        # Usa IANA bootstrap para domínios
        tld = ascii_dom.split(".")[-1]
        try:
            bootstrap = requests.get(f"https://data.iana.org/rdap/dns.json", timeout=5).json()
            for entry in bootstrap["services"]:
                if tld in entry[0]:
                    rdap_url = entry[1][0].rstrip("/") + "/" + ascii_dom
                    break
        except Exception:
            rdap_url = None
    if not rdap_url:
        return None
    try:
        resp = requests.get(rdap_url, timeout=7)
        if resp.status_code == 200:
            return resp.json()
    except Exception:
        return None
    return None

def analyze(target: str) -> Optional[Union[DomainInfo, IPAddressInfo]]:
    """
    Orquestra análise WHOIS, RDAP e DNS.
    Enriquecimento de dados, fallback, detecção de expiração.
    """
    target_type = _detect_target_type(target)
    if not target_type:
        print(ui.color(f"Alvo '{target}' não parece ser um domínio ou IPv4 válido.", ui.RED))
        return None

    if not utils.find_binary("whois"):
        print(ui.color("ERRO: Binário 'whois' não encontrado. Instale com 'sudo apt install whois'", ui.RED))
        return None

    print(ui.color(f"Iniciando análise de {target_type}: {target}", ui.CYAN))
    whois_result = utils.run_command(["whois", target])

    # Tenta RDAP em caso de erro ou como enriquecimento
    rdap_data = None
    if (not whois_result.success or not whois_result.stdout) and requests:
        print(ui.color("Tentando consulta RDAP como fallback...", ui.YELLOW))
        rdap_data = _rdap_lookup(target)

    # --- Domínio ---
    if target_type == "domain":
        whois_data = _parse_domain_whois(whois_result.stdout) if whois_result.stdout else {}
        dns_data = _query_dns(target)
        expired = whois_data.get("expired", False)
        expiring = whois_data.get("expiring", False)
        registrar = whois_data.get("registrar")
        creation = whois_data.get("creation_date")
        expiration = whois_data.get("expiration_date")
        status = whois_data.get("status", [])
        # RDAP enrichment
        if rdap_data:
            registrar = rdap_data.get("registrar", registrar)
            expiration = rdap_data.get("events", [{}])[-1].get("date", expiration) if "events" in rdap_data else expiration

        info = DomainInfo(
            domain_name=target,
            a_records=dns_data.get("A", []),
            aaaa_records=dns_data.get("AAAA", []),
            mx_records=[{"raw": mx} for mx in dns_data.get("MX", [])],
            ns_records=dns_data.get("NS", []),
            txt_records=dns_data.get("TXT", []),
            registrar=registrar,
            creation_date=creation,
            expiration_date=expiration,
            raw_data={
                "whois": whois_data.get("raw"),
                "rdap": rdap_data,
                "status": status,
                "expired": expired,
                "expiring": expiring,
            }
        )
        return info

    # --- IP ---
    elif target_type == "ip":
        whois_data = _parse_ip_whois(whois_result.stdout) if whois_result.stdout else {}
        ptr_record = None
        try:
            ptr_record = socket.gethostbyaddr(target)[0]
        except socket.herror:
            ptr_record = None

        isp = whois_data.get("isp")
        asn_number = whois_data.get("asn_number")
        asn_name = whois_data.get("asn_name")
        if rdap_data:
            # RDAP enrichment
            asn_number = rdap_data.get("asn", asn_number)
            asn_name = rdap_data.get("name", asn_name)
            isp = rdap_data.get("org", isp)

        info = IPAddressInfo(
            ip=target,
            version=4,
            ptr=ptr_record,
            isp=isp,
            asn_number=asn_number,
            asn_name=asn_name,
            raw_data={"whois": whois_data.get("raw"), "rdap": rdap_data}
        )
        return info
    
    return None

def _print_result(result: Union[DomainInfo, IPAddressInfo]):
    """Imprime o resultado da análise de forma bem formatada e enriquecida."""
    if isinstance(result, DomainInfo):
        print(ui.color(f"\n--- Análise do Domínio: {result.domain_name} ---", ui.BOLD + ui.CYAN))
        if result.registrar: print(f"{ui.BOLD}Registrar:{ui.RESET} {result.registrar}")
        if result.creation_date: print(f"{ui.BOLD}Criação:{ui.RESET} {result.creation_date}")
        if result.expiration_date: print(f"{ui.BOLD}Expiração:{ui.RESET} {result.expiration_date}")
        status = result.raw_data.get("status", [])
        if status:
            status_str = ', '.join(status)
            print(f"{ui.BOLD}Status:{ui.RESET} {status_str}")
        if result.raw_data.get("expired"):
            print(ui.color("  [!] DOMÍNIO EXPIRADO OU EM REDEMPTION PERIOD", ui.RED + ui.BOLD))
        if result.raw_data.get("expiring"):
            print(ui.color("  [!] DOMÍNIO EM PROCESSO DE EXCLUSÃO (pending delete)", ui.YELLOW + ui.BOLD))
        print(ui.color("\n--- DNS ---", ui.BOLD))
        if result.a_records: print(f"  A:    {', '.join(result.a_records)}")
        if result.aaaa_records: print(f"  AAAA: {', '.join(result.aaaa_records)}")
        if result.ns_records: print(f"  NS:   {', '.join(result.ns_records)}")
        if result.mx_records: print(f"  MX:   {', '.join(mx['raw'] for mx in result.mx_records)}")
        if result.txt_records: print(f"  TXT:  {', '.join(result.txt_records)}")

    elif isinstance(result, IPAddressInfo):
        print(ui.color(f"\n--- Análise do IP: {result.ip} ---", ui.BOLD + ui.CYAN))
        if result.isp: print(f"{ui.BOLD}ISP/Organização:{ui.RESET} {result.isp}")
        if result.asn_number: print(f"{ui.BOLD}ASN:{ui.RESET} AS{result.asn_number} ({result.asn_name or 'N/A'})")
        if result.ptr: print(f"{ui.BOLD}PTR (DNS Reverso):{ui.RESET} {result.ptr}")
    print()

def main():
    """Ponto de entrada para execução interativa do módulo."""
    ui.print_banner()
    print(ui.color("Módulo de Análise WHOIS/DNS (Robusto e Moderno)", ui.CYAN))
    try:
        target = input(ui.color("Alvo (domínio ou IP): ", ui.GREEN)).strip()
        if not target:
            print(ui.color("Nenhum alvo fornecido.", ui.YELLOW))
            return
        result = analyze(target)
        if result:
            _print_result(result)
        else:
            print(ui.color("Não foi possível obter informações para o alvo.", ui.RED))
    except KeyboardInterrupt:
        print(ui.color("\nOperação cancelada pelo usuário.", ui.YELLOW))

if __name__ == "__main__":
    main()
