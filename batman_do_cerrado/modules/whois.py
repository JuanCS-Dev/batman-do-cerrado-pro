# batman-do-cerrado-pro/batman_do_cerrado/modules/whois.py

"""
Módulo WHOIS (Refatorado) - Batman do Cerrado

Utiliza a biblioteca core para realizar consultas WHOIS, RDAP e DNS,
retornando objetos de dados padronizados para integração com outros módulos.
"""

import re
import json
import socket
from typing import Dict, List, Optional, Union, Any

from batman_do_cerrado.core import ui, utils
from batman_do_cerrado.core.models import DomainInfo, IPAddressInfo
from batman_do_cerrado.core.config import config

# --- Constantes e Expressões Regulares ---
IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}$")
WHOIS_KV_RE = re.compile(r"^\s*([^:]+?)\s*:\s*(.+?)\s*$")

# --- Funções de Parsing (Lógica Interna) ---

def _parse_whois_kv(text: str) -> Dict[str, List[str]]:
    """Transforma uma saída de texto WHOIS em um dicionário de chave-valor.

    Ignora linhas de comentário (iniciadas com '%' ou '#') e processa
    linhas no formato "Chave: Valor". Chaves são normalizadas para
    minúsculas e com underscores. Múltiplos valores para a mesma
    chave são agrupados em uma lista.

    Args:
        text: A string de texto bruto da saída do comando WHOIS.

    Returns:
        Um dicionário onde as chaves são os campos normalizados e os
        valores são listas de strings contendo os dados.
    """
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
    """Extrai os campos mais comuns de uma resposta WHOIS de domínio.

    Utiliza o parser genérico `_parse_whois_kv` e então busca por
    variações comuns de nomes de campo (ex: 'creation_date', 'created')
    para normalizar a saída.

    Args:
        text: A string de texto bruto da saída do WHOIS de um domínio.

    Returns:
        Um dicionário com chaves normalizadas para os dados extraídos.
    """
    kv = _parse_whois_kv(text)
    def get_first(keys: List[str]) -> Optional[str]:
        for key in keys:
            if key in kv:
                return kv[key][0]
        return None

    return {
        "registrar": get_first(["registrar", "sponsoring_registrar", "registrar_name"]),
        "creation_date": get_first(["creation_date", "registered_on", "created"]),
        "expiration_date": get_first(["registry_expiry_date", "expiration_date", "expires_on"]),
        "nameservers": kv.get("name_server", []) + kv.get("nserver", []),
        "raw": text,
    }

def _parse_ip_whois(text: str) -> Dict[str, Any]:
    """Extrai os campos mais comuns de uma resposta WHOIS de IP.

    Utiliza o parser genérico `_parse_whois_kv` e então busca por
    variações comuns de nomes de campo (ex: 'orgname', 'owner') e
    extrai o número do ASN de forma robusta.

    Args:
        text: A string de texto bruto da saída do WHOIS de um IP.

    Returns:
        Um dicionário com chaves normalizadas para os dados extraídos.
    """
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

# --- Funções de Análise ---

def _detect_target_type(target: str) -> Optional[str]:
    """Detecta se o alvo é um IPv4 ou um domínio usando regex.

    Args:
        target: A string do alvo a ser analisada.

    Returns:
        'ip' se for um IPv4 válido.
        'domain' se for um domínio válido.
        None caso contrário.
    """
    if IPV4_RE.match(target):
        return "ip"
    if DOMAIN_RE.match(target.encode("idna").decode("ascii")):
        return "domain"
    return None

def _query_dns(domain: str) -> Dict[str, List[str]]:
    """Executa consultas DNS básicas usando 'dig' através do core.utils."""
    records = {}
    if not utils.find_binary("dig"):
        print(ui.color("AVISO: Binário 'dig' não encontrado para consulta DNS.", ui.YELLOW))
        return records

    for rec_type in ["A", "AAAA", "MX", "NS", "TXT"]:
        result = utils.run_command(["dig", "+short", domain, rec_type])
        if result.success:
            records[rec_type] = result.stdout.splitlines()
    return records

def analyze(target: str) -> Optional[Union[DomainInfo, IPAddressInfo]]:
    """Orquestra a análise completa de um alvo (domínio ou IP).

    Esta é a função principal do módulo. Ela detecta o tipo de alvo,
    executa as ferramentas externas necessárias (como 'whois' e 'dig')
    de forma segura, chama os parsers auxiliares para processar a saída,
    e retorna um objeto de dados padronizado (DomainInfo ou IPAddressInfo).

    Args:
        target: O alvo (domínio ou IP) a ser analisado.

    Returns:
        Um objeto DomainInfo ou IPAddressInfo preenchido com os dados,
        ou None se a análise falhar ou o alvo for inválido.
    """
    target_type = _detect_target_type(target)
    if not target_type:
        print(ui.color(f"Alvo '{target}' não parece ser um domínio ou IPv4 válido.", ui.RED))
        return None

    if not utils.find_binary("whois"):
        print(ui.color("ERRO: Binário 'whois' não encontrado. Instale com 'sudo apt install whois'", ui.RED))
        return None

    print(f"Iniciando análise de {target_type}: {ui.color(target, ui.CYAN)}")
    whois_result = utils.run_command(["whois", target])

    if not whois_result.success and "No match for" in whois_result.stdout:
        print(ui.color(f"Nenhum resultado WHOIS encontrado para '{target}'.", ui.YELLOW))
        return None

    if target_type == "domain":
        whois_data = _parse_domain_whois(whois_result.stdout)
        dns_data = _query_dns(target)

        info = DomainInfo(
            domain_name=target,
            a_records=dns_data.get("A", []),
            aaaa_records=dns_data.get("AAAA", []),
            mx_records=[{"raw": mx} for mx in dns_data.get("MX", [])],
            ns_records=dns_data.get("NS", []),
            txt_records=dns_data.get("TXT", []),
            registrar=whois_data.get("registrar"),
            creation_date=whois_data.get("creation_date"),
            expiration_date=whois_data.get("expiration_date"),
            raw_data={"whois": whois_data["raw"]}
        )
        return info

    elif target_type == "ip":
        whois_data = _parse_ip_whois(whois_result.stdout)
        
        ptr_record = None
        try:
            ptr_record = socket.gethostbyaddr(target)[0]
        except socket.herror:
            pass

        info = IPAddressInfo(
            ip=target,
            version=4,
            ptr=ptr_record,
            isp=whois_data.get("isp"),
            asn_number=whois_data.get("asn_number"),
            asn_name=whois_data.get("asn_name"),
            raw_data={"whois": whois_data["raw"]}
        )
        return info
    
    return None

def main():
    """Ponto de entrada para execução interativa do módulo."""
    ui.print_banner()
    print(ui.color("Módulo de Análise WHOIS/DNS (Refatorado)", ui.CYAN))
    
    try:
        target = input(ui.color("Alvo (domínio ou IP): ", ui.GREEN)).strip()
        if not target:
            print(ui.color("Nenhum alvo fornecido.", ui.YELLOW))
            return

        result = analyze(target)
        if result:
            from pprint import pprint
            pprint(result)
            
    except KeyboardInterrupt:
        print(ui.color("\nOperação cancelada pelo usuário.", ui.YELLOW))
        
if __name__ == "__main__":
    main()
