# batman_do_cerrado/cli.py
# -*- coding: utf-8 -*-

"""
CLI principal — Batman do Cerrado
UI/UX aprimorado; resiliente a diferenças no core.ui; sem dependências novas.
"""

from __future__ import annotations
import argparse
import os
import sys
import time
from typing import Any, Dict, List, Optional, Sequence

# Núcleo do projeto
from .core import ui
from .core.dispatcher import run_module
from .core.models import IPAddressInfo, DomainInfo, Finding
from .core.config import config

# Importa os módulos principais
from .modules import (
    ip_analyzer,
    domain_analyzer,
    nmap_scanner,
    whois_helpers,
    selfcheck,
    fs_monitor,
    net_monitor,
    secrets_scanner, # <--- Importa o novo módulo
)


# ======================================================
# Emojis, Cores, e Helpers com Design Moderno
# ======================================================
EMOJI: Dict[str, str] = {
    "bat": "🦇", "ok": "✅", "warn": "⚠️", "err": "❌", "info": "ℹ️",
    "scan": "📡", "net": "🌐", "file": "📄", "shield": "🛡️", "target": "🎯",
    "mail": "✉️", "gear": "⚙️", "spark": "✨", "search": "🔎", "arrow": "➜",
    "star": "★", "check": "✔", "x": "✗", "clock": "⏰", "rocket": "🚀", "dot": "•",
}

def _emoji(key: str) -> str:
    return EMOJI.get(key, EMOJI["spark"])

def _get(attr: str, default: str = "") -> str:
    return getattr(ui, attr, default)

def c(text: str, *styles: str) -> str:
    if not styles: return text
    combo = "".join(s for s in styles if isinstance(s, str))
    try:
        return ui.color(text, combo)
    except Exception:
        return text

def _term_width(default: int = 80) -> int:
    try:
        import shutil
        return max(40, shutil.get_terminal_size().columns)
    except Exception:
        return default

def _rule(char: str = "─", color: Optional[str] = None) -> str:
    col = color or _get("GRAY", "")
    return c(char * _term_width(), col)

def _kv(label: str, value: Any, width: int = 24, vcolor: Optional[str] = None) -> str:
    txt = f"  {label:<{width}} "
    val = "N/A" if value is None else str(value)
    return c(txt, _get("GRAY", "")) + (c(val, vcolor, _get("BOLD", "")) if vcolor else val)

def _print_table(headers: Sequence[str], rows: Sequence[Sequence[Any]]) -> None:
    if not rows:
        print(c("  (sem dados)", _get("GRAY", ""), _get("BOLD", "")))
        return
    widths = [len(h) for h in headers]
    for r in rows:
        for i, col in enumerate(r):
            widths[i] = max(widths[i], len(str(col)))
    header_line = ("  " + "  ".join(c(f"{h:<{widths[i]}}", _get("BOLD", ""), _get("CYAN", "")) for i, h in enumerate(headers)))
    sep = "  " + c(" ".join("─" * w for w in widths), _get("GRAY", ""))
    print(header_line)
    print(sep)
    for r in rows:
        print("  " + "  ".join(c(f"{str(col):<{widths[i]}}", _get("WHITE", "")) for i, col in enumerate(r)))

def _highlight_box(lines: List[str], color: str = "", border: str = "┃") -> None:
    width = max(len(line) for line in lines) + 4
    top = c("╭" + "─" * (width - 2) + "╮", color)
    bottom = c("╰" + "─" * (width - 2) + "╯", color)
    print(top)
    for l in lines:
        print(f"{c(border,color)} {l.ljust(width-4)} {c(border,color)}")
    print(bottom)

# ======================================================
# Impressão de resultados com UI aprimorada
# ======================================================
def _print_ip_dossier(info: IPAddressInfo) -> None:
    try:
        print()
        _highlight_box([f"{_emoji('target')}  Dossiê do IP: {c(info.ip, _get('BOLD',''))}"], color=_get("CYAN", ""))
        print(_rule(color=_get("CYAN", "")))
        print(c(f"{_emoji('net')}  Dados de Rede e DNS", _get("BLUE", ""), _get("BOLD", "")))
        print(_kv("ISP/Organização:", getattr(info, "isp", None)))
        asn_num, asn_name = getattr(info, "asn_number", None), getattr(info, "asn_name", None)
        asn = f"AS{asn_num}" if asn_num else "N/A"
        print(_kv("ASN:", f"{asn} ({asn_name or 'N/A'})"))
        print(_kv("DNS Reverso (PTR):", getattr(info, "ptr", None) or "Nenhum"))
        print(c(f"\n{_emoji('info')}  Geolocalização", _get("BLUE", ""), _get("BOLD", "")))
        print(_kv("Cidade:", getattr(info, "city", None)))
        print(_kv("Região/Estado:", getattr(info, "region", None)))
        print(_kv("País:", getattr(info, "country_code", None)))
        
        # _ALTERADO_: Gera e exibe o link do Google Maps se tivermos as coordenadas.
        lat, lon = getattr(info, "latitude", None), getattr(info, "longitude", None)
        if lat is not None and lon is not None:
            maps_link = f"https://www.google.com/maps/search/?api=1&query={lat},{lon}"
            print(_kv("Mapa:", maps_link))
            
        rep = (getattr(info, "raw_data", {}) or {}).get("reputation", {})
        if rep:
            print(c(f"\n{_emoji('shield')}  Reputação (AbuseIPDB)", _get("BLUE", ""), _get("BOLD", "")))
            if "error" in rep:
                print(c(f"  {_emoji('warn')}  Erro: {rep['error']}", _get("YELLOW", "")))
            else:
                score = int(rep.get("abuseConfidenceScore", 0) or 0)
                col = _get("GREEN", "") if score < 25 else (_get("YELLOW", "") if score < 75 else _get("RED", ""))
                print(_kv("Pontuação de Abuso:", f"{score}/100", vcolor=col))
                print(_kv("Total de Denúncias:", rep.get("totalReports", 0)))
                print(_kv("Domínio:", rep.get("domain", "N/A")))
        ports = getattr(info, "ports", None)
        if ports:
            print(c(f"\n{_emoji('scan')}  Portas e Serviços (Nmap)", _get("BLUE", ""), _get("BOLD", "")))
            headers = ["PORTA", "PROTO", "ESTADO", "SERVIÇO", "VERSÃO"]
            rows: List[List[str]] = [[str(p.port_id), getattr(p, "protocol", "?"), getattr(p, "state", "?"), getattr(p, "service_name", "-"), f"{getattr(p, 'product', '') or ''} {getattr(p, 'version', '') or ''}".strip() or "-"] for p in sorted(ports, key=lambda x: x.port_id)]
            _print_table(headers, rows)
        print()
    except Exception as e:
        print(c(f"{_emoji('err')}  Erro ao exibir dossiê do IP: {e}", _get("RED", ""), _get("BOLD", "")))

def _print_domain_dossier(info: DomainInfo) -> None:
    try:
        print()
        _highlight_box([f"{_emoji('search')}  Dossiê do Domínio: {c(info.domain_name, _get('BOLD',''))}"], color=_get("CYAN", ""))
        print(_rule(color=_get("CYAN", "")))
        print(c(f"{_emoji('net')}  Registros DNS", _get("BLUE", ""), _get("BOLD", "")))
        print(_kv("A (IPv4):", ", ".join(info.a_records) if getattr(info, "a_records", None) else "Nenhum"))
        print(_kv("NS (Nameservers):", ", ".join(info.ns_records) if getattr(info, "ns_records", None) else "Nenhum"))
        print(c(f"\n{_emoji('mail')}  Análise de E-mail", _get("BLUE", ""), _get("BOLD", "")))
        mx = getattr(info, "mx_records", []) or []
        print(_kv("MX:", ", ".join(r.get("raw", "") for r in mx) if mx else "Nenhum"))
        spf = getattr(info, "spf_record", {}) or {}
        print(_kv("SPF:", spf.get("raw", "Nenhum")))
        dmarc = getattr(info, "dmarc_record", {}) or {}
        print(_kv("DMARC:", dmarc.get("raw", "Nenhum")))
        
        http_data = getattr(info, "http_info", {}) or {}
        if http_data:
            print(c(f"\n{_emoji('arrow')}  Análise HTTP", _get("BLUE", ""), _get("BOLD", "")))
            print(_kv("Status Code:", http_data.get("status_code")))
            print(_kv("Título:", http_data.get("title", "N/A")))
            print(_kv("Servidor:", http_data.get("headers", {}).get("Server", "N/A")))
            if http_data.get("redirect_location"):
                print(_kv("Redireciona para:", http_data.get("redirect_location")))

        cert_data = getattr(info, "tls_info", {}) or {}
        if cert_data:
            print(c(f"\n{_emoji('star')}  Certificado TLS/SSL", _get("BLUE", ""), _get("BOLD", "")))
            print(_kv("Emissor:", cert_data.get("issuer", {}).get("organizationName", "N/A")))
            print(_kv("Válido até:", cert_data.get("valid_until", "N/A")))
            print(_kv("Domínios Alternativos (SAN):", ", ".join(cert_data.get("sans", [])) or "N/A"))

        subdomains = getattr(info, "subdomains", [])
        if subdomains:
            print(c(f"\n{_emoji('target')}  Subdomínios Encontrados", _get("BLUE", ""), _get("BOLD", "")))
            print("  " + c(" ".join(subdomains), _get("WHITE", "")))
        
        print()
    except Exception as e:
        print(c(f"{_emoji('err')}  Erro ao exibir dossiê do Domínio: {e}", _get("RED", ""), _get("BOLD", "")))


# ======================================================
# Lógica do CLI
# ======================================================

def main():
    """
    Ponto de entrada do CLI, usando subcomandos.
    """
    parser = argparse.ArgumentParser(
        description=f"{_emoji('bat')} Batman do Cerrado PRO - Suíte de Segurança Pessoal",
        epilog=f"Use '{os.path.basename(sys.argv[0])} <comando> -h' para ajuda sobre um comando específico."
    )
    subparsers = parser.add_subparsers(dest="command", help="Comandos de análise e monitoramento")

    # Comando 'ip'
    ip_parser = subparsers.add_parser("ip", help="Realiza uma análise completa em um IP.", aliases=["ip-scan"])
    ip_parser.add_argument("target", help="Endereço IP para análise.")
    ip_parser.set_defaults(func=lambda args: _print_ip_dossier(ip_analyzer.analyze(args.target)))

    # Comando 'domain'
    domain_parser = subparsers.add_parser("domain", help="Realiza uma análise completa em um domínio.")
    domain_parser.add_argument("target", help="Domínio para análise (ex: exemplo.com).")
    domain_parser.set_defaults(func=lambda args: _print_domain_dossier(domain_analyzer.analyze(args.target)))

    # Comando 'nmap'
    nmap_parser = subparsers.add_parser("nmap", help="Realiza um escaneamento de portas rápido em um IP/host.")
    nmap_parser.add_argument("target", help="IP ou host para escanear.")
    nmap_parser.add_argument("-p", "--ports", help="Portas para escanear (ex: 80,443,1000-2000).")
    nmap_parser.set_defaults(func=lambda args: whois_helpers.run_and_print_nmap(args.target, args.ports))

    # Comando 'whois'
    whois_parser = subparsers.add_parser("whois", help="Consulta os dados de registro WHOIS de um IP ou domínio.")
    whois_parser.add_argument("target", help="Endereço IP ou domínio.")
    whois_parser.set_defaults(func=lambda args: whois_helpers.run_and_print_whois(args.target))

    # Comando 'fs-monitor'
    fs_parser = subparsers.add_parser("fs-monitor", help="Monitora o sistema de arquivos para mudanças e novos binários SUID.")
    fs_parser.add_argument("--mode", choices=["baseline", "scan", "monitor"], default="monitor", help="Modo de operação.")
    fs_parser.set_defaults(func=lambda args: fs_monitor.main_cli(args.mode))

    # Comando 'net-monitor'
    net_parser = subparsers.add_parser("net-monitor", help="Monitora o tráfego de rede e novas conexões.")
    net_parser.set_defaults(func=lambda args: net_monitor.main_cli())
    
    # Comando 'selfcheck'
    selfcheck_parser = subparsers.add_parser("selfcheck", help="Executa o autodiagnóstico do sistema.")
    selfcheck_parser.set_defaults(func=lambda args: selfcheck.analyze())

    # Comando 'secrets-scan' <--- NOVO COMANDO
    secrets_parser = subparsers.add_parser("secrets-scan", help="Varre o sistema de arquivos por segredos e credenciais.")
    secrets_parser.add_argument("target", nargs="?", help="Caminho do arquivo ou diretório para varrer.")
    secrets_parser.set_defaults(func=lambda args: secrets_scanner.main())


    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    args = parser.parse_args()
    if hasattr(args, "func"):
        args.func(args)
    else:
        parser.print_help(sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
