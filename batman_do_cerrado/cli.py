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

# ... (Helpers de UI e Funções de Impressão permanecem os mesmos) ...
# (Vou omiti-los aqui por brevidade, mas eles estão no arquivo completo abaixo)

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
        print(_kv("SPF:", (getattr(info, "spf", {}) or {}).get("raw", "Não encontrado")))
        print(_kv("DMARC:", (getattr(info, "dmarc", {}) or {}).get("raw", "Não encontrado")))
        axfr_open = bool(getattr(info, "is_axfr_open", False))
        axfr, axfr_col = ("ABERTA (VULNERÁVEL!)", _get("RED", "")) if axfr_open else ("Fechada", _get("GREEN", ""))
        print(_kv("AXFR:", c(axfr, axfr_col, _get("BOLD", ""))))
        print()
    except Exception as e:
        print(c(f"{_emoji('err')}  Erro ao exibir dossiê do domínio: {e}", _get("RED", ""), _get("BOLD", "")))

def _print_findings_list(findings: List[Finding]) -> None:
    try:
        print()
        magenta = _get("MAGENTA", _get("BLUE", ""))
        _highlight_box([f"{_emoji('file')}  Achados"], color=magenta)
        print(_rule(color=magenta))
        if not findings:
            print(c("  (sem achados)", _get("GRAY", ""), _get("BOLD", ""))); return
        for f in findings:
            level = (f.severity or "").lower()
            if level == "critical": badge = c(f"[{level.upper()}]", _get("RED", ""), _get("BOLD", "")) + " " + _emoji("err")
            elif level in ("high", "medium"): badge = c(f"[{level.upper()}]", _get("YELLOW", ""), _get("BOLD", "")) + " " + _emoji("warn")
            else: badge = c(f"[{level.upper()}]", _get("GREEN", ""), _get("BOLD", "")) + " " + _emoji("ok")
            print(f"\n  {badge} {getattr(f, 'description', '')}")
            print(_kv("Alvo:", getattr(f, "target", None)))
            print(_kv("Módulo/Tipo:", f"{getattr(f, 'module', '')} / {getattr(f, 'finding_type', '')}"))
            for k, v in (getattr(f, "details", {}) or {}).items():
                print(_kv(k.replace('_', ' ').capitalize() + ":", v))
        print()
    except Exception as e:
        print(c(f"{_emoji('err')}  Erro ao exibir achados: {e}", _get("RED", ""), _get("BOLD", "")))

def _print_results(results: Any) -> None:
    try:
        if not results:
            print(c(f"\n{_emoji('warn')}  Nenhum resultado retornado pelo módulo.", _get("YELLOW", ""), _get("BOLD", ""))); return
        if isinstance(results, IPAddressInfo): _print_ip_dossier(results)
        elif isinstance(results, DomainInfo): _print_domain_dossier(results)
        elif isinstance(results, list) and results and isinstance(results[0], Finding): _print_findings_list(results)
        else:
            print(c(f"\n{_emoji('info')}  Resultado genérico", _get("CYAN", ""), _get("BOLD", ""))); from pprint import pprint; pprint(results)
    except Exception as e:
        print(c(f"{_emoji('err')}  Erro ao exibir resultados: {e}", _get("RED", ""), _get("BOLD", "")))

# ======================================================
# Menu interativo (UI Moderna)
# ======================================================
def interactive_menu() -> None:
    try:
        # _ALTERADO_: A limpeza de tela foi restaurada agora que a depuração terminou.
        ui.clear_screen()
        ui.print_banner()
        print(_rule(color=_get("CYAN", "")))
        print(c(f"{_emoji('bat')}  BATMAN DO CERRADO", _get("BOLD", ""), _get("CYAN", "")) + "   " + c("Segurança & OSINT Suite", _get("GRAY", "")))
        print(c("          author: Juan Carlos", _get("BOLD", ""), _get("YELLOW", "")))
        print(_rule(color=_get("CYAN", "")))
        print(c(f"{_emoji('info')}  Selecione um módulo para iniciar a análise:", _get("BOLD", ""), _get("WHITE", "")))

        menu_items: Dict[str, Dict[str, Any]] = {
            "1": {"name": "ip_analyzer", "desc": "Dossiê completo para um endereço IP.", "icon": "target", "sudo": False},
            "2": {"name": "domain_analyzer", "desc": "Análise OSINT completa para um domínio.", "icon": "search", "sudo": False},
            "3": {"name": "nmap_scanner", "desc": "Varredura Nmap com perfis customizáveis.", "icon": "scan", "sudo": False},
            "4": {"name": "fs_monitor", "desc": "Integridade de arquivos em tempo real. (sudo)", "icon": "file", "sudo": True},
            "5": {"name": "net_monitor", "desc": "Monitoramento de rede em tempo real. (sudo)", "icon": "net", "sudo": True},
            "9": {"name": "ai_auditor", "desc": "Protocolo Oráculo (em breve).", "icon": "spark", "sudo": False, "wip": True},
        }

        def menu_section(title, keys, color):
            print()
            print(c(f"  {title}", color, _get("BOLD", "")))
            for key in keys:
                item = menu_items[key]
                tag = c(" (em breve)", _get("GRAY", ""), _get("BOLD", "")) if item.get("wip") else ""
                sudo = c(" (Requer sudo)", _get("YELLOW", ""), _get("BOLD", "")) if item.get("sudo") else ""
                icon = _emoji(item["icon"])
                print(f"   {c(key, _get('GREEN',''), _get('BOLD',''))}) {icon} {c(item['name'], _get('BOLD',''), color)}  {c('— ' + item['desc'], _get('GRAY',''))}{sudo}{tag}")

        menu_section("[ ANÁLISE E OSINT ]", ("1", "2", "3"), _get("CYAN", ""))
        menu_section("[ DEFESA E MONITORAMENTO ]", ("4", "5"), _get("MAGENTA", ""))
        menu_section("[ INTELIGÊNCIA ARTIFICIAL ]", ("9",), _get("YELLOW", ""))
        print(_rule(color=_get("GRAY", "")))
        choice = input(c(f"{_emoji('arrow')}  Escolha uma opção (ou 'q' para sair): ", _get("CYAN", ""), _get("BOLD", ""))).strip()
        
        if choice.lower() in ("q", "quit", "sair"): print(); sys.exit(0)
        
        selected = menu_items.get(choice) or next((it for it in menu_items.values() if it["name"] == choice), None)
        if not selected:
            print(c(f"{_emoji('err')}  Opção inválida.", _get("RED", ""), _get("BOLD", ""))); time.sleep(1); interactive_menu(); return

        module_name = selected["name"]
        kwargs: Dict[str, Any] = {}

        # _ALTERADO_: Lógica refatorada para a nova ordem dos prompts.
        if module_name in ("ip_analyzer", "domain_analyzer"):
            prompt = f"  {_emoji('target')}  Alvo para '{module_name}': "
            kwargs["target"] = input(c(prompt, _get("GREEN", ""), _get("BOLD", ""))).strip()
            if not kwargs["target"]:
                print(c(f"{_emoji('err')}  Alvo é obrigatório.", _get("RED", ""))); time.sleep(1); interactive_menu(); return

        elif module_name == "nmap_scanner":
            profiles = config.get_section("nmap_scanner.profiles")
            if not profiles:
                print(c(f"{_emoji('err')}  Nenhum perfil Nmap encontrado no settings.toml.", _get("RED", ""))); time.sleep(1); interactive_menu(); return
            
            keys = list(profiles.keys())
            print(c(f"\n{_emoji('scan')}  Perfis de varredura disponíveis:", _get("BLUE", "")))
            for i, name in enumerate(keys, 1):
                print(f"   {c(str(i)+')', _get('GREEN',''), _get('BOLD',''))} {c(name, _get('BOLD',''))} {c('('+profiles[name]+')', _get('GRAY',''))}")
            
            choice_idx = input(c(f"  {_emoji('gear')}  Escolha um perfil [1-{len(keys)}]: ", _get("GREEN", ""))).strip()
            try:
                kwargs["profile_name"] = keys[int(choice_idx) - 1]
            except Exception:
                print(c(f"{_emoji('err')}  Seleção inválida.", _get("RED", ""))); time.sleep(1); interactive_menu(); return

            prompt = f"  {_emoji('target')}  Alvo para a varredura '{kwargs['profile_name']}': "
            kwargs["target"] = input(c(prompt, _get("GREEN", ""), _get("BOLD", ""))).strip()
            if not kwargs["target"]:
                print(c(f"{_emoji('err')}  Alvo é obrigatório.", _get("RED", ""))); time.sleep(1); interactive_menu(); return

        try:
            results = run_module(module_name, **kwargs)
        except Exception as e:
            print(c(f"{_emoji('err')}  Erro ao executar módulo '{module_name}': {e}", _get("RED", ""))); results = None

        _print_results(results)

    except (KeyboardInterrupt, EOFError):
        print(c("\nOperação cancelada.", _get("YELLOW", ""), _get("BOLD", ""))); sys.exit(0)
    except Exception as e:
        print(c(f"{_emoji('err')}  Erro inesperado: {e}", _get("RED", ""), _get("BOLD", ""))); sys.exit(1)

    ui.pause()
    interactive_menu()

# ======================================================
# Entry point (subcomandos)
# ======================================================
def main() -> None:
    is_root = hasattr(os, "geteuid") and os.geteuid() == 0
    parser = argparse.ArgumentParser(description="Batman do Cerrado — Suíte de Segurança Pessoal", formatter_class=argparse.RawTextHelpFormatter)
    subparsers = parser.add_subparsers(dest="module", help="Módulo a ser executado")

    if len(sys.argv) == 1:
        interactive_menu(); return

    subparsers.required = True

    p_ip = subparsers.add_parser("ip_analyzer", help="Dossiê completo para um IP.", aliases=["ip"])
    p_ip.add_argument("target", help="Endereço IP a ser analisado.")
    p_domain = subparsers.add_parser("domain_analyzer", help="Análise OSINT para um domínio.", aliases=["domain"])
    p_domain.add_argument("target", help="Domínio a ser analisado.")
    p_nmap = subparsers.add_parser("nmap_scanner", help="Varredura Nmap.", aliases=["nmap"])
    p_nmap.add_argument("target", help="Alvo da varredura.")
    p_nmap.add_argument("-p", "--profile", required=True, help="Perfil de scan (definido em settings.toml).")
    p_fs = subparsers.add_parser("fs_monitor", help="Monitor de integridade de arquivos.", aliases=["fs"])
    if not is_root: p_fs.epilog = c("Sugestão: execute como root para mais sinal.", _get("YELLOW", ""))
    p_net = subparsers.add_parser("net_monitor", help="Monitor de rede.", aliases=["net"])
    if not is_root: p_net.epilog = c("Sugestão: execute como root para mais sinal.", _get("YELLOW", ""))
    
    args = parser.parse_args()

    alias_map = { "ip": "ip_analyzer", "domain": "domain_analyzer", "nmap": "nmap_scanner", "fs": "fs_monitor", "net": "net_monitor" }
    module = alias_map.get(args.module, args.module)
    
    params: Dict[str, Any] = vars(args).copy()
    params.pop("module", None)
    if module == "nmap_scanner" and "profile" in params:
        params["profile_name"] = params.pop("profile")

    try:
        results = run_module(module, **params)
    except Exception as e:
        print(c(f"{_emoji('err')}  Erro ao executar módulo '{module}': {e}", _get("RED", ""))); results = None
    
    _print_results(results)

if __name__ == "__main__":
    main()
