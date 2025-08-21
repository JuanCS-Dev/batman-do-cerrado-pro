# batman-do-cerrado-pro/batman_do_cerrado/cli.py

"""
Módulo CLI Principal (Refatorado) - Batman do Cerrado

Este é o ponto de entrada principal ('entry point') do framework quando instalado.
Ele orquestra a chamada para todos os outros módulos através do dispatcher,
analisa os argumentos da linha de comando e formata a apresentação dos resultados.
"""

import argparse
import os
import sys
import time # Adicionado para o sleep
from typing import Any, List, Dict, Optional

# Importações do nosso framework
from .core import ui
from .core.dispatcher import run_module
from .core.models import IPAddressInfo, DomainInfo, Finding
# _ALTERADO_: Importamos o objeto 'config' para ler o settings.toml
from .core.config import config

# --- (As funções _print_... permanecem exatamente as mesmas) ---
def _print_results(results: Any):
    if not results:
        print(ui.color("\nNenhum resultado retornado pelo módulo.", ui.YELLOW))
        return
    if isinstance(results, IPAddressInfo): _print_ip_dossier(results)
    elif isinstance(results, DomainInfo): _print_domain_dossier(results)
    elif isinstance(results, list) and results and isinstance(results[0], Finding): _print_findings_list(results)
    else:
        print(ui.color("\n--- RESULTADO GENÉRICO ---", ui.CYAN)); from pprint import pprint; pprint(results)

def _print_ip_dossier(info: IPAddressInfo):
    print(ui.color(f"\n--- Dossiê do IP: {info.ip} ---", ui.BOLD + ui.CYAN))
    print(ui.color("\n[ DADOS DE REDE E DNS ]", ui.BLUE))
    print(f"  {'ISP/Organização:':<20} {info.isp or 'N/A'}")
    asn = f"AS{info.asn_number}" if info.asn_number else "N/A"
    print(f"  {'ASN:':<20} {asn} ({info.asn_name or 'N/A'})")
    print(f"  {'DNS Reverso (PTR):':<20} {info.ptr or 'Nenhum'}")
    print(ui.color("\n[ GEOLOCALIZAÇÃO ]", ui.BLUE))
    print(f"  {'Cidade:':<20} {info.city or 'N/A'}")
    print(f"  {'País:':<20} {info.country_code or 'N/A'}")
    rep = info.raw_data.get("reputation", {})
    if rep:
        print(ui.color("\n[ REPUTAÇÃO (ABUSEIPDB) ]", ui.BLUE))
        if "error" in rep: print(ui.color(f"  Erro: {rep['error']}", ui.YELLOW))
        else:
            score = rep.get('abuseConfidenceScore', 0)
            score_color = ui.GREEN if score < 25 else (ui.YELLOW if score < 75 else ui.RED)
            print(f"  {'Pontuação de Abuso:':<20} {ui.color(str(score), ui.BOLD + score_color)} / 100")
    
    if hasattr(info, 'ports') and info.ports:
        print(ui.color("\n[ PORTAS E SERVIÇOS (NMAP) ]", ui.BLUE))
        for port in sorted(info.ports, key=lambda p: p.port_id):
             version_str = f"{port.product or ''} {port.version or ''}".strip()
             line = f"  - {port.port_id}/{port.protocol} ({port.state}): {port.service_name or ''} {version_str}"
             print(ui.color(line, ui.GREEN if port.state == 'open' else ui.GRAY))
    print()

def _print_domain_dossier(info: DomainInfo):
    print(ui.color(f"\n--- Dossiê do Domínio: {info.domain_name} ---", ui.BOLD + ui.CYAN))
    print(ui.color("\n[ REGISTROS DNS PRINCIPAIS ]", ui.BLUE))
    print(f"  {'A (IPv4):':<25} {', '.join(info.a_records) or 'Nenhum'}")
    print(f"  {'NS (Servidores de Nomes):':<25} {', '.join(info.ns_records) or 'Nenhum'}")
    print(ui.color("\n[ ANÁLISE DE E-MAIL ]", ui.BLUE))
    print(f"  {'MX (Mail Exchanger):':<25} {', '.join(r['raw'] for r in info.mx_records) or 'Nenhum'}")
    print(f"  {'SPF:':<25} {info.spf.get('raw', 'Não encontrado')}")
    print(f"  {'DMARC:':<25} {info.dmarc.get('raw', 'Não encontrado')}")
    axfr_status = ui.color("ABERTA (VULNERÁVEL!)", ui.RED + ui.BOLD) if info.is_axfr_open else ui.color("Fechada", ui.GREEN)
    print(f"  {'Transferência de Zona (AXFR):':<25} {axfr_status}")
    print()

def _print_findings_list(findings: List[Finding]):
    for finding in findings:
        color = ui.RED if finding.severity == "critical" else (ui.YELLOW if finding.severity in ("high", "medium") else ui.CYAN)
        print(ui.color(f"\n[ALERTA] {finding.description}", ui.BOLD + color))
        print(f"  - Alvo: {finding.target}")
        print(f"  - Módulo: {finding.module} ({finding.finding_type})")
        for key, value in finding.details.items():
            print(f"  - {key.replace('_', ' ').capitalize()}: {value}")
    print()

# --- Lógica do Menu Interativo ---

def interactive_menu():
    """Exibe o menu principal e lida com a seleção do usuário."""
    ui.clear_screen()
    ui.print_banner()
    
    print(ui.color("Selecione um módulo para iniciar a análise:", ui.BOLD))

    menu_items = {
        "1": {"name": "ip_analyzer", "desc": "Executa o dossiê completo para um endereço IP.", "sudo": False},
        "2": {"name": "domain", "desc": "Executa a análise OSINT completa para um domínio.", "sudo": False},
        # _ALTERADO_: Corrigido o nome do módulo para corresponder ao nome do arquivo.
        "3": {"name": "nmap_scanner", "desc": "Executa uma varredura Nmap com perfis customizáveis.", "sudo": False},
        "4": {"name": "fs", "desc": "Inicia o monitor de integridade de arquivos em tempo real.", "sudo": True},
        "5": {"name": "net", "desc": "Inicia o monitor de rede em tempo real.", "sudo": True},
        "9": {"name": "ai_auditor", "desc": "Inicia uma investigação autônoma com o Protocolo Oráculo.", "sudo": False, "wip": True},
    }

    print(ui.color("\n[ ANÁLISE E OSINT ]", ui.BLUE))
    for key, item in menu_items.items():
        if key in "123":
            wip_tag = ui.color(" (em breve)", ui.GRAY) if item.get("wip") else ""
            print(f"  {ui.color(key, ui.GREEN)}) {item['name']:<15} - {item['desc']}{wip_tag}")

    print(ui.color("\n[ DEFESA E MONITORAMENTO ]", ui.BLUE))
    for key, item in menu_items.items():
        if key in "45":
            sudo_tag = ui.color(" (Requer sudo)", ui.YELLOW) if item.get("sudo") else ""
            print(f"  {ui.color(key, ui.GREEN)}) {item['name']:<15} - {item['desc']}{sudo_tag}")

    print(ui.color("\n[ INTELIGÊNCIA ARTIFICIAL ]", ui.BLUE))
    for key, item in menu_items.items():
        if key in "9":
            wip_tag = ui.color(" (em breve)", ui.GRAY) if item.get("wip") else ""
            print(f"  {ui.color(key, ui.GREEN)}) {item['name']:<15} - {item['desc']}{wip_tag}")

    try:
        choice = input(ui.color("\nEscolha uma opção (ou 'q' para sair): ", ui.BOLD + ui.CYAN)).strip()
        if choice.lower() in ['q', 'quit', 'sair']: sys.exit(0)
        
        selected = menu_items.get(choice) or next((item for item in menu_items.values() if item['name'] == choice), None)
        if not selected:
            print(ui.color("Opção inválida.", ui.RED)); time.sleep(1); interactive_menu()
            return

        module_name = selected['name']
        kwargs = {}
        # _ALTERADO_: Verificação do nome corrigido.
        if module_name in ["ip_analyzer", "domain", "nmap_scanner"]:
            kwargs["target"] = input(ui.color(f"  -> Alvo para '{module_name}': ", ui.GREEN)).strip()
            if not kwargs["target"]: print(ui.color("Alvo é obrigatório.", ui.RED)); time.sleep(1); interactive_menu(); return

        # _ALTERADO_: Lógica de menu inteligente para o Nmap Scanner.
        if module_name == "nmap_scanner":
            profiles = config.get_section('nmap_scanner.profiles')
            if not profiles:
                print(ui.color("Nenhum perfil Nmap encontrado no settings.toml.", ui.RED)); time.sleep(1); interactive_menu(); return
            
            print(ui.color("\nPerfis de varredura disponíveis:", ui.BLUE))
            profile_keys = list(profiles.keys())
            for i, name in enumerate(profile_keys, 1):
                print(f"  {i}) {ui.BOLD}{name}{ui.RESET}")
            
            profile_choice = input(ui.color(f"  -> Escolha um perfil [1-{len(profiles)}]: ", ui.GREEN)).strip()
            try:
                # Converte a escolha numérica para o nome do perfil
                kwargs["profile"] = profile_keys[int(profile_choice) - 1]
            except (ValueError, IndexError):
                print(ui.color("Seleção inválida.", ui.RED)); time.sleep(1); interactive_menu(); return
        
        results = run_module(module_name, **kwargs)
        
        if results:
            _print_results(results)

    except (KeyboardInterrupt, EOFError):
        print(ui.color("\n\nOperação cancelada. Saindo.", ui.YELLOW)); sys.exit(0)
        
    ui.pause()
    interactive_menu()

# --- Lógica Principal do CLI ---

def main():
    """Ponto de entrada principal do framework."""
    is_root = os.geteuid() == 0 if hasattr(os, 'geteuid') else False
    parser = argparse.ArgumentParser(
        description="Batman do Cerrado - Suíte de Segurança Pessoal",
        formatter_class=argparse.RawTextHelpFormatter
    )
    subparsers = parser.add_subparsers(dest="module", help="Módulo a ser executado")

    if len(sys.argv) == 1:
        interactive_menu()
        return

    subparsers.required = True

    p_ip = subparsers.add_parser("ip_analyzer", help="Executa o dossiê completo para um IP.", aliases=["ip"])
    p_ip.add_argument("target", help="O endereço IP a ser analisado.")
    
    p_domain = subparsers.add_parser("domain", help="Executa a análise OSINT para um domínio.", aliases=["domain-analyzer"])
    p_domain.add_argument("target", help="O domínio a ser analisado.")
    
    # _ALTERADO_: Nome do sub-comando e alias corrigidos
    p_nmap = subparsers.add_parser("nmap_scanner", help="Executa uma varredura Nmap.", aliases=["nmap"])
    p_nmap.add_argument("target", help="O alvo para a varredura.")
    p_nmap.add_argument("-p", "--profile", required=True, help="O perfil de scan (definido em settings.toml).")
    
    p_fs = subparsers.add_parser("fs", help="Inicia o monitor de integridade de arquivos.", aliases=["fs-monitor"])
    if not is_root: p_fs.epilog = ui.color("AVISO: Recomenda-se executar este módulo como root.", ui.YELLOW)
    
    p_net = subparsers.add_parser("net", help="Inicia o monitor de rede.", aliases=["net-monitor"])
    if not is_root: p_net.epilog = ui.color("AVISO: Recomenda-se executar este módulo como root.", ui.YELLOW)
    
    args = parser.parse_args()
    
    module_to_run = args.module
    # _ALTERADO_: Normaliza o alias 'nmap' para o nome canônico
    if module_to_run == 'nmap':
        module_to_run = 'nmap_scanner'
    if module_to_run == 'ip':
        module_to_run = 'ip_analyzer'

    results = run_module(module_to_run, **vars(args))
    
    if results:
        _print_results(results)

if __name__ == "__main__":
    main()
