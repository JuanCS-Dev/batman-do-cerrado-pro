# batman-do-cerrado-pro/batman_do_cerrado/cli.py

"""
Módulo CLI Principal (Refatorado) - Batman do Cerrado

Este é o ponto de entrada principal ('entry point') do framework quando instalado.
Ele orquestra a chamada para todos os outros módulos através do dispatcher,
analisa os argumentos da linha de comando e formata a apresentação dos resultados.
"""

import argparse
import sys
from typing import Any, List

# Importações do nosso framework
from .core import ui
from .core.dispatcher import run_module
from .core.models import IPAddressInfo, DomainInfo, Finding, PortInfo

# --- Lógica de Apresentação de Resultados (Unificada) ---

def _print_results(results: Any):
    """
    Imprime os resultados de forma bonita, detectando o tipo de dados recebido.
    Este é o sistema de apresentação centralizado.
    """
    if not results:
        print(ui.color("\nNenhum resultado retornado pelo módulo.", ui.YELLOW))
        return

    # O tipo de impressão muda de acordo com o modelo de dados retornado
    if isinstance(results, IPAddressInfo):
        _print_ip_dossier(results)
    elif isinstance(results, DomainInfo):
        _print_domain_dossier(results)
    elif isinstance(results, list) and all(isinstance(item, Finding) for item in results):
        _print_findings_list(results)
    else:
        # Fallback para tipos de dados inesperados
        print(ui.color("\n--- RESULTADO GENÉRICO ---", ui.CYAN))
        from pprint import pprint
        pprint(results)

def _print_ip_dossier(info: IPAddressInfo):
    """Impressora especializada para o dossiê de IP do ip_analyzer."""
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
        if "error" in rep:
            print(ui.color(f"  Erro: {rep['error']}", ui.YELLOW))
        else:
            score = rep.get('abuseConfidenceScore', 0)
            score_color = ui.GREEN if score < 25 else (ui.YELLOW if score < 75 else ui.RED)
            print(f"  {'Pontuação de Abuso:':<20} {ui.color(str(score), ui.BOLD + score_color)} / 100")

    if info.ports:
        print(ui.color("\n[ PORTAS E SERVIÇOS (NMAP) ]", ui.BLUE))
        for port in sorted(info.ports, key=lambda p: p.port_id):
             version_str = f"{port.product or ''} {port.version or ''}".strip()
             line = f"  - {port.port_id}/{port.protocol} ({port.state}): {port.service_name or ''} {version_str}"
             print(ui.color(line, ui.GREEN if port.state == 'open' else ui.GRAY))

def _print_domain_dossier(info: DomainInfo):
    """Impressora especializada para o dossiê de Domínio."""
    print(ui.color(f"\n--- Dossiê do Domínio: {info.domain_name} ---", ui.BOLD + ui.CYAN))
    print(ui.color("\n[ REGISTROS DNS PRINCIPAIS ]", ui.BLUE))
    print(f"  {'A (IPv4):':<15} {', '.join(info.a_records) or 'Nenhum'}")
    print(f"  {'NS (Serv. Nomes):':<15} {', '.join(info.ns_records) or 'Nenhum'}")
    
def _print_findings_list(findings: List[Finding]):
    """Impressora especializada para listas de Findings (fs_monitor, net_monitor)."""
    for finding in findings:
        color = ui.RED if finding.severity == "critical" else (ui.YELLOW if finding.severity in ("high", "medium") else ui.CYAN)
        print(ui.color(f"\n[ALERTA] {finding.description}", ui.BOLD + color))
        print(f"  - Alvo: {finding.target}")
        print(f"  - Módulo: {finding.module} ({finding.finding_type})")
        for key, value in finding.details.items():
            print(f"  - {key.replace('_', ' ').capitalize()}: {value}")


# --- Lógica Principal do CLI ---

def main():
    """
    Ponto de entrada principal do framework, definido no pyproject.toml.
    Cria a interface de linha de comando com sub-comandos para cada módulo.
    """
    # Verificação de permissões: alguns módulos precisam de root
    is_root = os.geteuid() == 0

    parser = argparse.ArgumentParser(
        description="Batman do Cerrado - Suíte de Segurança Pessoal",
        formatter_class=argparse.RawTextHelpFormatter
    )
    subparsers = parser.add_subparsers(dest="module", help="Módulo a ser executado", required=True)

    # --- Comando para: ip_analyzer ---
    p_ip = subparsers.add_parser("ip", help="Executa o dossiê completo para um endereço IP.")
    p_ip.add_argument("target", help="O endereço IP a ser analisado.")

    # --- Comando para: domain_analyzer ---
    p_domain = subparsers.add_parser("domain", help="Executa a análise OSINT completa para um domínio.")
    p_domain.add_argument("target", help="O domínio a ser analisado.")
    
    # --- Comando para: nmap_scanner ---
    p_nmap = subparsers.add_parser("nmap", help="Executa uma varredura Nmap em um alvo.")
    p_nmap.add_argument("target", help="O alvo para a varredura (IP, hostname ou CIDR).")
    p_nmap.add_argument("-p", "--profile", required=True, help="O perfil de scan (definido em settings.toml).")

    # --- Comando para: fs_monitor ---
    p_fs = subparsers.add_parser("fs", help="Inicia o monitor de integridade de arquivos em tempo real.")
    if not is_root:
        p_fs.epilog = ui.color("AVISO: Recomenda-se executar este módulo como root.", ui.YELLOW)

    # --- Comando para: net_monitor ---
    p_net = subparsers.add_parser("net", help="Inicia o monitor de rede em tempo real.")
    if not is_root:
        p_net.epilog = ui.color("AVISO: Recomenda-se executar este módulo como root.", ui.YELLOW)

    # Adicione aqui os parsers para os outros módulos...
    
    args = parser.parse_args()
    
    # O despachante é chamado com o nome do módulo e os argumentos
    results = run_module(args.module, **vars(args))
    
    # Os resultados são passados para o sistema de impressão unificado
    if results:
        _print_results(results)

if __name__ == "__main__":
    main()
