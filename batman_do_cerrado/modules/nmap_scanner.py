"""
Módulo Nmap Scanner (Híbrido, Robusto e Moderno) - Batman do Cerrado

Executa varreduras Nmap utilizando perfis customizáveis, trata resultados XML,
inclui heurísticas de risco, trata erros comuns, enriquece findings e integra
ao framework. Pronto para uso em automação e para saída interativa limpa.
"""

import argparse
import sys
import xml.etree.ElementTree as ET
from typing import List, Optional, Dict, Any

from batman_do_cerrado.core import ui, utils
from batman_do_cerrado.core.config import config
from batman_do_cerrado.core.models import IPAddressInfo, PortInfo

# --- Parsing Robusto do XML do Nmap ---

def _parse_xml_to_models(xml_string: str) -> List[IPAddressInfo]:
    """
    Analisa a saída XML do Nmap e a converte em nossos modelos de dados.
    Detecta hosts, PTR, portas, serviços, scripts e anotações de risco.
    """
    results: List[IPAddressInfo] = []
    try:
        root = ET.fromstring(xml_string)
    except ET.ParseError as e:
        print(ui.color(f"Erro fatal ao analisar o XML do Nmap: {e}", ui.RED))
        return results

    for host_node in root.findall("host"):
        addr_node = host_node.find("address")
        if addr_node is None:
            continue

        ip_address = addr_node.get("addr", "N/A")
        ip_version = 4 if addr_node.get("addrtype") == "ipv4" else 6

        host_info = IPAddressInfo(ip=ip_address, version=ip_version)
        
        # PTR/hostnames
        hostnames_node = host_node.find("hostnames")
        if hostnames_node is not None:
            for hn in hostnames_node.findall("hostname"):
                if hn.get("type") == "PTR":
                    host_info.ptr = hn.get("name")
                    break
        
        # Ports
        ports_node = host_node.find("ports")
        if ports_node is not None:
            for port_node in ports_node.findall("port"):
                try:
                    port_id = int(port_node.get("portid", "0"))
                    protocol = port_node.get("protocol", "unknown")
                    state_node = port_node.find("state")
                    state = state_node.get("state") if state_node is not None else "unknown"

                    port_info = PortInfo(port_id=port_id, protocol=protocol, state=state)
                    
                    service_node = port_node.find("service")
                    if service_node is not None:
                        port_info.service_name = service_node.get("name")
                        port_info.product = service_node.get("product")
                        port_info.version = service_node.get("version")
                        port_info.extra_info = service_node.get("extrainfo")
                        port_info.cpe = [c.text for c in service_node.findall("cpe") if c.text]
                    
                    # Scripts NSE
                    for script_node in port_node.findall("script"):
                        script_id = script_node.get("id", "unknown_script")
                        script_output = script_node.get("output", "")
                        port_info.scripts_output[script_id] = script_output

                    # Heurística de risco automática (exemplo)
                    if state == "open":
                        if port_info.service_name in ("telnet", "ftp", "rdp"):
                            port_info.risk = "high"
                        elif port_info.service_name in ("ssh", "smtp", "mysql"):
                            port_info.risk = "medium"
                        elif port_info.service_name == "http":
                            port_info.risk = "info"
                    
                    host_info.ports.append(port_info)
                except (ValueError, TypeError):
                    continue # Ignora portas malformadas

        # Anota OS (hostscript/OS detection)
        os_node = host_node.find("os")
        if os_node is not None:
            osmatches = [osm.get("name", "") for osm in os_node.findall("osmatch")]
            if osmatches:
                host_info.os = osmatches[0]
        
        results.append(host_info)
        
    return results

# --- Apresentação Enriquecida ---

def _print_results(results: List[IPAddressInfo]):
    """
    Formata e imprime os resultados, enriquecendo com heurísticas e riscos.
    """
    if not results:
        print(ui.color("\nNenhum host ativo encontrado ou nenhuma informação retornada.", ui.YELLOW))
        return

    print(ui.color("\n--- Resultados da Varredura Nmap ---", ui.BOLD + ui.CYAN))

    for host in results:
        status_color = ui.GREEN
        ptr_info = f"({host.ptr})" if host.ptr else ""
        os_info = f" [SO: {host.os}]" if getattr(host, "os", None) else ""
        header = f"Host: {ui.color(host.ip, ui.BOLD)} {ptr_info}{os_info}"
        print(f"\n{ui.color(header, status_color)}")

        if not host.ports:
            print(ui.color("  -> Nenhuma porta aberta encontrada.", ui.GRAY))
            continue

        print(f"  {ui.BOLD}{'PORTA':<8} {'PROTO':<6} {'ESTADO':<10} {'SERVIÇO':<20} {'VERSÃO':<24} {'RISK'}{ui.RESET}")
        print(f"  {ui.GRAY}{'-'*90}{ui.RESET}")

        for port in sorted(host.ports, key=lambda p: p.port_id):
            version_str = f"{port.product or ''} {port.version or ''}".strip()
            risk_str = (port.risk or "-").upper() if hasattr(port, "risk") else "-"
            risk_color = ui.RED if risk_str == "HIGH" else (ui.YELLOW if risk_str == "MEDIUM" else ui.CYAN)
            line = (
                f"  {port.port_id:<8} "
                f"{port.protocol:<6} "
                f"{port.state:<10} "
                f"{port.service_name or '-':<20} "
                f"{version_str or '-':<24} "
                f"{ui.color(risk_str, risk_color)}"
            )
            print(line)

            # Scripts NSE
            for script_id, output in port.scripts_output.items():
                clean_output = ' '.join(output.strip().split())
                print(ui.color(f"    └── {script_id}: {clean_output}", ui.GRAY))

# --- Execução do Nmap com Robustez e Flexibilidade ---

def analyze(target: str, profile_name: str, extra_args: Optional[str] = None) -> Optional[List[IPAddressInfo]]:
    """
    Orquestra a execução e análise do Nmap. Retorna lista de IPAddressInfo.
    """
    profiles = config.get_section('nmap_scanner.profiles')
    if profile_name not in profiles:
        print(ui.color(f"ERRO: Perfil de Nmap '{profile_name}' não encontrado no settings.toml.", ui.RED))
        return None

    command = ["nmap"] + profiles[profile_name].split() + ["-oX", "-"]
    if extra_args:
        command.extend(extra_args.split())
    command.append(target)

    print(ui.color(f"\nExecutando Nmap com o perfil '{profile_name}'...", ui.CYAN))
    print(ui.color(f"Comando: {' '.join(command)}", ui.GRAY))

    result = utils.run_command(command, timeout=900) # Timeout de 15 min

    if not result.success:
        print(ui.color("\n--- ERRO NA EXECUÇÃO DO NMAP ---", ui.BOLD + ui.RED))
        print(ui.color(result.stderr or "O Nmap terminou com um erro inesperado.", ui.YELLOW))
        return None
    
    if not result.stdout:
        print(ui.color("\nO Nmap não produziu nenhuma saída. Verifique o alvo e as permissões.", ui.YELLOW))
        return None

    return _parse_xml_to_models(result.stdout)

# --- CLI e Fluxo Interativo Robusto ---

def main():
    """Ponto de entrada CLI/menu, robusto e amigável."""
    if not utils.find_binary("nmap"):
        print(ui.color("ERRO: O binário 'nmap' é essencial para este módulo.", ui.RED))
        print("Instale-o com 'sudo apt install nmap' ou equivalente.")
        sys.exit(1)

    parser = argparse.ArgumentParser(description="Módulo Nmap Scanner (Híbrido & Robusto) - Batman do Cerrado")
    parser.add_argument("-t", "--target", help="Alvo (IP, hostname ou CIDR) para escanear.")
    parser.add_argument("-p", "--profile", help="Nome do perfil a ser usado (definido em settings.toml).")
    parser.add_argument("--args", help="Argumentos extras para o Nmap.", default=None)
    args = parser.parse_args()

    ui.print_banner()
    print(ui.color("Módulo de Varredura Nmap (Híbrido & Robusto)", ui.CYAN))

    if args.target and args.profile:
        target, profile = args.target, args.profile
        extra_args = args.args
    else:
        target = input(ui.color("Alvo (IP/hostname/faixa): ", ui.GREEN)).strip()
        if not target:
            print(ui.color("Alvo é obrigatório.", ui.RED))
            return
        
        profiles = config.get_section('nmap_scanner.profiles')
        print(ui.color("Perfis disponíveis:", ui.BLUE))
        for i, (name, cmd) in enumerate(profiles.items(), 1):
            print(f"  {i}) {ui.BOLD}{name}{ui.RESET} {ui.GRAY}({cmd}){ui.RESET}")
        
        choice = input(ui.color(f"Escolha um perfil [1-{len(profiles)}]: ", ui.GREEN)).strip()
        try:
            profile = list(profiles.keys())[int(choice) - 1]
        except (ValueError, IndexError):
            print(ui.color("Seleção inválida. Abortando.", ui.RED))
            return
        extra_args = input(ui.color("Argumentos extras do Nmap (opcional): ", ui.GRAY)).strip() or None

    results = analyze(target, profile, extra_args)
    if results:
        _print_results(results)

if __name__ == "__main__":
    main()
