# batman-do-cerrado-pro/batman_do_cerrado/modules/nmap_scanner.py

"""
Módulo Nmap Scanner (Refatorado) - Batman do Cerrado

Executa varreduras Nmap utilizando perfis customizáveis a partir do arquivo
de configuração central. Analisa a saída XML e a transforma nos modelos
de dados padronizados do framework (IPAddressInfo, PortInfo).
"""

import argparse
import sys
import xml.etree.ElementTree as ET
from typing import List, Optional, Dict, Any

from batman_do_cerrado.core import ui, utils
from batman_do_cerrado.core.config import config
from batman_do_cerrado.core.models import IPAddressInfo, PortInfo

# --- Lógica de Parsing (Adaptada do original, agora mais robusta) ---

def _parse_xml_to_models(xml_string: str) -> List[IPAddressInfo]:
    """
    Analisa a saída XML do Nmap e a converte em nossos modelos de dados.
    Esta é a "ponte" entre a ferramenta externa e o nosso framework.
    """
    results: List[IPAddressInfo] = []
    try:
        root = ET.fromstring(xml_string)
    except ET.ParseError as e:
        # Em caso de XML malformado, use a função print padrão para notificar o erro.
        print(ui.color(f"Erro fatal ao analisar o XML do Nmap: {e}", ui.RED))
        return results

    for host_node in root.findall("host"):
        addr_node = host_node.find("address")
        if addr_node is None:
            continue

        ip_address = addr_node.get("addr", "N/A")
        ip_version = 4 if addr_node.get("addrtype") == "ipv4" else 6

        host_info = IPAddressInfo(ip=ip_address, version=ip_version)
        
        # Adiciona hostnames se disponíveis
        hostnames_node = host_node.find("hostnames")
        if hostnames_node is not None:
            # Um PTR pode aparecer aqui, então o adicionamos
            for hn in hostnames_node.findall("hostname"):
                if hn.get("type") == "PTR":
                    host_info.ptr = hn.get("name")
                    break
        
        # Analisa as portas
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
                    
                    # Adiciona scripts NSE
                    for script_node in port_node.findall("script"):
                        script_id = script_node.get("id", "unknown_script")
                        script_output = script_node.get("output", "")
                        port_info.scripts_output[script_id] = script_output

                    host_info.ports.append(port_info)
                except (ValueError, TypeError):
                    continue # Ignora portas malformadas

        results.append(host_info)
        
    return results

# --- Lógica de Apresentação ---

def _print_results(results: List[IPAddressInfo]):
    """
    Formata e imprime os resultados da varredura de forma legível,
    utilizando o módulo core.ui para consistência.
    """
    if not results:
        print(ui.color("\nNenhum host ativo encontrado ou nenhuma informação retornada.", ui.YELLOW))
        return

    print(ui.color("\n--- Resultados da Varredura Nmap ---", ui.BOLD + ui.CYAN))

    for host in results:
        status_color = ui.GREEN
        ptr_info = f"({host.ptr})" if host.ptr else ""
        header = f"Host: {ui.color(host.ip, ui.BOLD)} {ptr_info}"
        print(f"\n{ui.color(header, status_color)}")

        if not host.ports:
            print(ui.color("  -> Nenhuma porta aberta encontrada com este perfil.", ui.GRAY))
            continue

        # Cabeçalho da tabela
        print(f"  {ui.BOLD}{'PORTA':<8} {'PROTO':<6} {'ESTADO':<10} {'SERVIÇO':<20} {'VERSÃO'}{ui.RESET}")
        print(f"  {ui.GRAY}{'-'*80}{ui.RESET}")

        for port in sorted(host.ports, key=lambda p: p.port_id):
            version_str = f"{port.product or ''} {port.version or ''}".strip()
            line = (
                f"  {port.port_id:<8} "
                f"{port.protocol:<6} "
                f"{port.state:<10} "
                f"{port.service_name or '-':<20} "
                f"{version_str or '-'}"
            )
            print(ui.color(line, ui.GREEN))

            # Imprime saídas de scripts NSE de forma limpa
            for script_id, output in port.scripts_output.items():
                clean_output = ' '.join(output.strip().split())
                print(ui.color(f"    └── {script_id}: {clean_output}", ui.GRAY))

# --- Lógica Principal de Análise ---

def analyze(target: str, profile_name: str, extra_args: Optional[str] = None) -> Optional[List[IPAddressInfo]]:
    """
    Orquestra a execução e análise do Nmap.

    Returns:
        Uma lista de objetos IPAddressInfo em caso de sucesso, None em caso de falha.
    """
    # 1. Carrega os perfis do nosso arquivo de configuração central
    profiles = config.get_section('nmap_scanner.profiles')
    if profile_name not in profiles:
        print(ui.color(f"ERRO: Perfil de Nmap '{profile_name}' não encontrado no settings.toml.", ui.RED))
        return None

    # 2. Constrói o comando de forma segura
    # O "-oX -" é essencial para capturarmos a saída XML no stdout.
    command = ["nmap"] + profiles[profile_name].split() + ["-oX", "-"]
    if extra_args:
        command.extend(extra_args.split())
    command.append(target)

    print(ui.color(f"\nExecutando Nmap com o perfil '{profile_name}'...", ui.CYAN))
    print(ui.color(f"Comando: {' '.join(command)}", ui.GRAY))

    # 3. Executa o comando usando nosso wrapper robusto do core
    result = utils.run_command(command, timeout=600) # Timeout generoso de 10 min

    # 4. Tratamento de Erros
    if not result.success:
        print(ui.color("\n--- ERRO NA EXECUÇÃO DO NMAP ---", ui.BOLD + ui.RED))
        # O stderr do Nmap geralmente contém informações úteis sobre o erro
        print(ui.color(result.stderr or "O Nmap terminou com um erro inesperado.", ui.YELLOW))
        return None
    
    if not result.stdout:
        print(ui.color("\nO Nmap não produziu nenhuma saída. Verifique o alvo e as permissões.", ui.YELLOW))
        return None

    # 5. Análise e Retorno dos Dados Estruturados
    return _parse_xml_to_models(result.stdout)

# --- Ponto de Entrada do Módulo ---

def main():
    """Ponto de entrada para execução via CLI ou menu."""
    if not utils.find_binary("nmap"):
        print(ui.color("ERRO: O binário 'nmap' é essencial para este módulo.", ui.RED))
        print("Instale-o com 'sudo apt install nmap' ou equivalente.")
        sys.exit(1)

    parser = argparse.ArgumentParser(description="Módulo Nmap Scanner - Batman do Cerrado")
    parser.add_argument("-t", "--target", help="Alvo (IP, hostname ou CIDR) para escanear.")
    parser.add_argument("-p", "--profile", help="Nome do perfil a ser usado (definido em settings.toml).")
    args = parser.parse_args()

    ui.print_banner()
    print(ui.color("Módulo de Varredura Nmap (Refatorado)", ui.CYAN))

    if args.target and args.profile:
        target, profile = args.target, args.profile
    else:
        # Fluxo interativo
        target = input(ui.color("Alvo (IP/hostname/faixa): ", ui.GREEN)).strip()
        if not target:
            print(ui.color("Alvo é obrigatório.", ui.RED))
            return
        
        profiles = config.get_section('nmap_scanner.profiles')
        print(ui.color("Perfis disponíveis no seu settings.toml:", ui.BLUE))
        for i, (name, cmd) in enumerate(profiles.items(), 1):
            print(f"  {i}) {ui.BOLD}{name}{ui.RESET} {ui.GRAY}({cmd}){ui.RESET}")
        
        choice = input(ui.color(f"Escolha um perfil [1-{len(profiles)}]: ", ui.GREEN)).strip()
        try:
            profile = list(profiles.keys())[int(choice) - 1]
        except (ValueError, IndexError):
            print(ui.color("Seleção inválida. Abortando.", ui.RED))
            return

    results = analyze(target, profile)
    if results:
        _print_results(results)

if __name__ == "__main__":
    main()

