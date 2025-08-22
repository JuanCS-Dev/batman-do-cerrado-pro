# batman_do_cerrado/modules/selfcheck.py (Versão com salvamento em /app/logs)

import json
import time
import os
from typing import Optional, Dict, Any
from dataclasses import asdict
import requests

from batman_do_cerrado.core import ui
from batman_do_cerrado.core.models import IPAddressInfo
from . import ip_analyzer
from . import nmap_scanner

try:
    from batman_do_cerrado.cli import _print_ip_dossier
except ImportError:
    def _print_ip_dossier(info):
        print(json.dumps(asdict(info), indent=2))

def _get_public_ip() -> Optional[str]:
    # ... (código inalterado) ...
    urls = ["https://api.ipify.org", "https://ifconfig.me/ip", "https://icanhazip.com"]
    for url in urls:
        try:
            headers = {"User-Agent": "Batman-do-Cerrado-PRO/2.0"}
            response = requests.get(url, timeout=5, headers=headers)
            response.raise_for_status()
            ip = response.text.strip()
            if '.' in ip or ':' in ip:
                 return ip
        except requests.RequestException:
            continue
    return None

def _print_report(report: IPAddressInfo):
    """Imprime o relatório consolidado na tela."""
    ui.print_banner()
    print(ui.color(f"--- Relatório de Autoanálise (Self-Check) para o IP: {report.ip} ---", ui.BOLD + ui.CYAN))
    _print_ip_dossier(report)

def analyze() -> Optional[IPAddressInfo]:
    """Orquestra a autoanálise e retorna um único e consolidado objeto IPAddressInfo."""
    ui.print_banner()
    print(ui.color("Iniciando autoanálise completa do ambiente...", ui.BOLD + ui.CYAN))

    spinner = ui.Spinner("Determinando IP público...")
    spinner.start()
    public_ip = _get_public_ip()
    spinner.stop()

    if not public_ip:
        print(ui.color("ERRO: Não foi possível determinar o IP público.", ui.RED))
        return None

    print(ui.color(f"IP público detectado: {public_ip}", ui.GREEN))
    
    print(ui.color("\nExecutando dossiê de rede e geolocalização...", ui.BLUE))
    final_report_obj = ip_analyzer.analyze(target=public_ip)
    if not final_report_obj:
        return None

    print(ui.color("\nExecutando varredura de portas (perfil 'padrao')...", ui.BLUE))
    nmap_results = nmap_scanner.analyze(target=public_ip, profile_name="padrao")
    if nmap_results and nmap_results[0].ports:
        final_report_obj.ports = nmap_results[0].ports

    # _ALTERADO_: Lógica de salvamento para usar o diretório /app/logs
    logs_dir = "/app/logs"
    os.makedirs(logs_dir, exist_ok=True) # Garante que o diretório exista dentro do contêiner
    report_filename = f"selfcheck_report_{int(time.time())}.json"
    full_path = os.path.join(logs_dir, report_filename)
    
    try:
        with open(full_path, "w", encoding="utf-8") as f:
            json.dump(asdict(final_report_obj), f, indent=4, ensure_ascii=False)
        print(ui.color(f"\nRelatório completo salvo em: {full_path} (dentro do contêiner)", ui.BOLD + ui.GREEN))
    except IOError as e:
        print(ui.color(f"\nAVISO: Não foi possível salvar o relatório JSON: {e}", ui.YELLOW))

    return final_report_obj

def main():
    report = analyze()
    if report:
        _print_ip_dossier(report)

if __name__ == "__main__":
    main()
