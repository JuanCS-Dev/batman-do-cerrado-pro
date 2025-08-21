# batman-do-cerrado-pro/batman_do_cerrado/modules/net_monitor.py

"""
Módulo Net Monitor (Refatorado) - Batman do Cerrado

Monitor de rede assíncrono, agora totalmente integrado ao framework,
utilizando configuração central e gerando "Findings" padronizados.
"""

import argparse
import asyncio
import json
import os
import re
import sys
import time
from collections import deque
from typing import Deque, Dict, List, Optional, Set, Any

# Importações do nosso framework
from batman_do_cerrado.core import ui, utils
from batman_do_cerrado.core.config import config
from batman_do_cerrado.core.models import Finding

# --- Constantes e Helpers ---
ADDR_RE = re.compile(r"(.+?):(\*|\d+)$")
USERS_RE = re.compile(r'users:\(\("([^",]+)",pid=(\d+),fd=\d+\)\)')

def _parse_addr(addr: str) -> tuple[str, str]:
    """Extrai IP/host e porta de uma string 'addr:port'."""
    match = ADDR_RE.search(addr.strip())
    return (match.group(1), match.group(2)) if match else (addr, "")

# --- Motor de Detecção Assíncrono ---

class NetworkDetector:
    """
    O motor de detecção que executa em background, analisando a saída do 'ss'
    e colocando Findings em uma fila assíncrona.
    """
    def __init__(self, findings_queue: asyncio.Queue):
        self.queue = findings_queue
        # Carrega configurações do settings.toml
        self.window = config.get('net_monitor', 'window_seconds', 12)
        self.spike_thr = config.get('net_monitor', 'spike_threshold', 30)
        self.syn_thr = config.get('net_monitor', 'syn_recv_threshold', 60)
        
        # Estado interno
        self.last_listen_check: Dict[str, Any] = {}
        self.first_seen: Set[str] = set()
        self.ip_buckets: Dict[str, Deque[float]] = {}
        self.port_buckets: Dict[str, Deque[float]] = {}
        self.scan_buckets: Dict[str, Deque[tuple[float, str]]] = {}
        self.cooldowns: Dict[str, float] = {}

    async def _run_ss(self, args: List[str]) -> str:
        """Executa 'ss' de forma assíncrona."""
        cmd = ["ss", "-H", "-n"] + args
        result = await asyncio.to_thread(utils.run_command, cmd, timeout=5)
        return result.stdout if result.success else ""
    
    def _is_on_cooldown(self, key: str, duration: int) -> bool:
        """Verifica se um alerta para uma chave específica está em cooldown."""
        now = time.time()
        if now - self.cooldowns.get(key, 0) < duration:
            return True
        self.cooldowns[key] = now
        return False

    async def _check_new_listens(self):
        """Verifica novas portas em estado LISTEN."""
        output = await self._run_ss(["-ltup"]) # TCP e UDP
        current_listens = {}
        for line in output.splitlines():
            parts = line.split()
            if len(parts) < 5: continue
            proto, _, _, local_addr, _ = parts[0], parts[1], parts[2], parts[3], parts[4]
            _, port = _parse_addr(local_addr)
            key = f"{proto}:{port}"
            current_listens[key] = line
        
        for key, data in current_listens.items():
            if key not in self.last_listen_check:
                await self.queue.put(Finding(
                    target="localhost", module="net_monitor", finding_type="new_listen",
                    description=f"Nova porta em escuta detectada: {key}", severity="medium",
                    details={"raw_ss_line": data}
                ))
        self.last_listen_check = current_listens

    async def _check_connections(self):
        """Verifica conexões ativas, picos e varreduras."""
        output = await self._run_ss(["-taup"]) # TCP e UDP
        now = time.time()
        time_limit = now - self.window

        # Atualiza os buckets, removendo entradas antigas
        for bucket in [self.ip_buckets, self.port_buckets]:
            for key in list(bucket):
                while bucket[key] and bucket[key][0] < time_limit:
                    bucket[key].popleft()
        for key in list(self.scan_buckets):
            while self.scan_buckets[key] and self.scan_buckets[key][0][0] < time_limit:
                self.scan_buckets[key].popleft()

        # Processa as conexões atuais
        for line in output.splitlines():
            parts = line.split()
            if len(parts) < 6 or parts[1] == "LISTEN": continue
            proto, _, _, local_addr, peer_addr, _ = parts[0], parts[1], parts[2], parts[3], parts[4], parts[5]
            
            rip, rport = _parse_addr(peer_addr)
            _, lport = _parse_addr(local_addr)

            if rip == "0.0.0.0" or not rip: continue

            # --- Detecção de Primeiro Contato ---
            if rip not in self.first_seen:
                self.first_seen.add(rip)
                await self.queue.put(Finding(
                    target=rip, module="net_monitor", finding_type="first_seen",
                    description=f"Primeiro contato detectado do IP {rip}", severity="info",
                    details={"remote_port": rport, "local_port": lport, "protocol": proto}
                ))
            
            # --- Detecção de Picos ---
            self.ip_buckets.setdefault(rip, deque()).append(now)
            port_key = f"{proto}:{lport}"
            self.port_buckets.setdefault(port_key, deque()).append(now)
            
            if len(self.ip_buckets[rip]) >= self.spike_thr and not self._is_on_cooldown(f"spike:{rip}", 30):
                await self.queue.put(Finding(
                    target=rip, module="net_monitor", finding_type="connection_spike",
                    description=f"Pico de conexões do IP {rip}", severity="high",
                    details={"count": len(self.ip_buckets[rip]), "window_sec": self.window}
                ))
            
            # --- Detecção de Varredura de Portas ---
            self.scan_buckets.setdefault(rip, deque()).append((now, lport))
            unique_ports = {port for _, port in self.scan_buckets[rip]}
            if len(unique_ports) >= 15 and not self._is_on_cooldown(f"scan:{rip}", 60):
                await self.queue.put(Finding(
                    target=rip, module="net_monitor", finding_type="port_scan",
                    description=f"Possível varredura de portas vinda de {rip}", severity="critical",
                    details={"ports_hit": sorted(list(unique_ports))[:20], "port_count": len(unique_ports)}
                ))

    async def run(self, interval: float):
        """Loop principal do motor de detecção."""
        while True:
            await asyncio.gather(
                self._check_new_listens(),
                self._check_connections()
            )
            await asyncio.sleep(interval)


async def findings_printer(queue: asyncio.Queue):
    """Consome a fila e imprime os 'Findings' de forma bonita."""
    while True:
        finding = await queue.get()
        color = ui.RED if finding.severity == "critical" else (ui.YELLOW if finding.severity in ("high", "medium") else ui.CYAN)
        
        print(ui.color(f"\n[{time.strftime('%H:%M:%S')}] {finding.severity.upper()}: {finding.description}", ui.BOLD + color))
        print(f"  - Alvo: {finding.target}")
        for key, value in finding.details.items():
            print(f"  - {key.replace('_', ' ').capitalize()}: {value}")
        
        queue.task_done()

# --- Ponto de Entrada do Módulo ---

async def start_monitoring(interval: float):
    """Inicia e gerencia as tarefas assíncronas do monitor."""
    if not utils.find_binary("ss"):
        print(ui.color("ERRO: O binário 'ss' (do pacote iproute2) é essencial.", ui.RED))
        sys.exit(1)
        
    findings_queue = asyncio.Queue()
    detector = NetworkDetector(findings_queue)
    
    # Cria as tarefas que rodam em paralelo
    detector_task = asyncio.create_task(detector.run(interval))
    printer_task = asyncio.create_task(findings_printer(findings_queue))

    # Espera por um sinal de interrupção (Ctrl+C)
    loop = asyncio.get_running_loop()
    stop_event = asyncio.Event()
    loop.add_signal_handler(2, stop_event.set) # SIGINT

    await stop_event.wait()

    # Cancela as tarefas de forma limpa
    detector_task.cancel()
    printer_task.cancel()
    await asyncio.gather(detector_task, printer_task, return_exceptions=True)

def main():
    """Ponto de entrada para execução via CLI."""
    parser = argparse.ArgumentParser(description="Módulo Net Monitor - Batman do Cerrado")
    parser.add_argument("--interval", type=float, default=2.0, help="Intervalo de verificação em segundos.")
    args = parser.parse_args()

    ui.print_banner()
    print(ui.color("Módulo de Monitor de Rede em Tempo Real (Refatorado)", ui.CYAN))
    print(ui.color("Iniciando monitoramento... (Pressione Ctrl+C para sair)", ui.GREEN))
    
    try:
        asyncio.run(start_monitoring(args.interval))
    except KeyboardInterrupt:
        pass
    finally:
        print(ui.color("\nMonitoramento encerrado.", ui.YELLOW))

if __name__ == "__main__":
    if os.geteuid() != 0:
        print(ui.color("Aviso: Para melhores resultados, execute este monitor como root.", ui.YELLOW))
    main()
