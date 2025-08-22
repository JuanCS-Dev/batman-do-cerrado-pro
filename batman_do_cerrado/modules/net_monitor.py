"""
Módulo Net Monitor (Híbrido, Robusto e Moderno) - Batman do Cerrado

Monitoramento assíncrono de rede com detecção de comportamentos suspeitos,
controle de ruído, saída inteligente, e integração ao framework.
Suporta thresholds dinâmicos, alerta de comportamentos persistentes,
controle de flood, e findings enriquecidos.
"""

import argparse
import asyncio
import json
import os
import re
import sys
import time
from collections import deque, defaultdict
from typing import Deque, Dict, List, Optional, Set, Any, Tuple

# Importações do nosso framework
from batman_do_cerrado.core import ui, utils
from batman_do_cerrado.core.config import config
from batman_do_cerrado.core.models import Finding

# --- Regex Helpers ---
ADDR_RE = re.compile(r"(.+?):(\*|\d+)$")

def _parse_addr(addr: str) -> Tuple[str, str]:
    """Extrai IP/host e porta de uma string 'addr:port'."""
    match = ADDR_RE.search(addr.strip())
    return (match.group(1), match.group(2)) if match else (addr, "")

# --- Flood/Noise Control ---
class FindingDeduplicator:
    """
    Deduplicador e debounce para findings, para evitar floods de alertas repetidos.
    """
    def __init__(self, debounce_seconds: int = 20):
        self.last_finding: Dict[str, float] = defaultdict(float)
        self.debounce_seconds = debounce_seconds

    def should_emit(self, key: str) -> bool:
        now = time.time()
        if now - self.last_finding[key] < self.debounce_seconds:
            return False
        self.last_finding[key] = now
        return True

# --- Motor de Detecção Assíncrono ---

class NetworkDetector:
    """
    Motor de detecção assíncrono para comportamentos suspeitos em conexões de rede.
    """
    def __init__(self, findings_queue: asyncio.Queue, dedup: FindingDeduplicator):
        self.queue = findings_queue
        self.dedup = dedup

        # Configs modernas, ajustáveis via settings.toml
        self.window = config.get('net_monitor', 'window_seconds', 12)
        self.spike_thr = config.get('net_monitor', 'spike_threshold', 30)
        self.syn_thr = config.get('net_monitor', 'syn_recv_threshold', 60)
        self.scan_port_thr = config.get('net_monitor', 'portscan_ports_threshold', 15)
        self.persistent_scan_thr = config.get('net_monitor', 'persistent_scan_threshold', 3)
        self.cooldown_default = config.get('net_monitor', 'cooldown_seconds', 30)

        # Estado
        self.last_listen_check: Dict[str, Any] = {}
        self.first_seen: Set[str] = set()
        self.ip_buckets: Dict[str, Deque[float]] = defaultdict(deque)
        self.port_buckets: Dict[str, Deque[float]] = defaultdict(deque)
        self.scan_buckets: Dict[str, Deque[Tuple[float, str]]] = defaultdict(deque)
        self.syn_recv_buckets: Dict[str, Deque[float]] = defaultdict(deque)
        self.persistent_scan_cache: Dict[str, List[float]] = defaultdict(list)

    async def _run_ss(self, args: List[str]) -> str:
        """Executa 'ss' (socket stat) de forma assíncrona."""
        cmd = ["ss", "-H", "-n"] + args
        result = await asyncio.to_thread(utils.run_command, cmd, timeout=5)
        return result.stdout if result.success else ""
    
    async def _check_new_listens(self):
        """Detecta novas portas abertas/listen."""
        output = await self._run_ss(["-ltup"])
        current_listens = {}
        for line in output.splitlines():
            parts = line.split()
            if len(parts) < 5: continue
            proto, _, _, local_addr, _ = parts[0], parts[1], parts[2], parts[3], parts[4]
            _, port = _parse_addr(local_addr)
            key = f"{proto}:{port}"
            current_listens[key] = line

        for key, data in current_listens.items():
            if key not in self.last_listen_check and self.dedup.should_emit(f"listen:{key}"):
                await self.queue.put(Finding(
                    target="localhost", module="net_monitor", finding_type="new_listen",
                    description=f"Nova porta em escuta detectada: {key}", severity="medium",
                    details={"raw_ss_line": data}
                ))
        self.last_listen_check = current_listens

    async def _check_connections(self):
        """
        Detecta:
        - Primeiro contato de IP
        - Picos de conexões ("connection spike")
        - Varredura de portas (port scan)
        - SYN flood/SYN_RECV spikes
        - Escaneamento persistente (port scan que retorna em janelas distintas)
        """
        output = await self._run_ss(["-taup"])
        now = time.time()
        time_limit = now - self.window

        # Limpa buckets de eventos antigos
        for bucket in [self.ip_buckets, self.port_buckets]:
            for key in list(bucket):
                while bucket[key] and bucket[key][0] < time_limit:
                    bucket[key].popleft()
        for key in list(self.scan_buckets):
            while self.scan_buckets[key] and self.scan_buckets[key][0][0] < time_limit:
                self.scan_buckets[key].popleft()
        for key in list(self.syn_recv_buckets):
            while self.syn_recv_buckets[key] and self.syn_recv_buckets[key][0] < time_limit:
                self.syn_recv_buckets[key].popleft()

        for line in output.splitlines():
            parts = line.split()
            if len(parts) < 6: continue
            proto, state, _, local_addr, peer_addr, _ = parts[0], parts[1], parts[2], parts[3], parts[4], parts[5]

            # Detecta SYN_RECV (SYN flood)
            if state == "SYN-RECV":
                rip, _ = _parse_addr(peer_addr)
                if rip and rip != "0.0.0.0":
                    self.syn_recv_buckets[rip].append(now)
                    if len(self.syn_recv_buckets[rip]) >= self.syn_thr and self.dedup.should_emit(f"synrecv:{rip}"):
                        await self.queue.put(Finding(
                            target=rip, module="net_monitor", finding_type="syn_flood",
                            description=f"Muitos SYN_RECV do IP {rip} (possível SYN flood/DDOS)", severity="critical",
                            details={"count": len(self.syn_recv_buckets[rip]), "window_sec": self.window}
                        ))
                continue

            if state == "LISTEN":
                continue

            rip, rport = _parse_addr(peer_addr)
            _, lport = _parse_addr(local_addr)
            if rip == "0.0.0.0" or not rip:
                continue

            # --- Primeiro contato de IP externo ---
            if rip not in self.first_seen and self.dedup.should_emit(f"first_seen:{rip}"):
                self.first_seen.add(rip)
                await self.queue.put(Finding(
                    target=rip, module="net_monitor", finding_type="first_seen",
                    description=f"Primeiro contato detectado do IP {rip}", severity="info",
                    details={"remote_port": rport, "local_port": lport, "protocol": proto}
                ))

            # --- Pico de conexões abertas vindas do IP ---
            self.ip_buckets[rip].append(now)
            port_key = f"{proto}:{lport}"
            self.port_buckets[port_key].append(now)
            if len(self.ip_buckets[rip]) >= self.spike_thr and self.dedup.should_emit(f"spike:{rip}"):
                await self.queue.put(Finding(
                    target=rip, module="net_monitor", finding_type="connection_spike",
                    description=f"Pico de conexões do IP {rip}", severity="high",
                    details={"count": len(self.ip_buckets[rip]), "window_sec": self.window}
                ))

            # --- Varredura de portas na origem ---
            self.scan_buckets[rip].append((now, lport))
            unique_ports = {port for _, port in self.scan_buckets[rip]}
            if len(unique_ports) >= self.scan_port_thr and self.dedup.should_emit(f"portscan:{rip}"):
                await self.queue.put(Finding(
                    target=rip, module="net_monitor", finding_type="port_scan",
                    description=f"Possível varredura de portas do IP {rip}", severity="critical",
                    details={"ports_hit": sorted(list(unique_ports))[:20], "port_count": len(unique_ports)}
                ))
                # Armazena possíveis scanners persistentes
                self.persistent_scan_cache[rip].append(now)

            # --- Detecção de escaneamento persistente (mesmo IP, várias janelas) ---
            times = self.persistent_scan_cache[rip]
            # Mantém só os últimos 10 minutos
            self.persistent_scan_cache[rip] = [t for t in times if t > now - 600]
            if len(self.persistent_scan_cache[rip]) >= self.persistent_scan_thr and self.dedup.should_emit(f"persistent_scan:{rip}"):
                await self.queue.put(Finding(
                    target=rip, module="net_monitor", finding_type="persistent_portscan",
                    description=f"Varredura de portas persistente detectada do IP {rip}", severity="critical",
                    details={"count": len(self.persistent_scan_cache[rip]), "period_min": 10}
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
    """Consome a fila e imprime os 'Findings' de forma tratada e formatada."""
    while True:
        finding = await queue.get()
        color = ui.CYAN
        if finding.severity == "critical":
            color = ui.RED
        elif finding.severity in ("high", "medium"):
            color = ui.YELLOW
        elif finding.severity == "info":
            color = ui.BLUE

        print(ui.color(f"\n[{time.strftime('%H:%M:%S')}] {finding.severity.upper()}: {finding.description}", ui.BOLD + color))
        print(f"  - Alvo: {finding.target}")
        print(f"  - Tipo: {finding.finding_type}")
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
    dedup = FindingDeduplicator(debounce_seconds=config.get('net_monitor', 'debounce_seconds', 20))
    detector = NetworkDetector(findings_queue, dedup)

    detector_task = asyncio.create_task(detector.run(interval))
    printer_task = asyncio.create_task(findings_printer(findings_queue))

    loop = asyncio.get_running_loop()
    stop_event = asyncio.Event()
    try:
        loop.add_signal_handler(2, stop_event.set)  # SIGINT (Ctrl+C)
    except (NotImplementedError, AttributeError):
        # Windows/pytest environments: fallback
        pass

    await stop_event.wait()

    detector_task.cancel()
    printer_task.cancel()
    await asyncio.gather(detector_task, printer_task, return_exceptions=True)

def main():
    """Ponto de entrada para execução via CLI."""
    parser = argparse.ArgumentParser(description="Módulo Net Monitor - Batman do Cerrado (Híbrido e Robusto)")
    parser.add_argument("--interval", type=float, default=2.0, help="Intervalo de verificação em segundos.")
    args = parser.parse_args()

    ui.print_banner()
    print(ui.color("Módulo de Monitor de Rede em Tempo Real (Híbrido e Robusto)", ui.CYAN))
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
