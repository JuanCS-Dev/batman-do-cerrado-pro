"""
FS Monitor Híbrido - Batman do Cerrado

Combina monitoramento event-driven e baseline para máxima robustez e praticidade.
"""

import hashlib
import json
import os
import stat
import sys
import time
import threading
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, Optional, List, Set

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler, FileSystemEvent
except ImportError:
    print("O módulo 'watchdog' é necessário. Instale com: pip install watchdog")
    sys.exit(1)

from batman_do_cerrado.core import ui, utils
from batman_do_cerrado.core.config import PROJECT_ROOT as CORE_PROJECT_ROOT
from batman_do_cerrado.core.config import config
from batman_do_cerrado.core.models import Finding

@dataclass
class FileState:
    path: str
    size: int
    mtime: float
    mode: int
    uid: int
    gid: int
    sha256: Optional[str] = None

    @property
    def is_suid_root(self) -> bool:
        return bool(self.mode & stat.S_ISUID and self.uid == 0)

class FileSystemMonitor:
    def __init__(self):
        self.paths_to_watch = config.get('fs_monitor', 'default_paths', [])
        self.suid_allowlist = set(config.get('fs_monitor', 'suid_allowlist', []))
        self.exclude_globs = config.get('fs_monitor', 'default_excludes', [])
        self.baseline_path = CORE_PROJECT_ROOT / "data" / "baselines" / "fs_baseline.json"
        self.baseline: Dict[str, FileState] = self._load_baseline()
        self.hash_max_bytes = 5 * 1024 * 1024
        self.event_history: Dict[str, float] = {}  # path -> last event timestamp

        # Debounce: não alerta mais de uma vez por X segundos para o mesmo arquivo/evento
        self.debounce_seconds = config.get('fs_monitor', 'debounce_seconds', 10)

    def _hash_file(self, path: Path) -> Optional[str]:
        h = hashlib.sha256()
        try:
            with path.open("rb") as f:
                while chunk := f.read(1024 * 1024):
                    h.update(chunk)
            return h.hexdigest()
        except (IOError, PermissionError):
            return None

    def _get_current_state(self, path: Path) -> Optional[FileState]:
        try:
            st = path.lstat()
            should_hash = st.st_size <= self.hash_max_bytes
            return FileState(
                path=str(path),
                size=st.st_size,
                mtime=st.st_mtime,
                mode=stat.S_IMODE(st.st_mode),
                uid=st.st_uid,
                gid=st.st_gid,
                sha256=self._hash_file(path) if should_hash else None
            )
        except (FileNotFoundError, PermissionError):
            return None

    def _save_baseline(self):
        raw_data = {path: asdict(state) for path, state in self.baseline.items()}
        self.baseline_path.parent.mkdir(parents=True, exist_ok=True)
        self.baseline_path.write_text(json.dumps(raw_data, indent=2), encoding="utf-8")

    def _load_baseline(self) -> Dict[str, FileState]:
        self.baseline_path.parent.mkdir(parents=True, exist_ok=True)
        if not self.baseline_path.is_file():
            return {}
        try:
            raw_data = json.loads(self.baseline_path.read_text(encoding="utf-8"))
            return {path: FileState(**data) for path, data in raw_data.items()}
        except Exception:
            print(ui.color("AVISO: Baseline corrompida. Nova será criada!", ui.YELLOW))
            return {}

    def _should_alert(self, path: str, event_type: str) -> bool:
        key = f"{path}|{event_type}"
        now = time.time()
        last_event = self.event_history.get(key, 0)
        if now - last_event < self.debounce_seconds:
            return False
        self.event_history[key] = now
        return True

    def scan_integrity(self) -> List[Finding]:
        # Scanner periódico: varredura completa (baseline)
        findings: List[Finding] = []
        current_paths_on_disk = set()
        for watch_path_str in self.paths_to_watch:
            watch_path = Path(watch_path_str).expanduser()
            for root, _, files in os.walk(watch_path):
                for name in files:
                    path = Path(root) / name
                    if any(path.match(pattern) for pattern in self.exclude_globs):
                        continue
                    current_paths_on_disk.add(str(path))
                    old_state = self.baseline.get(str(path))
                    new_state = self._get_current_state(path)
                    if not new_state: continue

                    if not old_state:
                        self.baseline[str(path)] = new_state
                        findings.append(Finding(target=str(path), module="fs_monitor", finding_type="file_created", description="Novo arquivo detectado.", severity="medium", details={"size": new_state.size, "mode": oct(new_state.mode)}))
                        if new_state.is_suid_root and str(path) not in self.suid_allowlist:
                            findings.append(Finding(target=str(path), module="fs_monitor", finding_type="setuid_added", description="Arquivo SUID/root perigoso.", severity="critical", details={"mode": oct(new_state.mode)}))
                        continue

                    if new_state.mode != old_state.mode:
                        findings.append(Finding(target=str(path), module="fs_monitor", finding_type="perms_changed", description="Permissões do arquivo alteradas.", severity="high", details={"old": oct(old_state.mode), "new": oct(new_state.mode)}))
                    if not old_state.is_suid_root and new_state.is_suid_root and str(path) not in self.suid_allowlist:
                        findings.append(Finding(target=str(path), module="fs_monitor", finding_type="setuid_added", description="Permissão SUID perigosa adicionada.", severity="critical", details={"mode": oct(new_state.mode)}))
                    old_hash = old_state.sha256
                    new_hash = new_state.sha256
                    if not old_hash or (new_state.size != old_state.size or int(new_state.mtime) != int(old_state.mtime)):
                        if not new_hash:
                            new_hash = self._hash_file(path)
                    if old_hash != new_hash:
                        findings.append(Finding(target=str(path), module="fs_monitor", finding_type="file_modified", description="Conteúdo do arquivo modificado (hash diferente).", severity="critical", details={"old_hash": old_hash, "new_hash": new_hash}))
                    self.baseline[str(path)] = new_state
        deleted_paths = set(self.baseline.keys()) - current_paths_on_disk
        for path_str in deleted_paths:
            del self.baseline[path_str]
            findings.append(Finding(target=path_str, module="fs_monitor", finding_type="file_deleted", description="Arquivo deletado.", severity="high", details={}))
        self._save_baseline()
        return findings

    def handle_event(self, event: FileSystemEvent):
        path = Path(event.src_path)
        if any(path.match(pattern) for pattern in self.exclude_globs):
            return  # Excluído via glob
        # Só alerta se for relevante e não for flood
        if not self._should_alert(str(path), event.event_type):
            return
        # Consulta estado atual e compara com baseline
        old_state = self.baseline.get(str(path))
        new_state = self._get_current_state(path)
        findings = []
        if event.event_type == "created":
            self.baseline[str(path)] = new_state
            findings.append(Finding(target=str(path), module="fs_monitor", finding_type="file_created", description="Arquivo criado (evento ao vivo).", severity="medium", details={"size": new_state.size, "mode": oct(new_state.mode)}))
            if new_state.is_suid_root and str(path) not in self.suid_allowlist:
                findings.append(Finding(target=str(path), module="fs_monitor", finding_type="setuid_added", description="Arquivo SUID/root perigoso.", severity="critical", details={"mode": oct(new_state.mode)}))
        elif event.event_type == "deleted":
            if str(path) in self.baseline:
                del self.baseline[str(path)]
                findings.append(Finding(target=str(path), module="fs_monitor", finding_type="file_deleted", description="Arquivo deletado (evento ao vivo).", severity="high", details={}))
        elif event.event_type == "modified":
            if old_state and new_state:
                if new_state.mode != old_state.mode:
                    findings.append(Finding(target=str(path), module="fs_monitor", finding_type="perms_changed", description="Permissões alteradas (ao vivo).", severity="high", details={"old": oct(old_state.mode), "new": oct(new_state.mode)}))
                if not old_state.is_suid_root and new_state.is_suid_root and str(path) not in self.suid_allowlist:
                    findings.append(Finding(target=str(path), module="fs_monitor", finding_type="setuid_added", description="Permissão SUID adicionada.", severity="critical", details={"mode": oct(new_state.mode)}))
                old_hash = old_state.sha256
                new_hash = new_state.sha256
                if not old_hash or (new_state.size != old_state.size or int(new_state.mtime) != int(old_state.mtime)):
                    if not new_hash:
                        new_hash = self._hash_file(path)
                if old_hash != new_hash:
                    findings.append(Finding(target=str(path), module="fs_monitor", finding_type="file_modified", description="Conteúdo do arquivo modificado (hash diferente).", severity="critical", details={"old_hash": old_hash, "new_hash": new_hash}))
                self.baseline[str(path)] = new_state
        if findings:
            _print_findings(findings)
            self._save_baseline()

class HybridFsEventHandler(FileSystemEventHandler):
    def __init__(self, monitor: FileSystemMonitor):
        super().__init__()
        self.monitor = monitor

    def on_created(self, event): self.monitor.handle_event(event)
    def on_deleted(self, event): self.monitor.handle_event(event)
    def on_modified(self, event): self.monitor.handle_event(event)
    def on_moved(self, event):  # Moved = deleted + created
        self.monitor.handle_event(event)

def _print_findings(findings: List[Finding]):
    if not findings:
        print(ui.color(f"[{time.strftime('%H:%M:%S')}] Nenhuma mudança detectada.", ui.GRAY))
        return
    for finding in findings:
        color = ui.RED if finding.severity == "critical" else ui.YELLOW
        print(ui.color(f"\n[ALERTA] {finding.description}", ui.BOLD + color))
        print(f"  - Alvo: {finding.target}")
        print(f"  - Módulo: {finding.module} ({finding.finding_type})")
        for key, value in finding.details.items():
            print(f"  - {key.replace('_', ' ').capitalize()}: {value}")

def start_hybrid_monitor():
    ui.print_banner()
    print(ui.color("Monitor Híbrido de FS - Integridade + Eventos Ao Vivo", ui.CYAN))
    monitor = FileSystemMonitor()

    if not monitor.baseline:
        print(ui.color("Baseline não encontrada. Construindo baseline inicial...", ui.YELLOW))
        initial_findings = monitor.scan_integrity()
        print(ui.color(f"Baseline criada com {len(monitor.baseline)} arquivos.", ui.GREEN))
        _print_findings(initial_findings)

    print(ui.color("\nMonitoramento ao vivo iniciado... [Ctrl+C para sair]", ui.GREEN))

    observer = Observer()
    event_handler = HybridFsEventHandler(monitor)
    for path in monitor.paths_to_watch:
        observer.schedule(event_handler, path, recursive=True)
    observer.start()

    def periodic_scan():
        while True:
            time.sleep(60)  # Scanner a cada 60s (ajustável)
            findings = monitor.scan_integrity()
            _print_findings(findings)

    scanner_thread = threading.Thread(target=periodic_scan, daemon=True)
    scanner_thread.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print(ui.color("\nMonitoramento encerrado pelo usuário.", ui.YELLOW))
        observer.stop()
        observer.join()
        sys.exit(0)

if __name__ == "__main__":
    if os.geteuid() != 0:
        print(ui.color("Aviso: Para melhores resultados, execute este monitor como root.", ui.YELLOW))
    start_hybrid_monitor()
