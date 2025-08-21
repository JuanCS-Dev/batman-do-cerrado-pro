# batman-do-cerrado-pro/batman_do_cerrado/modules/fs_monitor.py

"""
Módulo FS Monitor (Refatorado) - Batman do Cerrado

Vigia a integridade de arquivos e diretórios, agora totalmente integrado
ao framework, utilizando a configuração central e retornando "Findings"
padronizados.
"""

import hashlib
import json
import os
import stat
import sys
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, Optional, List, Generator, Any

# Importações do nosso framework
from batman_do_cerrado.core import ui, utils
from batman_do_cerrado.core.config import PROJECT_ROOT as CORE_PROJECT_ROOT
from batman_do_cerrado.core.config import config
from batman_do_cerrado.core.models import Finding

# --- Modelo de Dados Interno do Módulo ---
@dataclass
class FileState:
    """Representa o estado de um arquivo em um ponto no tempo."""
    path: str
    size: int
    mtime: float
    mode: int
    uid: int
    gid: int
    sha256: Optional[str] = None

    @property
    def is_suid_root(self) -> bool:
        """Verifica se a permissão SUID está ativa e o dono é root."""
        return bool(self.mode & stat.S_ISUID and self.uid == 0)

# --- Lógica do Monitor ---

class FileSystemMonitor:
    """Encapsula a lógica de monitoramento de integridade de arquivos."""

    def __init__(self):
        # Carrega as configurações do arquivo settings.toml
        self.paths_to_watch = config.get('fs_monitor', 'default_paths', [])
        self.suid_allowlist = set(config.get('fs_monitor', 'suid_allowlist', []))
        self.exclude_globs = config.get('fs_monitor', 'default_excludes', [])
        
        # Define os caminhos de dados e logs usando a raiz do projeto. 'utils' não possui
        # PROJECT_ROOT, portanto usamos o valor da configuração central.
        self.baseline_path = CORE_PROJECT_ROOT / "data" / "baselines" / "fs_baseline.json"
        
        self.baseline: Dict[str, FileState] = self._load_baseline()
        self.hash_max_bytes = 5 * 1024 * 1024 # Limite para hashing (pode ir pra config)

    def _hash_file(self, path: Path) -> Optional[str]:
        """Calcula o hash SHA256 de um arquivo, com tratamento de erros."""
        h = hashlib.sha256()
        try:
            with path.open("rb") as f:
                while chunk := f.read(1024 * 1024): # Le em chunks de 1MB
                    h.update(chunk)
            return h.hexdigest()
        except (IOError, PermissionError):
            return None

    def _get_current_state(self, path: Path) -> Optional[FileState]:
        """Obtém o estado atual de um arquivo no disco."""
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

    def _load_baseline(self) -> Dict[str, FileState]:
        """Carrega a baseline do arquivo JSON."""
        self.baseline_path.parent.mkdir(parents=True, exist_ok=True)
        if not self.baseline_path.is_file():
            return {}
        try:
            raw_data = json.loads(self.baseline_path.read_text(encoding="utf-8"))
            return {path: FileState(**data) for path, data in raw_data.items()}
        except (json.JSONDecodeError, TypeError):
            print(ui.color("AVISO: Baseline corrompida. Uma nova será criada.", ui.YELLOW))
            return {}

    def _save_baseline(self):
        """Salva o estado atual da baseline em disco."""
        raw_data = {path: asdict(state) for path, state in self.baseline.items()}
        self.baseline_path.write_text(json.dumps(raw_data, indent=2), encoding="utf-8")

    def check_changes(self) -> Generator[Finding, None, None]:
        """
        Executa um ciclo de verificação e gera 'Findings' para cada mudança detectada.
        Esta é a implementação da lógica de "deltas".
        """
        current_paths_on_disk = set()
        
        # Itera sobre os arquivos no disco
        for watch_path_str in self.paths_to_watch:
            watch_path = Path(watch_path_str).expanduser()
            for root, _, files in os.walk(watch_path):
                for name in files:
                    path = Path(root) / name
                    current_paths_on_disk.add(str(path))
                    
                    old_state = self.baseline.get(str(path))
                    new_state = self._get_current_state(path)

                    if not new_state: continue

                    if not old_state:
                        # --- ARQUIVO NOVO ---
                        self.baseline[str(path)] = new_state
                        yield Finding(
                            target=str(path), module="fs_monitor", finding_type="file_created",
                            description=f"Novo arquivo detectado.", severity="medium",
                            details={"size": new_state.size, "mode": oct(new_state.mode)}
                        )
                        if new_state.is_suid_root and str(path) not in self.suid_allowlist:
                            yield Finding(
                                target=str(path), module="fs_monitor", finding_type="setuid_added",
                                description="Novo arquivo com permissão SUID perigosa.", severity="critical",
                                details={"mode": oct(new_state.mode)}
                            )
                        continue

                    # --- ARQUIVO EXISTENTE: COMPARAR ---
                    if new_state.mode != old_state.mode:
                        yield Finding(
                            target=str(path), module="fs_monitor", finding_type="perms_changed",
                            description="Permissões do arquivo foram alteradas.", severity="high",
                            details={"old": oct(old_state.mode), "new": oct(new_state.mode)}
                        )

                    if not old_state.is_suid_root and new_state.is_suid_root and str(path) not in self.suid_allowlist:
                        yield Finding(
                            target=str(path), module="fs_monitor", finding_type="setuid_added",
                            description="Permissão SUID perigosa foi adicionada a um arquivo existente.", severity="critical",
                            details{"mode": oct(new_state.mode)}
                        )
                    
                    # Para arquivos grandes, o hash só é calculado se o tamanho ou mtime mudar.
                    old_hash = old_state.sha256
                    new_hash = new_state.sha256
                    if not old_hash or (new_state.size != old_state.size or int(new_state.mtime) != int(old_state.mtime)):
                        if not new_hash: # Se o arquivo for grande, calcula o hash agora
                            new_hash = self._hash_file(path)
                    
                    if old_hash != new_hash:
                        yield Finding(
                            target=str(path), module="fs_monitor", finding_type="file_modified",
                            description="Conteúdo do arquivo foi modificado (hash diferente).", severity="critical",
                            details={"old_hash": old_hash, "new_hash": new_hash}
                        )

                    # Atualiza a baseline com o estado mais recente
                    self.baseline[str(path)] = new_state

        # --- ARQUIVOS DELETADOS ---
        deleted_paths = set(self.baseline.keys()) - current_paths_on_disk
        for path_str in deleted_paths:
            del self.baseline[path_str]
            yield Finding(
                target=path_str, module="fs_monitor", finding_type="file_deleted",
                description="Arquivo que estava na baseline foi deletado.", severity="high",
                details={}
            )
        
        self._save_baseline()


def _print_findings(findings: List[Finding]):
    """Imprime uma lista de achados de forma organizada."""
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


def main():
    """Ponto de entrada para o monitor em modo de loop contínuo."""
    ui.print_banner()
    print(ui.color("Módulo de Monitor de Integridade de Arquivos (Refatorado)", ui.CYAN))
    
    monitor = FileSystemMonitor()
    
    # Se a baseline estiver vazia, constrói a primeira versão
    if not monitor.baseline:
        print(ui.color("Baseline não encontrada. Construindo baseline inicial...", ui.YELLOW))
        # A primeira execução popula a baseline e gera "achados" informativos
        initial_findings = list(monitor.check_changes())
        print(ui.color(f"Baseline criada com {len(monitor.baseline)} arquivos.", ui.GREEN))
        _print_findings(initial_findings)

    print(ui.color("\nIniciando monitoramento em tempo real... (Pressione Ctrl+C para sair)", ui.GREEN))
    try:
        while True:
            findings = list(monitor.check_changes())
            _print_findings(findings)
            time.sleep(5) # Intervalo de verificação
    except KeyboardInterrupt:
        print(ui.color("\nMonitoramento encerrado pelo usuário.", ui.YELLOW))
        sys.exit(0)

if __name__ == "__main__":
    if os.geteuid() != 0:
        print(ui.color("Aviso: Para melhores resultados, execute este monitor como root.", ui.YELLOW))
    main()

