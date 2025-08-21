# batman-do-cerrado-pro/batman_do_cerrado/core/utils.py

"""
Módulo Core Utils - O canivete suíço do Batman do Cerrado.

Centraliza funções utilitárias para interações com o sistema operacional,
como execução de subprocessos e verificação de binários.
"""

import shutil
import subprocess
from dataclasses import dataclass
from typing import List, Optional

# --- Modelo de Dados para Comandos ---

@dataclass
class CommandResult:
    """Estrutura para encapsular o resultado de um comando de terminal."""
    stdout: str
    stderr: str
    return_code: int
    success: bool

    def __bool__(self) -> bool:
        """Permite checar o resultado como um booleano (if result: ...)."""
        return self.success

# --- Funções Utilitárias de Sistema ---

def run_command(cmd: List[str], timeout: int = 20) -> CommandResult:
    """
    Executa um comando de terminal de forma segura e robusta.

    Args:
        cmd: O comando e seus argumentos como uma lista de strings.
        timeout: Tempo máximo de espera em segundos.

    Returns:
        Um objeto CommandResult com a saída e o status da execução.
    """
    try:
        process = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='ignore',
            timeout=timeout,
            check=False  # Não levanta exceção para códigos de saída != 0
        )
        return CommandResult(
            stdout=process.stdout.strip(),
            stderr=process.stderr.strip(),
            return_code=process.returncode,
            success=(process.returncode == 0)
        )
    except FileNotFoundError:
        return CommandResult(
            stdout="",
            stderr=f"Erro: Comando '{cmd[0]}' não encontrado.",
            return_code=127,
            success=False
        )
    except subprocess.TimeoutExpired:
        return CommandResult(
            stdout="",
            stderr=f"Erro: Comando excedeu o tempo limite de {timeout}s.",
            return_code=124,
            success=False
        )
    except Exception as e:
        return CommandResult(
            stdout="",
            stderr=f"Erro inesperado ao executar o comando: {e}",
            return_code=1,
            success=False
        )

def find_binary(name: str) -> Optional[str]:
    """
    Verifica se um binário existe no PATH do sistema.

    Args:
        name: O nome do binário (ex: 'nmap', 'dig').

    Returns:
        O caminho completo para o binário se encontrado, senão None.
    """
    return shutil.which(name)
