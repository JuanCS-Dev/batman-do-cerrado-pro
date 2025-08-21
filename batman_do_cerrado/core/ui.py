# batman-do-cerrado-pro/batman_do_cerrado/core/ui.py

"""
Módulo Core UI - A fonte de verdade para toda a interface do usuário no terminal.

Centraliza cores, banners e funções de interação para manter a identidade visual
consistente em todo o framework "Batman do Cerrado".
"""

import os
import sys
from typing import List

# --- Constantes de Cores ANSI ---
RESET = "\033[0m"
BOLD = "\033[1m"
CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
GRAY = "\033[90m"
BLUE = "\033[94m"
MAGENTA = "\033[95m"

# --- Funções de UI ---

def color(text: str, col: str) -> str:
    """Aplica uma cor ANSI a um texto."""
    return f"{col}{text}{RESET}"

def clear_screen() -> None:
    """Limpa a tela do terminal de forma portável."""
    if os.name == "nt":
        os.system("cls")
    elif os.environ.get("TERM"):
        os.system("clear")
    else:
        # Fallback para ambientes sem 'clear' (ex: CI/CD)
        print("\n" * 100)

def pause(msg: str = "Pressione Enter para continuar...") -> None:
    """Pausa a execução até o usuário pressionar Enter."""
    try:
        input(color(f"\n{msg}", GRAY))
    except (EOFError, KeyboardInterrupt):
        # Lida com interrupções de forma graciosa
        print()
        sys.exit(0)

def print_banner() -> None:
    """Exibe o cabeçalho ASCII do Batman do Cerrado."""
    art = [
        r"      ____        _                       _            ",
        r"     |  _ \      | |                     | |           ",
        r"     | |_) | __ _| |_ __ _ _ __ ___   ___| | ___  ___  ",
        r"     |  _ < / _` | __/ _` | '_ ` _ \ / _ \ |/ _ \/ __| ",
        r"     | |_) | (_| | || (_| | | | | | |  __/ |  __/\__ \ ",
        r"     |____/ \__,_|\__\__,_|_| |_| |_|\___|_|\___||___/ ",
    ]
    print(color(BOLD + "🦇 Batman do Cerrado" + RESET, CYAN))
    for line in art:
        print(color(line, GRAY))
    print(color("Self‑system security • OSINT/Forensics • Linux-first", GRAY))
    print()
