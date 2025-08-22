# batman_do_cerrado/core/ui.py

"""
Módulo Core UI - Central de Cores, Banners e Componentes de Interface.
"""

import sys
import time
import itertools
from threading import Thread, Event

# --- Constantes de Cores (Fallback se a biblioteca falhar) ---
# (código das constantes de cores inalterado)
BLACK, RED, GREEN, YELLOW, BLUE, MAGENTA, CYAN, WHITE = (f"\033[{i}m" for i in range(30, 38))
BOLD, RESET = "\033[1m", "\033[0m"
GRAY = "\033[90m"

def color(text: str, *styles: str) -> str:
    """Aplica múltiplos estilos de cor/formatação a um texto."""
    style_str = "".join(styles)
    return f"{style_str}{text}{RESET}"

def print_banner():
    """Imprime o banner principal do programa."""
    banner_text = r"""
🦇 Batman do Cerrado
      ____              _            _            
     |  _ \            | |          | |           
     | |_) | __ _ _ __ | | __ _ _ __| | ___  ___  
     |  _ < / _` | '_ \| |/ _` | '__| |/ _ \/ __| 
     | |_) | (_| | |   <| | (_| | |  | |  __/\__ \ 
     |____/ \__,_|_|  \_\_|\__,_|_|  |_|\___||___/ 
Self-system security • OSINT/Forensics • Linux-first
    """
    print(color(banner_text, BOLD, YELLOW))

def clear_screen():
    """Limpa a tela do terminal."""
    print("\033[H\033[J", end="")

def pause():
    """Pausa a execução e espera o usuário pressionar Enter."""
    input(color("\nPressione Enter para continuar...", GRAY))

# _ADICIONADO_: Classe de Spinner para feedback visual em operações longas.
class Spinner:
    """
    Um spinner de terminal simples que roda em uma thread separada.
    Uso:
        with Spinner("Carregando..."):
            time.sleep(5)
    """
    def __init__(self, message: str = "Processando...", delay: float = 0.1):
        self.message = message
        self.delay = delay
        self._spinner = itertools.cycle(['⠇', '⠏', '⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧'])
        self._stop_event = Event()
        self._thread = Thread(target=self._spin, daemon=True)

    def _spin(self):
        """Função interna que roda na thread, atualizando o spinner."""
        while not self._stop_event.is_set():
            spin_char = next(self._spinner)
            # \r move o cursor para o início da linha
            sys.stdout.write(f"\r{color(spin_char, YELLOW)} {self.message} ")
            sys.stdout.flush()
            time.sleep(self.delay)

    def start(self):
        """Inicia a animação do spinner."""
        self._thread.start()

    def stop(self):
        """Para a animação do spinner e limpa a linha."""
        self._stop_event.set()
        # Espera a thread terminar para evitar sobreposição de prints
        if self._thread.is_alive():
            self._thread.join()
        # Limpa a linha do spinner
        sys.stdout.write(f"\r{' ' * (len(self.message) + 5)}\r")
        sys.stdout.flush()

    # Permite o uso com 'with' (ex: with Spinner(...):)
    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.stop()
