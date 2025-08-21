# batman-do-cerrado-pro/batman_do_cerrado/core/dispatcher.py

"""
Módulo Core Dispatcher - O Ponto de Entrada Único do Framework.

Esta função é a interface programática principal para o framework Batman do Cerrado.
Ela permite que qualquer aplicação externa (como um CLI, uma API web, etc.)
execute um módulo de análise de forma simples e receba os resultados de
forma estruturada.
"""

import importlib
from typing import Any, Optional

from batman_do_cerrado.core import ui

def run_module(module_name: str, **kwargs: Any) -> Any:
    """
    Carrega e executa dinamicamente a função 'analyze' de um módulo.

    Args:
        module_name: O nome do módulo a ser executado (ex: "whois", "nmap_scanner").
        **kwargs: Argumentos a serem passados para a função 'analyze' do módulo.

    Returns:
        O resultado estruturado da função 'analyze' do módulo (geralmente um
        dataclass ou uma lista deles), ou None em caso de erro.
    """
    try:
        # Caminho completo para o módulo dentro do nosso pacote
        module_path = f"batman_do_cerrado.modules.{module_name}"
        
        # Usamos importlib para importar o módulo dinamicamente a partir de seu nome
        module = importlib.import_module(module_path)

        # Por convenção, todos os nossos módulos devem ter uma função 'analyze'
        if hasattr(module, "analyze"):
            analyze_func = getattr(module, "analyze")
            # Executa a função, passando os argumentos recebidos
            return analyze_func(**kwargs)
        else:
            print(ui.color(f"ERRO: O módulo '{module_name}' não possui uma função 'analyze'.", ui.RED))
            return None

    except ImportError:
        print(ui.color(f"ERRO: Módulo de análise '{module_name}' não encontrado.", ui.RED))
        return None
    except Exception as e:
        print(ui.color(f"ERRO inesperado ao executar o módulo '{module_name}': {e}", ui.RED))
        return None
