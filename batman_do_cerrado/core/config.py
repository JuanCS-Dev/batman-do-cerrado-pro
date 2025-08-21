# batman-do-cerrado-pro/batman_do_cerrado/core/config.py

"""
Módulo Core Config - Ponto de acesso único para todas as configurações.

Lê o arquivo settings.toml e disponibiliza os valores de forma segura,
com suporte para fallbacks e leitura de variáveis de ambiente para segredos.
"""

import os
from pathlib import Path

# Tratamento de compatibilidade para a biblioteca TOML
try:
    import tomllib
except ImportError:
    # Para Python < 3.11, usamos a biblioteca de retrocompatibilidade 'tomli'
    import tomli as tomllib

from typing import Any, Dict

# --- Constantes ---
# A raiz do projeto é o diretório pai da pasta 'batman_do_cerrado'
PROJECT_ROOT = Path(__file__).parent.parent.parent
DEFAULT_CONFIG_PATH = PROJECT_ROOT / "config" / "settings.toml"

# --- O Leitor de Configuração ---

class Config:
    """
    Uma classe singleton para carregar e servir configurações do arquivo TOML.
    """
    _instance = None
    _config: Dict[str, Any] = {}

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super().__new__(cls)
            cls._instance._load_config()
        return cls._instance

    def _load_config(self, path: Path = DEFAULT_CONFIG_PATH):
        """Carrega o arquivo TOML. Chamado apenas uma vez."""
        if not path.is_file():
            # Em um cenário real, poderíamos logar um aviso ou erro aqui.
            # Por enquanto, operamos com um dicionário vazio se o arquivo não existir.
            print(f"AVISO: Arquivo de configuração não encontrado em {path}", flush=True)
            self._config = {}
            return

        with open(path, "rb") as f:
            self._config = tomllib.load(f)

    def get(self, section: str, key: str, fallback: Any = None) -> Any:
        """
        Busca um valor de uma seção específica.

        Ex: config.get('nmap_scanner', 'default_profile', 'padrao')
        """
        return self._config.get(section, {}).get(key, fallback)

    def get_section(self, section: str) -> Dict[str, Any]:
        """
        Retorna uma subseção do arquivo de configuração.

        Aceita nomes de seção separados por ponto para acessar níveis
        aninhados de configuração (ex: ``"nmap_scanner.profiles"``).

        Se qualquer parte do caminho não existir ou não for um dicionário,
        retorna um dicionário vazio.

        Args:
            section: O caminho da seção separado por pontos.

        Returns:
            Um dicionário com a subseção solicitada ou um dicionário vazio.
        """
        keys = section.split('.')
        data: Any = self._config
        for key in keys:
            if isinstance(data, dict):
                data = data.get(key, {})
            else:
                return {}
        return data if isinstance(data, dict) else {}

    def get_secret(self, key: str) -> str:
        """
        Busca um valor "secreto" de forma inteligente e segura.
        1. Tenta a variável de ambiente (em maiúsculas).
        2. Tenta o arquivo de configuração (na seção [core]).
        3. Retorna uma string vazia.
        """
        env_var = key.upper()
        value = os.environ.get(env_var)
        if value:
            return value
        
        return self.get('core', key, "")

# Instância única para ser importada por outros módulos.
# Desta forma, a configuração é carregada uma única vez na inicialização.
config = Config()

