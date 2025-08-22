# batman-do-cerrado-pro/batman_do_cerrado/core/config.py (Versão Kamikaze)

import os
import sys
from typing import Any, Dict, Optional
from importlib import resources

try:
    import tomllib
except ImportError:
    import tomli as tomllib

class Config:
    _instance: Optional['Config'] = None
    _config: Dict[str, Any] = {}

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super().__new__(cls)
            cls._instance._load_config()
        return cls._instance

    def _load_config(self):
        """
        Carrega o arquivo TOML. Se falhar, imprime o erro exato e aborta.
        """
        try:
            config_file = resources.files('batman_do_cerrado.config').joinpath('settings.toml')
            with config_file.open('rb') as f:
                self._config = tomllib.load(f)
        except Exception as e:
            # _ALTERADO_: Este bloco agora é barulhento e fatal.
            print("--- ERRO FATAL AO CARREGAR A CONFIGURAÇÃO ---", file=sys.stderr)
            try:
                # Tenta imprimir o caminho do arquivo para referência
                print(f"ARQUIVO: {resources.files('batman_do_cerrado.config').joinpath('settings.toml')}", file=sys.stderr)
            except Exception:
                print("ARQUIVO: Não foi possível determinar o caminho do arquivo de configuração.", file=sys.stderr)
            
            print(f"TIPO DE ERRO: {type(e).__name__}", file=sys.stderr)
            print(f"MENSAGEM: {e}", file=sys.stderr)
            print("-------------------------------------------------", file=sys.stderr)
            sys.exit(1) # Aborta a execução imediatamente.

    def get(self, section: str, key: str, fallback: Any = None) -> Any:
        return self._config.get(section, {}).get(key, fallback)

    def get_section(self, section: str) -> Dict[str, Any]:
        return self._config.get(section, {})

    def get_secret(self, key: str) -> str:
        env_var = key.upper()
        value = os.environ.get(env_var)
        if value:
            return value
        return self.get('core', key, "")

config = Config()
