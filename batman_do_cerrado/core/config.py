# batman-do-cerrado-pro/batman_do_cerrado/core/config.py

"""
Módulo Core Config - Ponto de acesso único para todas as configurações.
"""

import os
from pathlib import Path
from typing import Any, Dict, Optional

# ===================================================================
# ================= BLOCO DE DEPURAÇÃO ADICIONADO ===================
print("--- DEBUG: Iniciando a execução de core/config.py ---", flush=True)
settings_path_from_env = os.environ.get("BATMAN_SETTINGS_PATH")
print(f"DEBUG: Valor lido da variável de ambiente 'BATMAN_SETTINGS_PATH': {settings_path_from_env}", flush=True)
if settings_path_from_env:
    p = Path(settings_path_from_env)
    print(f"DEBUG: Objeto Path criado: {p}", flush=True)
    print(f"DEBUG: Verificando se o arquivo existe com p.is_file()...", flush=True)
    is_file_result = p.is_file()
    print(f"DEBUG: Resultado de p.is_file(): {is_file_result}", flush=True)
print("--- FIM DO BLOCO DE DEPURAÇÃO ---", flush=True)
# ===================================================================
# ===================================================================


# Tratamento de compatibilidade para a biblioteca TOML
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
            config_path = cls._instance._find_config_path()
            cls._instance._load_config(config_path)
        return cls._instance

    def _find_config_path(self) -> Optional[Path]:
        if env_path_str := os.environ.get("BATMAN_SETTINGS_PATH"):
            env_path = Path(env_path_str)
            if env_path.is_file():
                return env_path

        cwd = Path.cwd()
        possible_paths = [
            cwd / "config" / "settings.toml",
            cwd.parent / "config" / "settings.toml",
        ]
        for path in possible_paths:
            if path.is_file():
                return path
        
        return None

    def _load_config(self, path: Optional[Path]):
        if not path or not path.is_file():
            print(f"AVISO: Arquivo de configuração não encontrado. Operando com configurações padrão.", flush=True)
            self._config = {}
            return

        print(f"INFO: Carregando configuração de {path}", flush=True)
        with open(path, "rb") as f:
            self._config = tomllib.load(f)

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
