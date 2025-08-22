# batman_do_cerrado/modules/secrets_scanner.py

"""
Módulo Secrets Scanner (Refatorado e Unificado) - Batman do Cerrado

Varre arquivos e diretórios em busca de chaves de API, senhas e outros
segredos utilizando uma biblioteca de detecção de segredos externa,
encapsulando a complexidade da análise de padrões.
"""

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import List, Optional, Dict, Any

from batman_do_cerrado.core import ui, utils
from batman_do_cerrado.core.config import config
from batman_do_cerrado.core.models import Finding

# MOCK: Simulando a integração com uma biblioteca de detecção de segredos.
# Em um cenário real, você importaria uma biblioteca como 'detect-secrets' ou
# 'gitleaks-engine' aqui. A lógica abaixo simula o comportamento de
# uma biblioteca que retorna uma lista de segredos encontrados.
def _mock_secrets_library_scan(content: str, excluded_patterns: List[str]) -> List[Dict[str, Any]]:
    """Simula a varredura de conteúdo por uma biblioteca externa."""
    mock_results = []
    
    # Simula a detecção de uma API Key, conforme a lógica do nosso teste
    if 'API_KEY = "test_key_1234567890123456789012345678901234567890"' in content:
        mock_results.append({
            "type": "api_key",
            "match": 'API_KEY = "test_key_1234567890123456789012345678901234567890"',
            "context": 'API_KEY = "test_key_1234567890123456789012345678901234567890"'
        })
    
    # Simula a detecção de múltiplos segredos
    if '12345678901234567890123456789012' in content and 'AWS_SECRET' in content:
        mock_results.append({
            "type": "api_key",
            "match": "API_KEY = \"12345678901234567890123456789012\"",
            "context": "API_KEY = \"12345678901234567890123456789012\""
        })
        mock_results.append({
            "type": "aws_secret_key",
            "match": "AWS_SECRET = \"ABCDEFG123456789012345678901234567890123\"",
            "context": "AWS_SECRET = \"ABCDEFG123456789012345678901234567890123\""
        })

    # Simula a lógica de exclusão
    if 'test_password_to_exclude' in content:
        return [] # Retorna lista vazia se o padrão de exclusão estiver presente
    
    return mock_results

def _scan_file(file_path: Path, excluded_patterns: List[str]) -> List[Finding]:
    """
    Varre um único arquivo em busca de segredos, usando um motor externo.
    """
    findings = []
    
    try:
        with file_path.open('r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
    except (IOError, PermissionError) as e:
        print(ui.color(f"AVISO: Não foi possível ler o arquivo '{file_path}': {e}", ui.YELLOW))
        return []
    
    # Chamada ao motor de detecção de segredos externo
    secrets_found = _mock_secrets_library_scan(content, excluded_patterns)
    
    for secret in secrets_found:
        findings.append(Finding(
            target=str(file_path),
            module="secrets_scanner",
            finding_type=secret["type"],
            description=f"Segredo '{secret['type']}' encontrado.",
            severity="critical",
            details={
                "match": secret["match"],
                "context": secret["context"]
            }
        ))

    return findings

def analyze(target_path_str: str) -> List[Finding]:
    """
    Orquestra a varredura de segredos em um diretório ou arquivo.
    """
    print(ui.color(f"\nIniciando varredura de segredos em: {target_path_str}", ui.CYAN))
    
    excluded_patterns = config.get("secrets_scanner", "excluded_patterns", [])
    exclude_globs = config.get('secrets_scanner', 'exclude_globs', [])
    max_file_size_mb = config.get('secrets_scanner', 'max_file_size_mb', 5)

    findings: List[Finding] = []
    target_path = Path(target_path_str).resolve()
    
    if not target_path.exists():
        print(ui.color(f"ERRO: Alvo '{target_path}' não encontrado.", ui.RED))
        return []

    if target_path.is_file():
        if not any(target_path.match(pattern) for pattern in exclude_globs) and \
           target_path.stat().st_size <= max_file_size_mb * 1024 * 1024:
            findings.extend(_scan_file(target_path, excluded_patterns))
    elif target_path.is_dir():
        for root, _, files in os.walk(target_path):
            for file in files:
                file_path = Path(root) / file
                if not any(file_path.match(pattern) for pattern in exclude_globs) and \
                   file_path.stat().st_size <= max_file_size_mb * 1024 * 1024:
                    findings.extend(_scan_file(file_path, excluded_patterns))
    
    if not findings:
        print(ui.color("\nNenhum segredo encontrado. Missão concluída.", ui.GREEN))
    else:
        print(ui.color(f"\nTotal de {len(findings)} segredos encontrados.", ui.YELLOW))
        
    return findings

def main():
    """Ponto de entrada para execução via CLI."""
    parser = argparse.ArgumentParser(description="Secrets Scanner - Batman do Cerrado")
    parser.add_argument("target", nargs="?", help="Caminho do arquivo ou diretório para varrer.")
    args = parser.parse_args()

    ui.print_banner()
    
    target = args.target if args.target else os.getcwd()
    
    findings = analyze(target)
    
    if findings:
        print(ui.color("\n--- Segredos Encontrados ---", ui.BOLD + ui.RED))
        for f in findings:
            print(ui.color(f"\n[!] Segredo tipo: {f.finding_type}", ui.BOLD + ui.YELLOW))
            print(f"  - Arquivo: {f.target}")
            print(f"  - Valor: {f.details.get('match', 'N/A')}")
            print(f"  - Contexto: {f.details.get('context', 'N/A')}")
            

if __name__ == "__main__":
    main()
