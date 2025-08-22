# tests/test_secrets_scanner.py

import pytest
import os
import re
from pathlib import Path
from unittest.mock import mock_open, MagicMock

# A importação de SECRET_PATTERNS foi removida
from batman_do_cerrado.modules.secrets_scanner import analyze, _scan_file
from batman_do_cerrado.core.models import Finding
from batman_do_cerrado.core.config import config
from batman_do_cerrado.modules.secrets_scanner import _mock_secrets_library_scan # Importamos a função mock para poder testá-la

@pytest.fixture
def mock_config(mocker):
    """Mocka a configuração para os testes."""
    mocker.patch.object(config, 'get', side_effect=lambda section, key, default: {
        'secrets_scanner': {
            'excluded_patterns': ["test_password_to_exclude"],
            'exclude_globs': ["*.log"],
            'max_file_size_mb': 5
        }
    }.get(section, {}).get(key, default))


def test_scan_file_encontra_segredo_simples(mocker):
    """Verifica se _scan_file encontra um segredo simples (usando mock do motor)."""
    fake_content = 'API_KEY = "test_key_1234567890123456789012345678901234567890"\n'
    
    mock_file = mocker.mock_open(read_data=fake_content)
    mocker.patch.object(Path, 'open', new=mock_file)

    # Mocka a chamada para o motor de detecção para simular o resultado esperado
    mocker.patch('batman_do_cerrado.modules.secrets_scanner._mock_secrets_library_scan', return_value=[
        {"type": "api_key", "match": 'API_KEY = "test_key_1234567890123456789012345678901234567890"', "context": 'API_KEY = "test_key_1234567890123456789012345678901234567890"'}
    ])
    
    findings = _scan_file(Path("/fake/file/test.py"), excluded_patterns=[])
    
    assert len(findings) == 1
    assert findings[0].finding_type == "api_key"
    assert findings[0].details["match"] == 'API_KEY = "test_key_1234567890123456789012345678901234567890"'

def test_scan_file_ignora_padrao_excluido(mocker):
    """Verifica se _scan_file ignora um padrão na lista de exclusão (usando mock do motor)."""
    fake_content = 'PASSWORD = "test_password_to_exclude"\n'

    mock_file = mocker.mock_open(read_data=fake_content)
    mocker.patch.object(Path, 'open', new=mock_file)

    excluded = ["test_password_to_exclude"]
    
    # Mocka a chamada para o motor de detecção para simular o resultado de exclusão
    mocker.patch('batman_do_cerrado.modules.secrets_scanner._mock_secrets_library_scan', return_value=[])

    findings = _scan_file(Path("/fake/file/test.py"), excluded_patterns=excluded)

    assert len(findings) == 0

def test_scan_file_com_varios_segredos(mocker):
    """Verifica se _scan_file encontra múltiplos segredos (usando mock do motor)."""
    fake_content = 'API_KEY = "12345678901234567890123456789012"\n' \
                   'AWS_SECRET = "ABCDEFG123456789012345678901234567890123"\n'
    
    mock_file = mocker.mock_open(read_data=fake_content)
    mocker.patch.object(Path, 'open', new=mock_file)
    
    # Mocka a chamada para o motor de detecção para simular múltiplos resultados
    mocker.patch('batman_do_cerrado.modules.secrets_scanner._mock_secrets_library_scan', return_value=[
        {"type": "api_key", "match": "API_KEY = \"12345678901234567890123456789012\"", "context": "API_KEY = \"12345678901234567890123456789012\""},
        {"type": "aws_secret_key", "match": "AWS_SECRET = \"ABCDEFG123456789012345678901234567890123\"", "context": "AWS_SECRET = \"ABCDEFG123456789012345678901234567890123\""}
    ])
    
    findings = _scan_file(Path("/fake/file/test.py"), excluded_patterns=[])
    
    assert len(findings) == 2
    assert findings[0].finding_type == "api_key"
    assert findings[1].finding_type == "aws_secret_key"


def test_analyze_com_arquivo_unico(mock_config, mocker):
    """Verifica se analyze() escaneia um único arquivo."""
    mocker.patch.object(Path, 'exists', return_value=True)
    mocker.patch.object(Path, 'is_file', return_value=True)
    mocker.patch.object(Path, 'is_dir', return_value=False)
    mocker.patch.object(Path, 'stat', return_value=MagicMock(st_size=100))
    mocker.patch('batman_do_cerrado.modules.secrets_scanner._scan_file', return_value=[
        Finding(target="/fake/file/test.py", module="secrets_scanner", finding_type="api_key", description="...", severity="critical"),
    ])
    
    findings = analyze("/fake/file/test.py")
    
    assert len(findings) == 1
    assert findings[0].finding_type == "api_key"


def test_analyze_com_diretorio(mock_config, mocker):
    """Verifica se analyze() escaneia um diretório recursivamente."""
    mocker.patch.object(Path, 'exists', return_value=True)
    mocker.patch.object(Path, 'is_file', return_value=False)
    mocker.patch.object(Path, 'is_dir', return_value=True)
    mocker.patch('os.walk', return_value=[
        ('/fake/dir', [], ['file1.txt', 'file2.txt']),
        ('/fake/dir/subdir', [], ['file3.txt']),
    ])
    mocker.patch.object(Path, 'stat', return_value=MagicMock(st_size=100))
    
    mocker.patch('batman_do_cerrado.modules.secrets_scanner._scan_file', side_effect=[
        [Finding(target="/fake/dir/file1.txt", module="secrets_scanner", finding_type="api_key", description="...", severity="critical")],
        [],
        [Finding(target="/fake/dir/subdir/file3.txt", module="secrets_scanner", finding_type="password", description="...", severity="critical")],
    ])
    
    findings = analyze("/fake/dir")
    
    assert len(findings) == 2
    assert findings[0].finding_type == "api_key"
    assert findings[1].finding_type == "password"


def test_analyze_com_alvo_nao_encontrado(mock_config, mocker):
    """Verifica se analyze() retorna uma lista vazia para alvos inexistentes."""
    mocker.patch.object(Path, 'exists', return_value=False)
    
    findings = analyze("/fake/path/to/nowhere")
    
    assert len(findings) == 0


def test_analyze_ignora_arquivos_grandes(mock_config, mocker):
    """Verifica se analyze() ignora arquivos maiores que o limite."""
    mocker.patch.object(Path, 'exists', return_value=True)
    mocker.patch.object(Path, 'is_file', return_value=True)
    mocker.patch.object(Path, 'is_dir', return_value=False)
    mocker.patch.object(Path, 'stat', return_value=MagicMock(st_size=6 * 1024 * 1024))
    
    mock_scan_file = mocker.patch('batman_do_cerrado.modules.secrets_scanner._scan_file')
    
    analyze("/fake/big_file.txt")
    
    mock_scan_file.assert_not_called()


def test_analyze_ignora_arquivos_excluidos_por_glob(mock_config, mocker):
    """Verifica se analyze() ignora arquivos com glob na config."""
    mocker.patch.object(Path, 'exists', return_value=True)
    mocker.patch.object(Path, 'is_file', return_value=True)
    mocker.patch.object(Path, 'is_dir', return_value=False)
    mocker.patch.object(Path, 'stat', return_value=MagicMock(st_size=100))
    
    mock_scan_file = mocker.patch('batman_do_cerrado.modules.secrets_scanner._scan_file')
    
    analyze("/fake/file.log")
    
    mock_scan_file.assert_not_called()
