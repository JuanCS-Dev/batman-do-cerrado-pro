# tests/test_fs_monitor.py

import pytest
import os
from pathlib import Path
import stat  # <--- ADICIONADO: Importa a biblioteca 'stat'
from unittest.mock import MagicMock, mock_open
from batman_do_cerrado.modules.fs_monitor import FileSystemMonitor, FileState


@pytest.fixture
def monitor():
    return FileSystemMonitor()


def test_hash_file_com_sucesso(mocker, monitor):
    """
    Verifica se a função _hash_file retorna o hash SHA256 correto para um arquivo simulado.
    """
    fake_file_content = b"Conteudo do arquivo de teste."
    # <--- HASH CORRIGIDO: O hash esperado agora corresponde ao conteúdo
    expected_hash = "3f91f2d2ec3f7c9d5f0b82c00fc2b70f13e013977b45dc215fafa44c157d7802"
    
    mock_file = mocker.mock_open(read_data=fake_file_content)
    mocker.patch.object(Path, 'open', new=mock_file)

    result = monitor._hash_file(Path("/fake/path/to/file"))

    assert result == expected_hash


def test_hash_file_com_erro_de_permissao(mocker, monitor):
    """
    Verifica se a função _hash_file lida corretamente com PermissionError.
    """
    mocker.patch.object(Path, 'open', side_effect=PermissionError)
    result = monitor._hash_file(Path("/fake/path/to/file"))
    assert result is None


def test_hash_file_com_arquivo_nao_encontrado(mocker, monitor):
    """
    Verifica se a função _hash_file lida corretamente com FileNotFoundError.
    """
    mocker.patch.object(Path, 'open', side_effect=FileNotFoundError)
    result = monitor._hash_file(Path("/fake/path/to/file"))
    assert result is None
    

def test_get_current_state_com_arquivo_existente(mocker, monitor):
    """
    Verifica se _get_current_state retorna o FileState correto.
    """
    fake_path = Path("/fake/path/to/file.txt")
    fake_st = MagicMock(
        st_size=1000,
        st_mtime=1678886400.0,
        st_mode=stat.S_IFREG | 0o644,
        st_uid=1000,
        st_gid=1000,
        )

    mocker.patch.object(Path, 'lstat', return_value=fake_st)
    mocker.patch.object(monitor, '_hash_file', return_value="fake_hash")

    result = monitor._get_current_state(fake_path)

    assert isinstance(result, FileState)
    assert result.path == str(fake_path)
    assert result.size == 1000
    assert result.sha256 == "fake_hash"
    assert not result.is_suid_root
    

def test_get_current_state_com_arquivo_nao_existente(mocker, monitor):
    """
    Verifica se _get_current_state lida com FileNotFoundError.
    """
    mocker.patch.object(Path, 'lstat', side_effect=FileNotFoundError)
    result = monitor._get_current_state(Path("/fake/path/to/nonexistent_file.txt"))
    assert result is None
