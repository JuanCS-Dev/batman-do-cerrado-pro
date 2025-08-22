import pytest
import time
from unittest.mock import MagicMock
# A linha `from unittest.mock import mocker` foi removida.
# O `mocker` é injetado automaticamente pelo pytest.
from batman_do_cerrado.modules.net_monitor import _parse_addr, FindingDeduplicator

def test_parse_addr_com_host_e_porta():
    """Verifica se _parse_addr retorna host e porta de um formato válido."""
    addr = "192.168.1.1:8080"
    result = _parse_addr(addr)
    assert result == ("192.168.1.1", "8080")

def test_parse_addr_com_host_e_porta_asterisco():
    """Verifica se _parse_addr retorna host e asterisco para portas curinga."""
    addr = "0.0.0.0:*"
    result = _parse_addr(addr)
    assert result == ("0.0.0.0", "*")

def test_parse_addr_sem_porta():
    """Verifica se _parse_addr retorna uma tupla com a porta vazia se não houver."""
    addr = "10.0.0.1"
    result = _parse_addr(addr)
    assert result == ("10.0.0.1", "")

def test_parse_addr_com_endereco_ipv6():
    """Verifica o parsing de endereços IPv6."""
    addr = "[::]:443"
    result = _parse_addr(addr)
    assert result == ("[::]", "443")

def test_parse_addr_com_formato_invalido():
    """Verifica se _parse_addr retorna tupla com porta vazia para formatos inválidos."""
    addr = "localhost"
    result = _parse_addr(addr)
    assert result == ("localhost", "")
    
def test_parse_addr_com_string_vazia():
    """Verifica o comportamento com uma string de entrada vazia."""
    addr = ""
    result = _parse_addr(addr)
    assert result == ("", "")

def test_deduplicator_com_eventos_repetidos(mocker):
    """
    Verifica se o deduplicador evita alertas repetidos no tempo.
    """
    # Usamos o mock para controlar o tempo, tornando o teste determinístico
    mocked_time = 1000.0
    mocker.patch('time.time', return_value=mocked_time)
    
    # Criamos a classe com um debounce de 10 segundos
    dedup = FindingDeduplicator(debounce_seconds=10)
    
    # Primeiro evento: deve passar
    assert dedup.should_emit('scan_from_ip:1.1.1.1') == True
    
    # Segundo evento, 5 segundos depois: deve ser bloqueado
    mocked_time += 5
    mocker.patch('time.time', return_value=mocked_time)
    assert dedup.should_emit('scan_from_ip:1.1.1.1') == False
    
    # Terceiro evento, 11 segundos depois do primeiro: deve passar
    mocked_time += 6 # Total de 11 segundos
    mocker.patch('time.time', return_value=mocked_time)
    assert dedup.should_emit('scan_from_ip:1.1.1.1') == True
    
    # Quarto evento para um IP diferente: deve passar imediatamente
    assert dedup.should_emit('scan_from_ip:2.2.2.2') == True
