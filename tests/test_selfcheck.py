# tests/test_selfcheck.py

import pytest
from unittest.mock import MagicMock
from batman_do_cerrado.modules.selfcheck import _get_public_ip, analyze
from batman_do_cerrado.core.models import IPAddressInfo, PortInfo
from ipwhois.exceptions import IPDefinedError
import requests

# Testes de unidade para _get_public_ip
def test_get_public_ip_com_sucesso(mocker):
    """Verifica se _get_public_ip retorna o IP corretamente."""
    mocker.patch(
        'requests.get',
        return_value=MagicMock(text="1.2.3.4", status_code=200, raise_for_status=MagicMock())
    )
    assert _get_public_ip() == "1.2.3.4"

def test_get_public_ip_com_falha(mocker):
    """Verifica se _get_public_ip retorna None em caso de falha de conexão."""
    mocker.patch('requests.get', side_effect=requests.exceptions.RequestException)
    assert _get_public_ip() is None

# Teste de integração para analyze()
@pytest.fixture
def mock_all(mocker):
    """Fixture para mockar todas as dependências do analyze()."""
    # Mocka o IP público
    mocker.patch('batman_do_cerrado.modules.selfcheck._get_public_ip', return_value='8.8.8.8')
    
    # Mocka o ip_analyzer
    mock_ip_info = IPAddressInfo(ip='8.8.8.8', version=4, isp='Google', country_code='US')
    mocker.patch('batman_do_cerrado.modules.ip_analyzer.analyze', return_value=mock_ip_info)
    
    # Mocka o nmap_scanner
    # <--- CORREÇÃO: Adicionando o campo 'protocol' faltante no PortInfo.
    mock_nmap_info = IPAddressInfo(ip='8.8.8.8', version=4, ports=[PortInfo(port_id=53, protocol='tcp', state='open')])
    mocker.patch('batman_do_cerrado.modules.nmap_scanner.analyze', return_value=[mock_nmap_info])
    
    # Mocka o salvamento de arquivos
    mocker.patch('os.makedirs')
    mocker.patch('builtins.open')
    mocker.patch('json.dump')


def test_analyze_com_sucesso(mock_all):
    """Testa se analyze() executa com sucesso e retorna o objeto correto."""
    report = analyze()
    
    assert report is not None
    assert report.ip == '8.8.8.8'
    assert len(report.ports) == 1
    assert report.ports[0].port_id == 53
    assert report.ports[0].protocol == 'tcp' # <--- NOVA ASSERÇÃO
    assert report.isp == 'Google'


def test_analyze_com_falha_no_ip_publico(mocker):
    """Testa o comportamento quando _get_public_ip() falha."""
    mocker.patch('batman_do_cerrado.modules.selfcheck._get_public_ip', return_value=None)
    
    # O analyze() deve retornar None
    assert analyze() is None


def test_analyze_com_falha_no_ip_analyzer(mocker):
    """Testa o comportamento quando ip_analyzer.analyze() falha."""
    mocker.patch('batman_do_cerrado.modules.selfcheck._get_public_ip', return_value='8.8.8.8')
    mocker.patch('batman_do_cerrado.modules.ip_analyzer.analyze', return_value=None)
    
    # O analyze() deve retornar None
    assert analyze() is None

def test_analyze_salva_relatorio(mock_all, mocker):
    """Verifica se a função salva o relatório em JSON."""
    mock_json_dump = mocker.patch('json.dump')
    analyze()
    mock_json_dump.assert_called_once()
