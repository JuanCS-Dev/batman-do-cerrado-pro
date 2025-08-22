# tests/test_whois_integration.py

import pytest
from batman_do_cerrado.core.models import DomainInfo, IPAddressInfo
from batman_do_cerrado.core.utils import CommandResult
from batman_do_cerrado.modules import whois

def test_analyze_com_dominio_valido(mocker):
    """
    Testa a função principal `analyze` para um domínio, mockando as chamadas externas.
    """
    # 1. Preparamos os dados falsos que nossas dependências deveriam retornar
    fake_whois_output = "Registrar: FAKE REGISTRAR"
    
    # 2. Configuramos os mocks
    mocker.patch(
        'batman_do_cerrado.modules.whois.utils.run_command',
        return_value=CommandResult(success=True, stdout=fake_whois_output, stderr="", return_code=0)
    )
    mocker.patch(
        'batman_do_cerrado.modules.whois._query_dns',
        return_value={'A': ['192.0.2.1']}
    )

    # 3. Executamos a função que queremos testar
    result = whois.analyze("example.com")

    # 4. Verificamos se o resultado está correto
    assert isinstance(result, DomainInfo)
    assert result.domain_name == "example.com"
    assert result.registrar == "FAKE REGISTRAR"
    assert "192.0.2.1" in result.a_records

def test_analyze_com_ip_valido(mocker):
    """
    Testa a função principal `analyze` para um IP, mockando as chamadas externas.
    """
    # 1. Preparamos os dados falsos
    fake_ip = "8.8.8.8"
    fake_whois_output = "OrgName:        Google LLC\nOriginAS:       AS15169"
    fake_ptr_record = "dns.google"
    
    # 2. Configuramos os mocks
    mocker.patch(
        'batman_do_cerrado.modules.whois.utils.run_command',
        return_value=CommandResult(success=True, stdout=fake_whois_output, stderr="", return_code=0)
    )
    # Mock para a busca de DNS reverso
    mocker.patch(
        'batman_do_cerrado.modules.whois.socket.gethostbyaddr',
        return_value=(fake_ptr_record, [], [fake_ip])
    )

    # 3. Executamos a função
    result = whois.analyze(fake_ip)

    # 4. Verificamos o resultado
    assert isinstance(result, IPAddressInfo)
    assert result.ip == fake_ip
    assert result.isp == "Google LLC"
    assert result.asn_number == 15169
    assert result.ptr == fake_ptr_record
