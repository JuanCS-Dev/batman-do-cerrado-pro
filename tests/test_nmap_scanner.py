# tests/test_nmap_scanner.py

import pytest
import textwrap # _ADICIONADO_: A ferramenta certa para limpar strings multi-linha.
from batman_do_cerrado.core.models import IPAddressInfo, PortInfo
from batman_do_cerrado.core.utils import CommandResult
from batman_do_cerrado.modules import nmap_scanner

# _ALTERADO_: Usamos textwrap.dedent para remover o espaçamento inicial
# da string, garantindo que ela seja um XML válido.
FAKE_NMAP_XML_OUTPUT = textwrap.dedent("""
    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE nmaprun>
    <nmaprun scanner="nmap" args="nmap -T3 -sS -sV -oX - 8.8.8.8" start="1678886400" version="7.92">
        <host starttime="1678886401" endtime="1678886402">
            <status state="up" reason="echo-reply" reason_ttl="54"/>
            <address addr="8.8.8.8" addrtype="ipv4"/>
            <ports>
                <port protocol="tcp" portid="53">
                    <state state="open" reason="syn-ack" reason_ttl="54"/>
                    <service name="domain" product="Google DNS" method="probed" conf="10"/>
                </port>
                <port protocol="tcp" portid="443">
                    <state state="open" reason="syn-ack" reason_ttl="54"/>
                    <service name="https" product="Google httpd" method="probed" conf="10"/>
                </port>
            </ports>
        </host>
    </nmaprun>
""").strip()

def test_nmap_analyze_com_saida_valida(mocker):
    """
    Testa a função `analyze` do nmap_scanner com uma saída XML válida,
    mockando a execução do comando nmap.
    """
    # 1. Mockamos o run_command para retornar nosso XML falso.
    mocker.patch(
        'batman_do_cerrado.modules.nmap_scanner.utils.run_command',
        return_value=CommandResult(success=True, stdout=FAKE_NMAP_XML_OUTPUT, stderr="", return_code=0)
    )

    # 2. Executamos a função de análise.
    results = nmap_scanner.analyze(target="8.8.8.8", profile_name="padrao")

    # 3. Verificamos os resultados.
    assert results is not None
    assert len(results) == 1
    
    host_info = results[0]
    assert isinstance(host_info, IPAddressInfo)
    assert host_info.ip == "8.8.8.8"
    assert len(host_info.ports) == 2

    # Verifica a primeira porta
    port53 = sorted(host_info.ports, key=lambda p: p.port_id)[0]
    assert isinstance(port53, PortInfo)
    assert port53.port_id == 53
    assert port53.state == "open"
    assert port53.service_name == "domain"
    assert port53.product == "Google DNS"

    # Verifica a segunda porta
    port443 = sorted(host_info.ports, key=lambda p: p.port_id)[1]
    assert port443.port_id == 443
    assert port443.service_name == "https"
