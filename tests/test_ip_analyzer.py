# tests/test_ip_analyzer.py

import pytest
from unittest.mock import MagicMock
from batman_do_cerrado.modules.ip_analyzer import _normalize_and_merge
from batman_do_cerrado.core.models import IPAddressInfo


def test_normalize_and_merge_com_ipinfo_source():
    """Verifica se os dados do ipinfo.io são normalizados corretamente."""
    mock_ipinfo_data = {
        "source": "ipinfo.io",
        "data": {
            "country": "BR",
            "city": "Anápolis",
            "region": "Goiás",
            "org": "Google LLC",
            "loc": "-16.3262,-48.9515"
        }
    }
    
    # Adicionando o campo 'version' faltante.
    mock_whois_info = IPAddressInfo(
        ip="8.8.8.8",
        version=4,
        isp="Google",
        asn_number=15169,
        raw_data={"whois": "WHOIS data here"}
    )
    
    # Adicionando o campo 'version' faltante.
    ip_info = IPAddressInfo(ip="8.8.8.8", version=4)
    _normalize_and_merge(ip_info, mock_ipinfo_data, mock_whois_info)
    
    assert ip_info.ip == "8.8.8.8"
    assert ip_info.source_api == "ipinfo.io"
    assert ip_info.country_code == "BR"
    assert ip_info.city == "Anápolis"
    assert ip_info.region == "Goiás"
    assert ip_info.isp == "Google"
    assert ip_info.latitude == -16.3262
    assert ip_info.longitude == -48.9515
    assert ip_info.raw_data["geoip"]["country"] == "BR"
    assert ip_info.raw_data["whois"] == "WHOIS data here"

    
def test_normalize_and_merge_com_ip_api_source():
    """Verifica se os dados do ip-api.com são normalizados corretamente."""
    mock_ip_api_data = {
        "source": "ip-api.com",
        "data": {
            "countryCode": "US",
            "city": "Mountain View",
            "regionName": "California",
            "isp": "Google LLC",
            "lat": 37.4056,
            "lon": -122.0775
        }
    }

    # Adicionando o campo 'version' faltante.
    mock_whois_info = IPAddressInfo(
        ip="8.8.4.4",
        version=4,
        isp="Google",
        asn_number=15169,
        raw_data={"whois": "WHOIS data here"}
    )

    # Adicionando o campo 'version' faltante.
    ip_info = IPAddressInfo(ip="8.8.4.4", version=4)
    _normalize_and_merge(ip_info, mock_ip_api_data, mock_whois_info)

    assert ip_info.ip == "8.8.4.4"
    assert ip_info.source_api == "ip-api.com"
    assert ip_info.country_code == "US"
    assert ip_info.city == "Mountain View"
    assert ip_info.region == "California"
    assert ip_info.isp == "Google"
    assert ip_info.latitude == 37.4056
    assert ip_info.longitude == -122.0775
    assert ip_info.raw_data["geoip"]["countryCode"] == "US"
    assert ip_info.raw_data["whois"] == "WHOIS data here"

    
def test_normalize_and_merge_com_whois_prevalecendo():
    """Verifica se o whois prevalece nos campos de ASN e ISP."""
    mock_geo_data = {
        "source": "ip-api.com",
        "data": {
            "isp": "ISP from ip-api"
        }
    }
    
    # Adicionando o campo 'version' faltante.
    mock_whois_info = IPAddressInfo(
        ip="1.1.1.1",
        version=4,
        isp="Cloudflare",
        asn_number=13335,
    )
    
    # Adicionando o campo 'version' faltante.
    ip_info = IPAddressInfo(ip="1.1.1.1", version=4)
    _normalize_and_merge(ip_info, mock_geo_data, mock_whois_info)
    
    assert ip_info.isp == "Cloudflare"
    assert ip_info.asn_number == 13335
