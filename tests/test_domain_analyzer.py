# tests/test_domain_analyzer.py

import pytest
from batman_do_cerrado.modules.domain_analyzer import _parse_spf, _parse_dmarc


def test_parse_spf_com_registro_valido():
    """Verifica o parsing de um registro SPF válido."""
    txt_records = ['"v=spf1 include:_spf.google.com ~all"']
    result = _parse_spf(txt_records)
    assert result["raw"] == 'v=spf1 include:_spf.google.com ~all'
    assert "include:_spf.google.com" in result["mechanisms"]
    assert "~all" in result["mechanisms"]
    
def test_parse_spf_com_registro_sem_aspas():
    """Verifica o parsing de um registro SPF válido sem aspas."""
    txt_records = ['v=spf1 include:_spf.google.com ~all']
    result = _parse_spf(txt_records)
    assert result["raw"] == 'v=spf1 include:_spf.google.com ~all'
    assert "include:_spf.google.com" in result["mechanisms"]
    assert "~all" in result["mechanisms"]
    

def test_parse_spf_com_exp_e_diversos():
    """Verifica o parsing de um registro SPF com `exp` e outros mecanismos."""
    txt_records = ['"v=spf1 mx a:mail.example.com -all exp=explain.example.com"']
    result = _parse_spf(txt_records)
    assert result["raw"] == 'v=spf1 mx a:mail.example.com -all exp=explain.example.com'
    assert "mx" in result["mechanisms"]
    assert "a:mail.example.com" in result["mechanisms"]
    assert "-all" in result["mechanisms"]
    assert "exp=explain.example.com" not in result["mechanisms"]


def test_parse_spf_com_registro_ausente():
    """Verifica o retorno de None se nenhum SPF for encontrado."""
    txt_records = ['"google-site-verification=abcde"']
    result = _parse_spf(txt_records)
    assert result is None
    

def test_parse_dmarc_com_registro_valido():
    """Verifica o parsing de um registro DMARC válido."""
    dmarc_records = ['"v=DMARC1; p=none; sp=quarantine; rua=mailto:dmarc@example.com"']
    result = _parse_dmarc(dmarc_records)
    assert result["raw"] == 'v=DMARC1; p=none; sp=quarantine; rua=mailto:dmarc@example.com'
    assert result["p"] == "none"
    assert result["sp"] == "quarantine"
    assert result["rua"] == "mailto:dmarc@example.com"
    

def test_parse_dmarc_com_registro_ausente():
    """Verifica o retorno de None se nenhum DMARC for encontrado."""
    dmarc_records = []
    result = _parse_dmarc(dmarc_records)
    assert result is None
