# batman_do_cerrado/core/models.py

"""
Módulo Core Models - Define as estruturas de dados centrais do framework.
Usar dataclasses garante consistência, tipagem e facilidade de uso.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional

@dataclass
class PortInfo:
    """Representa uma única porta escaneada em um host."""
    port_id: int
    protocol: str
    state: str
    service_name: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    extra_info: Optional[str] = None
    cpe: List[str] = field(default_factory=list)
    scripts_output: Dict[str, str] = field(default_factory=dict)
    risk: Optional[str] = None # 'info', 'medium', 'high'

@dataclass
class IPAddressInfo:
    """Dossiê completo para um único endereço IP."""
    ip: str
    version: int
    ptr: Optional[str] = None
    isp: Optional[str] = None
    asn_number: Optional[int] = None
    asn_name: Optional[str] = None
    city: Optional[str] = None
    region: Optional[str] = None
    country_code: Optional[str] = None
    # _ADICIONADO_: Campos para coordenadas geográficas.
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    source_api: Optional[str] = None
    os: Optional[str] = None
    raw_data: Dict[str, Any] = field(default_factory=dict)
    ports: List[PortInfo] = field(default_factory=list)

@dataclass
class DomainInfo:
    """Dossiê completo para um único domínio."""
    domain_name: str
    a_records: List[str] = field(default_factory=list)
    aaaa_records: List[str] = field(default_factory=list)
    mx_records: List[Dict[str, Any]] = field(default_factory=list)
    ns_records: List[str] = field(default_factory=list)
    txt_records: List[str] = field(default_factory=list)
    spf: Dict[str, Any] = field(default_factory=dict)
    dmarc: Dict[str, Any] = field(default_factory=dict)
    is_axfr_open: bool = False
    registrar: Optional[str] = None
    creation_date: Optional[str] = None
    expiration_date: Optional[str] = None
    raw_data: Dict[str, Any] = field(default_factory=dict)

@dataclass
class Finding:
    """Representa um único "achado" de segurança ou ponto de interesse."""
    target: str
    module: str
    finding_type: str # Ex: 'suid_binary', 'open_port', 'misconfiguration'
    description: str
    severity: str # 'info', 'low', 'medium', 'high', 'critical'
    details: Dict[str, Any] = field(default_factory=dict)
