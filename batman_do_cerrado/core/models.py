# batman-do-cerrado-pro/batman_do_cerrado/core/models.py

"""
Módulo Core Models - A linguagem universal do Batman do Cerrado.

Este arquivo define as estruturas de dados centrais (dataclasses) que são usadas
para passar informações entre os diferentes módulos do framework.

Isso garante consistência, previsibilidade e facilita a integração,
seja em pipelines de CLI ou em uma futura API web.
"""

from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any

# --- Modelos de Entidades de Rede ---

@dataclass
class IPAddressInfo:
    """
    Representa a informação consolidada sobre um único endereço IP.
    Servirá como o objeto de retorno padrão para o ip_searcher e ip_forensics.
    """
    ip: str
    version: int  # 4 ou 6
    ptr: Optional[str] = None
    
    # Informações Geográficas e de Rede
    city: Optional[str] = None
    region: Optional[str] = None
    country_code: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    timezone: Optional[str] = None
    
    # Informações de ASN
    asn_number: Optional[int] = None
    asn_name: Optional[str] = None
    isp: Optional[str] = None
    
    # Metadados da coleta
    source_api: Optional[str] = None
    raw_data: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PortInfo:
    """
    Representa uma única porta escaneada em um host.
    Será o principal objeto de retorno do nmap_scanner.
    """
    port_id: int
    protocol: str  # "tcp" ou "udp"
    state: str     # "open", "closed", "filtered"
    
    service_name: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    extra_info: Optional[str] = None
    cpe: List[str] = field(default_factory=list)
    
    scripts_output: Dict[str, str] = field(default_factory=dict)


@dataclass
class DomainInfo:
    """

    Representa a informação consolidada sobre um domínio.
    Será o objeto de retorno do domain_analyzer e whois_lookup.
    """
    domain_name: str
    
    # Registros DNS principais
    a_records: List[str] = field(default_factory=list)
    aaaa_records: List[str] = field(default_factory=list)
    mx_records: List[Dict[str, Any]] = field(default_factory=list)
    ns_records: List[str] = field(default_factory=list)
    txt_records: List[str] = field(default_factory=list)
    
    # Informações de WHOIS/RDAP
    registrar: Optional[str] = None
    creation_date: Optional[str] = None
    expiration_date: Optional[str] = None
    
    # Análises de segurança
    spf: Dict[str, Any] = field(default_factory=dict)
    dmarc: Dict[str, Any] = field(default_factory=dict)
    is_axfr_open: bool = False
    
    # Metadados
    raw_data: Dict[str, Any] = field(default_factory=dict)


# --- Modelo Genérico para Resultados/Achados ---

@dataclass
class Finding:
    """
    Representa um "achado" genérico de segurança.
    
    Esta será a estrutura padrão para qualquer módulo que encontre uma
    vulnerabilidade, misconfiguration ou segredo.
    """
    target: str                  # O alvo onde o achado foi encontrado (IP, domínio, caminho do arquivo)
    module: str                  # Nome do módulo que gerou o achado (ex: "secrets_scanner")
    finding_type: str            # Tipo do achado (ex: "aws_access_key", "public_s3_bucket")
    description: str             # Descrição legível por humanos do achado
    severity: str                # Severidade ("critical", "high", "medium", "low", "info")
    details: Dict[str, Any] = field(default_factory=dict)
