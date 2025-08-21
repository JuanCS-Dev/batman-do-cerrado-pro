<div align="center">
  <pre><code>
      ____        _                       _            
     |  _ \      | |                     | |           
     | |_) | __ _| |_ __ _ _ __ ___   ___| | ___  ___  
     |  _ < / _` | __/ _` | '_ ` _ \ / _ \ |/ _ \/ __| 
     | |_) | (_| | || (_| | | | | | |  __/ |  __/\__ \ 
     |____/ \__,_|\__\__,_|_| |_| |_|\___|_|\___||___/ 
  </code></pre>
  <h1>🦇 Batman do Cerrado 🦇</h1>
  <strong>Suíte de segurança pessoal multifacetada para OSINT, Forense e Defesa de Sistemas.</strong>
  <br><br>
  <p>
    <img src="https://img.shields.io/badge/version-2.0.0--alpha-blue" alt="Version">
    <img src="https://img.shields.io/badge/python-3.8+-brightgreen" alt="Python Version">
    <img src="https://img.shields.io/badge/license-MIT-lightgrey" alt="License">
    <img src="https://img.shields.io/badge/status-em desenvolvimento-orange" alt="Status">
  </p>
</div>

---

> **Nota do Desenvolvedor:** Este projeto está passando por uma refatoração arquitetural completa para se tornar um framework de segurança coeso e extensível. Esta é a versão 2.0 (PRO), um trabalho colaborativo entre Juan Carlos e a IA Cora.

###  filozofia Central

O Batman do Cerrado é construído sobre três pilares fundamentais:

* **Pragmatismo:** Ferramentas diretas, eficazes e que resolvem problemas reais de segurança e análise.
* **Linux-First:** Projetado e otimizado para ambientes Linux, utilizando o poder das ferramentas de sistema nativas.
* **Mínimas Dependências:** Um esforço consciente para depender o mínimo possível de bibliotecas externas, garantindo portabilidade e robustez.

###  модули Principais

O framework é composto por um conjunto de módulos de análise e monitoramento, orquestrados por uma interface de linha de comando unificada.

| Módulo | Emoji | Descrição |
| :--- | :---: | :--- |
| **IP Analyzer** | 🛰️ | Dossiê completo de um IP: GeoIP multi-provider, WHOIS, DNS Reverso e Reputação. |
| **Domain Analyzer** | 🌐 | Análise OSINT profunda de domínios: DNS, e-mail (MX/SPF/DMARC), HTTP/TLS e mais. |
| **Nmap Scanner** | 🗺️ | Wrapper inteligente para o Nmap com perfis customizáveis para varreduras de rede. |
| **FS Monitor** | 🛡️ | Monitor de integridade de arquivos em tempo real. Detecta alterações, deleções e permissões perigosas. |
| **Net Monitor** | 🔭 | Sensor de rede em tempo real. Detecta novas portas, picos de conexão e varreduras. |
| **Secrets Scanner**| 🔑 | Varredura de arquivos e diretórios em busca de segredos e chaves de API expostas. |

### Instalação e Requisitos

**1. Requisitos de Sistema:**

O framework utiliza ferramentas de sistema que precisam estar no seu `PATH`:
* `git`
* `python3` e `pip`
* `nmap`
* `dig` (geralmente no pacote `dnsutils`)
* `whois`

**2. Instalação do Framework:**

Após clonar o repositório, instale-o em modo editável. Isso instala as dependências e cria o comando `batman` no seu terminal.

```bash
# Na raiz do projeto
pip install -e .
```

### Uso Básico

Após a instalação, todos os módulos são acessíveis através do comando `batman`.

```bash
# Ajuda geral
batman --help

# Exemplo: Analisar um IP
batman ip 8.8.8.8

# Exemplo: Analisar um domínio
batman domain google.com

# Exemplo: Rodar Nmap com o perfil 'inteligente'
batman nmap scanme.nmap.org -p inteligente

# Exemplo: Iniciar o monitor de arquivos (requer sudo)
sudo batman fs
```

### Roadmap Futuro

Este projeto está em constante evolução. Nossos planos futuros incluem:

* **Fase 3: O Legado** - Empacotamento para o PyPI, containerização com Docker e documentação completa.
* **Fase 4: O Protocolo Sentinela** - Um novo módulo para auditoria profunda de redes internas.
* **Fase 5: O Protocolo Oráculo** - Um motor de IA para orquestrar investigações de forma autônoma.

### Licença

Este projeto é distribuído sob a licença MIT. Veja o arquivo `LICENSE` para mais detalhes.
