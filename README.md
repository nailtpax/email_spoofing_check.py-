# Email Spoofing Validation Tool

Ferramenta para **validação automatizada de possíveis vulnerabilidades de Email Spoofing** em um domínio informado, destinada ao uso em **pentests autorizados e avaliações de postura de segurança**.

O script realiza análise técnica dos principais mecanismos de autenticação de e-mail utilizados para mitigar spoofing e phishing, sem realizar envio real de mensagens.

---

## Funcionalidades

- Consulta e análise de registros DNS:
  - **SPF (TXT)**
  - **DMARC (`_dmarc.dominio`)**
  - **DKIM** (detecção básica por selectors comuns)
- Verificação de:
  - Existência ou ausência de SPF
  - Política final do SPF (`~all`, `-all`, `+all` ou ausente)
  - Existência ou ausência de DMARC
  - Política DMARC (`none`, `quarantine`, `reject`)
- Identificação de **configurações permissivas ou ausentes** que possibilitam Email Spoofing
- Classificação simples de risco:
  - **Baixo**
  - **Médio**
  - **Alto**
- Output estruturado e legível para uso em relatórios
- Tratamento de erros DNS (NXDOMAIN, timeout, ausência de registros)

---

## O que a ferramenta **não faz**

- ❌ Não envia e-mails reais
- ❌ Não executa ataques
- ❌ Não realiza exploração ativa

A ferramenta realiza **apenas validação técnica e passiva**, sendo segura para ambientes de teste autorizados.

---

## Requisitos

- Python **3.8+**
- Biblioteca `dnspython`

Instalação da dependência:

```bash
pip install dnspython
