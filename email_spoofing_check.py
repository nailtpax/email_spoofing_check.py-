#!/usr/bin/env python3
"""
Email Spoofing Validation Script
--------------------------------
Uso autorizado em testes de segurança.

Funcionalidades:
- Consulta SPF (TXT)
- Analisa política SPF (~all, -all, +all, ausência)
- Consulta DMARC (_dmarc.domain)
- Analisa política DMARC (none, quarantine, reject)
- Tentativa de detecção básica de DKIM (selectors comuns)
- Classificação simples de risco
- Tratamento de erros DNS

NÃO realiza envio real de e-mails.
"""

import dns.resolver
import dns.exception
import sys
import socket

TIMEOUT = 5

COMMON_DKIM_SELECTORS = [
    "default",
    "selector1",
    "selector2",
    "google",
    "mail",
    "smtp",
]

def query_txt(name):
    try:
        answers = dns.resolver.resolve(name, "TXT", lifetime=TIMEOUT)
        return ["".join(r.strings.decode() if isinstance(r.strings, bytes)
                        else b"".join(r.strings).decode())
                for r in answers]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return []
    except dns.exception.Timeout:
        return ["TIMEOUT"]
    except Exception as e:
        return [f"ERROR: {e}"]

def analyze_spf(txt_records):
    spf_records = [r for r in txt_records if r.lower().startswith("v=spf1")]

    if not spf_records:
        return {
            "exists": False,
            "policy": None,
            "risk": "Alto",
            "note": "SPF ausente"
        }

    spf = spf_records[0].lower()

    if "-all" in spf:
        policy = "-all"
        risk = "Baixo"
    elif "~all" in spf:
        policy = "~all"
        risk = "Médio"
    elif "+all" in spf or " all" in spf:
        policy = "+all"
        risk = "Alto"
    else:
        policy = "sem all"
        risk = "Médio"

    return {
        "exists": True,
        "policy": policy,
        "risk": risk,
        "note": "SPF presente"
    }

def analyze_dmarc(domain):
    records = query_txt(f"_dmarc.{domain}")
    dmarc_records = [r for r in records if r.lower().startswith("v=dmarc1")]

    if not dmarc_records:
        return {
            "exists": False,
            "policy": None,
            "risk": "Alto",
            "note": "DMARC ausente"
        }

    dmarc = dmarc_records[0].lower()

    if "p=reject" in dmarc:
        policy = "reject"
        risk = "Baixo"
    elif "p=quarantine" in dmarc:
        policy = "quarantine"
        risk = "Médio"
    else:
        policy = "none"
        risk = "Alto"

    return {
        "exists": True,
        "policy": policy,
        "risk": risk,
        "note": "DMARC presente"
    }

def detect_dkim(domain):
    found = []

    for selector in COMMON_DKIM_SELECTORS:
        name = f"{selector}._domainkey.{domain}"
        records = query_txt(name)
        for r in records:
            if r.lower().startswith("v=dkim1"):
                found.append(selector)

    if found:
        return {
            "exists": True,
            "selectors": found,
            "note": "DKIM identificado (parcial)"
        }

    return {
        "exists": False,
        "selectors": [],
        "note": "DKIM não identificado (selectors comuns)"
    }

def classify_overall(spf, dmarc):
    if not spf["exists"] and not dmarc["exists"]:
        return "Alto"

    if spf["risk"] == "Alto" or dmarc["risk"] == "Alto":
        return "Alto"

    if spf["risk"] == "Médio" or dmarc["risk"] == "Médio":
        return "Médio"

    return "Baixo"

def main():
    if len(sys.argv) != 2:
        print(f"Uso: {sys.argv[0]} dominio.com")
        sys.exit(1)

    domain = sys.argv[1].strip().lower()

    print(f"\n[+] Analisando domínio: {domain}\n")

    txt_records = query_txt(domain)
    spf_result = analyze_spf(txt_records)
    dmarc_result = analyze_dmarc(domain)
    dkim_result = detect_dkim(domain)

    overall_risk = classify_overall(spf_result, dmarc_result)

    print("=== RESULTADO ===\n")

    print("[SPF]")
    print(f"  Existe      : {spf_result['exists']}")
    print(f"  Política    : {spf_result['policy']}")
    print(f"  Risco       : {spf_result['risk']}")
    print(f"  Observação  : {spf_result['note']}\n")

    print("[DMARC]")
    print(f"  Existe      : {dmarc_result['exists']}")
    print(f"  Política    : {dmarc_result['policy']}")
    print(f"  Risco       : {dmarc_result['risk']}")
    print(f"  Observação  : {dmarc_result['note']}\n")

    print("[DKIM]")
    print(f"  Existe      : {dkim_result['exists']}")
    print(f"  Selectors   : {', '.join(dkim_result['selectors']) if dkim_result['selectors'] else 'Nenhum'}")
    print(f"  Observação  : {dkim_result['note']}\n")

    print("[CLASSIFICAÇÃO FINAL]")
    print(f"  Risco Geral : {overall_risk}\n")

    if overall_risk != "Baixo":
        print("[!] Possível cenário de Email Spoofing identificado.")
    else:
        print("[+] Configuração adequada contra spoofing.")

if __name__ == "__main__":
    main()
