#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
==============================================================================
Script de Health Check de Conectividade VPS -> UniFi Controller / Cloud API
==============================================================================
Objetivo:
  Monitorar continuamente na VPS se a rota segura até a UDM Pro ou UniFi OS
  está ativa, responsiva e autenticando com sucesso.
  Pode ser executado manualmente, via Cron (a cada 5min) ou pelo Systemd.

Uso:
  python3 deploy/healthcheck_vps_unifi.py [--verbose]
==============================================================================
"""

import sys
import os
import time
import json
import urllib.parse
from pathlib import Path

# Adiciona o diretório raiz ao path para importar config
ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

try:
    from config import Config
except ImportError:
    class Config:
        UNIFI_CONTROLLER_URL = os.environ.get("UNIFI_CONTROLLER_URL", "https://api.ui.com")
        UNIFI_API_KEY = os.environ.get("UNIFI_API_KEY", "")
        UNIFI_USERNAME = os.environ.get("UNIFI_USERNAME", "")
        UNIFI_PASSWORD = os.environ.get("UNIFI_PASSWORD", "")
        UNIFI_VERIFY_SSL = os.environ.get("UNIFI_VERIFY_SSL", "false").lower() == "true"
        UNIFI_SITE = os.environ.get("UNIFI_SITE", "default")
        UNIFI_MOCK = os.environ.get("UNIFI_MOCK", "false").lower() == "true"

try:
    import httpx
except ImportError:
    print("\033[91m[ERRO]\033[0m Biblioteca 'httpx' não instalada. Execute: pip install httpx")
    sys.exit(2)

# Códigos de cor ANSI para terminal
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BLUE = "\033[94m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"

def print_header():
    print(f"{BOLD}{BLUE}=============================================================================={RESET}")
    print(f"{BOLD}{CYAN} JM CYBER PROTECT • HEALTH CHECK DE CONECTIVIDADE VPS -> UNIFI CONSOLE{RESET}")
    print(f"{BOLD}{BLUE}=============================================================================={RESET}")
    print(f"Data/Hora Local : {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Target URL      : {Config.UNIFI_CONTROLLER_URL}")
    print(f"Site Target     : {Config.UNIFI_SITE}")
    print(f"SSL Strict      : {Config.UNIFI_VERIFY_SSL}")
    print(f"Modo Mock       : {Config.UNIFI_MOCK}")
    print(f"{BLUE}------------------------------------------------------------------------------{RESET}")

def run_healthcheck(verbose=False) -> bool:
    print_header()

    if Config.UNIFI_MOCK:
        print(f"{YELLOW}[AVISO]{RESET} UNIFI_MOCK=true está ativado no ambiente. Testando simulação local.")
        return True

    url = Config.UNIFI_CONTROLLER_URL
    api_key = Config.UNIFI_API_KEY
    is_cloud = "api.ui.com" in url or bool(api_key and not Config.UNIFI_PASSWORD)

    client_kwargs = {
        "timeout": 10.0,
        "verify": Config.UNIFI_VERIFY_SSL
    }

    start_time = time.time()

    # 1. Teste de Conexão com Cloud API (Site Manager)
    if is_cloud:
        print(f"[*] Modo de Conexão: {BOLD}UniFi Site Manager Cloud API (api.ui.com){RESET}")
        if not api_key:
            print(f"{RED}[FALHA]{RESET} UNIFI_API_KEY não foi configurada no arquivo .env!")
            return False

        headers = {
            "X-API-KEY": api_key,
            "Accept": "application/json",
            "User-Agent": "JM-CyberProtect-HealthCheck/2.0"
        }

        try:
            with httpx.Client(**client_kwargs) as client:
                # Teste 1: Endpoint de Sites
                t0 = time.time()
                resp_sites = client.get(f"{url.rstrip('/')}/v1/sites", headers=headers)
                lat_sites = int((time.time() - t0) * 1000)

                if resp_sites.status_code == 200:
                    sites_data = resp_sites.json()
                    sites_count = len(sites_data.get("data", []))
                    print(f"{GREEN}[OK]{RESET} Endpoint /v1/sites acessível ({lat_sites} ms) • {sites_count} sites localizados.")
                else:
                    print(f"{RED}[FALHA]{RESET} Erro ao consultar /v1/sites: HTTP {resp_sites.status_code} - {resp_sites.text[:120]}")
                    return False

                # Teste 2: Endpoint de Dispositivos
                t1 = time.time()
                resp_dev = client.get(f"{url.rstrip('/')}/v1/devices", headers=headers)
                lat_dev = int((time.time() - t1) * 1000)

                if resp_dev.status_code == 200:
                    dev_data = resp_dev.json()
                    devices = dev_data.get("data", [])
                    total_dev = len(devices)
                    online_dev = sum(1 for d in devices if d.get("state") in ["CONNECTED", "ONLINE"])
                    print(f"{GREEN}[OK]{RESET} Endpoint /v1/devices acessível ({lat_dev} ms) • {total_dev} equipamentos catalogados ({online_dev} online).")
                else:
                    print(f"{YELLOW}[AVISO]{RESET} /v1/devices retornou HTTP {resp_dev.status_code}.")

            total_elapsed = int((time.time() - start_time) * 1000)
            print(f"{BLUE}------------------------------------------------------------------------------{RESET}")
            print(f"{BOLD}{GREEN}[SUCESSO] Rota VPS -> UniFi Site Manager API está 100% OPERACIONAL!{RESET} ({total_elapsed} ms)")
            return True

        except httpx.ConnectError as ce:
            print(f"{RED}[FALHA]{RESET} Erro de conexão de rede ou DNS com {url}: {ce}")
            return False
        except httpx.TimeoutException:
            print(f"{RED}[FALHA]{RESET} Timeout de resposta (>10s) ao contactar a API UniFi.")
            return False
        except Exception as ex:
            print(f"{RED}[FALHA]{RESET} Exceção inesperada: {ex}")
            return False

    # 2. Teste de Conexão com Console Local UDM Pro via VPN/WireGuard
    else:
        print(f"[*] Modo de Conexão: {BOLD}UDM Pro Local / VPN Direta ({url}){RESET}")
        username = Config.UNIFI_USERNAME
        password = Config.UNIFI_PASSWORD

        if not username or not password:
            print(f"{RED}[FALHA]{RESET} UNIFI_USERNAME ou UNIFI_PASSWORD não declarados no .env para acesso local!")
            return False

        try:
            with httpx.Client(**client_kwargs) as client:
                t0 = time.time()
                login_payload = {"username": username, "password": password}
                login_url = f"{url.rstrip('/')}/api/auth/login"
                
                resp = client.post(login_url, json=login_payload)
                lat_ms = int((time.time() - t0) * 1000)

                if resp.status_code == 200:
                    print(f"{GREEN}[OK]{RESET} Autenticação local na UDM Pro realizada com sucesso ({lat_ms} ms).")
                    print(f"{BLUE}------------------------------------------------------------------------------{RESET}")
                    print(f"{BOLD}{GREEN}[SUCESSO] Rota direta VPS -> UDM Pro está ATIVA e RESPONDENDO!{RESET}")
                    return True
                else:
                    print(f"{RED}[FALHA]{RESET} UDM Pro rejeitou autenticação: HTTP {resp.status_code} - {resp.text[:120]}")
                    return False

        except httpx.ConnectError as ce:
            print(f"{RED}[FALHA]{RESET} Não foi possível alcançar o IP local da UDM Pro: {ce}")
            print(f"         Certifique-se de que o túnel VPN (WireGuard/OpenVPN) entre a VPS e a UDM Pro está UP.")
            return False
        except httpx.TimeoutException:
            print(f"{RED}[FALHA]{RESET} Timeout ao conectar com a UDM Pro local.")
            return False
        except Exception as ex:
            print(f"{RED}[FALHA]{RESET} Exceção ao testar UDM Pro: {ex}")
            return False

if __name__ == "__main__":
    is_verbose = "--verbose" in sys.argv
    success = run_healthcheck(verbose=is_verbose)
    sys.exit(0 if success else 1)
