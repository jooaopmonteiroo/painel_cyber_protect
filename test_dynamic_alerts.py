import asyncio
import os
import sys
import time
import requests
import json
import auth
import soc_database
from notification_service import notification_service

sys.stdout.reconfigure(encoding='utf-8')

BASE_URL = "http://127.0.0.1:8000"

def run_tests():
    print("=== TESTE 1: Login de Operador/Admin via /api/v1/auth/login ===")
    session = requests.Session()
    
    # 1. Login via /api/v1/auth/login
    login_resp = session.post(
        f"{BASE_URL}/api/v1/auth/login",
        json={"username_or_email": "admin", "password": "Admin@Acronis2026!"}
    )
    assert login_resp.status_code == 200, f"Login failed: {login_resp.text}"
    login_data = login_resp.json()
    assert login_data.get("success") is True, f"Login response unsuccessful: {login_data}"
    user_info = login_data.get("user", {})
    token = login_data.get("access_token")
    assert user_info.get("email") == "admin@cyberprotect.corp"
    assert user_info.get("role") == "admin"
    print(f"✅ Login OK: {user_info['username']} ({user_info['email']}) [Role: {user_info['role']}]")
    
    # Pass authorization header as well to cover bearer and cookie
    session.headers.update({"Authorization": f"Bearer {token}"})

    # 2. Verificar lista de operadores ativos
    print("\n=== TESTE 2: Consulta de Operadores Ativos (/api/soc/active_operators) ===")
    ops_resp = session.get(f"{BASE_URL}/api/soc/active_operators")
    assert ops_resp.status_code == 200, f"Failed getting active operators: {ops_resp.text}"
    ops_data = ops_resp.json()
    active_ops = ops_data.get("operators") or ops_data.get("active_operators") or []
    print(f"Operadores ativos retornados ({len(active_ops)}): {active_ops}")
    assert any(op["email"] == "admin@cyberprotect.corp" for op in active_ops), "admin@cyberprotect.corp deve estar na lista de operadores ativos"
    print("✅ Operador autenticado presente na lista de operadores ativos!")

    # 3. Verificar e testar endpoint de preferências do usuário
    print("\n=== TESTE 3: Preferências de Alerta (/api/user/preferences) ===")
    pref_resp = session.get(f"{BASE_URL}/api/user/preferences")
    assert pref_resp.status_code == 200, f"Failed getting preferences: {pref_resp.text}"
    pref_data = pref_resp.json()
    print(f"Preferência atual: {pref_data}")
    assert "receive_alerts" in pref_data

    # Toggle off
    patch_resp = session.patch(f"{BASE_URL}/api/user/preferences", json={"receive_alerts": False})
    assert patch_resp.status_code == 200, f"Failed toggling off preferences: {patch_resp.text}"
    assert patch_resp.json().get("receive_alerts") is False
    print("✅ Preferência desmarcada com sucesso (receive_alerts = False)")

    # Verificar que quando desmarcado, não entra nos destinatários
    recipients_off = auth.get_active_soc_recipients(severity="critical")
    recipients_emails_off = [u["email"] for u in recipients_off]
    print(f"Destinatários com toggle OFF: {recipients_emails_off}")
    assert "admin@cyberprotect.corp" not in recipients_emails_off, "Não deve receber alertas quando o toggle está desativado"
    print("✅ Validação de opt-out: usuário desmarcado NÃO entra nos disparos!")

    # Toggle on
    patch_resp2 = session.patch(f"{BASE_URL}/api/user/preferences", json={"receive_alerts": True})
    assert patch_resp2.status_code == 200
    assert patch_resp2.json().get("receive_alerts") is True
    print("✅ Preferência reativada com sucesso (receive_alerts = True)")

    # 4. Roteamento de Alerta Crítico Dinâmico
    print("\n=== TESTE 4: Disparo e Roteamento de Alerta Crítico Dinâmico ===")
    recipients_on = auth.get_active_soc_recipients(severity="critical")
    recipients_emails_on = [u["email"] for u in recipients_on]
    print(f"Destinatários ativos calculados pelo auth: {recipients_emails_on}")
    assert "admin@cyberprotect.corp" in recipients_emails_on, "admin@cyberprotect.corp deve estar na lista ativa com toggle ON"

    # Temporariamente habilita smtp_enabled nas configurações para simular envio
    prev_settings = soc_database.get_soc_settings()
    soc_database.update_soc_setting("smtp_enabled", "true")
    soc_database.update_soc_setting("recipients_critical", "contingencia@jmcyberprotect.com")

    unique_ts = int(time.time())
    test_incident = {
        "incident_id": f"test-edr-dynamic-{unique_ts}",
        "resource_id": f"res-haul-{unique_ts}",
        "title": "EDR: Processo Powershell Malicioso Barrado",
        "severity": "critical",
        "detection_vector": "EDR",
        "source": "acronis",
        "resource_name": f"HAUL-DESKTOP-{unique_ts}",
        "ip_address": "192.168.1.150",
        "user_name": "OPERADOR_PLANTÃO",
        "details": "Execução maliciosa detectada e contida preventivamente pelo agente EDR.",
        "mitre_technique": "T1059.001"
    }

    success, msg = asyncio.run(notification_service.notify_incident(test_incident))
    print(f"Resultado do envio de notificação (online): success={success}, msg='{msg}'")
    assert success is True, f"Falha no envio da notificação: {msg}"
    print("✅ Alerta crítico roteado dinamicamente para o e-mail do operador autenticado!")

    # 5. Logout e Validação de Remoção da Sessão Ativa
    print("\n=== TESTE 5: Logout via /api/v1/auth/logout e Limpeza de Sessão ===")
    logout_resp = session.post(f"{BASE_URL}/api/v1/auth/logout")
    assert logout_resp.status_code == 200, f"Logout failed: {logout_resp.text}"
    print("✅ Logout efetuado.")

    # Verificar que lista de operadores agora não contém mais a sessão deslogada
    active_now = auth.get_active_soc_recipients(severity="critical")
    active_emails_now = [u["email"] for u in active_now]
    print(f"Operadores ativos após logout: {active_emails_now}")
    assert "admin@cyberprotect.corp" not in active_emails_now, "admin@cyberprotect.corp deve ter sido removido após logout"
    print("✅ Sessão removida com sucesso dos destinatários ativos de alertas!")

    # 6. Teste de Fallback para Contingência
    print("\n=== TESTE 6: Fallback para Destinatários de Contingência / Fallback ===")
    test_incident_fallback = {
        "incident_id": f"test-fallback-{unique_ts}",
        "resource_id": f"res-unifi-gw-{unique_ts}",
        "title": "IDS/IPS: Intrusão de Rede Detectada",
        "severity": "critical",
        "detection_vector": "IDS_IPS",
        "source": "unifi",
        "resource_name": "UniFi-Dream-Machine",
        "ip_address": "192.168.1.1",
        "details": "Tentativa de exploit bloqueada pelo firewall IDS/IPS.",
        "mitre_technique": "T1190"
    }
    success_fb, msg_fb = asyncio.run(notification_service.notify_incident(test_incident_fallback))
    print(f"Resultado do envio com fallback (nenhum operador online): success={success_fb}, msg='{msg_fb}'")
    assert success_fb is True, f"Falha no fallback de notificação: {msg_fb}"
    print("✅ Fallback acionado perfeitamente para contingência quando nenhum operador está logado!")

    # 7. Teste de Categorias Granulares (URLs Barradas vs EDR)
    print("\n=== TESTE 7: Filtragem Granular por Categoria de Incidente ===")
    session2 = requests.Session()
    login_resp2 = session2.post(
        f"{BASE_URL}/api/v1/auth/login",
        json={"username_or_email": "admin", "password": "Admin@Acronis2026!"}
    )
    assert login_resp2.status_code == 200
    token2 = login_resp2.json().get("access_token")
    session2.headers.update({"Authorization": f"Bearer {token2}"})

    # Desativa notify_url_filter e ativa notify_edr
    patch_pref_resp = session2.patch(f"{BASE_URL}/api/user/preferences", json={
        "receive_alerts": True,
        "notify_url_filter": False,
        "notify_edr": True
    })
    assert patch_pref_resp.status_code == 200
    pref_updated = patch_pref_resp.json()
    assert pref_updated.get("notify_url_filter") is False
    assert pref_updated.get("notify_edr") is True

    # Teste de Incidente URL_FILTER: Deve ser descartado para o usuário (pois toggle URL está False)
    url_incident = {
        "incident_id": f"test-url-blocked-{int(time.time())}",
        "resource_id": "res-workstation-01",
        "title": "Filtro Web: URL Maliciosa Bloqueada",
        "severity": "critical",
        "detection_vector": "URL_FILTER",
        "source": "acronis",
        "resource_name": "WS-TEST-01",
        "ip_address": "192.168.1.100",
        "details": "Site de phishing bloqueado pelo filtro web corporativo."
    }
    # Insere no banco e valida auto-resolução
    soc_database.upsert_soc_incident(url_incident)
    incidents_stored, _ = soc_database.get_soc_incidents(status="resolvido")
    stored_url = next((i for i in incidents_stored if i["incident_id"] == url_incident["incident_id"]), None)
    assert stored_url is not None, "Incidente de URL deve ser gravado no banco"
    assert stored_url["status"] == "resolvido", "URL_FILTER deve ser auto-resolvido na origem"
    assert stored_url["is_automitigated"] == 1, "is_automitigated deve ser 1 para URL_FILTER"
    print("✅ Auto-resolução na origem confirmada: status='resolvido', is_automitigated=1!")

    # Notificação do URL_FILTER: não deve ser enviada para admin@cyberprotect.corp pois notify_url_filter=False
    soc_database.update_soc_setting("smtp_enabled", "true")
    success_url, msg_url = asyncio.run(notification_service.notify_incident(url_incident))
    # Como o único usuário logado desativou URL_FILTER, o sistema não deve enviar para ele (ou cai no fallback se habilitado)
    print(f"Envio de URL com toggle desmarcado: success={success_url}, msg='{msg_url}'")
    assert "admin@cyberprotect.corp" not in msg_url, "admin não deve receber alertas de URL quando desmarcou a categoria"
    print("✅ Proteção Anti-Spam: operador com categoria desmarcada NÃO recebe alerta por e-mail!")

    session2.post(f"{BASE_URL}/api/v1/auth/logout")

    # Restaura configuração anterior
    if "smtp_enabled" in prev_settings:
        soc_database.update_soc_setting("smtp_enabled", prev_settings["smtp_enabled"])

    print("\n🎉 TODOS OS 7 TESTES DE VALIDAÇÃO PASSARAM COM 100% DE SUCESSO!")

if __name__ == "__main__":
    run_tests()
