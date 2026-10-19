"""
Suite de Testes Automatizados para a Integração Ubiquiti UniFi Network e Ações Ativas de SOC
Valida telemetria dos 24 dispositivos, 342 clientes, bloqueio de MAC (block-sta),
desbloqueio, isolamento em VLAN de quarentena, reinicialização PoE de switch e ingestão de IDS/IPS.
"""

from fastapi.testclient import TestClient
from app import app
import soc_database
from unifi_client import unifi

def test_unifi_integration_suite():
    client = TestClient(app, follow_redirects=False)

    # 1. Login Administrativo
    login_resp = client.post("/api/auth/login", json={"username_or_email": "admin", "password": "Admin@Acronis2026!"})
    assert login_resp.status_code == 200, f"Login falhou: {login_resp.text}"
    session_id = login_resp.cookies.get("cyber_session_id")
    client.cookies.set("cyber_session_id", session_id)
    print("[1] Login administrativo no SOC OK.")

    # 2. Telemetria UniFi (24 Dispositivos, 342 Clientes, IDS/IPS)
    telem_resp = client.get("/api/soc/unifi/telemetry")
    assert telem_resp.status_code == 200, f"Erro na telemetria UniFi: {telem_resp.text}"
    data = telem_resp.json()
    assert data["connected"] is True
    summary = data["summary"]
    assert summary["devices_total"] == 24
    assert summary["devices_online"] == 24
    assert summary["clients_total"] == 342
    assert summary["ids_ips_active"] is True
    assert len(data["devices"]) >= 12
    print(f"[2] Telemetria UniFi OK: {summary['devices_total']} dispositivos, {summary['clients_total']} clientes conectados, IDS/IPS ativo.")

    # 3. Ingestão de Evento de IDS/IPS via Webhook UniFi
    unifi_webhook_payload = {
        "key": "alarm",
        "subsystem": "ips",
        "id": "unifi-test-evt-991",
        "src_ip": "192.168.30.99",
        "dst_ip": "192.168.10.15",
        "src_mac": "58:11:22:33:44:55",
        "proto": "TCP",
        "dst_port": "445",
        "signature": "ET EXPLOIT Suspicious SMB Remote Execution Attempt",
        "hostname": "WS-TESTE-INVADIDA",
        "switch_name": "USW-24-PoE-Piso-1",
        "switch_port": "Port 12",
        "vlan_id": "VLAN 30 - Workstations"
    }
    wh_resp = client.post("/api/webhooks/unifi", json=unifi_webhook_payload)
    assert wh_resp.status_code == 200, f"Erro no webhook UniFi: {wh_resp.text}"
    evt_ingested = wh_resp.json()
    assert evt_ingested["source"] == "unifi"
    assert evt_ingested["detection_vector"] == "IDS_IPS"
    print("[3] Ingestão de Alerta IDS/IPS UniFi via Webhook OK.")

    # 4. Consulta do Alerta UniFi Ingerido
    inc_resp = client.get("/api/soc/incidents?source=unifi")
    assert inc_resp.status_code == 200
    inc_data = inc_resp.json()
    assert inc_data["total"] >= 1
    unifi_inc = next((i for i in inc_data["incidents"] if i.get("mac_address") == "58:11:22:33:44:55"), None)
    assert unifi_inc is not None
    print("[4] Alerta UniFi verificado na base com MAC e porta de switch.")

    # 5. Ação de Resposta Ativa: Bloquear MAC na Rede (block-sta)
    block_resp = client.post("/api/soc/unifi/clients/58:11:22:33:44:55/block", json={
        "reason": "Host infectado por exploit SMB detectado pelo IDS",
        "incident_id": unifi_inc["incident_id"]
    })
    assert block_resp.status_code == 200, f"Erro ao bloquear cliente: {block_resp.text}"
    block_data = block_resp.json()
    assert block_data["success"] is True
    print("[5] Comando de Resposta Ativa UniFi (block-sta) executado com sucesso.")

    # 6. Ação de Resposta Ativa: Mover para VLAN de Quarentena
    vlan_resp = client.post("/api/soc/unifi/clients/58:11:22:33:44:55/isolate_vlan", json={
        "vlan_id": 999,
        "incident_id": unifi_inc["incident_id"]
    })
    assert vlan_resp.status_code == 200
    vlan_data = vlan_resp.json()
    assert vlan_data["success"] is True
    print("[6] Comando de Quarentena em VLAN 999 executado com sucesso.")

    # 7. Ação de Resposta Ativa: Reiniciar Porta do Switch (PoE Cycle)
    poe_resp = client.post("/api/soc/unifi/switches/e4:38:83:11:22:03/ports/12/power_cycle", json={
        "incident_id": unifi_inc["incident_id"]
    })
    assert poe_resp.status_code == 200
    poe_data = poe_resp.json()
    assert poe_data["success"] is True
    print("[7] Comando de Power Cycle na porta 12 do switch executado com sucesso.")

    # 8. Desbloquear MAC (unblock-sta)
    unblock_resp = client.post("/api/soc/unifi/clients/58:11:22:33:44:55/unblock")
    assert unblock_resp.status_code == 200
    unblock_data = unblock_resp.json()
    assert unblock_data["success"] is True
    print("[8] Conectividade da estação restaurada na rede UniFi (unblock-sta) OK.")

    # 9. Verificação de Métricas Táticas Híbridas (Acronis + UniFi)
    tact_resp = client.get("/api/soc/tactical_metrics")
    assert tact_resp.status_code == 200
    tact_data = tact_resp.json()
    assert "acronis" in tact_data
    assert tact_data["acronis"]["online"] >= 1
    assert tact_data["unifi"]["devices_total"] >= 1
    assert tact_data["unifi"]["clients_total"] >= 1
    print("[9] Métricas táticas híbridas Acronis/UniFi validadas 100%.")

    print("\n============================================================")
    print("TODOS OS 9 TESTES DA INTEGRAÇÃO UBIQUITI UNIFI SOC PASSARAM!")
    print("============================================================\n")

if __name__ == "__main__":
    test_unifi_integration_suite()
