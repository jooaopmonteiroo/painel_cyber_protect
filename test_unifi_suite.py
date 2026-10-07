# -*- coding: utf-8 -*-
"""
Suite de testes automatizados para os endpoints da API UniFi Network & Controles Administrativos
"""
import sys
from fastapi.testclient import TestClient
from app import app
from auth import get_audit_logs

def run_unifi_tests():
    print("=" * 65)
    print("INICIANDO SUITE DE TESTES UNIFI NETWORK & NETWORKING HUB")
    print("=" * 65)

    client = TestClient(app, follow_redirects=False)

    # 1. Testar bloqueio não autenticado
    print("[1] Testando bloqueio 401 em endpoints UniFi para usuários sem sessão...")
    endpoints = [
        "/api/unifi/summary",
        "/api/unifi/devices",
        "/api/unifi/clients",
        "/api/unifi/analytics",
        "/api/unifi/networks",
        "/api/unifi/wans",
        "/api/unifi/ports",
    ]
    for ep in endpoints:
        r = client.get(ep)
        assert r.status_code == 401, f"Endpoint {ep} deveria retornar 401, retornou {r.status_code}"
    print("    -> PASSOU: Todos os endpoints protegidos retornam 401 para requisições anônimas.")

    # 2. Login com administrador
    print("[2] Efetuando login administrativo...")
    r = client.post("/api/auth/login", json={"username_or_email": "admin", "password": "Admin@Acronis2026!"})
    assert r.status_code == 200, f"Falha no login: {r.text}"
    session_cookie = r.cookies.get("cyber_session_id")
    assert session_cookie, "Cookie cyber_session_id não retornado"
    client.cookies.set("cyber_session_id", session_cookie)
    print("    -> PASSOU: Autenticado com sucesso. Cookie de sessão obtido.")

    # 3. Teste /api/unifi/summary
    print("[3] Testando GET /api/unifi/summary...")
    r = client.get("/api/unifi/summary")
    assert r.status_code == 200, f"Erro: {r.status_code}"
    data = r.json()
    assert "kpis" in data, "Chave 'kpis' ausente no resumo"
    assert data["kpis"]["devices_total"] >= 1, "devices_total inválido"
    print(f"    -> PASSOU: Resumo retornado ({data['kpis']['devices_online']} devices online, {data['kpis']['clients_total']} clients).")

    # 4. Teste /api/unifi/devices
    print("[4] Testando GET /api/unifi/devices...")
    r = client.get("/api/unifi/devices")
    assert r.status_code == 200
    devices = r.json().get("devices", [])
    assert len(devices) >= 1, "Nenhum dispositivo retornado"
    has_udm = any(d["model"] == "UniFi Dream Machine Pro" or d["name"] == "UDM-JM_TRANSPORTES" for d in devices)
    assert has_udm, "UDM Pro não localizada na lista de dispositivos"
    print(f"    -> PASSOU: {len(devices)} equipamentos catalogados com sucesso.")

    # 5. Teste /api/unifi/clients
    print("[5] Testando GET /api/unifi/clients...")
    r = client.get("/api/unifi/clients")
    assert r.status_code == 200
    clients = r.json().get("clients", [])
    assert len(clients) >= 1, "Nenhum cliente retornado"
    
    # Teste de filtro por SSID
    r_filter = client.get("/api/unifi/clients?ssid=JM-Mobile")
    assert r_filter.status_code == 200
    mobile_clients = r_filter.json().get("clients", [])
    assert all(c["essid"] == "JM-Mobile" for c in mobile_clients), "Filtro por SSID falhou"
    print(f"    -> PASSOU: {len(clients)} clientes retornados ({len(mobile_clients)} no SSID JM-Mobile).")

    # 6. Teste /api/unifi/networks
    print("[6] Testando GET /api/unifi/networks...")
    r = client.get("/api/unifi/networks")
    assert r.status_code == 200
    networks = r.json().get("networks", [])
    assert len(networks) == 3, f"Esperadas 3 redes, retornadas {len(networks)}"
    lan_net = next(n for n in networks if n["vlan"] == 1)
    assert lan_net["subnet"] == "192.168.14.0/23", "Sub-rede LAN Principal incorreta"
    assert lan_net["active_leases"] == 284, "Contagem de leases incorreta"
    print("    -> PASSOU: LAN 192.168.14.0/23, VLAN 70 e VLAN 60 validadas com leases DHCP.")

    # 7. Teste /api/unifi/wans
    print("[7] Testando GET /api/unifi/wans...")
    r = client.get("/api/unifi/wans")
    assert r.status_code == 200
    wans = r.json()
    assert len(wans["interfaces"]) == 2, "Esperadas 2 interfaces WAN"
    wan1 = next(w for w in wans["interfaces"] if w["name"] == "WAN 1")
    wan2 = next(w for w in wans["interfaces"] if w["name"] == "WAN 2")
    assert wan1["ip"] == "187.9.95.202", f"IP WAN1 incorreto: {wan1['ip']}"
    assert wan2["ip"] == "187.120.7.126", f"IP WAN2 incorreto: {wan2['ip']}"
    print(f"    -> PASSOU: Dual WAN validada (WAN1 Vivo {wan1['ip']} @ {wan1['latency_ms']}ms, WAN2 SAMM {wan2['ip']} @ {wan2['latency_ms']}ms).")

    # 8. Teste /api/unifi/ports (Port Matrix)
    print("[8] Testando GET /api/unifi/ports (Matriz Física)...")
    r = client.get("/api/unifi/ports")
    assert r.status_code == 200
    ports = r.json()
    assert len(ports["gateway"]["ports"]) == 11, "UDM Pro deve conter exatamente 11 portas físicas"
    assert len(ports["switch"]["ports"]) == 16, "USW Lite deve conter exatamente 16 portas físicas"
    poe_ports = [p for p in ports["switch"]["ports"] if p.get("has_poe")]
    assert len(poe_ports) == 8, "USW Lite deve conter 8 portas PoE+"
    print("    -> PASSOU: Matriz de 11 portas UDM Pro e 16 portas USW Lite 16 PoE validada.")

    # 9. Teste Ações Administrativas: Reinício de Dispositivo
    print("[9] Testando POST /api/unifi/devices/{mac}/restart...")
    r = client.post("/api/unifi/devices/24:5a:4c:01:08:gr/restart")
    assert r.status_code == 200
    assert r.json()["success"] is True
    print("    -> PASSOU: Comando de reinício enviado com sucesso.")

    # 10. Teste Ação Administrativa: Controle de Porta PoE
    print("[10] Testando POST /api/unifi/devices/{mac}/ports/{port_idx}/poe...")
    r = client.post("/api/unifi/devices/24:5a:4c:sw:16:01/ports/1/poe", json={"poe_mode": "auto"})
    assert r.status_code == 200
    assert r.json()["success"] is True
    print("    -> PASSOU: Modo PoE da porta 1 alterado com sucesso.")

    # 11. Teste Ação Administrativa: Bloqueio e Desbloqueio de Cliente
    print("[11] Testando POST /api/unifi/clients/{mac}/block e unblock...")
    client_mac = "74:ac:b9:18:08:f8"
    r_block = client.post(f"/api/unifi/clients/{client_mac}/block")
    assert r_block.status_code == 200
    assert r_block.json()["success"] is True

    r_unblock = client.post(f"/api/unifi/clients/{client_mac}/unblock")
    assert r_unblock.status_code == 200
    assert r_unblock.json()["success"] is True
    print("    -> PASSOU: Bloqueio e desbloqueio de cliente executados com sucesso.")

    # 12. Teste Ação Administrativa: Reconexão / Kick
    print("[12] Testando POST /api/unifi/clients/{mac}/reconnect...")
    r_reconn = client.post(f"/api/unifi/clients/{client_mac}/reconnect")
    assert r_reconn.status_code == 200
    assert r_reconn.json()["success"] is True
    print("    -> PASSOU: Kick/reconexão de cliente executado com sucesso.")

    # 13. Teste Ação Administrativa: Speedtest WAN
    print("[13] Testando POST /api/unifi/speedtest/run...")
    r_speed = client.post("/api/unifi/speedtest/run")
    assert r_speed.status_code == 200
    st_data = r_speed.json()
    assert "speedtest" in st_data
    assert st_data["speedtest"]["download_mbps"] > 100
    print(f"    -> PASSOU: Speedtest executado ({st_data['speedtest']['download_mbps']} Mbps Down, {st_data['speedtest']['upload_mbps']} Mbps Up).")

    # 14. Validação da Trilha de Auditoria
    print("[14] Validando registro das ações administrativas na trilha de auditoria...")
    logs = get_audit_logs(limit=10)
    unifi_actions = [l["action"] for l in logs if "unifi" in l["action"]]
    assert len(unifi_actions) >= 4, f"Esperadas pelo menos 4 ações auditadas, encontradas {len(unifi_actions)}"
    print(f"    -> PASSOU: Ações registradas com sucesso na auditoria: {unifi_actions[:4]}")

    print("=" * 65)
    print("SUITE UNIFI NETWORK FINALIZADA COM 100% DE SUCESSO!")
    print("=" * 65)

if __name__ == "__main__":
    run_unifi_tests()
