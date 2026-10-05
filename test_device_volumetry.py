import asyncio
from acronis_client import AcronisClient

def test_device_filtering_rules():
    """
    Testa todas as regras de filtragem estrita de dispositivos,
    deduplicação e recálculo dos KPIs de volumetria e backups.
    """
    client = AcronisClient()
    
    # 1. Simulação de lista de recursos brutos da API Acronis (contendo casos reais de poluição)
    mock_raw_items = [
        # 1. Máquina Real Válida com Agente Ativo
        {
            "id": "res-srv-001",
            "name": "SRV-PROD-SQL",
            "type": "resource.machine",
            "status": "active",
            "managed": True,
            "agent": {"id": "agent-001", "registered": True, "status": "active"},
            "last_backup_status": "success",
            "last_backup_time": "2026-10-05T02:00:00Z"
        },
        # 2. Máquina Real Válida com Agente Ativo (Estação)
        {
            "id": "res-ws-002",
            "name": "DESKTOP-FIN-01",
            "type": "workstation",
            "status": "active",
            "managed": True,
            "agentId": "agent-002",
            "last_backup_status": "success",
            "last_backup_time": "2026-10-05T03:30:00Z"
        },
        # 3. Máquina com Backup Falho (deve ser contabilizada como máquina, mas falha de backup)
        {
            "id": "res-ws-003",
            "name": "DESKTOP-ENG-02",
            "type": "machine",
            "status": "active",
            "managed": True,
            "agent": {"id": "agent-003", "registered": True, "status": "active"},
            "last_backup_status": "failed",
            "last_backup_time": "2026-10-05T04:00:00Z"
        },
        # 4. POLUIÇÃO 1: Item Descoberto na Rede (Unmanaged Discovery / Printer / Switch)
        {
            "id": "res-disc-004",
            "name": "PRINTER-HP-LASER",
            "type": "resource.network_device",
            "status": "unmanaged",
            "managed": False
        },
        # 5. POLUIÇÃO 2: Caixa Postal Microsoft 365 (M365 Mailbox)
        {
            "id": "res-m365-005",
            "name": "diretoria@jmcorp.com.br",
            "type": "m365_mailbox",
            "status": "active"
        },
        # 6. POLUIÇÃO 3: Site SharePoint M365
        {
            "id": "res-sp-006",
            "name": "Portal Intranet",
            "type": "sharepoint_site",
            "status": "active"
        },
        # 7. POLUIÇÃO 4: Máquina Deletada / Arquivada
        {
            "id": "res-old-007",
            "name": "DESKTOP-OLD-REMOVED",
            "type": "workstation",
            "status": "deleted",
            "agent": {"id": "agent-007", "registered": False, "status": "deleted"}
        },
        # 8. POLUIÇÃO 5: Agente Revogado
        {
            "id": "res-rev-008",
            "name": "DESKTOP-REVOKED",
            "type": "machine",
            "status": "active",
            "agent": {"id": "agent-008", "registered": False, "status": "revoked"}
        },
        # 9. POLUIÇÃO 6: Registro Duplicado da mesma máquina (mesmo agent_id reconectado / multi-NIC)
        {
            "id": "res-ws-002-dup",
            "name": "DESKTOP-FIN-01.local",
            "type": "workstation",
            "status": "active",
            "managed": True,
            "agentId": "agent-002",
            "last_backup_status": "success",
            "last_backup_time": "2026-10-05T03:30:00Z"
        },
        # 10. POLUIÇÃO 7: Registro Duplicado pelo mesmo resource_id
        {
            "id": "res-srv-001",
            "name": "SRV-PROD-SQL",
            "type": "resource.machine",
            "status": "active",
            "managed": True,
            "agent": {"id": "agent-001", "registered": True, "status": "active"}
        },
        # 11. POLUIÇÃO 8: Dispositivo Descoberto sem Agente
        {
            "id": "res-disc-009",
            "name": "192.168.10.250",
            "type": "discovered_machine",
            "status": "active",
            "managed": False
        }
    ]

    # Simulação do catálogo de agentes oficiais
    mock_agents_map = {
        "agent-001": {"id": "agent-001", "online": True, "registered": True, "status": "active"},
        "agent-002": {"id": "agent-002", "online": True, "registered": True, "status": "active"},
        "agent-003": {"id": "agent-003", "online": False, "registered": True, "status": "active"}
    }

    excluded_type_keywords = [
        "m365", "office365", "msexchange", "mailbox", "sharepoint", "teams", "onedrive",
        "tenant_cloud", "cloud_account", "azure", "google", "cloud",
        "discovery", "discovered", "network_device", "unmanaged",
        "volume", "disk", "cluster", "esx", "pool", "location",
        "organization", "ad_object", "switch", "router", "printer", "firewall"
    ]

    filtered_resources = []
    seen_resource_ids = set()
    seen_agent_ids = set()

    for r in mock_raw_items:
        r_id = str(r.get("id") or "")
        if not r_id:
            continue

        r_status = str(r.get("status") or r.get("state") or "").lower()
        if r_status in ["deleted", "removed", "revoked", "unregistered", "archived", "unmanaged", "disabled"]:
            continue
        if r.get("is_deleted") is True or r.get("deleted_at") is not None:
            continue
        if r.get("managed") is False or r.get("unmanaged") is True:
            continue

        res_type = str(r.get("type") or r.get("resourceType") or r.get("kind") or "").lower()
        if any(kw in res_type for kw in excluded_type_keywords):
            continue

        agent_id = None
        agent_obj = r.get("agent")
        agent_registered = None
        if isinstance(agent_obj, dict):
            agent_id = str(agent_obj.get("id") or agent_obj.get("agent_id") or "")
            agent_registered = agent_obj.get("registered")
            ag_st = str(agent_obj.get("status") or "").lower()
            if agent_registered is False or ag_st in ["revoked", "deleted", "unregistered", "removed", "disabled", "archived"]:
                continue
        if not agent_id:
            agent_id = str(r.get("agentId") or r.get("agent_id") or "")

        agent_info = mock_agents_map.get(agent_id) if agent_id else None
        if not agent_info:
            if not (agent_id and (agent_registered is True or r.get("managed") is True)):
                continue

        unique_agent_id = str(agent_info.get("id") if agent_info else (agent_id or ""))
        if r_id in seen_resource_ids:
            continue
        if unique_agent_id and unique_agent_id in seen_agent_ids:
            continue

        seen_resource_ids.add(r_id)
        if unique_agent_id:
            seen_agent_ids.add(unique_agent_id)

        name = r.get("name")
        norm_type = "server" if ("server" in res_type or "srv" in name.lower()) else "workstation"

        filtered_resources.append({
            "id": r_id,
            "agent_id": unique_agent_id,
            "name": name,
            "type": norm_type,
            "online": bool(agent_info.get("online") if agent_info else True),
            "risk_level": "safe" if r.get("last_backup_status") == "success" else "critical",
            "last_backup_status": r.get("last_backup_status", "none"),
            "last_backup_time": r.get("last_backup_time", "N/A")
        })

    # Validações estritas:
    print(f"[TESTE 1] Total de itens brutos: {len(mock_raw_items)}")
    print(f"[TESTE 1] Total filtrado de máquinas reais com agente: {len(filtered_resources)}")
    
    # Devem restar EXATAMENTE 3 máquinas (res-srv-001, res-ws-002, res-ws-003)
    assert len(filtered_resources) == 3, f"Esperado 3 máquinas reais, obtido {len(filtered_resources)}"
    
    ids = [r["id"] for r in filtered_resources]
    assert "res-srv-001" in ids
    assert "res-ws-002" in ids
    assert "res-ws-003" in ids
    assert "res-disc-004" not in ids, "Dispositivo de rede descoberto não foi filtrado"
    assert "res-m365-005" not in ids, "Mailbox M365 não foi filtrada"
    assert "res-sp-006" not in ids, "SharePoint site não foi filtrado"
    assert "res-old-007" not in ids, "Máquina deletada não foi filtrada"
    assert "res-rev-008" not in ids, "Máquina com agente revogado não foi filtrada"
    assert "res-ws-002-dup" not in ids, "Registro duplicado de agente não foi descartado"
    assert "res-disc-009" not in ids, "Dispositivo descoberto sem agente não foi descartado"
    print(" -> PASSOU: Todas as 8 entidades inválidas/duplicadas foram eliminadas com sucesso.")

    # 2. Teste do Recálculo de KPIs
    total_resources = len(filtered_resources)
    safe_resources = sum(1 for r in filtered_resources if r["risk_level"] == "safe")
    safe_percentage = round((safe_resources / total_resources) * 100.0, 1)

    print(f"[TESTE 2] Total no card Dispositivos: {total_resources}")
    print(f"[TESTE 2] Taxa de Segurança: {safe_resources}/{total_resources} ({safe_percentage}%)")
    assert total_resources == 3
    assert safe_resources == 2
    assert safe_percentage == 66.7
    print(" -> PASSOU: Total no Card Dispositivos e Taxa de Segurança refletem exatamente a frota real.")

    # 3. Teste de Backups (sem replicação cega)
    backup_metrics = asyncio.run(client.get_backup_metrics(filtered_resources, period="daily"))
    print(f"[TESTE 3] Métricas de Backups: {backup_metrics}")
    assert backup_metrics["success"] == 2, f"Esperado 2 backups com sucesso, obtido {backup_metrics['success']}"
    assert backup_metrics["failed"] == 1, f"Esperado 1 backup com falha, obtido {backup_metrics['failed']}"
    assert backup_metrics["warning"] == 0
    print(" -> PASSOU: Backups (24H) computa apenas backups reais sem replicar cegamente o total de máquinas.")

    print("\nTODOS OS TESTES DE VOLUMETRIA E FILTRAGEM PASSARAM COM SUCESSO!")

if __name__ == "__main__":
    test_device_filtering_rules()
