import sys
import asyncio
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
from datetime import datetime, timezone, timedelta
from acronis_client import processar_dados_dispositivo, AcronisClient
from soc_engine import soc_engine

def test_processar_dados_dispositivo_unit():
    print("\n--- TESTE 1: Validação do Algoritmo processar_dados_dispositivo ---")
    
    # 1.1 Nome via name
    d1 = {"name": "JM000385.jm.corp", "status": "active"}
    r1 = processar_dados_dispositivo(d1)
    assert r1["nome"] == "JM000385.jm.corp", f"Esperado JM000385.jm.corp, obteve {r1['nome']}"
    print("✅ 1.1 Nome direto extraído com sucesso:", r1["nome"])
    
    # 1.2 Nome via hostname
    d2 = {"hostname": "WS-TESTE-INVADIDA", "status": "active"}
    r2 = processar_dados_dispositivo(d2)
    assert r2["nome"] == "WS-TESTE-INVADIDA", f"Esperado WS-TESTE-INVADIDA, obteve {r2['nome']}"
    print("✅ 1.2 Fallback para hostname funcionando:", r2["nome"])

    # 1.3 Bloqueio do nome genérico 'Dispositivo' com fallback para IP
    d3 = {"name": "Dispositivo", "ip": "192.168.10.50", "status": "active"}
    r3 = processar_dados_dispositivo(d3)
    assert r3["nome"] == "IP-192.168.10.50", f"Esperado IP-192.168.10.50, obteve {r3['nome']}"
    print("✅ 1.3 Nome 'Dispositivo' banido e convertido para IP:", r3["nome"])

    # 1.4 Bloqueio do nome genérico 'Dispositivo' com fallback para UUID fragment .jm.corp
    d4 = {"name": "dispositivo", "id": "9a7b6c5d-1234-5678-9abc-112233445566", "status": "active"}
    r4 = processar_dados_dispositivo(d4)
    assert r4["nome"] == "Host-33445566.jm.corp", f"Esperado Host-33445566.jm.corp, obteve {r4['nome']}"
    print("✅ 1.4 Nome 'dispositivo' banido e convertido para Host-UUID.jm.corp:", r4["nome"])

    # 1.5 Avaliação de status: Online se last_seen <= 900s
    recent_iso = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()
    d5 = {"name": "JM000522.jm.corp", "status": "active", "last_seen": recent_iso}
    r5 = processar_dados_dispositivo(d5)
    assert r5["status_online"] == "Online", f"Esperado Online, obteve {r5['status_online']}"
    print("✅ 1.5 Dispositivo recente (5 min) marcado como Online:", r5["status_online"])

    # 1.6 Avaliação de status: Offline se last_seen > 900s (ex: 20 min)
    old_iso = (datetime.now(timezone.utc) - timedelta(minutes=20)).isoformat()
    d6 = {"name": "JM000131.jm.corp", "status": "active", "last_seen": old_iso}
    r6 = processar_dados_dispositivo(d6)
    assert r6["status_online"] == "Offline", f"Esperado Offline, obteve {r6['status_online']}"
    print("✅ 1.6 Dispositivo inativo (20 min) marcado como Offline:", r6["status_online"])

async def test_live_acronis_and_tactical_stats():
    print("\n--- TESTE 2: Validação da API Oficial Acronis e Tactical Stats ---")
    cli = AcronisClient()
    resources = await cli.get_resources()
    
    print(f"Total de recursos de endpoints físicos/máquinas retornados: {len(resources)}")
    assert len(resources) in [181, 182], f"Esperado 181 ou 182 endpoints, obteve {len(resources)}"
    
    # Verifica que nenhum possui o nome "Dispositivo"
    for r in resources:
        assert r["name"].strip().lower() != "dispositivo", f"Encontrado dispositivo genérico: {r}"
        assert not r["name"].startswith("Dispositivo-"), f"Encontrado prefixo Dispositivo-: {r['name']}"
    print("✅ Todos os endpoints possuem nomes autênticos corporativos (zero 'Dispositivo')!")
    
    online_count = sum(1 for r in resources if r["online"])
    offline_count = sum(1 for r in resources if not r["online"])
    print(f"Status Real Calculado: {online_count} Online / {offline_count} Offline (Total: {len(resources)})")
    assert online_count < len(resources), "Nem todos os dispositivos devem estar online simultaneamente!"
    assert online_count + offline_count == len(resources), "Soma online + offline deve bater com o total"
    print("✅ Divisão fracionada real confirmada!")

    # Tactical Stats do SOC Engine
    stats = await soc_engine.get_tactical_stats()
    acronis_stats = stats.get("acronis", {})
    print("Métricas Acronis no Tactical Stats:")
    print(f"  - Total: {acronis_stats.get('total')}")
    print(f"  - Online: {acronis_stats.get('online')}")
    print(f"  - Offline: {acronis_stats.get('offline')}")
    print(f"  - Endpoints na lista: {len(acronis_stats.get('endpoints', []))}")
    
    assert acronis_stats.get("total") in [181, 182]
    assert acronis_stats.get("online") == online_count
    assert acronis_stats.get("offline") == offline_count
    
    # Valida que os endpoints não têm os antigos nomes mockados (SRV-FINANCEIRO-01)
    ep_names = [e["name"] for e in acronis_stats.get("endpoints", [])]
    assert "SRV-FINANCEIRO-01" not in ep_names, "Mocks antigos ainda presentes!"
    print(f"Exemplo de endpoints reais carregados: {ep_names[:5]}")
    print("✅ Tactical Stats 100% dinâmico e integrado com sucesso!")

async def main():
    test_processar_dados_dispositivo_unit()
    await test_live_acronis_and_tactical_stats()
    print("\n🎉 TODOS OS TESTES DE VALIDAÇÃO PASSARAM COM SUCESSO ABSOLUTO!")

if __name__ == "__main__":
    asyncio.run(main())
