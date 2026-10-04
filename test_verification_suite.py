import sys
from fastapi.testclient import TestClient
from app import app as main_app
from admin_server import app as admin_app
from config import Config
import auth

def run_tests():
    print("=" * 60)
    print("INICIANDO SUITE DE TESTES END-TO-END DE SEGURANÇA E ACESSO")
    print("=" * 60)
    
    main_client = TestClient(main_app, follow_redirects=False)
    admin_client = TestClient(admin_app, follow_redirects=False)

    # 1. Teste de Acesso Não Autenticado ao Dashboard Principal
    print("[1] Testando redirecionamento de usuário não autenticado em '/'...")
    resp = main_client.get("/")
    assert resp.status_code == 303, f"Esperado 303 redirect, obtido {resp.status_code}"
    assert resp.headers["location"] == "/login", f"Esperado redirecionamento para /login, obtido {resp.headers.get('location')}"
    print("    -> PASSOU: '/' redireciona para '/login' com status 303.")

    # 2. Teste de Bloqueio de APIs Não Autenticadas (Zero-Trust)
    print("[2] Testando bloqueio de acesso a APIs protegidas sem autenticação...")
    endpoints = ["/api/status", "/api/kpis", "/api/resources", "/api/alerts", "/api/policies", "/api/url_filtering/summary"]
    for ep in endpoints:
        resp = main_client.get(ep)
        assert resp.status_code == 401, f"Endpoint {ep} deveria retornar 401, retornou {resp.status_code}"
    print("    -> PASSOU: Todos os endpoints de dados retornaram 401 Unauthorized.")

    # 3. Teste de Tentativa de Login com Senha Incorreta
    print("[3] Testando login com credenciais inválidas...")
    resp = main_client.post("/api/auth/login", json={"username_or_email": "admin", "password": "WrongPassword!"})
    assert resp.status_code == 401, f"Esperado 401, obtido {resp.status_code}"
    print("    -> PASSOU: Credenciais inválidas devidamente rejeitadas.")

    # 4. Teste de Login com Admin Mestre
    print("[4] Testando login de administrador no dashboard principal...")
    resp = main_client.post("/api/auth/login", json={"username_or_email": "admin", "password": "Admin@Acronis2026!"})
    assert resp.status_code == 200, f"Esperado 200, obtido {resp.status_code}: {resp.text}"
    session_cookie = resp.cookies.get("cyber_session_id")
    assert session_cookie, "Cookie de sessão cyber_session_id não foi retornado"
    print(f"    -> PASSOU: Login bem-sucedido. Cookie de sessão obtido.")

    # 5. Teste de Acesso Autenticado com Cookie de Sessão
    print("[5] Testando acesso ao dashboard principal com cookie de sessão...")
    main_client.cookies.set("cyber_session_id", session_cookie)
    resp = main_client.get("/")
    assert resp.status_code == 200, f"Esperado 200, obtido {resp.status_code}"
    assert "Administrador Master" in resp.text, "Nome do usuário não encontrado na interface"
    assert "Sair" in resp.text, "Botão de logout não encontrado no template"
    print("    -> PASSOU: Dashboard carregado com sucesso para usuário autenticado.")

    # 6. Teste de Acesso aos Endpoints Protegidos com Sessão
    print("[6] Testando chamada à API autenticada (/api/auth/me e /api/status)...")
    resp = main_client.get("/api/auth/me")
    assert resp.status_code == 200
    user_data = resp.json()["user"]
    assert user_data["username"] == "admin"
    assert user_data["role"] == "admin"
    print("    -> PASSOU: Perfil do usuário verificado com sucesso.")

    # 7. Teste do Console Administrativo Externo (Sem Chave Mestra)
    print("[7] Testando segurança do Console Administrativo Externo sem autenticação...")
    resp = admin_client.get("/api/admin/users")
    assert resp.status_code == 401, f"Esperado 401 sem chave mestra, obtido {resp.status_code}"
    print("    -> PASSOU: Console externo bloqueou acesso sem a Chave Mestra.")

    # 8. Teste do Console Administrativo Externo (Com Chave Mestra)
    print("[8] Testando acesso ao Console Administrativo Externo com Chave Mestra...")
    master_headers = {"X-Admin-Master-Key": Config.ADMIN_MASTER_KEY}
    resp = admin_client.get("/api/admin/users", headers=master_headers)
    assert resp.status_code == 200, f"Esperado 200, obtido {resp.status_code}"
    users = resp.json()
    assert len(users) >= 1
    print(f"    -> PASSOU: Console externo listou {len(users)} usuário(s) com sucesso.")

    # 9. Teste do Fluxo de Aprovação de Novo Usuário
    print("[9] Criando novo usuário de teste com status PENDENTE (is_active=False)...")
    test_user_payload = {
        "username": "operador_teste",
        "email": "operador@teste.local",
        "full_name": "Operador de Segurança Teste",
        "password": "SenhaSeguraTeste#2026",
        "role": "operator",
        "is_active": False
    }
    resp = admin_client.post("/api/admin/users", json=test_user_payload, headers=master_headers)
    assert resp.status_code == 200, f"Falha ao criar usuário: {resp.text}"
    new_user_id = resp.json()["user_id"]
    print(f"    -> PASSOU: Usuário 'operador_teste' (ID {new_user_id}) criado com status pendente.")

    # 10. Teste de Tentativa de Login de Usuário Pendente no Site Principal
    print("[10] Testando tentativa de login de usuário pendente no site principal...")
    resp = main_client.post("/api/auth/login", json={"username_or_email": "operador_teste", "password": "SenhaSeguraTeste#2026"})
    assert resp.status_code == 401, f"Esperado 401 para conta pendente, obtido {resp.status_code}"
    data = resp.json()
    assert "ainda não foi liberada" in data["message"], f"Mensagem inesperada: {data['message']}"
    print(f"    -> PASSOU: Acesso negado com mensagem explicativa: '{data['message']}'")

    # 11. Teste de Liberação/Aprovação do Usuário pelo Console Externo
    print(f"[11] Aprovando e liberando usuário ID {new_user_id} via Console Externo...")
    resp = admin_client.post(f"/api/admin/users/{new_user_id}/approve", headers=master_headers)
    assert resp.status_code == 200, f"Falha ao aprovar usuário: {resp.text}"
    print(f"    -> PASSOU: Usuário ID {new_user_id} aprovado com sucesso.")

    # 12. Teste de Login do Usuário Recém-Aprovado no Site Principal
    print("[12] Testando login do usuário agora aprovado...")
    resp = main_client.post("/api/auth/login", json={"username_or_email": "operador_teste", "password": "SenhaSeguraTeste#2026"})
    assert resp.status_code == 200, f"Esperado 200 após aprovação, obtido {resp.status_code}: {resp.text}"
    op_session_cookie = resp.cookies.get("cyber_session_id")
    assert op_session_cookie, "Cookie de sessão não emitido para novo usuário aprovado"
    print("    -> PASSOU: Usuário aprovado efetuou login com sucesso no dashboard principal.")

    # 13. Teste de Bloqueio Imediato e Revogação de Sessão pelo Console Externo
    print(f"[13] Bloqueando usuário ID {new_user_id} e verificando revogação de sessão...")
    resp = admin_client.post(f"/api/admin/users/{new_user_id}/block", headers=master_headers)
    assert resp.status_code == 200, f"Falha ao bloquear usuário: {resp.text}"
    
    # Testar com o cookie anterior do usuário bloqueado
    op_client = TestClient(main_app, follow_redirects=False)
    op_client.cookies.set("cyber_session_id", op_session_cookie)
    resp = op_client.get("/api/auth/me")
    assert resp.status_code == 401, f"Esperado 401 após bloqueio, obtido {resp.status_code}"
    print("    -> PASSOU: Sessão do usuário bloqueado foi imediatamente revogada.")

    # 14. Limpeza do usuário de teste
    print(f"[14] Excluindo usuário de teste ID {new_user_id}...")
    resp = admin_client.delete(f"/api/admin/users/{new_user_id}", headers=master_headers)
    assert resp.status_code == 200, f"Falha ao excluir usuário: {resp.text}"
    print("    -> PASSOU: Usuário de teste removido.")

    # 15. Verificação da Trilha de Auditoria
    print("[15] Verificando logs de auditoria do console externo...")
    resp = admin_client.get("/api/admin/audit", headers=master_headers)
    assert resp.status_code == 200
    logs = resp.json()
    assert len(logs) > 0
    print(f"    -> PASSOU: Trilha de auditoria contém {len(logs)} eventos registrados.")

    # 16. Teste de Exibição dos Dashboards por Período (/api/kpis)
    print("[16] Testando comportamento padrão diário e filtros temporais em /api/kpis...")
    # Padrão: daily (estritamente hoje)
    resp_def = main_client.get("/api/kpis")
    assert resp_def.status_code == 200
    data_def = resp_def.json()
    assert data_def.get("period") == "daily"
    # Semanal
    resp_w = main_client.get("/api/kpis?period=weekly")
    assert resp_w.status_code == 200
    assert resp_w.json().get("period") == "weekly"
    # Mensal
    resp_m = main_client.get("/api/kpis?period=monthly")
    assert resp_m.status_code == 200
    assert resp_m.json().get("period") == "monthly"
    # Inválido
    resp_inv = main_client.get("/api/kpis?period=invalid_period")
    assert resp_inv.status_code == 422
    print(f"    -> PASSOU: Período padrão diário validado ({data_def.get('total_alerts')} alertas diários vs {resp_m.json().get('total_alerts')} mensais).")

    # 17. Teste de Gráficos Analíticos por Período (/api/analytics/charts)
    print("[17] Testando gráficos analíticos filtrados por período...")
    for p in ["daily", "weekly", "monthly"]:
        resp_c = main_client.get(f"/api/analytics/charts?period={p}")
        assert resp_c.status_code == 200
        cdata = resp_c.json()
        assert "alert_threat_timeline" in cdata
        assert "protection_success_rate" in cdata
    print("    -> PASSOU: Gráficos de telemetria gerados dinamicamente para daily, weekly e monthly.")

    # 18. Teste de Exportação de Relatório em Excel (.xlsx) na Aba Planos de Segurança
    print("[18] Testando exportação executiva de relatório em Excel (.xlsx)...")
    # Não autenticado
    anon_client = TestClient(main_app, follow_redirects=False)
    resp_anon = anon_client.get("/api/policies/export")
    assert resp_anon.status_code == 401
    # Autenticado
    resp_exp = main_client.get("/api/policies/export")
    assert resp_exp.status_code == 200
    assert resp_exp.headers.get("content-type") == "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    assert "attachment" in resp_exp.headers.get("content-disposition", "")
    assert ".xlsx" in resp_exp.headers.get("content-disposition", "")
    
    import openpyxl, io
    wb = openpyxl.load_workbook(io.BytesIO(resp_exp.content))
    assert "Planos de Segurança" in wb.sheetnames
    assert "Dispositivos e Cobertura" in wb.sheetnames
    ws_policies = wb["Planos de Segurança"]
    ws_devices = wb["Dispositivos e Cobertura"]
    assert ws_policies.max_row >= 5
    assert ws_devices.max_row >= 5
    print(f"    -> PASSOU: Planilha XLSX gerada com abas '{wb.sheetnames}', formatação e dados oficiais ({ws_policies.max_row} linhas de planos, {ws_devices.max_row} linhas de dispositivos).")

    print("\n" + "=" * 60)
    print("TODOS OS 18 TESTES END-TO-END PASSARAM COM 100% DE SUCESSO!")
    print("=" * 60)

if __name__ == "__main__":
    run_tests()
