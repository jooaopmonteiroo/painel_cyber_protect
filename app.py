import os
from typing import Optional
from fastapi import FastAPI, Request, Query
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
import uvicorn
from config import Config
from acronis_client import AcronisClient
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(
    title="Dashboard Acronis Cyber Protect Cloud",
    description="Painel web para monitoramento centralizado de alertas, dispositivos, status de risco e planos de proteção via API Acronis.",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
# Instância do cliente Acronis
acronis = AcronisClient()
# Configuração de templates HTML (Jinja2)
templates_dir = os.path.join(os.path.dirname(__file__), "templates")
templates = Jinja2Templates(directory=templates_dir)
@app.get("/", response_class=HTMLResponse)
async def index_page(request: Request):
    """Renderiza a página principal do Dashboard (SPA com Tailwind CSS e Chart.js)."""
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "is_mock": acronis.is_mock,
            "acronis_url": Config.ACRONIS_URL
        }
    )
@app.get("/api/status")
async def get_status():
    """Retorna o status da conexão com a API Acronis e modo de operação."""
    if acronis.is_mock:
        return {
            "status": "mock_mode",
            "is_mock": True,
            "acronis_url": Config.ACRONIS_URL,
            "message": "Executando em Modo Demonstração (Dados Simulados)"
        }
    
    try:
        await acronis.get_access_token()
        return {
            "status": "connected",
            "is_mock": False,
            "acronis_url": acronis.base_url,
            "message": f"Conectado com Sucesso à API Acronis ({acronis.base_url})"
        }
    except Exception as e:
        return {
            "status": "auth_error",
            "is_mock": False,
            "acronis_url": Config.ACRONIS_URL,
            "message": f"Falha de Autenticação na API: {str(e)}"
        }
@app.get("/api/kpis")
async def get_kpis():
    """Retorna métricas e resumo para o Painel Geral / KPI Overview."""
    summary = await acronis.get_summary_kpis()
    return summary
@app.get("/api/alerts")
async def get_alerts(
    severity: Optional[str] = Query(None, description="Filtro de severidade: all, critical, warning, info"),
    search: Optional[str] = Query(None, description="Busca textual por nome da máquina ou mensagem de alerta")
):
    """Retorna a lista de Alertas da plataforma Acronis com filtros aplicados."""
    alerts = await acronis.get_alerts(severity=severity, search=search)
    return {"alerts": alerts, "count": len(alerts)}
@app.get("/api/resources")
async def get_resources(
    search: Optional[str] = Query(None, description="Busca textual por nome ou IP da máquina")
):
    """Retorna a lista de Dispositivos/Máquinas e seus níveis de risco e saúde."""
    resources = await acronis.get_resources(search=search)
    return {"resources": resources, "count": len(resources)}
@app.get("/api/policies")
async def get_policies():
    """Retorna a lista de Planos de Segurança / Proteção aplicados aos dispositivos."""
    policies = await acronis.get_protection_policies()
    return {"policies": policies, "count": len(policies)}

@app.get("/api/m365/summary")
async def get_m365_summary():
    """Retorna métricas consolidadas do ambiente Microsoft 365 Cloud."""
    return await acronis.get_m365_summary()

@app.get("/api/m365/accounts")
async def get_m365_accounts():
    """Retorna a lista de contas/tenants M365 gerenciados."""
    accounts = await acronis.get_m365_accounts()
    return {"accounts": accounts, "count": len(accounts)}

@app.get("/api/m365/accounts/{account_id}/details")
async def get_m365_account_details(account_id: str):
    """Retorna a visão detalhada (caixas de e-mail, sites e alertas) de um tenant M365."""
    return await acronis.get_m365_account_details(account_id)

@app.get("/api/analytics/charts")
async def get_analytics_charts():
    """Retorna dados consolidados para alimentar os 5 gráficos analíticos do Dashboard."""
    return await acronis.get_analytics_charts()

@app.get("/api/url_filtering/alerts")
async def get_url_filtering_alerts(
    category: Optional[str] = Query(None, description="Filtro por categoria de URL: Apostas/Jogos, Malware/Phishing, Redes Sociais, Conteúdo Adulto, Outros"),
    search: Optional[str] = Query(None, description="Busca textual por URL, dispositivo ou IP")
):
    """Retorna a lista de eventos de bloqueio de URL e ameaças web com filtros aplicados."""
    alerts = await acronis.get_url_filtering_alerts(category=category, search=search)
    return {"alerts": alerts, "count": len(alerts)}

@app.get("/api/url_filtering/summary")
async def get_url_filtering_summary():
    """Retorna métricas consolidadas e estatísticas do Filtro de URLs / Ameaças Web."""
    return await acronis.get_url_filtering_summary()

if __name__ == "__main__":
    print(f"[+] Iniciando Painel Acronis em http://localhost:{Config.PORT}")
    print(f"[i] Modo Mock / Demonstração: {'ATIVADO' if Config.is_mock_enabled() else 'DESATIVADO (API Real)'}")
    uvicorn.run("app:app", host="0.0.0.0", port=Config.PORT, reload=True)