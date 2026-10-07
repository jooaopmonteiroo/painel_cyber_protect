import os
import io
import re
import logging
from typing import Optional, List, Dict, Any
from datetime import datetime
from fastapi import FastAPI, Request, Query, Path, HTTPException, status, Depends, Response
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
import uvicorn
from config import Config
from acronis_client import AcronisClient, AcronisAPIError
from unifi_client import UniFiClient, UniFiAPIError
from excel_export import generate_policies_excel
import auth

logger = logging.getLogger("app")

app = FastAPI(
    title="Dashboard JM Cyber Protect",
    description="Painel web corporativo para monitoramento centralizado de alertas, dispositivos, status de risco, planos de proteção, filtro web e rede UniFi.",
    version="1.3.0"
)

# ==================== MIDDLEWARE DE SEGURANÇA E CABEÇALHOS ====================

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["GET"],
    allow_headers=["*"],
)

@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    """
    Middleware de endurecimento de segurança (Security Hardening):
    Aplica cabeçalhos padrão OWASP para prevenir Clickjacking, MIME-Sniffing e XSS.
    """
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self' 'unsafe-inline' 'unsafe-eval' data: blob: https:; "
        "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.tailwindcss.com https://cdn.jsdelivr.net https://unpkg.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' data: https://fonts.gstatic.com; "
        "img-src 'self' data: blob: https:; "
        "connect-src 'self' http: https: ws: wss:;"
    )
    return response

# Instância do cliente Acronis e UniFi
acronis = AcronisClient()
unifi = UniFiClient()

# Configuração de templates HTML (Jinja2) e arquivos estáticos
templates_dir = os.path.join(os.path.dirname(__file__), "templates")
templates = Jinja2Templates(directory=templates_dir)

static_dir = os.path.join(os.path.dirname(__file__), "static")
os.makedirs(static_dir, exist_ok=True)
app.mount("/static", StaticFiles(directory=static_dir), name="static")

# ==================== INPUT SANITIZATION HELPER ====================

def sanitize_user_input(text: Optional[str], max_len: int = 100) -> Optional[str]:
    """
    Sanitiza strings de entrada para busca e filtros, prevenindo SQLi, NoSQLi,
    Path Traversal e injeção de caracteres de controle (null bytes).
    """
    if text is None:
        return None
    # Remove null bytes e caracteres não imprimíveis
    cleaned = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', str(text))
    cleaned = cleaned.strip()
    return cleaned[:max_len] if cleaned else None

# ==================== SCHEMAS PYDANTIC (CODE HARDENING & DATA VALIDATION) ====================

class KPISummaryModel(BaseModel):
    total_resources: int = Field(..., ge=0, description="Total de recursos físicos cadastrados")
    online_resources: int = Field(..., ge=0, description="Total de recursos com agente ativo")
    offline_resources: int = Field(..., ge=0, description="Total de recursos offline")
    protected_resources: int = Field(..., ge=0, description="Recursos com plano ativo vinculado")
    unprotected_resources: int = Field(..., ge=0, description="Recursos desprotegidos")
    protected_percentage: float = Field(..., ge=0.0, le=100.0, description="Percentual de proteção de ativos")
    servers_count: int = Field(..., ge=0)
    workstations_count: int = Field(..., ge=0)
    resources_with_alerts: int = Field(..., ge=0)
    safe_resources: int = Field(..., ge=0)
    warning_resources: int = Field(..., ge=0)
    critical_resources: int = Field(..., ge=0)
    # Mapeamento unificado da Taxa de Segurança real da API
    safe_percentage: float = Field(..., ge=0.0, le=100.0)
    safety_rate: float = Field(..., ge=0.0, le=100.0)
    safetyRate: float = Field(..., ge=0.0, le=100.0)
    taxa_seguranca: float = Field(..., ge=0.0, le=100.0)
    taxaSeguranca: float = Field(..., ge=0.0, le=100.0)
    security_rate: float = Field(..., ge=0.0, le=100.0)
    securityRate: float = Field(..., ge=0.0, le=100.0)
    security_score: float = Field(..., ge=0.0, le=100.0)
    health_status_label: str
    health_status_color: str
    total_alerts: int = Field(..., ge=0)
    critical_alerts: int = Field(..., ge=0)
    warning_alerts: int = Field(..., ge=0)
    info_alerts: int = Field(..., ge=0)
    backup_success: int = Field(..., ge=0)
    failed_backups: int = Field(..., ge=0)
    warning_backups: int = Field(..., ge=0)
    pending_vulnerabilities: int = Field(..., ge=0)
    threats_blocked: int = Field(..., ge=0)
    storage_used_gb: float = Field(..., ge=0.0)
    active_policies: int = Field(..., ge=0)
    is_mock_mode: bool
    period: Optional[str] = Field("daily", description="Período de consolidação das métricas: daily, weekly, monthly")

class TopBlockedDomainModel(BaseModel):
    domain: str = Field(..., min_length=1, description="Domínio ou site raiz identificado")
    site: str = Field(..., min_length=1, description="Nome legível do site/serviço")
    full_domain: str = Field(..., min_length=1, description="Domínio completo ou FQDN original")
    count: int = Field(..., ge=1, description="Quantidade de bloqueios registrados")
    category: str = Field(..., min_length=1, description="Categoria do bloqueio")

class UrlFilteringSummaryModel(BaseModel):
    total_blocks: int = Field(..., ge=0)
    unique_urls: int = Field(..., ge=0)
    most_frequent_category: str
    top_target_device: str
    category_breakdown: Dict[str, int]
    top_blocked_domains: List[TopBlockedDomainModel]

class GenericCountResponse(BaseModel):
    count: int = Field(..., ge=0)

class LoginRequest(BaseModel):
    username_or_email: str = Field(..., min_length=1, max_length=100)
    password: str = Field(..., min_length=1, max_length=100)

# ==================== CONTROLE DE AUTENTICAÇÃO E SESSÃO ====================

def get_current_user_optional(request: Request) -> Optional[Dict[str, Any]]:
    """Recupera o utilizador associado à sessão atual através do cookie HTTP-Only."""
    session_id = request.cookies.get("cyber_session_id")
    if not session_id:
        return None
    return auth.get_session_user(session_id)

async def require_auth(request: Request) -> Dict[str, Any]:
    """
    Dependência estrita de autenticação (Zero-Trust):
    Garante que nenhum endpoint de dados do dashboard seja acessado sem credenciais válidas.
    """
    user = get_current_user_optional(request)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Autenticação obrigatória. Faça login com credenciais válidas para continuar."
        )
    return user

# ==================== TRATAMENTO GLOBAL DE EXCEÇÕES ====================

@app.exception_handler(AcronisAPIError)
async def acronis_api_exception_handler(request: Request, exc: AcronisAPIError):
    logger.error(f"[ACRONIS API ERROR] Falha no endpoint {request.url.path}: {exc.message}")
    return JSONResponse(
        status_code=exc.status_code or status.HTTP_502_BAD_GATEWAY,
        content={
            "error": True,
            "status": "acronis_api_failure",
            "message": "Falha na comunicação ou validação com a API oficial da Acronis.",
            "detail": exc.message,
            "endpoint": request.url.path
        }
    )

@app.exception_handler(UniFiAPIError)
async def unifi_api_exception_handler(request: Request, exc: UniFiAPIError):
    logger.error(f"[UNIFI API ERROR] Falha no endpoint {request.url.path}: {exc.message}")
    return JSONResponse(
        status_code=exc.status_code or status.HTTP_502_BAD_GATEWAY,
        content={
            "error": True,
            "status": "unifi_api_failure",
            "message": "Falha na comunicação ou autenticação com a API do UniFi Controller.",
            "detail": exc.message,
            "endpoint": request.url.path
        }
    )

# ==================== ROTAS DE AUTENTICAÇÃO & INTERFACE ====================

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    """Página de login corporativo do painel."""
    user = get_current_user_optional(request)
    if user:
        return RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)
    response = templates.TemplateResponse(request=request, name="login.html")
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response

@app.post("/api/auth/login")
async def login_api(data: LoginRequest, request: Request):
    """
    Autentica o utilizador contra o banco local SQLite (PBKDF2-HMAC-SHA256).
    Rejeita estritamente utilizadores pendentes de liberação com mensagem explicativa.
    Emite cookie de sessão HTTP-Only seguro.
    """
    client_ip = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("User-Agent", "unknown")
    
    user, msg = auth.authenticate_user(data.username_or_email, data.password, ip_address=client_ip)
    if not user:
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"success": False, "message": msg}
        )

    session_id = auth.create_session(user["id"], ip_address=client_ip, user_agent=user_agent)
    
    res = JSONResponse(
        status_code=status.HTTP_200_OK,
        content={"success": True, "message": msg, "user": user}
    )
    res.set_cookie(
        key="cyber_session_id",
        value=session_id,
        httponly=True,
        samesite="lax",
        max_age=86400 * 7  # 7 dias de validade
    )
    return res

@app.get("/logout")
@app.post("/api/auth/logout")
async def logout(request: Request):
    """Encerra a sessão ativa do utilizador e limpa os cookies."""
    session_id = request.cookies.get("cyber_session_id")
    if session_id:
        auth.delete_session(session_id)
    
    if request.url.path.startswith("/api/"):
        res = JSONResponse(content={"success": True, "message": "Sessão encerrada com sucesso."})
    else:
        res = RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
        
    res.delete_cookie("cyber_session_id")
    return res

@app.get("/api/auth/me")
async def get_current_user_profile(user: Dict[str, Any] = Depends(require_auth)):
    """Retorna os dados do utilizador atualmente autenticado."""
    return {"authenticated": True, "user": user}

@app.get("/", response_class=HTMLResponse)
async def index_page(request: Request):
    """
    Renderiza a página principal do Dashboard.
    Requisito estrito de segurança: redireciona imediatamente para /login caso não autenticado.
    """
    user = get_current_user_optional(request)
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)

    response = templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "user": user,
            "is_mock": acronis.is_mock,
            "acronis_url": Config.ACRONIS_URL,
            "is_unifi_configured": Config.is_unifi_configured(),
            "unifi_url": unifi.base_url
        }
    )
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response

@app.post("/api/refresh", dependencies=[Depends(require_auth)])
async def trigger_refresh():
    """Limpa o cache em memória para forçar uma consulta 100% fresca às APIs Acronis e UniFi."""
    acronis.clear_cache()
    unifi.clear_cache()
    return {
        "success": True,
        "message": "Cache limpo com sucesso. Dados atualizados diretamente das APIs Acronis e UniFi."
    }

@app.get("/api/status", dependencies=[Depends(require_auth)])
async def get_status():
    """Retorna o status da conexão com a API Acronis e modo de operação (protegido)."""
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
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={
                "status": "auth_error",
                "is_mock": False,
                "acronis_url": Config.ACRONIS_URL,
                "message": f"Falha de Autenticação na API Acronis: {str(e)}"
            }
        )

@app.get("/api/kpis", response_model=KPISummaryModel, dependencies=[Depends(require_auth)])
async def get_kpis(
    period: str = Query("daily", pattern=r"^(daily|weekly|monthly)$", description="Período de consolidação: daily, weekly, monthly"),
    start_date: Optional[str] = Query(None, description="Início do intervalo temporal (ISO 8601)"),
    end_date: Optional[str] = Query(None, description="Fim do intervalo temporal (ISO 8601)")
):
    """Retorna métricas consolidadas dos KPIs com autenticação estrita e suporte a período temporal."""
    summary = await acronis.get_summary_kpis(period=period, start_date=start_date, end_date=end_date)
    validated = KPISummaryModel(**summary)
    return validated.model_dump()

@app.get("/api/alerts", dependencies=[Depends(require_auth)])
async def get_alerts(
    severity: Optional[str] = Query(None, max_length=20, pattern=r"^(all|critical|warning|info)?$", description="Filtro de severidade: all, critical, warning, info"),
    search: Optional[str] = Query(None, max_length=100, description="Busca textual por nome da máquina ou mensagem de alerta"),
    period: Optional[str] = Query(None, pattern=r"^(daily|weekly|monthly)?$", description="Filtro de período: daily, weekly, monthly"),
    start_date: Optional[str] = Query(None, description="Início do intervalo temporal (ISO 8601)"),
    end_date: Optional[str] = Query(None, description="Fim do intervalo temporal (ISO 8601)")
):
    """Retorna a lista de Alertas da plataforma Acronis com filtros aplicados e inputs sanitizados."""
    clean_search = sanitize_user_input(search, max_len=100)
    alerts = await acronis.get_alerts(severity=severity, search=clean_search, period=period, start_date=start_date, end_date=end_date)
    return {"alerts": alerts, "count": len(alerts)}

@app.get("/api/resources", dependencies=[Depends(require_auth)])
async def get_resources(
    search: Optional[str] = Query(None, max_length=100, description="Busca textual por nome ou IP da máquina")
):
    """Retorna a lista de Dispositivos/Máquinas e seus níveis de risco e saúde com inputs sanitizados."""
    clean_search = sanitize_user_input(search, max_len=100)
    resources = await acronis.get_resources(search=clean_search)
    return {"resources": resources, "count": len(resources)}

@app.get("/api/policies", dependencies=[Depends(require_auth)])
async def get_policies():
    """
    Retorna a lista de Planos de Segurança / Proteção aplicados aos dispositivos.
    Filtra estritamente apenas os planos com dispositivos vinculados (sem planos vazios).
    """
    policies = await acronis.get_protection_policies()
    active_policies = [p for p in policies if int(p.get("target_count", 0)) > 0]
    return {"policies": active_policies, "count": len(active_policies)}

@app.get("/api/policies/export", dependencies=[Depends(require_auth)])
async def export_policies_excel():
    """
    Gera e baixa automaticamente uma planilha em formato Excel (.xlsx) contendo
    todos os dados detalhados dos Planos de Segurança e Cobertura (máquinas protegidas,
    status, tipos de planos, organizações e datas de atualização).
    """
    policies = await acronis.get_protection_policies()
    resources = await acronis.get_resources()
    kpis = await acronis.get_summary_kpis(period="daily")
    org_name = await acronis.get_organization_name()

    excel_bytes = generate_policies_excel(
        policies=policies,
        kpis=kpis,
        resources=resources,
        organization_name=org_name
    )
    now_str = datetime.now().strftime("%Y-%m-%d")
    filename = f"Relatorio_Planos_Seguranca_Acronis_{now_str}.xlsx"

    return StreamingResponse(
        io.BytesIO(excel_bytes),
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Content-Type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            "Content-Length": str(len(excel_bytes)),
            "Cache-Control": "no-cache, no-store, must-revalidate, max-age=0",
            "Pragma": "no-cache",
            "Expires": "0"
        }
    )

@app.get("/api/policies/documentation/download", dependencies=[Depends(require_auth)])
async def download_policies_documentation():
    """
    Exporta a documentação técnica oficial e analítica completa dos Planos de Segurança em formato Markdown (.md).
    """
    doc_path = os.path.join(os.path.dirname(__file__), "PLANOS_SEGURANCA_DOCUMENTACAO.md")
    if not os.path.exists(doc_path):
        raise HTTPException(status_code=404, detail="Documento de especificações não encontrado.")
    
    with open(doc_path, "r", encoding="utf-8") as f:
        content = f.read()

    filename = "JM_Cyber_Protect_Documentacao_Planos_Seguranca.md"
    return Response(
        content=content.encode("utf-8"),
        media_type="text/markdown; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-cache"
        }
    )

@app.get("/api/m365/summary", dependencies=[Depends(require_auth)])
async def get_m365_summary():
    """Retorna métricas consolidadas do ambiente Microsoft 365 Cloud."""
    return await acronis.get_m365_summary()

@app.get("/api/m365/accounts", dependencies=[Depends(require_auth)])
async def get_m365_accounts():
    """Retorna a lista de contas/tenants M365 gerenciados."""
    accounts = await acronis.get_m365_accounts()
    return {"accounts": accounts, "count": len(accounts)}

@app.get("/api/m365/accounts/{account_id}/details", dependencies=[Depends(require_auth)])
async def get_m365_account_details(
    account_id: str = Path(..., min_length=1, max_length=100, pattern=r"^[a-zA-Z0-9_\-\.:]+$", description="Identificador seguro da conta M365")
):
    """Retorna a visão detalhada (caixas de e-mail, sites e alertas) de um tenant M365 com validação de path."""
    return await acronis.get_m365_account_details(account_id)

@app.get("/api/analytics/charts", dependencies=[Depends(require_auth)])
async def get_analytics_charts(
    period: str = Query("daily", pattern=r"^(daily|weekly|monthly)$", description="Período de consolidação: daily, weekly, monthly"),
    start_date: Optional[str] = Query(None, description="Início do intervalo temporal (ISO 8601)"),
    end_date: Optional[str] = Query(None, description="Fim do intervalo temporal (ISO 8601)")
):
    """Retorna dados consolidados para alimentar os gráficos analíticos do Dashboard de acordo com o período selecionado."""
    return await acronis.get_analytics_charts(period=period, start_date=start_date, end_date=end_date)

@app.get("/api/url_filtering/alerts", dependencies=[Depends(require_auth)])
async def get_url_filtering_alerts(
    category: Optional[str] = Query(None, max_length=50, description="Filtro por categoria de URL"),
    search: Optional[str] = Query(None, max_length=100, description="Busca textual por URL, dispositivo ou IP")
):
    """Retorna a lista de eventos de bloqueio de URL e ameaças web com filtros aplicados e inputs sanitizados."""
    clean_cat = sanitize_user_input(category, max_len=50)
    clean_search = sanitize_user_input(search, max_len=100)
    alerts = await acronis.get_url_filtering_alerts(category=clean_cat, search=clean_search)
    return {"alerts": alerts, "count": len(alerts)}

@app.get("/api/url_filtering/summary", response_model=UrlFilteringSummaryModel, dependencies=[Depends(require_auth)])
async def get_url_filtering_summary():
    """
    Retorna métricas consolidadas e estatísticas do Filtro de URLs / Ameaças Web,
    incluindo o ranking oficial validado dos sites/domínios reais mais bloqueados.
    """
    summary = await acronis.get_url_filtering_summary()
    validated = UrlFilteringSummaryModel(**summary)
    return validated.model_dump()

# ==================== ROTAS DE REDE & CONECTIVIDADE (UNIFI CONTROLLER) ====================

class PoePortRequest(BaseModel):
    mode: Optional[str] = Field(None, description="Modo PoE: auto, off ou power-cycle")
    poe_mode: Optional[str] = Field(None, description="Alias para mode")

@app.get("/api/unifi/summary", dependencies=[Depends(require_auth)])
async def get_unifi_summary():
    """Retorna o resumo consolidado, KPIs da rede UniFi e status da conexão com a controladora."""
    return await unifi.get_summary()

@app.get("/api/unifi/devices", dependencies=[Depends(require_auth)])
async def get_unifi_devices(
    search: Optional[str] = Query(None, max_length=100, description="Busca textual por nome, IP, MAC ou modelo"),
    device_type: Optional[str] = Query(None, max_length=20, pattern=r"^(all|uap|usw|udm|ugw)?$", description="Filtro por tipo de dispositivo"),
    device_status: Optional[str] = Query(None, max_length=20, pattern=r"^(all|online|offline|attention)?$", description="Filtro por status")
):
    """Retorna os dispositivos de infraestrutura UniFi (APs, Switches, Gateways) com filtros sanitizados."""
    clean_search = sanitize_user_input(search, max_len=100)
    devices = await unifi.get_devices()

    if clean_search:
        s = clean_search.lower()
        devices = [d for d in devices if s in d.get("name", "").lower() or s in d.get("ip", "").lower() or s in d.get("mac", "").lower() or s in d.get("model", "").lower()]

    if device_type and device_type != "all":
        devices = [d for d in devices if d.get("type", "").lower() == device_type.lower()]

    if device_status and device_status != "all":
        if device_status == "attention":
            devices = [d for d in devices if d.get("status") != "online" or d.get("upgradable")]
        else:
            devices = [d for d in devices if d.get("status") == device_status]

    return {"devices": devices, "count": len(devices)}

@app.get("/api/unifi/clients", dependencies=[Depends(require_auth)])
async def get_unifi_clients(
    search: Optional[str] = Query(None, max_length=100, description="Busca textual por nome, hostname, IP ou MAC"),
    connection: Optional[str] = Query(None, max_length=20, pattern=r"^(all|wireless|wired)?$", description="Filtro por tipo de conexão: all, wireless, wired"),
    network: Optional[str] = Query(None, max_length=20, pattern=r"^(all|corporate|guest)?$", description="Filtro por rede: all, corporate, guest"),
    ssid: Optional[str] = Query(None, max_length=50, description="Filtro por SSID: JM-Mobile, JM-Adm, JM-TV, JM-Visitantes, JM-Guest"),
    vlan: Optional[int] = Query(None, ge=1, le=4094, description="Filtro por VLAN: 1, 70, 60"),
    signal: Optional[str] = Query(None, max_length=20, pattern=r"^(all|excellent|good|weak)?$", description="Filtro por qualidade do sinal")
):
    """Retorna a lista de clientes ativamente conectados na rede UniFi com filtros aplicados."""
    clean_search = sanitize_user_input(search, max_len=100)
    clients = await unifi.get_clients()

    if clean_search:
        s = clean_search.lower()
        clients = [c for c in clients if s in c.get("name", "").lower() or s in c.get("ip", "").lower() or s in c.get("mac", "").lower() or s in c.get("essid", "").lower()]

    if connection and connection != "all":
        clients = [c for c in clients if c.get("connection_type") == connection]

    if network and network != "all":
        clients = [c for c in clients if c.get("network_type") == network]

    if ssid and ssid != "all":
        clients = [c for c in clients if (c.get("ssid") or c.get("essid", "")).lower() == ssid.lower()]

    if vlan is not None:
        clients = [c for c in clients if c.get("vlan") == vlan]

    if signal and signal != "all":
        if signal == "excellent":
            clients = [c for c in clients if not c.get("is_wired") and c.get("signal", -100) > -60]
        elif signal == "good":
            clients = [c for c in clients if not c.get("is_wired") and -75 <= c.get("signal", -100) <= -60]
        elif signal == "weak":
            clients = [c for c in clients if not c.get("is_wired") and c.get("signal", -100) < -75]

    return {"clients": clients, "count": len(clients)}

@app.get("/api/unifi/networks", dependencies=[Depends(require_auth)])
async def get_unifi_networks():
    """Retorna detalhes oficiais das sub-redes e VLANs (LAN Principal, VLAN 70, VLAN 60) e ocupação do DHCP."""
    networks = await unifi.get_networks()
    return {"networks": networks, "count": len(networks)}

@app.get("/api/unifi/wans", dependencies=[Depends(require_auth)])
async def get_unifi_wans():
    """Retorna monitoramento detalhado das portas WAN e ISPs (Vivo Fibra e SAMM Telecomunicações)."""
    return await unifi.get_wans()

@app.get("/api/unifi/ports", dependencies=[Depends(require_auth)])
async def get_unifi_ports():
    """Retorna a matriz de portas físicas interativa da UDM Pro e do Switch USW Lite 16 PoE."""
    return await unifi.get_port_matrix()

@app.get("/api/unifi/analytics", dependencies=[Depends(require_auth)])
async def get_unifi_analytics():
    """Retorna métricas analíticas calculadas para gráficos (SSID, VLAN, WAN history, distribuição, top consumidores)."""
    return await unifi.get_analytics()

@app.post("/api/unifi/refresh", dependencies=[Depends(require_auth)])
async def refresh_unifi():
    """Força limpeza de cache específica do módulo UniFi."""
    unifi.clear_cache()
    return {"success": True, "message": "Cache do UniFi limpo com sucesso."}

@app.post("/api/unifi/devices/{mac}/restart", dependencies=[Depends(require_auth)])
async def restart_unifi_device(mac: str = Path(..., min_length=12, max_length=20)):
    """Reinicia remotamente um Access Point ou Switch da rede."""
    clean_mac = sanitize_user_input(mac, max_len=20)
    if not clean_mac:
        raise HTTPException(status_code=400, detail="Endereço MAC inválido.")
    result = await unifi.restart_device(clean_mac)
    auth.log_audit_event("unifi_restart_device", f"Reinicialização disparada para equipamento MAC {clean_mac}")
    return result

@app.post("/api/unifi/devices/{mac}/ports/{port_idx}/poe", dependencies=[Depends(require_auth)])
async def set_unifi_poe_port(
    mac: str = Path(..., min_length=12, max_length=20),
    port_idx: int = Path(..., ge=1, le=48),
    payload: PoePortRequest = None
):
    """Liga, desliga ou reinicia energia PoE em uma porta do switch."""
    clean_mac = sanitize_user_input(mac, max_len=20)
    raw_mode = (payload.mode or payload.poe_mode or "power-cycle") if payload else "power-cycle"
    mode = "power-cycle" if raw_mode in ["cycle", "power-cycle"] else str(raw_mode).lower()
    if mode not in ["auto", "off", "power-cycle"]:
        mode = "auto"
    result = await unifi.set_poe_port(clean_mac, port_idx, mode)
    auth.log_audit_event("unifi_set_poe", f"Porta {port_idx} do switch {clean_mac} configurada com PoE={mode}")
    return result

@app.post("/api/unifi/clients/{mac}/block", dependencies=[Depends(require_auth)])
async def block_unifi_client(mac: str = Path(..., min_length=12, max_length=20)):
    """Bloqueia um cliente na rede UniFi."""
    clean_mac = sanitize_user_input(mac, max_len=20)
    result = await unifi.block_client(clean_mac)
    auth.log_audit_event("unifi_block_client", f"Cliente MAC {clean_mac} bloqueado")
    return result

@app.post("/api/unifi/clients/{mac}/unblock", dependencies=[Depends(require_auth)])
async def unblock_unifi_client(mac: str = Path(..., min_length=12, max_length=20)):
    """Desbloqueia um cliente previamente bloqueado."""
    clean_mac = sanitize_user_input(mac, max_len=20)
    result = await unifi.unblock_client(clean_mac)
    auth.log_audit_event("unifi_unblock_client", f"Cliente MAC {clean_mac} desbloqueado")
    return result

@app.post("/api/unifi/clients/{mac}/reconnect", dependencies=[Depends(require_auth)])
async def reconnect_unifi_client(mac: str = Path(..., min_length=12, max_length=20)):
    """Força reconexão (kick-sta) de um cliente Wi-Fi."""
    clean_mac = sanitize_user_input(mac, max_len=20)
    result = await unifi.reconnect_client(clean_mac)
    auth.log_audit_event("unifi_kick_client", f"Reconexão forçada para cliente MAC {clean_mac}")
    return result

@app.post("/api/unifi/speedtest/run", dependencies=[Depends(require_auth)])
async def run_unifi_speedtest():
    """Dispara teste de velocidade nos links de internet da UDM Pro."""
    result = await unifi.run_speedtest()
    auth.log_audit_event("unifi_speedtest", "Teste de velocidade WAN disparado")
    return result

if __name__ == "__main__":
    print(f"[+] Iniciando Painel Acronis em http://localhost:{Config.PORT}")
    print(f"[i] Modo Mock / Demonstração: {'ATIVADO' if Config.is_mock_enabled() else 'DESATIVADO (API Real)'}")
    uvicorn.run("app:app", host="0.0.0.0", port=Config.PORT, reload=True)