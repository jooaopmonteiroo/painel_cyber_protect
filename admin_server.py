"""
Servidor e Painel de Controle de Utilizadores Externo / Isolado
JM Cyber Protect - Administração de Acesso & Aprovação de Contas
Executado em porta e processo estritamente separados do painel principal.
"""

import os
import secrets
import logging
from typing import Optional, Dict, Any
from fastapi import FastAPI, Request, Form, HTTPException, status, Depends, Response
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
import uvicorn

from config import Config
import auth

logger = logging.getLogger("admin_server")
logging.basicConfig(level=logging.INFO)

app = FastAPI(
    title="Console Administrativo Externo - JM Cyber Protect",
    description="Painel isolado para controle de acesso, aprovação e liberação de utilizadores.",
    version="1.0.0"
)

templates_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates")
templates = Jinja2Templates(directory=templates_dir)

static_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
os.makedirs(static_dir, exist_ok=True)
app.mount("/static", StaticFiles(directory=static_dir), name="static")

# Armazenamento em memória de tokens válidos de sessão mestre do admin
MASTER_SESSIONS = set()

def verify_master_access(request: Request) -> bool:
    """Verifica se a requisição possui autenticação mestra via Cookie ou Header."""
    # 1. Header direto (útil para automações/scripts)
    header_key = request.headers.get("X-Admin-Master-Key")
    if header_key and secrets.compare_digest(header_key.strip(), Config.ADMIN_MASTER_KEY.strip()):
        return True

    # 2. Cookie de sessão mestre
    cookie_token = request.cookies.get("admin_master_session")
    if cookie_token and cookie_token in MASTER_SESSIONS:
        return True

    return False

def require_master_auth(request: Request):
    if not verify_master_access(request):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Acesso não autorizado ao Console Administrativo Externo. Forneça a Chave Mestra válida."
        )

# ==================== SCHEMAS PYDANTIC ====================

class CreateUserSchema(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: str = Field(..., min_length=5, max_length=100)
    full_name: str = Field(..., min_length=2, max_length=100)
    password: str = Field(..., min_length=6, max_length=100)
    role: str = Field(default="operator")
    is_active: bool = Field(default=False)

class ResetPasswordSchema(BaseModel):
    new_password: str = Field(..., min_length=6, max_length=100)

class UpdateRoleSchema(BaseModel):
    role: str = Field(..., min_length=3, max_length=20)

# ==================== ROTAS DE INTERFACE ====================

@app.head("/")
@app.head("/admin")
@app.head("/health")
async def head_check():
    """Suporte a requisições HEAD (healthchecks e verificações de uptime)."""
    return Response(status_code=status.HTTP_200_OK)

@app.get("/health")
async def health_check():
    """Endpoint leve de verificação de integridade / healthcheck."""
    return {"status": "healthy", "service": "admin-console"}

@app.get("/", response_class=HTMLResponse)
@app.get("/admin", response_class=HTMLResponse)
async def admin_index(request: Request):
    """Renderiza o Painel de Administração Externo."""
    is_auth = verify_master_access(request)
    return templates.TemplateResponse(
        request=request,
        name="admin_external.html",
        context={
            "is_authenticated": is_auth,
            "error": None
        }
    )

@app.post("/auth")
async def admin_auth_post(request: Request, master_key: str = Form(...)):
    """Valida a Chave Mestra informada e emite o cookie de sessão do console externo."""
    client_ip = request.client.host if request.client else "unknown"
    if secrets.compare_digest(master_key.strip(), Config.ADMIN_MASTER_KEY.strip()):
        token = secrets.token_urlsafe(32)
        MASTER_SESSIONS.add(token)
        response = RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)
        response.set_cookie(
            key="admin_master_session",
            value=token,
            httponly=True,
            samesite="lax",
            max_age=86400  # 24 horas
        )
        auth.log_audit(None, None, "master_admin", "admin_console_login_success", client_ip, "Autenticação mestre efetuada no console isolado.")
        return response
    else:
        auth.log_audit(None, None, "unknown", "admin_console_login_failed", client_ip, "Tentativa com chave mestra incorreta.")
        return templates.TemplateResponse(
            request=request,
            name="admin_external.html",
            context={
                "is_authenticated": False,
                "error": "Chave Mestra incorreta. Verifique o valor de ADMIN_MASTER_KEY no seu arquivo .env."
            },
            status_code=status.HTTP_401_UNAUTHORIZED
        )

@app.get("/logout")
async def admin_logout(request: Request):
    """Encerra a sessão do console mestre."""
    cookie_token = request.cookies.get("admin_master_session")
    if cookie_token in MASTER_SESSIONS:
        MASTER_SESSIONS.remove(cookie_token)
    response = RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)
    response.delete_cookie("admin_master_session")
    return response

# ==================== ROTAS DE API DO CONSOLE EXTERNO ====================

@app.get("/api/admin/stats", dependencies=[Depends(require_master_auth)])
async def get_stats():
    return auth.get_stats()

@app.get("/api/admin/users", dependencies=[Depends(require_master_auth)])
async def list_users():
    return auth.list_users()

@app.post("/api/admin/users", dependencies=[Depends(require_master_auth)])
async def create_user_api(data: CreateUserSchema, request: Request):
    client_ip = request.client.host if request.client else "unknown"
    success, msg, user_id = auth.create_user(
        username=data.username,
        email=data.email,
        full_name=data.full_name,
        password=data.password,
        role=data.role,
        is_active=data.is_active,
        actor_admin="master_admin",
        ip_address=client_ip
    )
    if not success:
        raise HTTPException(status_code=400, detail=msg)
    return {"success": True, "message": msg, "user_id": user_id}

@app.post("/api/admin/users/{user_id}/approve", dependencies=[Depends(require_master_auth)])
async def approve_user_api(user_id: int, request: Request):
    client_ip = request.client.host if request.client else "unknown"
    success, msg = auth.approve_user(user_id, admin_actor="master_admin", ip_address=client_ip)
    if not success:
        raise HTTPException(status_code=400, detail=msg)
    return {"success": True, "message": msg}

@app.post("/api/admin/users/{user_id}/block", dependencies=[Depends(require_master_auth)])
async def block_user_api(user_id: int, request: Request):
    client_ip = request.client.host if request.client else "unknown"
    success, msg = auth.block_user(user_id, admin_actor="master_admin", ip_address=client_ip)
    if not success:
        raise HTTPException(status_code=400, detail=msg)
    return {"success": True, "message": msg}

@app.post("/api/admin/users/{user_id}/reset-password", dependencies=[Depends(require_master_auth)])
async def reset_password_api(user_id: int, data: ResetPasswordSchema, request: Request):
    client_ip = request.client.host if request.client else "unknown"
    success, msg = auth.reset_password(user_id, data.new_password, admin_actor="master_admin", ip_address=client_ip)
    if not success:
        raise HTTPException(status_code=400, detail=msg)
    return {"success": True, "message": msg}

@app.post("/api/admin/users/{user_id}/role", dependencies=[Depends(require_master_auth)])
@app.put("/api/admin/users/{user_id}/role", dependencies=[Depends(require_master_auth)])
async def update_user_role_api(user_id: int, data: UpdateRoleSchema, request: Request):
    client_ip = request.client.host if request.client else "unknown"
    success, msg = auth.update_user_role(
        user_id_or_username=user_id,
        new_role=data.role,
        admin_actor="master_admin",
        ip_address=client_ip
    )
    if not success:
        raise HTTPException(status_code=400, detail=msg)
    return {"success": True, "message": msg}

@app.delete("/api/admin/users/{user_id}", dependencies=[Depends(require_master_auth)])
async def delete_user_api(user_id: int, request: Request):
    client_ip = request.client.host if request.client else "unknown"
    success, msg = auth.delete_user(user_id, admin_actor="master_admin", ip_address=client_ip)
    if not success:
        raise HTTPException(status_code=400, detail=msg)
    return {"success": True, "message": msg}

@app.get("/api/admin/audit", dependencies=[Depends(require_master_auth)])
async def get_audit():
    return auth.get_audit_logs(limit=50)

if __name__ == "__main__":
    print(f"[+] Iniciando Console Administrativo Externo em http://localhost:{Config.ADMIN_PORT}")
    print(f"[i] Chave Mestra Configurada: {Config.ADMIN_MASTER_KEY[:4]}***{Config.ADMIN_MASTER_KEY[-3:]}")
    uvicorn.run("admin_server:app", host="0.0.0.0", port=Config.ADMIN_PORT, reload=True)
