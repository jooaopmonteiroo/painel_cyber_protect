import os
import secrets
from dotenv import load_dotenv

# Carrega variáveis de ambiente do arquivo .env ou .env.example caso exista
if os.path.exists(".env"):
    load_dotenv(".env", override=True)
elif os.path.exists(".env.example"):
    load_dotenv(".env.example", override=True)
else:
    load_dotenv()

class Config:
    # ==================== AMBIENTE E RENOVAÇÃO ====================
    ENVIRONMENT = os.getenv("ENVIRONMENT", "production").lower()
    API_REFRESH_INTERVAL = os.getenv("API_REFRESH_INTERVAL", "30s")

    # ==================== API ACRONIS CYBER PROTECT (BR02) ====================
    # Suporta tanto ACRONIS_BASE_URL quanto ACRONIS_URL
    ACRONIS_URL = (os.getenv("ACRONIS_BASE_URL") or os.getenv("ACRONIS_URL") or "https://br02-cloud.acronis.com").rstrip("/")
    ACRONIS_BASE_URL = ACRONIS_URL
    
    # Credenciais OAuth2 da API da Acronis
    CLIENT_ID = os.getenv("ACRONIS_CLIENT_ID") or os.getenv("CLIENT_ID", "")
    ACRONIS_CLIENT_ID = CLIENT_ID
    
    CLIENT_SECRET = os.getenv("ACRONIS_CLIENT_SECRET") or os.getenv("CLIENT_SECRET", "")
    ACRONIS_CLIENT_SECRET = CLIENT_SECRET
    
    TENANT_ID = os.getenv("ACRONIS_TENANT_ID") or os.getenv("TENANT_ID", "")
    ACRONIS_TENANT_ID = TENANT_ID

    # Modo de Operação (false = 100% API oficial sem dados fictícios)
    FORCE_MOCK = os.getenv("MOCK_MODE", "false").lower() in ("true", "1", "yes")

    # ==================== API UBIQUITI UNIFI NETWORK ====================
    UNIFI_CONTROLLER_URL = os.getenv("UNIFI_CONTROLLER_URL") or os.getenv("UNIFI_HOST", "https://192.168.15.1:8443").rstrip("/")
    UNIFI_USERNAME = os.getenv("UNIFI_USERNAME") or os.getenv("UNIFI_USER", "admin")
    UNIFI_PASSWORD = os.getenv("UNIFI_PASSWORD", "")
    UNIFI_SITE_ID = os.getenv("UNIFI_SITE_ID") or os.getenv("UNIFI_SITE", "default")
    UNIFI_CHECK_SSL = os.getenv("UNIFI_CHECK_SSL", "false").lower() in ("true", "1", "yes")

    # ==================== SEGURANÇA, JWT E CONTROLE RBAC ====================
    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "CyberSocJwtMasterSecret#2026!ProdDefenseKeyToken")
    JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
    ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))
    
    # Rate Limiting (Prevenção contra Brute-Force e Abuso de Comandos)
    RATE_LIMIT_LOGIN_MAX = int(os.getenv("RATE_LIMIT_LOGIN_MAX", "10"))
    RATE_LIMIT_SOC_COMMANDS_MAX = int(os.getenv("RATE_LIMIT_SOC_COMMANDS_MAX", "30"))

    # Origens CORS permitidas
    ALLOWED_ORIGINS = [orig.strip() for orig in os.getenv("ALLOWED_ORIGINS", "*").split(",") if orig.strip()]

    # ==================== NOTIFICAÇÕES CRÍTICAS POR E-MAIL ====================
    EMAIL_SMTP_SERVER = os.getenv("EMAIL_SMTP_SERVER", "")
    EMAIL_SMTP_PORT = int(os.getenv("EMAIL_SMTP_PORT", "587"))
    EMAIL_SENDER = os.getenv("EMAIL_SENDER", "")
    EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD", "")

    # ==================== SERVIDOR & PAINEL DE CONTROLE ISOLADO ====================
    PORT = int(os.getenv("PORT", "8000"))
    ADMIN_MASTER_KEY = os.getenv("ADMIN_MASTER_KEY", "AcronisCyberAdminMasterKey#2026!")
    ADMIN_PORT = int(os.getenv("ADMIN_PORT", "8001"))

    @classmethod
    def is_mock_enabled(cls) -> bool:
        """Retorna se o modo Mock/Demonstração deve ser ativado."""
        if cls.FORCE_MOCK:
            return True
        if not cls.CLIENT_ID or not cls.CLIENT_SECRET or "SEU_CLIENT_ID" in cls.CLIENT_ID:
            return True
        return False

