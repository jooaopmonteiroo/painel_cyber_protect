import os
from dotenv import load_dotenv

# Carrega variáveis de ambiente do arquivo .env ou .env.example caso exista
if os.path.exists(".env"):
    load_dotenv(".env")
elif os.path.exists(".env.example"):
    load_dotenv(".env.example")
else:
    load_dotenv()

class Config:
    # URL base do Data Center da Acronis (ex: https://us-cloud.acronis.com ou https://eu-cloud.acronis.com)
    ACRONIS_URL = os.getenv("ACRONIS_URL", "https://us-cloud.acronis.com").rstrip("/")
    
    # Credenciais OAuth2 da API da Acronis
    CLIENT_ID = os.getenv("CLIENT_ID", "")
    CLIENT_SECRET = os.getenv("CLIENT_SECRET", "")
    TENANT_ID = os.getenv("TENANT_ID", "")

    # Forçar modo de dados demonstrativos/mock (útil para desenvolvimento ou testes sem conta ativa)
    # Se MOCK_MODE for "true" ou se as credenciais não estiverem configuradas, o sistema usará dados simulados.
    FORCE_MOCK = os.getenv("MOCK_MODE", "false").lower() in ("true", "1", "yes")

    # Porta do servidor da aplicação
    PORT = int(os.getenv("PORT", "8000"))

    # Configurações do Painel de Administração Externo/Isolado
    ADMIN_MASTER_KEY = os.getenv("ADMIN_MASTER_KEY", "AcronisCyberAdminMasterKey#2026!")
    ADMIN_PORT = int(os.getenv("ADMIN_PORT", "8001"))

    # =========================================================================
    # Configurações de Conexão com a API UniFi Controller / UniFi OS / UDM Pro
    # Conexão direta via túnel OpenVPN na VPS (IP local UDM Pro: https://192.168.99.1)
    # =========================================================================
    UNIFI_LOCAL_URL = os.getenv("UNIFI_LOCAL_URL", "https://192.168.99.1").rstrip("/")
    _raw_host = (os.getenv("UNIFI_HOST") or os.getenv("UNIFI_CONTROLLER_URL") or "").strip()
    # Migração definitiva: Se não configurado ou se apontando para api.ui.com, prioriza a UDM Pro local pela VPN
    if not _raw_host or "api.ui.com" in _raw_host:
        UNIFI_HOST = UNIFI_LOCAL_URL
    else:
        UNIFI_HOST = _raw_host.rstrip("/")

    UNIFI_CONTROLLER_URL = UNIFI_HOST
    UNIFI_SITE = os.getenv("UNIFI_SITE", "default")
    UNIFI_USERNAME = os.getenv("UNIFI_USERNAME") or os.getenv("UNIFI_USER") or "jp.monteiro"
    UNIFI_PASSWORD = os.getenv("UNIFI_PASSWORD") or os.getenv("UNIFI_PASS") or "41441130JOao@@"
    UNIFI_API_KEY = os.getenv("UNIFI_API_KEY", "")
    # Autoassinado na UDM local: verify=False (rejectUnauthorized: false) por padrão
    UNIFI_VERIFY_SSL = os.getenv("UNIFI_VERIFY_SSL", "false").lower() in ("true", "1", "yes")
    UNIFI_MOCK = os.getenv("UNIFI_MOCK", "false").lower() in ("true", "1", "yes")

    # Segredo para criptografia e integridade de sessões na VPS
    SESSION_SECRET = os.getenv("SESSION_SECRET", "CyberProtectUniFiMasterSecretKey#2026!SecureSession")

    @classmethod
    def is_mock_enabled(cls) -> bool:
        """Retorna se o modo Mock/Demonstração da Acronis deve ser ativado."""
        if cls.FORCE_MOCK:
            return True
        # Se as credenciais forem vazias ou padrão de exemplo
        c_id = (cls.CLIENT_ID or "").lower()
        c_sec = (cls.CLIENT_SECRET or "").lower()
        if not c_id or not c_sec or "seu_client_id" in c_id or "seu_client_secret" in c_sec:
            return True
        return False

    @classmethod
    def is_unifi_configured(cls) -> bool:
        """Verifica se a URL e credenciais básicas da controladora UniFi foram fornecidas."""
        if cls.UNIFI_MOCK:
            return False
        if cls.UNIFI_API_KEY:
            return True
        url = (cls.UNIFI_HOST or "").strip()
        if not url:
            return False
        u = (cls.UNIFI_USERNAME or "").strip()
        p = (cls.UNIFI_PASSWORD or "").strip()
        if u and p and "seu_usuario" not in u.lower():
            return True
        # Se apontando para gateway local da VPN (192.168.99.1 / 192.168.15.1), considera configurado
        return "192.168" in url or "10." in url or "172." in url
