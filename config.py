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

    @classmethod
    def is_mock_enabled(cls) -> bool:
        """Retorna se o modo Mock/Demonstração deve ser ativado."""
        if cls.FORCE_MOCK:
            return True
        # Se as credenciais forem vazias ou padrão de exemplo
        if not cls.CLIENT_ID or not cls.CLIENT_SECRET or "SEU_CLIENT_ID" in cls.CLIENT_ID:
            return True
        return False
