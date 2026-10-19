# 🛡️ Painel de Monitoramento Acronis Cyber Protect Cloud

Uma aplicação web moderna e responsiva em **Python (FastAPI)** com frontend em **Tailwind CSS**, **Chart.js** e **Lucide Icons** para monitoramento centralizado de alertas, dispositivos, status de risco e planos de proteção gerenciados pela API do Acronis Cyber Protect Cloud.

---

## 🚀 Funcionalidades Principais

- **📊 Painel Geral (KPI Overview):**
  - Métricas em tempo real: Total de Máquinas, Alertas Críticos Ativos, Porcentagem de Dispositivos Seguros e Falhas de Backup recentes.
  - Gráficos interativos (Chart.js) de distribuição de alertas, níveis de risco e execução dos planos de segurança.
- **🚨 Módulo de Alertas:**
  - Tabela responsiva com badges coloridos por severidade (*Crítico*, *Aviso*, *Informativo*).
  - Filtros rápidos por severidade e busca por texto (nome da máquina ou mensagem do alerta).
- **💻 Módulo de Dispositivos & Riscos:**
  - Mapeamento visual da saúde da infraestrutura (Verde = Seguro, Amarelo = Atenção, Vermelho = Alto Risco).
  - Exibição de IP, Sistema Operacional, Versão do Agente, Vulnerabilidades e Último Backup.
- **🛡️ Módulo de Planos de Segurança:**
  - Visualização dos planos de proteção ativos (Backup, Antivírus, Patch Management) por dispositivo e status da última execução.
- **⚡ Modo Demonstração (Mock Mode) Integrado:**
  - Se as credenciais da API não estiverem configuradas no `.env`, a aplicação inicia automaticamente com **dados simulados realistas**, permitindo testar a interface imediatamente sem bloqueio.

---

## 📂 Estrutura do Projeto

```text
Painel_Acronis/
├── config.py             # Configuração e leitura de variáveis de ambiente
├── .env.example          # Modelo de configuração com as credenciais da Acronis
├── acronis_client.py     # Cliente HTTP para API Acronis (OAuth2 JWT, Alertas, Recursos e Mock Data)
├── app.py                # Servidor FastAPI com rotas REST e inicializador do servidor
├── templates/
│   └── index.html        # Interface frontend SPA (Tailwind CSS, Chart.js, Lucide Icons)
├── requirements.txt      # Dependências Python do projeto

## 🛡️ Tratamento de Erros e Resiliência

- **Renovação de Token OAuth2:** O módulo `acronis_client.py` gerencia automaticamente o ciclo de vida do token JWT (`/api/2/idp/token`), renovando-o preventivamente antes do vencimento.
- **Fail-Safe Automatic Fallback:** Caso a API do Acronis fique indisponível ou retorne erro HTTP de rede/credenciais inválidas, a aplicação captura a exceção, registra o erro no log e exibe os dados com resiliência sem derrubar o dashboard.
