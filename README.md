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
└── README.md             # Instruções de configuração e uso
```

---

## 🛠️ Pré-requisitos

- **Python 3.9+** instalado na sua máquina.
- Conta de administrador ou parceiro no **Acronis Cyber Protect Cloud**.

---

## ⚙️ Passo a Passo para Configuração

### 1. Clonar ou Baixar o Projeto
Certifique-se de estar no diretório raiz da aplicação:
```bash
cd Painel_Acronis
```

### 2. Instalar as Dependências
Recomenda-se criar um ambiente virtual Python:
```bash
# Criar ambiente virtual (opcional, mas recomendado)
python -m venv venv

# Ativar ambiente virtual no Windows (PowerShell)
.\venv\Scripts\Activate.ps1

# Ou no Linux/macOS
source venv/bin/activate

# Instalar dependências
pip install -r requirements.txt
```

---

## 🔑 Como Obter Credenciais na API do Acronis

Para conectar a aplicação ao seu tenant real do Acronis:

1. Acesse o **Console do Acronis Cyber Protect Cloud** da sua organização.
2. No menu lateral esquerdo, vá em **Configurações** (*Settings*) > **Clientes de API** (*API Clients*).
3. Clique em **+ Adicionar Cliente de API** (*Add API Client*).
4. Defina um nome para a integração (exemplo: `Dashboard Monitoramento`).
5. Conceda as permissões necessárias para leitura de Alertas, Recursos e Planos de Proteção (Escopo Read/View).
6. Após salvar, copie o **Client ID** e o **Client Secret** gerados *(guarde o Secret em local seguro, pois ele só é exibido uma vez)*.
7. Verifique a URL do seu Data Center Acronis no navegador:
   - Estados Unidos: `https://us-cloud.acronis.com`
   - Europa: `https://eu-cloud.acronis.com`
   - América Latina / Outros: consulte a URL exibida na barra de endereço ao estar logado no console.

---

## 📄 Configurar o Arquivo `.env`

Crie um arquivo `.env` na raiz do projeto (ou copie do `.env.example`):

```bash
# No Windows (PowerShell)
copy .env.example .env
```

Edite o arquivo `.env` com suas credenciais:

```env
ACRONIS_URL=https://us-cloud.acronis.com
CLIENT_ID=seu_client_id_aqui
CLIENT_SECRET=seu_client_secret_aqui
TENANT_ID=seu_tenant_id_opcional

# Defina como false para usar a API real
MOCK_MODE=false

PORT=8000
```

> 💡 **Nota:** Se deixar `CLIENT_ID` e `CLIENT_SECRET` vazios ou com valores padrão, a aplicação entrará automaticamente em **Modo Demonstração (Mock Mode)**, permitindo visualizar o painel com dados fictícios.

---

## 🏃 Como Executar a Aplicação

Inicie o servidor principal executando:

```bash
python app.py
```

Ou diretamente via `uvicorn`:

```bash
uvicorn app:app --reload --port 8000
```

Abra o navegador e acesse:
👉 **[http://localhost:8000](http://localhost:8000)**

---

## 📡 Endpoints da API REST do Dashboard

A aplicação disponibiliza os seguintes endpoints JSON:

- `GET /api/status`: Retorna o estado da conexão e se o modo Mock está ativo.
- `GET /api/kpis`: Retorna o resumo consolidado de métricas e contadores.
- `GET /api/alerts`: Retorna alertas ativos com suporte aos parâmetros `severity` (`critical`, `warning`, `info`) e `search`.
- `GET /api/resources`: Retorna dispositivos com filtro por `search`.
- `GET /api/policies`: Retorna planos de proteção ativos e o status da última execução.

Documentação Swagger automática acessível em: **`http://localhost:8000/docs`**

---

## 🛡️ Tratamento de Erros e Resiliência

- **Renovação de Token OAuth2:** O módulo `acronis_client.py` gerencia automaticamente o ciclo de vida do token JWT (`/api/2/idp/token`), renovando-o preventivamente antes do vencimento.
- **Fail-Safe Automatic Fallback:** Caso a API do Acronis fique indisponível ou retorne erro HTTP de rede/credenciais inválidas, a aplicação captura a exceção, registra o erro no log e exibe os dados com resiliência sem derrubar o dashboard.
