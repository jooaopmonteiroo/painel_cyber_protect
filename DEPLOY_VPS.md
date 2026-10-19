# 🚀 Guia de Hospedagem em VPS - JM Cyber Protect

Este guia detalha o passo a passo completo para hospedar o **JM Cyber Protect** em uma máquina VPS Linux (Ubuntu 22.04 / 24.04 LTS ou Debian 11/12).

---

## 📋 Pré-requisitos
- 1 Servidor VPS (ex: Hostinger, Contabo, DigitalOcean, Hetzner, AWS, etc.) com pelo menos **1 vCPU e 1 GB de RAM**.
- Sistema Operacional recomendado: **Ubuntu 22.04 LTS** ou **Ubuntu 24.04 LTS**.
- Um domínio ou subdomínio apontado para o IP da VPS (ex: `painel.seudominio.com.br`).

---

## 🛠️ Método 1: Deploy com Docker Compose (Mais Rápido & Recomendado)

Com o Docker, você sobe toda a aplicação com apenas um comando e reinicialização automática em caso de queda do servidor.

### 1. Conecte na sua VPS via SSH:
```bash
ssh root@SEU_IP_VPS
```

### 2. Atualize o sistema e instale o Docker:
```bash
apt update && apt upgrade -y
apt install -y git curl ufw

# Instalar Docker e Docker Compose
curl -fsSL https://get.docker.com | sh
```

### 3. Clone ou envie os arquivos para a VPS:
```bash
# Crie o diretório da aplicação
mkdir -p /var/www/painel_cyber_protect
cd /var/www/painel_cyber_protect

# Se estiver usando Git:
git clone https://seu-repositorio.git .

# Se for enviar via SCP do seu computador Windows (no PowerShell local):
# scp -r c:\Users\Pichau\painel_cyber_protect\* root@SEU_IP_VPS:/var/www/painel_cyber_protect/
```

### 4. Configure o arquivo `.env`:
```bash
cp .env.example .env
nano .env
```
> Preencha suas credenciais oficiais da Acronis e a `ADMIN_MASTER_KEY`. Salve com `Ctrl + O` e saia com `Ctrl + X`.

### 5. Inicie a aplicação com Docker Compose:
```bash
docker compose up -d --build
```

### 6. Verifique o status dos contêineres:
```bash
docker compose ps
docker compose logs -f
```
O painel estará respondendo na porta **8000** e o console administrativo na porta **8001**!

---

## 🐧 Método 2: Deploy Nativo Linux (Systemd + Nginx + SSL Grátis)

Se você não quiser usar Docker e preferir rodar nativamente com Python e Nginx:

### 1. Instale o Python, Nginx e ferramentas necessárias:
```bash
apt update && apt upgrade -y
apt install -y python3 python3-pip python3-venv nginx certbot python3-certbot-nginx ufw
```

### 2. Crie o ambiente virtual e instale as dependências:
```bash
cd /var/www/painel_cyber_protect
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

### 3. Teste a execução manual:
```bash
python3 -m uvicorn app:app --host 0.0.0.0 --port 8000
# Pressione Ctrl + C para encerrar após testar
```

### 4. Configure os Serviços Automáticos no Systemd:
Copie os arquivos de serviço prontos da pasta `deploy/`:
```bash
cp deploy/painel_cyber.service /etc/systemd/system/
cp deploy/painel_admin.service /etc/systemd/system/

# Recarregue e ative para iniciar no boot da VPS:
systemctl daemon-reload
systemctl enable --now painel_cyber.service
systemctl enable --now painel_admin.service

# Verifique o status:
systemctl status painel_cyber.service
systemctl status painel_admin.service
```

### 5. Configure o Nginx como Proxy Reverso com SSL:
Copie a configuração do Nginx:
```bash
cp deploy/nginx.conf /etc/nginx/sites-available/painel_cyber_protect

# Edite o domínio:
nano /etc/nginx/sites-available/painel_cyber_protect
# Substitua 'seudominio.com.br' pelo seu domínio real

# Ative o site:
ln -s /etc/nginx/sites-available/painel_cyber_protect /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default
nginx -t
systemctl reload nginx
```

### 6. Emita o Certificado SSL Gratuito (HTTPS Let's Encrypt):
```bash
certbot --nginx -d seudominio.com.br
```

---

## 🔒 Configuração de Firewall (Segurança Essencial na VPS)

Proteja seu servidor ativando o firewall UFW:
```bash
ufw default deny incoming
ufw default allow outgoing

# Permitir SSH (não se tranque para fora!)
ufw allow 22/tcp

# Permitir portas Web HTTP e HTTPS
ufw allow 80/tcp
ufw allow 443/tcp

# (Opcional) Se não usar Nginx reverso e quiser acessar as portas diretamente:
# ufw allow 8000/tcp # Dashboard
# ufw allow 8001/tcp # Admin

ufw enable
ufw status
```

---

## 🛡️ Arquitetura de Segurança Máxima para SOC em Produção

Antes de disponibilizar o painel em produção, certifique-se de aplicar as seguintes blindagens implementadas:

### 1. Permissões Rígidas do Arquivo de Credenciais
```bash
# O arquivo .env deve ser legível apenas pelo usuário do sistema que executa o processo
chmod 600 .env
chmod 664 auth.db
```

### 2. Execução Não-Root no Docker
O container do backend roda automaticamente sob o usuário de sistema restrito `socuser` (UID `10001` / GID `10001`), impedindo que qualquer vulnerabilidade na aplicação permita escalonamento de privilégios para o host.

### 3. Isolamento de Rede Interna (Zero-Trust Docker)
No `docker-compose.yml`, o container da aplicação está isolado na rede bridge interna `soc_internal_net` e exposto apenas em `127.0.0.1:8000`. Todo o tráfego externo deve passar obrigatoriamente pelo reverse proxy Nginx (`deploy/nginx_soc.conf`) nas portas 80 e 443 (HTTPS forçado).

### 4. Controle de Acesso Baseado em Funções (RBAC) e JWT
- **Tokens JWT:** Com expiração curta de 15 a 30 minutos assinados com chave HS256 (`JWT_SECRET_KEY`).
- **Ações Destrutivas Protegidas:** Isolamento de Endpoints, Banimento de MAC (`block-sta`), Quarentena em VLAN 999 e Reinício de Portas PoE exigem estritamente as roles `admin` ou `analista_soc_l2`.
- **Auditoria Total:** Toda tentativa de ação fica registrada em log imutável no banco com IP, operador, ação e status de retorno.

### 5. Rate Limiting no Nginx e no Backend
A aplicação conta com proteção em camadas contra abuso:
- Rate limiting no Nginx (`soc_login_limit: 5r/m`, `soc_cmd_limit: 10r/m`).
- Rate limiting deslizante em memória implementado no FastAPI para endpoints sensíveis.

---

## 💾 Backup do Banco de Dados (`auth.db`)
O banco de dados SQLite fica no arquivo `auth.db` na raiz da pasta do projeto. Ele guarda todos os utilizadores, senhas e logs de auditoria. Para fazer backup regular:
```bash
# Backup manual:
cp /var/www/painel_cyber_protect/auth.db /backup/auth_$(date +%Y%m%d).db
```
