# 🚀 Guia Oficial de Deployment em Produção (VPS) - JM Cyber Protect & UniFi Hub

Este guia reúne as instruções corporativas completas para implantação do **JM Cyber Protect & UniFi Networking Hub** em uma VPS Linux de produção (Ubuntu 22.04 LTS / 24.04 LTS ou Debian 12), aplicando as melhores práticas de **Segurança Corporativa, Zero-Trust, Proxy Reverso Nginx com SSL Let's Encrypt e Monitoramento de Conectividade com a UDM Pro**.

---

## 🏛️ Arquitetura de Produção e Segurança

```
[ Usuários / Administradores ]
             │ HTTPS (Porta 443)
             ▼
[ Nginx Reverse Proxy (VPS) ]
  ├── Terminação SSL (Let's Encrypt TLSv1.3)
  ├── Rate Limiting (30 req/s geral, 5 req/m login)
  ├── Cabeçalhos HSTS, X-Frame-Options, CSP
  └── Gzip / WebSockets Upgrades
             │
      ┌──────┴─────────────────────────────────┐
      │ (Rede Interna 127.0.0.1)               │
      ▼                                        ▼
[ painel-cyber :8000 ]               [ admin-console :8001 ]
  ├── FastAPI Backend Proxy            ├── Console Mestre Isolado
  ├── SQLite auth.db (Sessões & Logs)  └── Gestão de Usuários
  └── UI Enterprise Dark Mode
             │
             ├── Chamadas Seguras HTTPS com X-API-KEY / Bearer Token
             ▼
[ Ubiquiti UDM Pro / UniFi OS ]
  ├── Site Manager API (https://api.ui.com/v1/)
  └── (Opcional) WireGuard VPN -> UDM Pro Local (192.168.14.1 / 192.168.15.1)
```

### Princípios de Segurança Implementados:
1. **Zero Credential Leakage**: O frontend nunca recebe chaves de API, senhas ou tokens administrativos da UDM Pro ou Acronis. Toda comunicação passa pelo backend FastAPI.
2. **Cookies HTTP-Only & SameSite**: Sessões gerenciadas via cookie assinado `cyber_session_id`, impedindo roubo via scripts XSS.
3. **Auditoria Administrativa**: Todas as ações (reinício de AP, bloqueio de cliente Wi-Fi, alteração PoE de porta) são registradas no banco de auditoria (`auth.db`).
4. **Isolamento de Console**: O painel administrativo de aprovação de usuários roda em porta isolada (`:8001`), protegida pela Chave Mestra `ADMIN_MASTER_KEY`.

---

## 📋 Pré-requisitos da VPS
- Servidor VPS (Hostinger, Contabo, Hetzner, DigitalOcean, AWS, etc.):
  - **Mínimo**: 1 vCPU, 1 GB RAM, 20 GB SSD.
  - **Recomendado**: 2 vCPUs, 2 GB RAM, 40 GB SSD.
- Sistema Operacional: **Ubuntu 22.04 LTS** ou **Ubuntu 24.04 LTS**.
- Domínio/Subdomínio apontado no DNS (Tipo A para o IPv4 da VPS):
  - `monitor.jmcyberprotect.tech` (Painel Principal)
  - `admin.jmcyberprotect.tech` (Console Administrativo Externo)

---

## 🛠️ Método Recomendado: Deploy via Docker Compose + Nginx

### 1. Conectar na VPS e Atualizar o Sistema
```bash
ssh root@SEU_IP_VPS
apt update && apt upgrade -y
apt install -y git curl ufw certbot python3-certbot-nginx
```

### 2. Instalar o Docker e Docker Compose
```bash
curl -fsSL https://get.docker.com | sh
usermod -aG docker $USER
docker --version && docker compose version
```

### 3. Configurar Firewall (UFW)
```bash
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp     # SSH
ufw allow 80/tcp     # HTTP (Certbot / Redirecionamento)
ufw allow 443/tcp    # HTTPS
ufw enable
```

### 4. Clonar o Repositório do Projeto
```bash
mkdir -p /var/www/painel_cyber_protect
cd /var/www/painel_cyber_protect

# Clone seu repositório:
git clone https://seu-repositorio.git .
```

### 5. Configurar as Variáveis de Ambiente (`.env`)
```bash
cp .env.example .env
nano .env
```
Preencha os valores de produção:
```ini
# Segurança
SESSION_SECRET=gere_uma_chave_longa_aleatoria_aqui
ADMIN_MASTER_KEY=DefinaUmaSenhaForteMaster#2026!
ADMIN_PORT=8001
PORT=8000

# UniFi Integration (Site Manager API - 100% Real)
UNIFI_CONTROLLER_URL=https://api.ui.com
UNIFI_API_KEY=sua_chave_de_api_unifi_aqui
UNIFI_SITE=default
UNIFI_VERIFY_SSL=false
UNIFI_MOCK=false

# Acronis Cyber Protect
ACRONIS_URL=https://br02-cloud.acronis.com
CLIENT_ID=seu_client_id_acronis
CLIENT_SECRET=seu_client_secret_acronis
MOCK_MODE=false
```

### 6. Subir os Contêineres Docker
```bash
docker compose up -d --build
```
Verifique se os serviços subiram com status saudável (`healthy`):
```bash
docker compose ps
docker compose logs -f
```

---

## 🌐 Configuração do Proxy Reverso Nginx & Certificados SSL

### 1. Copiar a Configuração do Nginx
```bash
cp deploy/nginx.conf /etc/nginx/sites-available/jmcyberprotect.tech
ln -s /etc/nginx/sites-available/jmcyberprotect.tech /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default
```

### 2. Gerar Certificados SSL Gratuitos (Let's Encrypt / Certbot)
```bash
# Certifique-se de que os subdomínios já apontam para a VPS
certbot --nginx -d monitor.jmcyberprotect.tech -d jmcyberprotect.tech -d admin.jmcyberprotect.tech
```

### 3. Testar a Configuração do Nginx e Reiniciar
```bash
nginx -t
systemctl restart nginx
systemctl enable nginx
```

---

## 🩺 Verificação de Conectividade VPS -> UniFi (Health Check)

O projeto inclui um script autônomo de diagnóstico que valida em tempo real se a rota entre a VPS e a UDM Pro está ativa, medindo latência, autenticação e resposta dos endpoints:

```bash
# Executar teste imediato:
python3 deploy/healthcheck_vps_unifi.py
```

### Saída Esperada:
```
==============================================================================
 JM CYBER PROTECT • HEALTH CHECK DE CONECTIVIDADE VPS -> UNIFI CONSOLE
==============================================================================
Target URL      : https://api.ui.com
Site Target     : default
SSL Strict      : False
Modo Mock       : False
------------------------------------------------------------------------------
[*] Modo de Conexão: UniFi Site Manager Cloud API (api.ui.com)
[OK] Endpoint /v1/sites acessível (598 ms) • 1 sites localizados.
[OK] Endpoint /v1/devices acessível (240 ms) • 1 equipamentos catalogados (0 online).
------------------------------------------------------------------------------
[SUCESSO] Rota VPS -> UniFi Site Manager API está 100% OPERACIONAL! (904 ms)
```

### (Opcional) Agendar Monitoramento Contínuo no Cron da VPS
Para receber alertas ou registrar logs automáticos a cada 5 minutos:
```bash
crontab -e
```
Adicione a linha:
```cron
*/5 * * * * cd /var/www/painel_cyber_protect && python3 deploy/healthcheck_vps_unifi.py >> /var/log/unifi_healthcheck.log 2>&1
```

---

## 🔒 Opção Avançada: Conexão Local UDM Pro via WireGuard VPN

Caso prefira conectar a VPS diretamente à interface web interna da UDM Pro (ex: `https://192.168.14.1` ou `https://192.168.15.1`) em vez da Site Manager Cloud API:

1. **Na UDM Pro**:
   - Vá em **Network Settings** -> **VPN** -> **VPN Server** -> Criar Servidor **WireGuard**.
   - Adicione um cliente para a VPS e baixe o arquivo de configuração `wg0.conf`.
2. **Na VPS**:
   ```bash
   apt install -y wireguard
   cp wg0.conf /etc/wireguard/
   systemctl enable --now wg-quick@wg0
   ```
3. **No `.env`**:
   ```ini
   UNIFI_CONTROLLER_URL=https://192.168.14.1
   UNIFI_USERNAME=seu_usuario_admin_local
   UNIFI_PASSWORD=sua_senha_admin_local
   UNIFI_VERIFY_SSL=false
   ```
4. **Validar com o Health Check**:
   ```bash
   python3 deploy/healthcheck_vps_unifi.py
   ```

---

## 🛠️ Comandos de Manutenção & Operação

| Ação | Comando |
| :--- | :--- |
| **Ver logs em tempo real** | `docker compose logs -f --tail=100 painel-cyber` |
| **Reiniciar a aplicação** | `docker compose restart` |
| **Atualizar código e recriar contêineres** | `git pull && docker compose up -d --build` |
| **Backup do banco de usuários** | `cp auth.db auth.db.backup_$(date +%Y%m%d)` |
| **Verificar status dos serviços** | `docker compose ps` |
| **Testar conectividade com a UniFi** | `python3 deploy/healthcheck_vps_unifi.py` |

---

## ✅ Checklist de Homologação em Produção
- [x] Backend Proxy FastAPI sem vazamento de tokens para o navegador.
- [x] Cookies HTTP-Only com proteção SameSite=Lax e CSRF.
- [x] Nginx configurado com SSL TLSv1.3 e Rate Limiting.
- [x] Portas físicas da UDM Pro (1 a 11) e Switch Lite 16 PoE representadas visualmente.
- [x] Telemetria de Dual-WAN (Vivo Fibra + SAMM Telecom) em tempo real.
- [x] Sub-redes e VLANs com medidores de lease DHCP (LAN Principal, VLAN 70, VLAN 60).
- [x] Ações administrativas (Reboot AP, PoE Switch toggle, Block/Kick client, Speedtest).
- [x] Health check script testado com retorno de código de saída `0`.
