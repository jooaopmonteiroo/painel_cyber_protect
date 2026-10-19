#!/usr/bin/env bash
# ====================================================================
# Script de Diagnóstico e Recuperação Automática - JM Cyber Protect VPS
# ====================================================================

set -e

echo "=================================================="
echo "🔍 DIAGNÓSTICO E RESTAURAÇÃO DA VPS - JM CYBER"
echo "=================================================="

# 1. Informações do Servidor
echo "[1/7] Verificando recursos do servidor (RAM, Swap, Disco)..."
free -h
df -h /

# 2. Garantir Swap para evitar queda por falta de memória (OOM Killer)
TOTAL_SWAP=$(free -m | awk '/^Swap:/ {print $2}')
if [ "$TOTAL_SWAP" -lt 1000 ]; then
    echo "⚠️ Pouca ou nenhuma Swap detectada (${TOTAL_SWAP}MB). Criando Swap de 2GB para estabilidade..."
    if [ ! -f /swapfile ]; then
        fallocate -l 2G /swapfile || dd if=/dev/zero of=/swapfile bs=1M count=2048
        chmod 600 /swapfile
        mkswap /swapfile
        swapon /swapfile
        if ! grep -q "/swapfile" /etc/fstab; then
            echo '/swapfile none swap sw 0 0' >> /etc/fstab
        fi
        echo "✅ Swap de 2GB configurada e ativa!"
    else
        swapon /swapfile || true
    fi
else
    echo "✅ Swap OK (${TOTAL_SWAP}MB)."
fi

# 3. Navegar para a pasta da aplicação
APP_DIR="/var/www/painel_cyber_protect"
if [ ! -d "$APP_DIR" ]; then
    echo "❌ Diretório $APP_DIR não encontrado!"
    exit 1
fi
cd "$APP_DIR"

# 4. Corrigir anomalias de arquivos/diretórios do Docker
echo "[2/7] Validando integridade de auth.db e .env..."
if [ -d "auth.db" ]; then
    echo "⚠️ auth.db foi criado como pasta pelo Docker! Corrigindo..."
    rm -rf auth.db
    touch auth.db
    chmod 664 auth.db
elif [ ! -f "auth.db" ]; then
    echo "Criando arquivo auth.db inicial..."
    touch auth.db
    chmod 664 auth.db
fi

if [ -d ".env" ]; then
    echo "⚠️ .env foi criado como pasta pelo Docker! Corrigindo..."
    rm -rf .env
    cp .env.example .env
elif [ ! -f ".env" ]; then
    echo "Criando .env a partir de .env.example..."
    cp .env.example .env
fi

# 5. Liberar espaço em disco se necessário
echo "[3/7] Limpando caches e imagens antigas do Docker..."
docker system prune -f || true

# 6. Garantir portas abertas no Firewall UFW
echo "[4/7] Verificando e liberando portas essenciais no Firewall UFW..."
if command -v ufw > /dev/null 2>&1; then
    ufw allow 22/tcp || true
    ufw allow 80/tcp || true
    ufw allow 443/tcp || true
    ufw allow 8000/tcp || true
    ufw allow 8001/tcp || true
fi

# 7. Reiniciar contêineres Docker
echo "[5/7] Reiniciando contêineres Docker..."
docker compose down || true
docker compose up -d --build

# 8. Testar e reiniciar Nginx se presente
echo "[6/7] Verificando Nginx..."
if command -v nginx > /dev/null 2>&1; then
    nginx -t && systemctl restart nginx || echo "⚠️ Alerta ao reiniciar Nginx."
    systemctl enable nginx || true
fi

# 9. Status final
echo "[7/7] Verificando status e portas em escuta..."
echo "--- Status dos Contêineres ---"
docker compose ps

echo "--- Portas em Escuta no Servidor ---"
ss -tulpn | grep -E ':(80|443|8000|8001)' || netstat -tulpn | grep -E ':(80|443|8000|8001)' || true

echo "--- Últimos Logs do Dashboard (15 linhas) ---"
docker compose logs --tail=15 painel-cyber || true

echo "=================================================="
echo "✅ PROCEDIMENTO CONCLUÍDO!"
echo "Teste o acesso em: https://monitor.jmcyberprotect.tech"
echo "=================================================="
