#!/usr/bin/env bash
set -e
echo "=========================================="
echo "🚀 INICIANDO DEPLOY - JM CYBER PROTECT"
echo "=========================================="

cd /var/www/painel_cyber_protect

echo "[1/4] Atualizando código do repositório GitHub..."
git fetch origin
git reset --hard origin/main

# Prevenção contra bug do Docker criar arquivos inexistentes como pastas
if [ -d "auth.db" ]; then
    echo "⚠️ Corrigindo auth.db que foi criado erroneamente como diretório pelo Docker..."
    rm -rf auth.db
fi
if [ ! -f "auth.db" ]; then
    touch auth.db
    chmod 664 auth.db
fi

if [ -d ".env" ]; then
    echo "⚠️ Corrigindo .env que foi criado erroneamente como diretório pelo Docker..."
    rm -rf .env
    cp .env.example .env
fi
if [ ! -f ".env" ]; then
    cp .env.example .env
fi

# Blindagem de permissões do arquivo de segredos (Nenhum outro usuário lê)
chmod 600 .env
chmod 664 auth.db

echo "[2/4] Parando contêineres antigos..."
docker compose down

echo "[3/4] Reconstruindo imagens e iniciando contêineres..."
docker compose up -d --build

echo "[4/4] Verificando status dos contêineres..."
docker compose ps

if command -v nginx > /dev/null 2>&1; then
    echo "Recarregando Nginx..."
    systemctl reload nginx || systemctl restart nginx
fi

echo "=========================================="
echo "✅ DEPLOY CONCLUÍDO COM SUCESSO!"
echo "Acesse: https://monitor.jmcyberprotect.tech"
echo "=========================================="
