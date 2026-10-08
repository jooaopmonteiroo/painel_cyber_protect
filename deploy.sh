#!/usr/bin/env bash
set -e
echo "=========================================="
echo "🚀 INICIANDO DEPLOY - JM CYBER PROTECT"
echo "=========================================="

cd /var/www/painel_cyber_protect

echo "[1/4] Atualizando código do repositório GitHub..."
git fetch origin
git reset --hard origin/main

echo "[2/4] Parando contêineres antigos..."
docker compose down

echo "[3/4] Reconstruindo imagens e iniciando contêineres..."
docker compose up -d --build

echo "[4/4] Verificando status dos contêineres..."
docker compose ps

echo "=========================================="
echo "✅ DEPLOY CONCLUÍDO COM SUCESSO!"
echo "Acesse: https://monitor.jmcyberprotect.tech"
echo "=========================================="
