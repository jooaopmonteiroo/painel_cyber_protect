FROM python:3.11-slim

# Evita criação de arquivos .pyc e buffer de saída
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Instala dependências básicas do sistema operacional
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    tzdata \
    && rm -rf /var/lib/apt/lists/*

# Copia e instala dependências Python
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copia o código da aplicação
COPY . .

# Criação de usuário não-privilegiado de sistema (Zero-Root Security)
RUN groupadd -g 10001 socgroup && \
    useradd -u 10001 -g socgroup -s /bin/bash -m socuser && \
    chown -R socuser:socgroup /app

# Executa estritamente como usuário não-root
USER socuser

# Expõe as portas internas do painel (8000) e do console administrativo (8001)
EXPOSE 8000 8001

# Comando padrão
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]

