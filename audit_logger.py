"""
Módulo de Auditoria Estruturada do SOC (soc_operations.log)
Registra todas as operações de intervenção, testes de velocidade e comandos
disparados pelos analistas com operador, timestamp ISO-8601, IP, parâmetros e status.
"""

import os
import json
from datetime import datetime, timezone
from typing import Optional, Dict, Any

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOGS_DIR = os.path.join(BASE_DIR, "logs")
OPERATIONS_LOG_FILE = os.path.join(LOGS_DIR, "soc_operations.log")

# Garante que a pasta logs/ exista
os.makedirs(LOGS_DIR, exist_ok=True)

def log_soc_operation(
    operator_username: str,
    action: str,
    target: Optional[str] = None,
    operator_ip: Optional[str] = None,
    parameters: Optional[Dict[str, Any]] = None,
    status: str = "success",
    task_id: Optional[str] = None,
    details: Optional[str] = None
) -> Dict[str, Any]:
    """
    Grava uma entrada estruturada em JSON no arquivo logs/soc_operations.log.
    """
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "operator": operator_username or "sistema",
        "operator_ip": operator_ip or "127.0.0.1",
        "action": action,
        "target": target or "N/A",
        "status": status,
        "task_id": task_id,
        "parameters": parameters or {},
        "details": details or ""
    }
    
    try:
        with open(OPERATIONS_LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception as e:
        print(f"[AUDIT LOG ERROR] Falha ao gravar em {OPERATIONS_LOG_FILE}: {e}")
        
    return entry
