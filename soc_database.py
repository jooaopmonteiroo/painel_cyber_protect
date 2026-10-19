"""
Módulo de Banco de Dados e Armazenamento do SOC / War Room
Gerencia persistência de incidentes, logs de ações de resposta ativa,
regras de bloqueio e configurações de notificações.
"""

import os
import sqlite3
import json
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any, List, Tuple

logger = logging.getLogger("soc_database")

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "auth.db")

def is_alert_automitigated(alert_type: str = "", title: str = "", details: str = "", vector: str = "") -> bool:
    """
    Identifica ocorrências 100% bloqueadas/revertidas na origem pela ferramenta (Acronis/UniFi)
    sem risco residual e sem necessidade de intervenção humana (ex: bloqueios rotineiros de URL web).
    """
    t = (title or "").lower()
    d = (details or "").lower()
    v = (vector or "").upper()
    at = (alert_type or "").lower()
    if v == "URL_FILTER":
        return True
    if any(k in t for k in ["deniedcategory", "maliciousurl", "acesso bloqueado", "peripheraldeviceaccessblocked", "protectionplanconflict"]):
        return True
    if any(k in at for k in ["deniedcategory", "maliciousurl", "peripheraldeviceaccessblocked", "protectionplanconflict"]):
        return True
    return False

def get_soc_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=30.0)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA busy_timeout=30000;")
    except Exception:
        pass
    return conn

def init_soc_db() -> None:
    """Inicializa as tabelas da Central de Operações de Segurança (SOC)."""
    conn = get_soc_db_connection()
    try:
        with conn:
            cursor = conn.cursor()

            # 1. Tabela de Incidentes / Alertas SOC Granulares
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS soc_incidents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    incident_id TEXT UNIQUE NOT NULL,
                    alert_id TEXT,
                    source TEXT DEFAULT 'acronis',  -- 'acronis', 'unifi'
                    resource_id TEXT NOT NULL,
                    resource_name TEXT NOT NULL,
                    ip_address TEXT,
                    mac_address TEXT,
                    switch_name TEXT,
                    switch_port TEXT,
                    vlan_id TEXT,
                    signature_id TEXT,
                    user_name TEXT,
                    detection_vector TEXT NOT NULL, -- 'EDR', 'URL_FILTER', 'ACTIVE_PROTECTION', 'RANSOMWARE', 'BACKUP_FAIL', 'IDS_IPS', 'FIREWALL'
                    severity TEXT NOT NULL,         -- 'critical', 'warning', 'info'
                    status TEXT DEFAULT 'novo',     -- 'novo', 'investigando', 'resolvido', 'falso_positivo'
                    title TEXT NOT NULL,
                    details TEXT NOT NULL,
                    blocked_command TEXT,           -- Comando exato mitigado (ex: cmd.exe /c certutil.exe...) ou assinatura UniFi
                    blocked_url TEXT,               -- URL específica bloqueada
                    file_path TEXT,                 -- Caminho do executável/arquivo malicioso
                    file_hash TEXT,                 -- SHA-256 do arquivo se disponível
                    mitre_technique TEXT,           -- Ex: T1059.001 (PowerShell), T1566 (Phishing)
                    is_automitigated INTEGER DEFAULT 0, -- 1 se bloqueado automaticamente sem risco residual
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    resolved_by TEXT,
                    resolution_notes TEXT,
                    raw_payload TEXT
                )
            """)

            # Migração suave para instâncias existentes
            columns_to_add = [
                ("source", "TEXT DEFAULT 'acronis'"),
                ("mac_address", "TEXT"),
                ("switch_name", "TEXT"),
                ("switch_port", "TEXT"),
                ("vlan_id", "TEXT"),
                ("signature_id", "TEXT"),
                ("is_automitigated", "INTEGER DEFAULT 0"),
            ]
            for col_name, col_def in columns_to_add:
                try:
                    cursor.execute(f"ALTER TABLE soc_incidents ADD COLUMN {col_name} {col_def};")
                except Exception:
                    pass

            # Classifica retrospectivamente os eventos automitigados existentes
            cursor.execute("""
                UPDATE soc_incidents
                SET is_automitigated = 1,
                    status = CASE WHEN status = 'novo' THEN 'resolvido' ELSE status END
                WHERE detection_vector = 'URL_FILTER'
                    OR LOWER(title) LIKE '%deniedcategory%'
                    OR LOWER(title) LIKE '%acesso bloqueado%'
                    OR LOWER(title) LIKE '%maliciousurl%'
                    OR LOWER(title) LIKE '%peripheraldeviceaccessblocked%'
                    OR LOWER(title) LIKE '%protectionplanconflict%';
            """)

            # 2. Tabela de Logs de Resposta Ativa do SOC (Auditoria de Intervenção)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS soc_actions_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    action_type TEXT NOT NULL,      -- 'isolate', 'unisolate', 'antivirus_scan', 'trigger_policy', 'toggle_policy', 'block_rule', 'status_change'
                    resource_id TEXT,
                    resource_name TEXT,
                    incident_id TEXT,
                    operator_username TEXT NOT NULL,
                    operator_ip TEXT,
                    status TEXT NOT NULL,           -- 'success', 'failed', 'pending'
                    details TEXT,
                    acronis_task_id TEXT,
                    timestamp TEXT NOT NULL
                )
            """)

            # 3. Tabela de Estado de Dispositivos (Isolamento e Varreduras)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS soc_endpoint_states (
                    resource_id TEXT PRIMARY KEY,
                    resource_name TEXT,
                    is_isolated INTEGER DEFAULT 0,
                    isolated_at TEXT,
                    isolated_by TEXT,
                    isolation_reason TEXT,
                    last_scan_at TEXT,
                    last_scan_type TEXT,
                    last_scan_status TEXT,
                    last_scan_task_id TEXT,
                    updated_at TEXT NOT NULL
                )
            """)

            # 4. Tabela de Regras Globais de Bloqueio / Exceções
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS soc_block_rules (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    rule_type TEXT NOT NULL,        -- 'url', 'domain', 'process_path', 'ip', 'hash'
                    rule_value TEXT NOT NULL,
                    action TEXT DEFAULT 'block',    -- 'block', 'allow'
                    description TEXT,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    enabled INTEGER DEFAULT 1
                )
            """)

            # 5. Tabela de Configurações do SOC e Notificações
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS soc_settings (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
            """)

            # 6. Tabela de Registro de Disparos de E-mail para Throttling / Deduplicação
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS soc_email_throttle (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    throttle_key TEXT UNIQUE NOT NULL,
                    resource_id TEXT,
                    detection_vector TEXT,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    suppressed_count INTEGER DEFAULT 0
                )
            """)

            # Inserir configurações padrão caso ainda não existam
            default_settings = {
                "smtp_enabled": "false",
                "smtp_host": "smtp.office365.com",
                "smtp_port": "587",
                "smtp_user": "soc-alerts@jmcyberprotect.com",
                "smtp_password": "",
                "smtp_from": "JM SOC Alerting <soc-alerts@jmcyberprotect.com>",
                "smtp_use_tls": "true",
                "recipients_critical": "soc-team@jmcyberprotect.com, admin@jmcyberprotect.com",
                "recipients_warning": "soc-team@jmcyberprotect.com",
                "recipients_info": "",
                "notify_edr": "true",
                "notify_url_filter": "true",
                "notify_ransomware": "true",
                "notify_backup_fail": "true",
                "throttle_cooldown_minutes": "15",
                "auto_refresh_seconds": "5",
                "webhook_secret": "acronis_soc_webhook_secret_2026"
            }

            now_iso = datetime.now(timezone.utc).isoformat()
            for k, v in default_settings.items():
                cursor.execute("""
                    INSERT OR IGNORE INTO soc_settings (key, value, updated_at)
                    VALUES (?, ?, ?)
                """, (k, v, now_iso))

            logger.info("Tabelas do SOC inicializadas com sucesso.")
    except Exception as e:
        logger.error(f"Erro ao inicializar tabelas do SOC: {e}")
    finally:
        conn.close()

# ==================== OPERAÇÕES DE CONFIGURAÇÃO ====================

def get_soc_settings() -> Dict[str, str]:
    """Retorna todas as configurações ativas do SOC."""
    conn = get_soc_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT key, value FROM soc_settings")
        return {row["key"]: row["value"] for row in cursor.fetchall()}
    finally:
        conn.close()

def update_soc_setting(key: str, value: str) -> None:
    """Atualiza ou insere uma configuração no SOC."""
    conn = get_soc_db_connection()
    now_iso = datetime.now(timezone.utc).isoformat()
    try:
        with conn:
            conn.execute("""
                INSERT INTO soc_settings (key, value, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at
            """, (key, str(value), now_iso))
    finally:
        conn.close()

def update_soc_settings_bulk(settings_dict: Dict[str, Any]) -> None:
    """Atualiza em lote as configurações do SOC."""
    conn = get_soc_db_connection()
    now_iso = datetime.now(timezone.utc).isoformat()
    try:
        with conn:
            for k, v in settings_dict.items():
                conn.execute("""
                    INSERT INTO soc_settings (key, value, updated_at)
                    VALUES (?, ?, ?)
                    ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at
                """, (k, str(v), now_iso))
    finally:
        conn.close()

# ==================== OPERAÇÕES DE INCIDENTES ====================

def upsert_soc_incident(incident: Dict[str, Any]) -> Tuple[int, bool]:
    """
    Insere ou atualiza um incidente no banco.
    Retorna (id, is_new).
    """
    conn = get_soc_db_connection()
    now_iso = datetime.now(timezone.utc).isoformat()
    try:
        with conn:
            cursor = conn.cursor()
            incident_id = incident["incident_id"]
            cursor.execute("SELECT id, status FROM soc_incidents WHERE incident_id = ?", (incident_id,))
            existing = cursor.fetchone()

            raw_payload = incident.get("raw_payload")
            if isinstance(raw_payload, dict):
                raw_payload = json.dumps(raw_payload)

            is_auto = 1 if is_alert_automitigated(
                alert_type=incident.get("type", ""),
                title=incident.get("title", ""),
                details=incident.get("details", ""),
                vector=incident.get("detection_vector", "")
            ) else 0

            final_status = incident.get("status") or ("resolvido" if is_auto else "novo")
            if is_auto:
                final_status = "resolvido"

            if existing:
                cursor.execute("""
                    UPDATE soc_incidents
                    SET updated_at = ?,
                        title = ?,
                        details = ?,
                        severity = ?,
                        status = CASE WHEN ? = 1 AND status = 'novo' THEN 'resolvido' ELSE status END,
                        source = COALESCE(?, source),
                        mac_address = COALESCE(?, mac_address),
                        switch_name = COALESCE(?, switch_name),
                        switch_port = COALESCE(?, switch_port),
                        vlan_id = COALESCE(?, vlan_id),
                        signature_id = COALESCE(?, signature_id),
                        blocked_command = COALESCE(?, blocked_command),
                        blocked_url = COALESCE(?, blocked_url),
                        file_path = COALESCE(?, file_path),
                        file_hash = COALESCE(?, file_hash),
                        mitre_technique = COALESCE(?, mitre_technique),
                        is_automitigated = ?,
                        raw_payload = COALESCE(?, raw_payload)
                    WHERE incident_id = ?
                """, (
                    now_iso,
                    incident.get("title", "Alerta SOC"),
                    incident.get("details", ""),
                    incident.get("severity", "warning"),
                    is_auto,
                    incident.get("source"),
                    incident.get("mac_address"),
                    incident.get("switch_name"),
                    incident.get("switch_port"),
                    incident.get("vlan_id"),
                    incident.get("signature_id"),
                    incident.get("blocked_command"),
                    incident.get("blocked_url"),
                    incident.get("file_path"),
                    incident.get("file_hash"),
                    incident.get("mitre_technique"),
                    is_auto,
                    raw_payload,
                    incident_id
                ))
                return existing["id"], False
            else:
                cursor.execute("""
                    INSERT INTO soc_incidents (
                        incident_id, alert_id, source, resource_id, resource_name, ip_address,
                        mac_address, switch_name, switch_port, vlan_id, signature_id,
                        user_name, detection_vector, severity, status, title, details,
                        blocked_command, blocked_url, file_path, file_hash,
                        mitre_technique, is_automitigated, created_at, updated_at, raw_payload
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    incident_id,
                    incident.get("alert_id", incident_id),
                    incident.get("source", "acronis"),
                    incident.get("resource_id", "N/A"),
                    incident.get("resource_name") if incident.get("resource_name") and str(incident.get("resource_name")).strip().lower() not in ["dispositivo", "dispositivo desconhecido"] else (
                        f"IP-{incident.get('ip_address')}" if incident.get("ip_address") and incident.get("ip_address") not in ["--", "127.0.0.1"] else f"Host-{str(incident.get('resource_id', 'host'))[-8:]}.jm.corp"
                    ),
                    incident.get("ip_address", "--"),
                    incident.get("mac_address"),
                    incident.get("switch_name"),
                    incident.get("switch_port"),
                    incident.get("vlan_id"),
                    incident.get("signature_id"),
                    incident.get("user_name", "NT AUTHORITY\\SYSTEM"),
                    incident.get("detection_vector", "ACTIVE_PROTECTION"),
                    incident.get("severity", "warning"),
                    final_status,
                    incident.get("title", "Alerta de Segurança"),
                    incident.get("details", ""),
                    incident.get("blocked_command"),
                    incident.get("blocked_url"),
                    incident.get("file_path"),
                    incident.get("file_hash"),
                    incident.get("mitre_technique", "T1059"),
                    is_auto,
                    incident.get("created_at") or now_iso,
                    now_iso,
                    raw_payload
                ))
                return cursor.lastrowid, True
    finally:
        conn.close()

def get_soc_incidents(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    vector: Optional[str] = None,
    source: Optional[str] = None,
    search: Optional[str] = None,
    period: Optional[str] = None,
    active_only: bool = False,
    limit: int = 100,
    offset: int = 0
) -> Tuple[List[Dict[str, Any]], int]:
    """Consulta incidentes com filtros, período temporal e paginação."""
    conn = get_soc_db_connection()
    try:
        cursor = conn.cursor()
        query = "SELECT * FROM soc_incidents WHERE 1=1"
        count_query = "SELECT COUNT(*) as total FROM soc_incidents WHERE 1=1"
        params: List[Any] = []

        # 1. Filtro Temporal Dinâmico (Hoje / 24h, 7 Dias, 30 Dias)
        if period:
            p = period.lower().strip()
            if p in ("today", "24h", "daily", "hoje"):
                today_str = datetime.now().strftime("%Y-%m-%d")
                query += " AND created_at >= ?"
                count_query += " AND created_at >= ?"
                params.append(f"{today_str}T00:00:00")
            elif p in ("7d", "7days", "weekly"):
                start_7d = (datetime.now() - timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%S")
                query += " AND created_at >= ?"
                count_query += " AND created_at >= ?"
                params.append(start_7d)
            elif p in ("30d", "30days", "monthly"):
                start_30d = (datetime.now() - timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%S")
                query += " AND created_at >= ?"
                count_query += " AND created_at >= ?"
                params.append(start_30d)

        # 2. Filtro de Triagem de Alertas Ativos vs Resolvidos/Automitigados
        if active_only:
            # Se status específico foi requisitado (ex: usuário clicou na aba 'resolvidos')
            if status and status.lower() not in ("all", "todos", "active"):
                query += " AND status = ?"
                count_query += " AND status = ?"
                params.append(status.lower())
            else:
                # Descarta resolvidos/falsos positivos e eventos automitigados sem risco residual
                query += " AND status NOT IN ('resolvido', 'falso_positivo') AND is_automitigated = 0"
                count_query += " AND status NOT IN ('resolvido', 'falso_positivo') AND is_automitigated = 0"
        else:
            if status and status.lower() not in ("all", "todos"):
                query += " AND status = ?"
                count_query += " AND status = ?"
                params.append(status.lower())

        if severity and severity.lower() not in ("all", "todos"):
            query += " AND severity = ?"
            count_query += " AND severity = ?"
            params.append(severity.lower())

        if vector and vector.lower() not in ("all", "todos"):
            query += " AND detection_vector = ?"
            count_query += " AND detection_vector = ?"
            params.append(vector.upper())

        if source and source.lower() not in ("all", "todos"):
            query += " AND source = ?"
            count_query += " AND source = ?"
            params.append(source.lower())

        if search:
            s = f"%{search.strip().lower()}%"
            filter_search = """ AND (
                LOWER(resource_name) LIKE ? OR
                LOWER(ip_address) LIKE ? OR
                LOWER(COALESCE(mac_address, '')) LIKE ? OR
                LOWER(COALESCE(switch_name, '')) LIKE ? OR
                LOWER(user_name) LIKE ? OR
                LOWER(title) LIKE ? OR
                LOWER(details) LIKE ? OR
                LOWER(COALESCE(blocked_command, '')) LIKE ? OR
                LOWER(COALESCE(blocked_url, '')) LIKE ? OR
                LOWER(COALESCE(mitre_technique, '')) LIKE ?
            )"""
            query += filter_search
            count_query += filter_search
            params.extend([s] * 10)

        # Count total
        cursor.execute(count_query, params)
        total_count = cursor.fetchone()["total"]

        # Order by created_at DESC
        query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
        exec_params = list(params) + [limit, offset]
        cursor.execute(query, exec_params)
        
        incidents = [dict(row) for row in cursor.fetchall()]
        return incidents, total_count
    finally:
        conn.close()

def get_soc_incident_by_id(incident_id: str) -> Optional[Dict[str, Any]]:
    """Busca um incidente específico por ID textual ou numérico."""
    conn = get_soc_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM soc_incidents 
            WHERE incident_id = ? OR CAST(id AS TEXT) = ?
        """, (incident_id, incident_id))
        row = cursor.fetchone()
        return dict(row) if row else None
    finally:
        conn.close()

def update_incident_status(
    incident_id: str,
    new_status: str,
    resolved_by: str,
    notes: Optional[str] = None
) -> bool:
    """Atualiza o status de um incidente (novo, investigando, resolvido, falso_positivo)."""
    conn = get_soc_db_connection()
    now_iso = datetime.now(timezone.utc).isoformat()
    try:
        with conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE soc_incidents
                SET status = ?,
                    resolved_by = ?,
                    resolution_notes = COALESCE(?, resolution_notes),
                    updated_at = ?
                WHERE incident_id = ? OR CAST(id AS TEXT) = ?
            """, (new_status.lower(), resolved_by, notes, now_iso, incident_id, incident_id))
            return cursor.rowcount > 0
    finally:
        conn.close()

# ==================== OPERAÇÕES DE ESTADO DE DISPOSITIVOS ====================

def get_endpoint_state(resource_id: str) -> Optional[Dict[str, Any]]:
    """Consulta o estado de contenção / varredura de um dispositivo."""
    conn = get_soc_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM soc_endpoint_states WHERE resource_id = ?", (resource_id,))
        row = cursor.fetchone()
        return dict(row) if row else None
    finally:
        conn.close()

def set_endpoint_isolation(
    resource_id: str,
    resource_name: str,
    is_isolated: bool,
    operator_username: str,
    reason: Optional[str] = None
) -> None:
    """Registra ou atualiza o status de isolamento de rede do endpoint."""
    conn = get_soc_db_connection()
    now_iso = datetime.now(timezone.utc).isoformat()
    try:
        with conn:
            conn.execute("""
                INSERT INTO soc_endpoint_states (
                    resource_id, resource_name, is_isolated, isolated_at,
                    isolated_by, isolation_reason, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(resource_id) DO UPDATE SET
                    is_isolated = excluded.is_isolated,
                    isolated_at = CASE WHEN excluded.is_isolated = 1 THEN excluded.isolated_at ELSE soc_endpoint_states.isolated_at END,
                    isolated_by = excluded.isolated_by,
                    isolation_reason = excluded.isolation_reason,
                    updated_at = excluded.updated_at
            """, (
                resource_id,
                resource_name,
                1 if is_isolated else 0,
                now_iso if is_isolated else None,
                operator_username,
                reason,
                now_iso
            ))
    finally:
        conn.close()

def set_endpoint_scan_status(
    resource_id: str,
    resource_name: str,
    scan_type: str,
    status: str,
    task_id: Optional[str] = None
) -> None:
    """Registra a execução de varredura antivírus no endpoint."""
    conn = get_soc_db_connection()
    now_iso = datetime.now(timezone.utc).isoformat()
    try:
        with conn:
            conn.execute("""
                INSERT INTO soc_endpoint_states (
                    resource_id, resource_name, last_scan_at, last_scan_type,
                    last_scan_status, last_scan_task_id, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(resource_id) DO UPDATE SET
                    last_scan_at = excluded.last_scan_at,
                    last_scan_type = excluded.last_scan_type,
                    last_scan_status = excluded.last_scan_status,
                    last_scan_task_id = excluded.last_scan_task_id,
                    updated_at = excluded.updated_at
            """, (resource_id, resource_name, now_iso, scan_type, status, task_id, now_iso))
    finally:
        conn.close()

def get_all_isolated_endpoints() -> List[Dict[str, Any]]:
    """Retorna lista de todos os dispositivos atualmente isolados."""
    conn = get_soc_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM soc_endpoint_states WHERE is_isolated = 1")
        return [dict(row) for row in cursor.fetchall()]
    finally:
        conn.close()

# ==================== LOG DE RESPOSTA ATIVA (AUDITORIA SOC) ====================

def log_soc_action(
    action_type: str,
    resource_id: Optional[str],
    resource_name: Optional[str],
    incident_id: Optional[str],
    operator_username: str,
    operator_ip: Optional[str],
    status: str,
    details: str,
    acronis_task_id: Optional[str] = None
) -> int:
    """Registra uma ação de resposta ativa com timestamp e rastreabilidade."""
    conn = get_soc_db_connection()
    now_iso = datetime.now(timezone.utc).isoformat()
    try:
        with conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO soc_actions_log (
                    action_type, resource_id, resource_name, incident_id,
                    operator_username, operator_ip, status, details,
                    acronis_task_id, timestamp
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                action_type, resource_id, resource_name, incident_id,
                operator_username, operator_ip or "127.0.0.1",
                status, details, acronis_task_id, now_iso
            ))
            return cursor.lastrowid
    finally:
        conn.close()

def get_soc_actions_log(limit: int = 50) -> List[Dict[str, Any]]:
    """Retorna o histórico das últimas ações de resposta realizadas."""
    conn = get_soc_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM soc_actions_log
            ORDER BY timestamp DESC
            LIMIT ?
        """, (limit,))
        return [dict(row) for row in cursor.fetchall()]
    finally:
        conn.close()

# ==================== REGRAS DE BLOQUEIO / EXCEÇÕES ====================

def add_soc_block_rule(
    rule_type: str,
    rule_value: str,
    action: str,
    description: str,
    created_by: str
) -> int:
    """Cadastra nova regra de bloqueio ou exceção."""
    conn = get_soc_db_connection()
    now_iso = datetime.now(timezone.utc).isoformat()
    try:
        with conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO soc_block_rules (
                    rule_type, rule_value, action, description, created_by, created_at, enabled
                ) VALUES (?, ?, ?, ?, ?, ?, 1)
            """, (rule_type.lower(), rule_value.strip(), action.lower(), description, created_by, now_iso))
            return cursor.lastrowid
    finally:
        conn.close()

def get_soc_block_rules() -> List[Dict[str, Any]]:
    """Retorna todas as regras de bloqueio cadastradas."""
    conn = get_soc_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM soc_block_rules ORDER BY created_at DESC")
        return [dict(row) for row in cursor.fetchall()]
    finally:
        conn.close()

def delete_soc_block_rule(rule_id: int) -> bool:
    """Remove uma regra de bloqueio."""
    conn = get_soc_db_connection()
    try:
        with conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM soc_block_rules WHERE id = ?", (rule_id,))
            return cursor.rowcount > 0
    finally:
        conn.close()

# ==================== CONTROLE DE THROTTLING DE E-MAILS ====================

def check_email_throttle(
    throttle_key: str,
    cooldown_minutes: int,
    resource_id: Optional[str] = None,
    detection_vector: Optional[str] = None
) -> Tuple[bool, int]:
    """
    Verifica se um evento similar ocorreu dentro do período de cooldown.
    Retorna (should_send_email: bool, suppressed_count: int).
    """
    conn = get_soc_db_connection()
    now_dt = datetime.now(timezone.utc)
    now_iso = now_dt.isoformat()
    try:
        with conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, first_seen, last_seen, suppressed_count
                FROM soc_email_throttle
                WHERE throttle_key = ?
            """, (throttle_key,))
            row = cursor.fetchone()

            if not row:
                # Primeiro envio para esta assinatura
                cursor.execute("""
                    INSERT INTO soc_email_throttle (
                        throttle_key, resource_id, detection_vector,
                        first_seen, last_seen, suppressed_count
                    ) VALUES (?, ?, ?, ?, ?, 0)
                """, (throttle_key, resource_id, detection_vector, now_iso, now_iso))
                return True, 0

            # Registro existente: verifica o tempo decorrido desde o último envio
            try:
                last_dt = datetime.fromisoformat(row["last_seen"])
                diff_seconds = (now_dt - last_dt).total_seconds()
            except Exception:
                diff_seconds = 999999

            cooldown_seconds = cooldown_minutes * 60

            if diff_seconds < cooldown_seconds:
                # Bloqueia envio de e-mail e incrementa contador de supressões
                suppressed = row["suppressed_count"] + 1
                cursor.execute("""
                    UPDATE soc_email_throttle
                    SET suppressed_count = ?, last_seen = ?
                    WHERE id = ?
                """, (suppressed, now_iso, row["id"]))
                return False, suppressed
            else:
                # Cooldown expirou: permite o envio e reseta contador
                cursor.execute("""
                    UPDATE soc_email_throttle
                    SET last_seen = ?, suppressed_count = 0
                    WHERE id = ?
                """, (now_iso, row["id"]))
                return True, row["suppressed_count"]
    finally:
        conn.close()

# Auto-inicializa o banco ao carregar o módulo
init_soc_db()
