"""
Módulo de Autenticação, Gestão de Utilizadores e Auditoria de Segurança
Armazenamento seguro em SQLite com senhas protegidas via PBKDF2-HMAC-SHA256 (NIST compliant).
"""

import os
import sqlite3
import hashlib
import secrets
import time
import logging
import threading
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List, Tuple
import jwt
from config import Config

logger = logging.getLogger("auth")

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "auth.db")

def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=30.0)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA busy_timeout=30000;")
    except Exception:
        pass
    return conn

def hash_password(password: str, salt: Optional[str] = None) -> Tuple[str, str]:
    """Gera o hash PBKDF2-HMAC-SHA256 com salt seguro de 32 bytes."""
    if not salt:
        salt = secrets.token_hex(16)
    pwd_bytes = password.encode("utf-8")
    salt_bytes = bytes.fromhex(salt)
    dk = hashlib.pbkdf2_hmac("sha256", pwd_bytes, salt_bytes, 100000)
    return dk.hex(), salt

def verify_password(password: str, stored_hash: str, salt: str) -> bool:
    """Valida se a senha informada corresponde ao hash com o salt armazenado."""
    calculated_hash, _ = hash_password(password, salt)
    return secrets.compare_digest(calculated_hash, stored_hash)

# ==================== SEGURANÇA JWT & RBAC ESTREITO ====================

SOC_ROLES = {"admin", "adm", "operator", "operador", "analista_soc_l1", "analista_soc_l2", "soc_analyst"}

def is_soc_role(role: Optional[str]) -> bool:
    """Verifica se o papel do usuário pertence à equipe operacional ou administração do SOC."""
    if not role:
        return False
    return str(role).lower().strip() in SOC_ROLES

def create_access_token(user_id: int, username: str, role: str, email: Optional[str] = None, expires_delta_minutes: Optional[int] = None) -> str:
    """Gera um Token JWT assinado com expiração curta (15 a 30 minutos)."""
    minutes = expires_delta_minutes or Config.ACCESS_TOKEN_EXPIRE_MINUTES
    now = datetime.now(timezone.utc)
    expire = now.timestamp() + (minutes * 60)
    payload = {
        "sub": str(user_id),
        "user_id": user_id,
        "username": username,
        "email": email or "",
        "role": role,
        "iat": int(now.timestamp()),
        "exp": int(expire)
    }
    return jwt.encode(payload, Config.JWT_SECRET_KEY, algorithm=Config.JWT_ALGORITHM)

def decode_access_token(token: str) -> Optional[Dict[str, Any]]:
    """Decodifica e valida assinatura e expiração do Token JWT."""
    if not token:
        return None
    try:
        payload = jwt.decode(token, Config.JWT_SECRET_KEY, algorithms=[Config.JWT_ALGORITHM])
        return payload
    except jwt.PyJWTError:
        return None

def is_role_authorized_for_destructive(role: str) -> bool:
    """
    Verifica se o papel do usuário possui permissão para comandos destrutivos
    (Isolamento de Máquina, Bloqueio de MAC na UniFi, Quarentena VLAN, PoE Power Cycle).
    Requisito estrito: apenas 'admin' ou 'analista_soc_l2' possuem privilégios.
    """
    return str(role).lower().strip() in ("admin", "analista_soc_l2")

# ==================== GERENCIADOR DE SESSÕES ATIVAS DE SOC ====================

_active_soc_sessions: Dict[str, Dict[str, Any]] = {}
_soc_sessions_lock = threading.Lock()

def register_active_soc_user(session_id: str, user: Dict[str, Any], expires_at: float) -> None:
    """Registra operador/administrador ativo no SOC no momento do login."""
    role = user.get("role", "operator")
    if not is_soc_role(role):
        return
    with _soc_sessions_lock:
        _active_soc_sessions[session_id] = {
            "session_id": session_id,
            "user_id": user.get("id"),
            "username": user.get("username"),
            "email": user.get("email"),
            "full_name": user.get("full_name"),
            "role": role,
            "receive_alerts": bool(user.get("receive_alerts", True)),
            "login_time": time.time(),
            "expires_at": expires_at
        }
    logger.info(f"[SOC SESSION LOGIN] Operador '{user.get('username')}' ({user.get('email')}, role: {role}) registrado para alertas dinâmicos.")

def unregister_active_soc_user(session_id: str) -> None:
    """Remove a sessão do operador no logout ou expiração."""
    with _soc_sessions_lock:
        removed = _active_soc_sessions.pop(session_id, None)
    if removed:
        logger.info(f"[SOC SESSION LOGOUT] Operador '{removed.get('username')}' ({removed.get('email')}) removido da lista de plantão.")

def cleanup_expired_soc_sessions() -> None:
    """Descarta sessões expiradas em memória e no banco SQLite."""
    now = time.time()
    with _soc_sessions_lock:
        expired_keys = [sid for sid, d in _active_soc_sessions.items() if d.get("expires_at", 0) <= now]
        for sid in expired_keys:
            _active_soc_sessions.pop(sid, None)

    conn = get_db_connection()
    try:
        with conn:
            conn.execute("DELETE FROM sessions WHERE expires_at < ?", (now,))
    except Exception:
        pass
    finally:
        conn.close()

def get_active_soc_recipients(severity: str = "critical", only_subscribed: bool = True) -> List[Dict[str, Any]]:
    """
    Retorna a lista de usuários de SOC (operadores e adms) com sessões ativas.
    Se only_subscribed=True, filtra estritamente quem está com receive_alerts=True.
    Verifica integridade cruzada de memória e banco de dados SQLite.
    Garante que contas desativadas ou de outros setores (ex: viewer) nunca sejam incluídas.
    Inclui preferências granulares de notificação por categoria de incidente.
    """
    cleanup_expired_soc_sessions()
    now = time.time()
    active_by_user_id: Dict[int, Dict[str, Any]] = {}

    # 1. Busca sessões válidas no SQLite
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT DISTINCT u.id as user_id, u.username, u.email, u.full_name, u.role, u.is_active,
                            COALESCE(u.receive_alerts, 1) as receive_alerts,
                            COALESCE(u.notify_url_filter, 0) as notify_url_filter,
                            COALESCE(u.notify_edr, 1) as notify_edr,
                            COALESCE(u.notify_unifi_ips, 1) as notify_unifi_ips,
                            COALESCE(u.notify_backup_fail, 1) as notify_backup_fail,
                            COALESCE(u.notify_device_offline, 0) as notify_device_offline
            FROM sessions s
            JOIN users u ON s.user_id = u.id
            WHERE s.expires_at > ? AND u.is_active = 1
        """, (now,))
        for row in cursor.fetchall():
            uid = row["user_id"]
            role = row["role"]
            if is_soc_role(role) and row["email"] and "@" in row["email"]:
                user_receive = bool(row["receive_alerts"])
                if not only_subscribed or user_receive:
                    active_by_user_id[uid] = {
                        "user_id": uid,
                        "username": row["username"],
                        "email": row["email"],
                        "full_name": row["full_name"],
                        "role": role,
                        "receive_alerts": user_receive,
                        "notify_url_filter": bool(row["notify_url_filter"]),
                        "notify_edr": bool(row["notify_edr"]),
                        "notify_unifi_ips": bool(row["notify_unifi_ips"]),
                        "notify_backup_fail": bool(row["notify_backup_fail"]),
                        "notify_device_offline": bool(row["notify_device_offline"])
                    }
    except Exception as e:
        logger.warning(f"Erro ao consultar sessões ativas do banco: {e}")
    finally:
        conn.close()

    # 2. Mescla com o registro em memória
    with _soc_sessions_lock:
        for sid, sess in _active_soc_sessions.items():
            if sess.get("expires_at", 0) > now:
                uid = sess.get("user_id")
                role = sess.get("role")
                user_receive = bool(sess.get("receive_alerts", True))
                if uid and is_soc_role(role) and sess.get("email"):
                    if not only_subscribed or user_receive:
                        active_by_user_id[uid] = {
                            "user_id": uid,
                            "username": sess.get("username"),
                            "email": sess.get("email"),
                            "full_name": sess.get("full_name"),
                            "role": role,
                            "receive_alerts": user_receive,
                            "notify_url_filter": bool(sess.get("notify_url_filter", active_by_user_id.get(uid, {}).get("notify_url_filter", False))),
                            "notify_edr": bool(sess.get("notify_edr", active_by_user_id.get(uid, {}).get("notify_edr", True))),
                            "notify_unifi_ips": bool(sess.get("notify_unifi_ips", active_by_user_id.get(uid, {}).get("notify_unifi_ips", True))),
                            "notify_backup_fail": bool(sess.get("notify_backup_fail", active_by_user_id.get(uid, {}).get("notify_backup_fail", True))),
                            "notify_device_offline": bool(sess.get("notify_device_offline", active_by_user_id.get(uid, {}).get("notify_device_offline", False)))
                        }

    return list(active_by_user_id.values())

def update_user_alert_preference(
    user_id: int,
    receive_alerts: Optional[bool] = None,
    notify_url_filter: Optional[bool] = None,
    notify_edr: Optional[bool] = None,
    notify_unifi_ips: Optional[bool] = None,
    notify_backup_fail: Optional[bool] = None,
    notify_device_offline: Optional[bool] = None
) -> bool:
    """Atualiza a preferência geral e as categorias granulares de alerta por e-mail do usuário."""
    conn = get_db_connection()
    try:
        fields = []
        vals = []
        if receive_alerts is not None:
            fields.append("receive_alerts = ?")
            vals.append(1 if receive_alerts else 0)
        if notify_url_filter is not None:
            fields.append("notify_url_filter = ?")
            vals.append(1 if notify_url_filter else 0)
        if notify_edr is not None:
            fields.append("notify_edr = ?")
            vals.append(1 if notify_edr else 0)
        if notify_unifi_ips is not None:
            fields.append("notify_unifi_ips = ?")
            vals.append(1 if notify_unifi_ips else 0)
        if notify_backup_fail is not None:
            fields.append("notify_backup_fail = ?")
            vals.append(1 if notify_backup_fail else 0)
        if notify_device_offline is not None:
            fields.append("notify_device_offline = ?")
            vals.append(1 if notify_device_offline else 0)

        if not fields:
            return True

        vals.append(user_id)
        sql = f"UPDATE users SET {', '.join(fields)} WHERE id = ?"

        with conn:
            conn.execute(sql, tuple(vals))

        with _soc_sessions_lock:
            for sid, sess in _active_soc_sessions.items():
                if sess.get("user_id") == user_id:
                    if receive_alerts is not None:
                        sess["receive_alerts"] = bool(receive_alerts)
                    if notify_url_filter is not None:
                        sess["notify_url_filter"] = bool(notify_url_filter)
                    if notify_edr is not None:
                        sess["notify_edr"] = bool(notify_edr)
                    if notify_unifi_ips is not None:
                        sess["notify_unifi_ips"] = bool(notify_unifi_ips)
                    if notify_backup_fail is not None:
                        sess["notify_backup_fail"] = bool(notify_backup_fail)
                    if notify_device_offline is not None:
                        sess["notify_device_offline"] = bool(notify_device_offline)
        return True
    except Exception as e:
        logger.error(f"Erro ao atualizar preferência de alertas do usuário {user_id}: {e}")
        return False
    finally:
        conn.close()

def init_db() -> None:
    """Inicializa as tabelas de utilizadores, sessões e logs de auditoria."""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        
        # Tabela de Utilizadores
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                full_name TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                is_active INTEGER DEFAULT 0,
                role TEXT DEFAULT 'operator',
                receive_alerts INTEGER DEFAULT 1,
                notify_url_filter INTEGER DEFAULT 0,
                notify_edr INTEGER DEFAULT 1,
                notify_unifi_ips INTEGER DEFAULT 1,
                notify_backup_fail INTEGER DEFAULT 1,
                notify_device_offline INTEGER DEFAULT 0,
                created_at TEXT NOT NULL,
                last_login TEXT
            )
        """)

        # Migrações seguras para tabelas existentes
        migrations = [
            "ALTER TABLE users ADD COLUMN receive_alerts INTEGER DEFAULT 1",
            "ALTER TABLE users ADD COLUMN notify_url_filter INTEGER DEFAULT 0",
            "ALTER TABLE users ADD COLUMN notify_edr INTEGER DEFAULT 1",
            "ALTER TABLE users ADD COLUMN notify_unifi_ips INTEGER DEFAULT 1",
            "ALTER TABLE users ADD COLUMN notify_backup_fail INTEGER DEFAULT 1",
            "ALTER TABLE users ADD COLUMN notify_device_offline INTEGER DEFAULT 0"
        ]
        for mig in migrations:
            try:
                cursor.execute(mig)
                conn.commit()
            except Exception:
                pass

        # Tabela de Sessões Ativas
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                session_id TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                created_at REAL NOT NULL,
                expires_at REAL NOT NULL,
                ip_address TEXT,
                user_agent TEXT,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            )
        """)

        # Tabela de Auditoria e Logs de Acesso
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                username TEXT,
                action TEXT NOT NULL,
                ip_address TEXT,
                details TEXT,
                timestamp TEXT NOT NULL
            )
        """)

        # Criação do administrador inicial caso não haja nenhum usuário
        cursor.execute("SELECT COUNT(*) as count FROM users")
        row = cursor.fetchone()
        if row and row["count"] == 0:
            default_pwd = os.getenv("DEFAULT_ADMIN_PASSWORD", "Admin@Acronis2026!")
            pwd_hash, salt = hash_password(default_pwd)
            now_iso = datetime.now(timezone.utc).isoformat()
            cursor.execute("""
                INSERT INTO users (username, email, full_name, password_hash, salt, is_active, role, created_at)
                VALUES (?, ?, ?, ?, ?, 1, 'admin', ?)
            """, ("admin", "admin@cyberprotect.corp", "Administrador Master", pwd_hash, salt, now_iso))
            conn.commit()
            log_audit(cursor, None, "admin", "admin_bootstrap_created", "127.0.0.1", "Administrador padrão inicial criado com sucesso.")
            conn.commit()
    finally:
        conn.close()

def log_audit(cursor_or_conn, user_id: Optional[int], username: Optional[str], action: str, ip_address: Optional[str], details: str) -> None:
    now_iso = datetime.now(timezone.utc).strftime("%d/%m/%Y %H:%M:%S")
    sql = """
        INSERT INTO audit_logs (user_id, username, action, ip_address, details, timestamp)
        VALUES (?, ?, ?, ?, ?, ?)
    """
    if cursor_or_conn is None:
        conn = get_db_connection()
        try:
            with conn:
                conn.execute(sql, (user_id, username or "anonymous", action, ip_address or "unknown", details, now_iso))
        finally:
            conn.close()
    elif isinstance(cursor_or_conn, sqlite3.Connection):
        with cursor_or_conn:
            cursor_or_conn.execute(sql, (user_id, username or "anonymous", action, ip_address or "unknown", details, now_iso))
    elif hasattr(cursor_or_conn, "execute"):
        cursor_or_conn.execute(sql, (user_id, username or "anonymous", action, ip_address or "unknown", details, now_iso))

# ==================== OPERAÇÕES DE UTILIZADORES ====================

def create_user(
    username: str,
    email: str,
    full_name: str,
    password: str,
    role: str = "operator",
    is_active: bool = False,
    actor_admin: Optional[str] = None,
    ip_address: Optional[str] = None
) -> Tuple[bool, str, Optional[int]]:
    """Cria um novo utilizador. Se is_active for False, fica pendente para aprovação."""
    conn = get_db_connection()
    try:
        username = username.strip().lower()
        email = email.strip().lower()
        full_name = full_name.strip()

        if not username or len(username) < 3:
            return False, "O nome de utilizador deve ter pelo menos 3 caracteres.", None
        if not password or len(password) < 6:
            return False, "A senha deve ter pelo menos 6 caracteres.", None
        if not email or "@" not in email:
            return False, "E-mail inválido.", None
        if role not in ("admin", "analista_soc_l2", "operator", "viewer", "soc_analyst"):
            role = "operator"

        pwd_hash, salt = hash_password(password)
        now_iso = datetime.now(timezone.utc).isoformat()

        cursor = conn.cursor()
        cursor.execute("SELECT id FROM users WHERE username = ? OR email = ?", (username, email))
        if cursor.fetchone():
            return False, "Já existe um utilizador cadastrado com este nome de utilizador ou e-mail.", None

        cursor.execute("""
            INSERT INTO users (username, email, full_name, password_hash, salt, is_active, role, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (username, email, full_name, pwd_hash, salt, 1 if is_active else 0, role, now_iso))
        user_id = cursor.lastrowid
        
        status_msg = "aprovado/liberado" if is_active else "aguardando liberação"
        log_audit(
            cursor,
            user_id,
            username,
            "user_created",
            ip_address,
            f"Utilizador '{username}' criado ({status_msg}) pelo administrador '{actor_admin or 'sistema'}'."
        )
        conn.commit()
        return True, f"Utilizador '{username}' cadastrado com sucesso ({status_msg}).", user_id
    except sqlite3.IntegrityError:
        return False, "Utilizador ou e-mail já existe.", None
    except Exception as e:
        return False, f"Erro ao criar utilizador: {str(e)}", None
    finally:
        conn.close()

def authenticate_user(
    username_or_email: str,
    password: str,
    ip_address: Optional[str] = None
) -> Tuple[Optional[Dict[str, Any]], str]:
    """
    Autentica um utilizador verificando credenciais e o status de aprovação (is_active).
    Se a conta não estiver aprovada/liberada, o acesso é negado com mensagem explícita.
    """
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        query_val = username_or_email.strip().lower()

        cursor.execute("""
            SELECT id, username, email, full_name, password_hash, salt, is_active, role,
                   COALESCE(receive_alerts, 1) as receive_alerts,
                   COALESCE(notify_url_filter, 0) as notify_url_filter,
                   COALESCE(notify_edr, 1) as notify_edr,
                   COALESCE(notify_unifi_ips, 1) as notify_unifi_ips,
                   COALESCE(notify_backup_fail, 1) as notify_backup_fail,
                   COALESCE(notify_device_offline, 0) as notify_device_offline,
                   created_at, last_login
            FROM users
            WHERE username = ? OR email = ?
        """, (query_val, query_val))
        row = cursor.fetchone()

        if not row:
            log_audit(cursor, None, query_val, "login_failed_user_not_found", ip_address, "Tentativa de login com usuário inexistente.")
            conn.commit()
            return None, "Usuário ou senha incorretos."

        user = dict(row)

        if not verify_password(password, user["password_hash"], user["salt"]):
            log_audit(cursor, user["id"], user["username"], "login_failed_bad_password", ip_address, "Senha incorreta informada.")
            conn.commit()
            return None, "Usuário ou senha incorretos."

        # Verificação rigorosa do requisito: utilizador precisa estar liberado/aprovado
        if not user["is_active"]:
            log_audit(cursor, user["id"], user["username"], "login_blocked_not_approved", ip_address, "Tentativa de login em conta não liberada/pendente.")
            conn.commit()
            return None, "Sua conta ainda não foi liberada pelo administrador. Solicite a liberação para ter acesso."

        # Atualiza timestamp de último login
        now_iso = datetime.now(timezone.utc).strftime("%d/%m/%Y %H:%M:%S")
        cursor.execute("UPDATE users SET last_login = ? WHERE id = ?", (now_iso, user["id"]))
        log_audit(cursor, user["id"], user["username"], "login_success", ip_address, "Login efetuado com sucesso no painel.")
        conn.commit()

        # Remove dados sensíveis do retorno
        user.pop("password_hash", None)
        user.pop("salt", None)
        user["last_login"] = now_iso
        user["receive_alerts"] = bool(row["receive_alerts"])
        user["notify_url_filter"] = bool(row["notify_url_filter"])
        user["notify_edr"] = bool(row["notify_edr"])
        user["notify_unifi_ips"] = bool(row["notify_unifi_ips"])
        user["notify_backup_fail"] = bool(row["notify_backup_fail"])
        user["notify_device_offline"] = bool(row["notify_device_offline"])
        return user, "Login realizado com sucesso."
    finally:
        conn.close()

def create_session(user_id: int, ip_address: Optional[str] = None, user_agent: Optional[str] = None, ttl_hours: int = 24) -> str:
    """Cria uma sessão segura com token criptograficamente aleatório."""
    session_id = secrets.token_urlsafe(32)
    created_at = time.time()
    expires_at = created_at + (ttl_hours * 3600)

    conn = get_db_connection()
    try:
        with conn:
            conn.execute("""
                INSERT INTO sessions (session_id, user_id, created_at, expires_at, ip_address, user_agent)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (session_id, user_id, created_at, expires_at, ip_address, user_agent))
        return session_id
    finally:
        conn.close()

def get_session_user(session_id: str) -> Optional[Dict[str, Any]]:
    """Recupera o utilizador associado à sessão se ela for válida e não expirada."""
    if not session_id:
        return None
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        now = time.time()
        cursor.execute("""
            SELECT s.expires_at, u.id, u.username, u.email, u.full_name, u.is_active, u.role,
                   COALESCE(u.receive_alerts, 1) as receive_alerts,
                   COALESCE(u.notify_url_filter, 0) as notify_url_filter,
                   COALESCE(u.notify_edr, 1) as notify_edr,
                   COALESCE(u.notify_unifi_ips, 1) as notify_unifi_ips,
                   COALESCE(u.notify_backup_fail, 1) as notify_backup_fail,
                   COALESCE(u.notify_device_offline, 0) as notify_device_offline,
                   u.last_login
            FROM sessions s
            JOIN users u ON s.user_id = u.id
            WHERE s.session_id = ?
        """, (session_id,))
        row = cursor.fetchone()

        if not row:
            return None

        # Expirada?
        if row["expires_at"] < now:
            delete_session(session_id)
            return None

        # Se o usuário foi bloqueado enquanto tinha sessão aberta, invalida o acesso
        if not row["is_active"]:
            delete_session(session_id)
            return None

        return {
            "id": row["id"],
            "username": row["username"],
            "email": row["email"],
            "full_name": row["full_name"],
            "is_active": bool(row["is_active"]),
            "role": row["role"],
            "receive_alerts": bool(row["receive_alerts"]),
            "notify_url_filter": bool(row["notify_url_filter"]),
            "notify_edr": bool(row["notify_edr"]),
            "notify_unifi_ips": bool(row["notify_unifi_ips"]),
            "notify_backup_fail": bool(row["notify_backup_fail"]),
            "notify_device_offline": bool(row["notify_device_offline"]),
            "last_login": row["last_login"]
        }
    finally:
        conn.close()

def delete_session(session_id: str) -> None:
    unregister_active_soc_user(session_id)
    conn = get_db_connection()
    try:
        with conn:
            conn.execute("DELETE FROM sessions WHERE session_id = ?", (session_id,))
    finally:
        conn.close()

def delete_user_sessions(user_id: int) -> None:
    """Revoga todas as sessões ativas de um determinado utilizador."""
    with _soc_sessions_lock:
        to_del = [sid for sid, data in _active_soc_sessions.items() if data.get("user_id") == user_id]
        for sid in to_del:
            _active_soc_sessions.pop(sid, None)
    conn = get_db_connection()
    try:
        with conn:
            conn.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
    finally:
        conn.close()

# ==================== GESTÃO ADMINISTRATIVA ====================

def list_users() -> List[Dict[str, Any]]:
    """Retorna todos os utilizadores cadastrados com status e metadados."""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, username, email, full_name, is_active, role, created_at, last_login
            FROM users
            ORDER BY id ASC
        """)
        return [dict(r) for r in cursor.fetchall()]
    finally:
        conn.close()

def approve_user(user_id_or_username: Any, admin_actor: Optional[str] = None, ip_address: Optional[str] = None) -> Tuple[bool, str]:
    """Aprova e libera um utilizador para aceder ao painel."""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        if isinstance(user_id_or_username, int) or str(user_id_or_username).isdigit():
            cursor.execute("SELECT id, username FROM users WHERE id = ?", (int(user_id_or_username),))
        else:
            cursor.execute("SELECT id, username FROM users WHERE username = ?", (str(user_id_or_username).lower(),))
        row = cursor.fetchone()
        if not row:
            return False, "Utilizador não encontrado."

        user_id = row["id"]
        username = row["username"]

        cursor.execute("UPDATE users SET is_active = 1 WHERE id = ?", (user_id,))
        log_audit(cursor, user_id, username, "user_approved", ip_address, f"Acesso liberado/aprovado pelo administrador '{admin_actor or 'mestre'}'.")
        conn.commit()
        return True, f"Utilizador '{username}' foi liberado e aprovado com sucesso!"
    finally:
        conn.close()

def block_user(user_id_or_username: Any, admin_actor: Optional[str] = None, ip_address: Optional[str] = None) -> Tuple[bool, str]:
    """Bloqueia/desativa um utilizador e derruba suas sessões ativas."""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        if isinstance(user_id_or_username, int) or str(user_id_or_username).isdigit():
            cursor.execute("SELECT id, username FROM users WHERE id = ?", (int(user_id_or_username),))
        else:
            cursor.execute("SELECT id, username FROM users WHERE username = ?", (str(user_id_or_username).lower(),))
        row = cursor.fetchone()
        if not row:
            return False, "Utilizador não encontrado."

        user_id = row["id"]
        username = row["username"]

        cursor.execute("UPDATE users SET is_active = 0 WHERE id = ?", (user_id,))
        cursor.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
        log_audit(cursor, user_id, username, "user_blocked", ip_address, f"Acesso bloqueado/revogado pelo administrador '{admin_actor or 'mestre'}'.")
        conn.commit()
        return True, f"Utilizador '{username}' foi bloqueado e suas sessões foram encerradas."
    finally:
        conn.close()

def reset_password(user_id_or_username: Any, new_password: str, admin_actor: Optional[str] = None, ip_address: Optional[str] = None) -> Tuple[bool, str]:
    """Redefine a senha de um utilizador e encerra sessões anteriores."""
    if not new_password or len(new_password) < 6:
        return False, "A nova senha deve ter pelo menos 6 caracteres."
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        if isinstance(user_id_or_username, int) or str(user_id_or_username).isdigit():
            cursor.execute("SELECT id, username FROM users WHERE id = ?", (int(user_id_or_username),))
        else:
            cursor.execute("SELECT id, username FROM users WHERE username = ?", (str(user_id_or_username).lower(),))
        row = cursor.fetchone()
        if not row:
            return False, "Utilizador não encontrado."

        user_id = row["id"]
        username = row["username"]

        pwd_hash, salt = hash_password(new_password)
        cursor.execute("UPDATE users SET password_hash = ?, salt = ? WHERE id = ?", (pwd_hash, salt, user_id))
        cursor.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
        log_audit(cursor, user_id, username, "password_reset", ip_address, f"Senha redefinida pelo administrador '{admin_actor or 'mestre'}'.")
        conn.commit()
        return True, f"Senha do utilizador '{username}' redefinida com sucesso."
    finally:
        conn.close()

def delete_user(user_id_or_username: Any, admin_actor: Optional[str] = None, ip_address: Optional[str] = None) -> Tuple[bool, str]:
    """Exclui permanentemente um utilizador e seus dados de sessão."""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        if isinstance(user_id_or_username, int) or str(user_id_or_username).isdigit():
            cursor.execute("SELECT id, username FROM users WHERE id = ?", (int(user_id_or_username),))
        else:
            cursor.execute("SELECT id, username FROM users WHERE username = ?", (str(user_id_or_username).lower(),))
        row = cursor.fetchone()
        if not row:
            return False, "Utilizador não encontrado."

        user_id = row["id"]
        username = row["username"]

        cursor.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
        cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
        log_audit(cursor, user_id, username, "user_deleted", ip_address, f"Utilizador '{username}' excluído permanentemente por '{admin_actor or 'mestre'}'.")
        conn.commit()
        return True, f"Utilizador '{username}' excluído com sucesso."
    finally:
        conn.close()

def get_audit_logs(limit: int = 50) -> List[Dict[str, Any]]:
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, user_id, username, action, ip_address, details, timestamp
            FROM audit_logs
            ORDER BY id DESC
            LIMIT ?
        """, (limit,))
        return [dict(r) for r in cursor.fetchall()]
    finally:
        conn.close()

def get_stats() -> Dict[str, int]:
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) as c FROM users")
        total = cursor.fetchone()["c"]
        cursor.execute("SELECT COUNT(*) as c FROM users WHERE is_active = 1")
        active = cursor.fetchone()["c"]
        cursor.execute("SELECT COUNT(*) as c FROM users WHERE is_active = 0")
        pending = cursor.fetchone()["c"]
        cursor.execute("SELECT COUNT(*) as c FROM users WHERE role = 'admin'")
        admins = cursor.fetchone()["c"]
        return {
            "total_users": total,
            "active_users": active,
            "pending_users": pending,
            "admin_users": admins
        }
    finally:
        conn.close()

# Auto-inicializa na importação
init_db()
