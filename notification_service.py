"""
Serviço de Notificação e Alertas Críticos do SOC
Disparo assíncrono de e-mails via aiosmtplib (com fallback para smtplib),
sistema de templates visuais de alta fidelidade e controle anti-flooding (throttling).
"""

import os
import asyncio
import smtplib
import logging
from email.message import EmailMessage
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple

import soc_database

logger = logging.getLogger("notification_service")

try:
    import aiosmtplib
    HAS_AIOSMTPLIB = True
except ImportError:
    HAS_AIOSMTPLIB = False

class NotificationService:
    """
    Gerencia o envio de alertas operacionais por e-mail para equipes de SOC,
    aplicando throttling inteligente, formatação HTML com indicadores visuais de severidade
    e tolerância a falhas na infraestrutura de rede.
    """

    def __init__(self):
        self._lock = asyncio.Lock()

    def _generate_throttle_key(self, incident: Dict[str, Any]) -> str:
        """Gera uma chave única de deduplicação por dispositivo, vetor e atividade."""
        res_id = str(incident.get("resource_id", "generic"))
        vector = str(incident.get("detection_vector", "GENERIC"))
        cmd_or_url = str(incident.get("blocked_command") or incident.get("blocked_url") or incident.get("title", ""))[:60]
        return f"{res_id}:{vector}:{cmd_or_url}".lower().replace(" ", "_")

    def _build_html_email(self, incident: Dict[str, Any], suppressed_count: int = 0) -> str:
        """Constrói um e-mail HTML moderno e profissional de alerta de SOC."""
        severity = str(incident.get("severity", "critical")).lower()
        if severity == "critical":
            color_primary = "#EF4444"
            badge_bg = "#FEE2E2"
            badge_text = "#991B1B"
            sev_title = "CRÍTICO (Ação Imediata Requerida)"
        elif severity == "warning":
            color_primary = "#F59E0B"
            badge_bg = "#FEF3C7"
            badge_text = "#92400E"
            sev_title = "AVISO / ATENÇÃO"
        else:
            color_primary = "#3B82F6"
            badge_bg = "#DBEAFE"
            badge_text = "#1E40AF"
            sev_title = "INFORMATIVO"

        device_name = incident.get("resource_name", "Desconhecido")
        ip_addr = incident.get("ip_address", "--")
        user_name = incident.get("user_name", "NT AUTHORITY\\SYSTEM")
        vector = incident.get("detection_vector", "EDR / Active Protection")
        title = incident.get("title", "Alerta de Incidente Detectado")
        details = incident.get("details", "Sem descrição adicional.")
        blocked_cmd = incident.get("blocked_command")
        blocked_url = incident.get("blocked_url")
        file_path = incident.get("file_path")
        file_hash = incident.get("file_hash")
        mitre = incident.get("mitre_technique", "T1059")
        created_at = incident.get("created_at", datetime.now(timezone.utc).isoformat())

        cmd_section = ""
        if blocked_cmd:
            cmd_section = f"""
            <div style="margin-top: 15px; background-color: #0F172A; border-radius: 6px; padding: 12px; border-left: 4px solid {color_primary};">
                <div style="color: #94A3B8; font-size: 11px; font-weight: bold; text-transform: uppercase; margin-bottom: 6px;">
                    Comando Mitigado / Prompt Barrado (EDR):
                </div>
                <code style="color: #38BDF8; font-family: 'Consolas', 'Courier New', monospace; font-size: 13px; word-break: break-all; display: block;">
                    {blocked_cmd}
                </code>
            </div>
            """

        url_section = ""
        if blocked_url:
            url_section = f"""
            <div style="margin-top: 15px; background-color: #0F172A; border-radius: 6px; padding: 12px; border-left: 4px solid #EAB308;">
                <div style="color: #94A3B8; font-size: 11px; font-weight: bold; text-transform: uppercase; margin-bottom: 6px;">
                    URL / Domínio Malicioso Bloqueado (Filtro Web):
                </div>
                <code style="color: #FACC15; font-family: 'Consolas', 'Courier New', monospace; font-size: 13px; word-break: break-all; display: block;">
                    {blocked_url}
                </code>
            </div>
            """

        throttle_banner = ""
        if suppressed_count > 0:
            throttle_banner = f"""
            <div style="background-color: #EFF6FF; border: 1px solid #BFDBFE; color: #1E40AF; padding: 10px 14px; border-radius: 6px; margin-bottom: 18px; font-size: 12px;">
                <strong>Nota de Throttling Anti-Flooding:</strong> Este endpoint gerou <strong>{suppressed_count} ocorrências idênticas</strong> nos últimos minutos que foram agrupadas para evitar sobrecarga da sua caixa de entrada.
            </div>
            """

        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <title>Alerta SOC - {device_name}</title>
        </head>
        <body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #0B0F19; margin: 0; padding: 24px; color: #F1F5F9;">
            <div style="max-width: 680px; margin: 0 auto; background-color: #111827; border: 1px solid #1F2937; border-radius: 12px; overflow: hidden; box-shadow: 0 10px 25px rgba(0,0,0,0.5);">
                
                <!-- Header -->
                <div style="background-color: #1E2A4A; padding: 20px 24px; border-bottom: 3px solid {color_primary}; display: flex; align-items: center; justify-content: space-between;">
                    <div>
                        <div style="font-size: 18px; font-weight: 800; color: #FFFFFF; letter-spacing: -0.5px;">
                            JM CYBER PROTECT &bull; SOC WAR ROOM
                        </div>
                        <div style="font-size: 12px; color: #94A3B8; margin-top: 2px;">
                            Central de Notificações de Resposta a Incidentes
                        </div>
                    </div>
                </div>

                <!-- Body Container -->
                <div style="padding: 24px;">
                    {throttle_banner}

                    <!-- Severity Badge & Title -->
                    <div style="margin-bottom: 16px;">
                        <span style="display: inline-block; background-color: {badge_bg}; color: {badge_text}; font-size: 11px; font-weight: 800; text-transform: uppercase; padding: 4px 10px; border-radius: 20px; border: 1px solid {color_primary};">
                            {sev_title}
                        </span>
                        <span style="display: inline-block; background-color: #1E293B; color: #CBD5E1; font-size: 11px; font-weight: 700; padding: 4px 10px; border-radius: 20px; margin-left: 6px;">
                            MITRE: {mitre}
                        </span>
                        <h2 style="font-size: 20px; font-weight: 700; color: #FFFFFF; margin: 12px 0 6px 0;">
                            {title}
                        </h2>
                        <p style="font-size: 14px; color: #94A3B8; margin: 0 0 16px 0; line-height: 1.5;">
                            {details}
                        </p>
                    </div>

                    <!-- Critical Forensics Table -->
                    <table style="width: 100%; border-collapse: collapse; margin-bottom: 20px; background-color: #0F172A; border-radius: 8px; overflow: hidden; border: 1px solid #1E293B;">
                        <tbody>
                            <tr style="border-bottom: 1px solid #1E293B;">
                                <td style="padding: 10px 14px; color: #64748B; font-size: 12px; font-weight: bold; width: 140px;">Dispositivo:</td>
                                <td style="padding: 10px 14px; color: #F8FAFC; font-size: 13px; font-weight: 600;">{device_name}</td>
                            </tr>
                            <tr style="border-bottom: 1px solid #1E293B;">
                                <td style="padding: 10px 14px; color: #64748B; font-size: 12px; font-weight: bold;">Endereço IP:</td>
                                <td style="padding: 10px 14px; color: #38BDF8; font-family: monospace; font-size: 13px;">{ip_addr}</td>
                            </tr>
                            <tr style="border-bottom: 1px solid #1E293B;">
                                <td style="padding: 10px 14px; color: #64748B; font-size: 12px; font-weight: bold;">Usuário / Conta:</td>
                                <td style="padding: 10px 14px; color: #F8FAFC; font-size: 13px;">{user_name}</td>
                            </tr>
                            <tr style="border-bottom: 1px solid #1E293B;">
                                <td style="padding: 10px 14px; color: #64748B; font-size: 12px; font-weight: bold;">Vetor de Detecção:</td>
                                <td style="padding: 10px 14px; color: #F8FAFC; font-size: 13px;">{vector}</td>
                            </tr>
                            {f'''<tr style="border-bottom: 1px solid #1E293B;">
                                <td style="padding: 10px 14px; color: #64748B; font-size: 12px; font-weight: bold;">Caminho do Arquivo:</td>
                                <td style="padding: 10px 14px; color: #CBD5E1; font-family: monospace; font-size: 12px; word-break: break-all;">{file_path}</td>
                            </tr>''' if file_path else ''}
                            {f'''<tr style="border-bottom: 1px solid #1E293B;">
                                <td style="padding: 10px 14px; color: #64748B; font-size: 12px; font-weight: bold;">Hash (SHA-256):</td>
                                <td style="padding: 10px 14px; color: #CBD5E1; font-family: monospace; font-size: 11px; word-break: break-all;">{file_hash}</td>
                            </tr>''' if file_hash else ''}
                            <tr>
                                <td style="padding: 10px 14px; color: #64748B; font-size: 12px; font-weight: bold;">Data / Hora:</td>
                                <td style="padding: 10px 14px; color: #94A3B8; font-size: 12px;">{created_at}</td>
                            </tr>
                        </tbody>
                    </table>

                    {cmd_section}
                    {url_section}

                    <!-- Action Link CTA -->
                    <div style="margin-top: 24px; text-align: center;">
                        <a href="http://localhost:8000" style="display: inline-block; background-color: {color_primary}; color: #FFFFFF; font-weight: 700; font-size: 13px; text-decoration: none; padding: 12px 26px; border-radius: 8px; box-shadow: 0 4px 12px rgba(239, 68, 68, 0.3);">
                            Acessar Central de Resposta Ativa &rarr;
                        </a>
                    </div>
                </div>

                <!-- Footer -->
                <div style="background-color: #0F172A; padding: 16px 24px; border-top: 1px solid #1E293B; font-size: 11px; color: #64748B; text-align: center;">
                    Este é um e-mail automático gerado pelo sistema de Resposta Ativa do JM Cyber Protect integrado à API Acronis.
                </div>
            </div>
        </body>
        </html>
        """
        return html

    async def _send_smtp(
        self,
        to_recipients: List[str],
        subject: str,
        html_body: str,
        text_body: str,
        settings: Dict[str, str]
    ) -> Tuple[bool, str]:
        """Envia e-mail usando aiosmtplib ou smtplib tradicional com timeout rígido e tratamento de exceções."""
        smtp_host = settings.get("smtp_host", "localhost")
        smtp_port = int(settings.get("smtp_port", "587"))
        smtp_user = settings.get("smtp_user", "")
        smtp_pass = settings.get("smtp_password", "")
        smtp_from = settings.get("smtp_from") or smtp_user or "soc-alerts@jmcyberprotect.com"
        use_tls = settings.get("smtp_use_tls", "true").lower() in ("true", "1", "yes")

        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = smtp_from
        msg["To"] = ", ".join(to_recipients)
        msg.set_content(text_body)
        msg.add_alternative(html_body, subtype="html")

        if not smtp_pass or "exemplo" in smtp_pass.lower():
            # MODO SIMULAÇÃO / TESTE DE INTERFACE
            logger.info(f"[EMAIL SOC SIMULADO] Disparo para {to_recipients} | Assunto: '{subject}' (Senha de SMTP não configurada)")
            return True, f"Modo Demonstração: E-mail formatado e registrado no log para {len(to_recipients)} destinatários."

        # Tentativa de Envio Real
        try:
            if HAS_AIOSMTPLIB:
                await aiosmtplib.send(
                    msg,
                    hostname=smtp_host,
                    port=smtp_port,
                    username=smtp_user if smtp_user else None,
                    password=smtp_pass if smtp_pass else None,
                    start_tls=use_tls and smtp_port in (587, 25),
                    use_tls=use_tls and smtp_port == 465,
                    timeout=12.0
                )
            else:
                def sync_send():
                    if smtp_port == 465:
                        with smtplib.SMTP_SSL(smtp_host, smtp_port, timeout=12.0) as server:
                            if smtp_user and smtp_pass:
                                server.login(smtp_user, smtp_pass)
                            server.send_message(msg)
                    else:
                        with smtplib.SMTP(smtp_host, smtp_port, timeout=12.0) as server:
                            if use_tls:
                                server.starttls()
                            if smtp_user and smtp_pass:
                                server.login(smtp_user, smtp_pass)
                            server.send_message(msg)
                await asyncio.to_thread(sync_send)

            logger.info(f"[EMAIL SOC ENVIADO] Alerta entregue com sucesso para {to_recipients}")
            return True, f"E-mail de alerta entregue com sucesso para {', '.join(to_recipients)}"
        except Exception as e:
            err_msg = f"Falha no envio de e-mail SMTP para {to_recipients} via {smtp_host}:{smtp_port}: {str(e)}"
            logger.error(err_msg)
            return False, err_msg

    async def notify_incident(self, incident: Dict[str, Any]) -> Tuple[bool, str]:
        """
        Processa um incidente, avalia regras de severidade e vetor,
        aplica throttling anti-flooding e envia e-mail caso aplicável.
        """
        settings = soc_database.get_soc_settings()
        enabled = settings.get("smtp_enabled", "false").lower() in ("true", "1", "yes")
        if not enabled:
            return False, "Envio de e-mails está desativado nas configurações do SOC."

        severity = str(incident.get("severity", "warning")).lower()
        vector = str(incident.get("detection_vector", "")).upper()

        # 1. Filtro por tipo de evento / vetor
        if "EDR" in vector or "ACTIVE" in vector:
            if settings.get("notify_edr", "true").lower() not in ("true", "1", "yes"):
                return False, "Notificações de EDR estão desativadas."
        elif "URL" in vector:
            if settings.get("notify_url_filter", "true").lower() not in ("true", "1", "yes"):
                return False, "Notificações de Filtro de URLs estão desativadas."
        elif "RANSOMWARE" in vector:
            if settings.get("notify_ransomware", "true").lower() not in ("true", "1", "yes"):
                return False, "Notificações de Ransomware estão desativadas."
        elif "BACKUP" in vector:
            if settings.get("notify_backup_fail", "true").lower() not in ("true", "1", "yes"):
                return False, "Notificações de Falha de Backup estão desativadas."

        # 2. Roteamento Dinâmico de Destinatários por Operadores / ADMs Logados
        import auth
        usuarios_online = auth.get_active_soc_recipients(severity=severity)
        
        # Filtra operadores ativos de acordo com as preferências por categoria
        filtered_active_emails: List[str] = []
        for u in usuarios_online:
            if not u.get("receive_alerts", True):
                continue
            email = (u.get("email") or "").strip()
            if not email or "@" not in email:
                continue

            # Cruzamento estrito da categoria do alerta com as preferências do analista
            if "URL" in vector:
                if not u.get("notify_url_filter", False):
                    logger.info(f"[PREFERENCIA SOC] Alerta URL suprimido para {email} (categoria desmarcada nas preferências)")
                    continue
            elif "EDR" in vector or "ACTIVE" in vector:
                if not u.get("notify_edr", True):
                    logger.info(f"[PREFERENCIA SOC] Alerta EDR suprimido para {email} (categoria desmarcada nas preferências)")
                    continue
            elif "IDS" in vector or "IPS" in vector or "FIREWALL" in vector:
                if not u.get("notify_unifi_ips", True):
                    logger.info(f"[PREFERENCIA SOC] Alerta de Rede UniFi suprimido para {email} (categoria desmarcada)")
                    continue
            elif "BACKUP" in vector:
                if not u.get("notify_backup_fail", True):
                    logger.info(f"[PREFERENCIA SOC] Alerta de Backup suprimido para {email} (categoria desmarcada)")
                    continue
            elif "OFFLINE" in vector or "DEVICE" in vector:
                if not u.get("notify_device_offline", False):
                    continue

            filtered_active_emails.append(email)

        active_recipients = list(dict.fromkeys(filtered_active_emails))

        if active_recipients:
            recipients = active_recipients
            logger.info(f"[ROTEAMENTO DINAMICO SOC] Alerta ({severity.upper()}) roteado para {len(recipients)} operador(es) online em plantão ativo: {recipients}")
        else:
            # Fallback para destinatários de contingência do .env ou soc_settings caso nenhum operador esteja logado ou apto
            fallback_env = os.getenv("EMAIL_PADRAO_SOC") or os.getenv("EMAIL_SENDER")
            if severity == "critical":
                recipients_raw = settings.get("recipients_critical", "") or fallback_env or ""
            elif severity == "warning":
                recipients_raw = settings.get("recipients_warning", "") or fallback_env or ""
            else:
                recipients_raw = settings.get("recipients_info", "") or fallback_env or ""

            recipients = [r.strip() for r in recipients_raw.split(",") if r.strip() and "@" in r]
            if not recipients and fallback_env and "@" in fallback_env:
                recipients = [fallback_env.strip()]

            if not recipients:
                return False, f"Nenhum operador de SOC online e nenhum e-mail de contingência configurado para severidade '{severity}'."
            logger.info(f"[ROTEAMENTO SOC CONTINGÊNCIA] Nenhum operador ativo logado no momento. Utilizando e-mails de contingência: {recipients}")

        # 3. Throttling inteligente (Anti-Flooding)
        cooldown_min = int(settings.get("throttle_cooldown_minutes", "15"))
        throttle_key = self._generate_throttle_key(incident)

        should_send, suppressed_count = soc_database.check_email_throttle(
            throttle_key=throttle_key,
            cooldown_minutes=cooldown_min,
            resource_id=incident.get("resource_id"),
            detection_vector=incident.get("detection_vector")
        )

        if not should_send:
            logger.info(f"[THROTTLE SOC] E-mail suprimido para {throttle_key} (contador: {suppressed_count})")
            return False, f"Alerta repetido suprimido pelo controle de throttling ({suppressed_count} ocorrências no período)."

        # 4. Formatação e Envio
        subject = f"[{severity.upper()}] SOC ALERTA: {incident.get('title', 'Ameaça Detectada')} - {incident.get('resource_name', 'Endpoint')}"
        html_body = self._build_html_email(incident, suppressed_count=suppressed_count)
        
        text_body = f"""
        ALERTA DE INCIDENTE SOC - JM CYBER PROTECT
        Severidade: {severity.upper()}
        Dispositivo: {incident.get('resource_name')}
        IP: {incident.get('ip_address')}
        Usuário: {incident.get('user_name')}
        Vetor: {incident.get('detection_vector')}
        Título: {incident.get('title')}
        Detalhes: {incident.get('details')}
        Comando Mitigado: {incident.get('blocked_command') or 'N/A'}
        URL Bloqueada: {incident.get('blocked_url') or 'N/A'}
        Data: {incident.get('created_at')}
        """

        return await self._send_smtp(recipients, subject, html_body, text_body, settings)

    async def send_test_email(self, target_email: str) -> Tuple[bool, str]:
        """Dispara um e-mail de teste para validar a conectividade e configurações do SMTP."""
        settings = soc_database.get_soc_settings()
        mock_incident = {
            "incident_id": "test-soc-001",
            "resource_id": "res-test-endpoint",
            "resource_name": "TESTE-ESTACAO-SOC.corp.local",
            "ip_address": "192.168.1.100",
            "user_name": "OPERADOR\\analista_soc",
            "detection_vector": "EDR (Teste Operacional)",
            "severity": "critical",
            "title": "Teste de Comunicação e Resposta Ativa do SOC",
            "details": "Este é um disparo de validação das rotinas de notificação do cockpit de cibersegurança.",
            "blocked_command": "powershell.exe -ExecutionPolicy Bypass -Command Write-Host 'Verificacao_SOC_OK'",
            "blocked_url": "https://malicious-test-domain.acronis.sample/phishing",
            "mitre_technique": "T1059.001 - Command and Scripting Interpreter",
            "created_at": datetime.now(timezone.utc).isoformat()
        }

        subject = "[TESTE] Conexão do Serviço de Notificações SOC Concluída"
        html = self._build_html_email(mock_incident, suppressed_count=0)
        text = "Teste de comunicação do sistema de alerta do SOC concluído com sucesso."

        return await self._send_smtp([target_email], subject, html, text, settings)

notification_service = NotificationService()
