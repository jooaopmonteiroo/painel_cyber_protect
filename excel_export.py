import io
import re
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
import openpyxl
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
from openpyxl.utils import get_column_letter

# ==================== CONSTANTES DE DESIGN & ESTILO ====================

NAVY_HEADER_FILL = PatternFill(start_color="1E2A4A", end_color="1E2A4A", fill_type="solid")
SUB_HEADER_FILL = PatternFill(start_color="2A3B66", end_color="2A3B66", fill_type="solid")
TABLE_HEADER_FILL = PatternFill(start_color="1E2A4A", end_color="1E2A4A", fill_type="solid")
TABLE_HEADER_SEC_FILL = PatternFill(start_color="24335A", end_color="24335A", fill_type="solid")
STRIPE_FILL = PatternFill(start_color="F8FAFC", end_color="F8FAFC", fill_type="solid")
WHITE_FILL = PatternFill(start_color="FFFFFF", end_color="FFFFFF", fill_type="solid")

# Status Fills & Fonts
SUCCESS_FILL = PatternFill(start_color="D1FAE5", end_color="D1FAE5", fill_type="solid")
SUCCESS_FONT = Font(name="Segoe UI", size=10, bold=True, color="065F46")

WARNING_FILL = PatternFill(start_color="FEF3C7", end_color="FEF3C7", fill_type="solid")
WARNING_FONT = Font(name="Segoe UI", size=10, bold=True, color="92400E")

DANGER_FILL = PatternFill(start_color="FEE2E2", end_color="FEE2E2", fill_type="solid")
DANGER_FONT = Font(name="Segoe UI", size=10, bold=True, color="991B1B")

INFO_FILL = PatternFill(start_color="E0F2FE", end_color="E0F2FE", fill_type="solid")
INFO_FONT = Font(name="Segoe UI", size=10, bold=True, color="0369A1")

KPI_BOX_FILL = PatternFill(start_color="F1F5F9", end_color="F1F5F9", fill_type="solid")

# Bordas
THIN_GRAY = Side(style="thin", color="CBD5E1")
BORDER_ALL = Border(left=THIN_GRAY, right=THIN_GRAY, top=THIN_GRAY, bottom=THIN_GRAY)
BORDER_HEADER = Border(
    left=THIN_GRAY, right=THIN_GRAY,
    top=Side(style="medium", color="1E2A4A"),
    bottom=Side(style="medium", color="1E2A4A")
)

# Fontes
FONT_TITLE = Font(name="Segoe UI", size=14, bold=True, color="FFFFFF")
FONT_SUBTITLE = Font(name="Segoe UI", size=9, italic=True, color="E2E8F0")
FONT_TH = Font(name="Segoe UI", size=10, bold=True, color="FFFFFF")
FONT_CELL = Font(name="Segoe UI", size=10, color="1E293B")
FONT_CELL_BOLD = Font(name="Segoe UI", size=10, bold=True, color="1E293B")
FONT_KPI_LABEL = Font(name="Segoe UI", size=9, bold=True, color="64748B")
FONT_KPI_VAL = Font(name="Segoe UI", size=14, bold=True, color="1E2A4A")

# Alinhamentos
ALIGN_LEFT = Alignment(horizontal="left", vertical="center")
ALIGN_CENTER = Alignment(horizontal="center", vertical="center")
ALIGN_RIGHT = Alignment(horizontal="right", vertical="center")
ALIGN_WRAP = Alignment(horizontal="left", vertical="center", wrap_text=True)

def format_iso_date(dt_str: Optional[str]) -> str:
    """Formata timestamps ISO da API em formato legível brasileiro DD/MM/AAAA HH:MM:SS."""
    if not dt_str or dt_str == "N/A":
        return "N/A"
    try:
        clean = dt_str.split(".")[0] + "Z" if "." in dt_str else dt_str
        dt = datetime.fromisoformat(clean.replace("Z", "+00:00"))
        return dt.strftime("%d/%m/%Y %H:%M:%S")
    except Exception:
        return str(dt_str)[:19].replace("T", " ")

def generate_policies_excel(
    policies: List[Dict[str, Any]],
    kpis: Optional[Dict[str, Any]] = None,
    organization_name: str = "JM Distribuição"
) -> bytes:
    """
    Gera uma planilha Excel (.xlsx) altamente profissional e formatada,
    contendo duas abas:
    1. 'Resumo dos Planos': Visão executiva das políticas de proteção e cobertura.
    2. 'Dispositivos e Cobertura': Detalhamento minucioso máquina a máquina de cada plano.
    """
    wb = openpyxl.Workbook()
    
    # -------------------------------------------------------------------------
    # ABA 1: RESUMO DOS PLANOS DE SEGURANÇA
    # -------------------------------------------------------------------------
    ws_summary = wb.active
    ws_summary.title = "Planos de Segurança"
    ws_summary.views.sheetView[0].showGridLines = True

    now_str = datetime.now().strftime("%d/%m/%Y %H:%M:%S")

    # Banner de Título (Linhas 1 e 2)
    ws_summary.merge_cells("A1:J1")
    cell_title = ws_summary["A1"]
    cell_title.value = "JM CYBER PROTECT - RELATÓRIO EXECUTIVO DE PLANOS DE SEGURANÇA & COBERTURA"
    cell_title.font = FONT_TITLE
    cell_title.fill = NAVY_HEADER_FILL
    cell_title.alignment = ALIGN_CENTER
    ws_summary.row_dimensions[1].height = 36

    ws_summary.merge_cells("A2:J2")
    cell_sub = ws_summary["A2"]
    cell_sub.value = f"Data de Emissão: {now_str} | Organização: {organization_name} | Origem: API Oficial Acronis Cyber Protect Cloud"
    cell_sub.font = FONT_SUBTITLE
    cell_sub.fill = SUB_HEADER_FILL
    cell_sub.alignment = ALIGN_CENTER
    ws_summary.row_dimensions[2].height = 22

    # Cards Resumo / KPIs (Linha 4 e 5)
    total_policies = len(policies)
    total_protected = sum(p.get("target_count", 0) for p in policies)
    
    if kpis:
        total_res = kpis.get("total_resources", total_protected)
        unprotected = kpis.get("unprotected_resources", max(0, total_res - total_protected))
        prot_pct = kpis.get("protected_percentage", round((total_protected / max(1, total_res)) * 100, 1))
    else:
        unprotected = 0
        prot_pct = 100.0

    kpi_cards = [
        ("A4", "B4", "A5", "B5", "TOTAL DE POLÍTICAS", str(total_policies)),
        ("D4", "E4", "D5", "E5", "MÁQUINAS PROTEGIDAS", str(total_protected)),
        ("G4", "H4", "G5", "H5", "MÁQUINAS DESPROTEGIDAS", str(unprotected)),
        ("I4", "J4", "I5", "J5", "TAXA DE COBERTURA", f"{prot_pct}%"),
    ]

    for start_l, end_l, start_v, end_v, label, val in kpi_cards:
        ws_summary.merge_cells(f"{start_l}:{end_l}")
        ws_summary.merge_cells(f"{start_v}:{end_v}")
        
        lbl_cell = ws_summary[start_l]
        lbl_cell.value = label
        lbl_cell.font = FONT_KPI_LABEL
        lbl_cell.alignment = ALIGN_CENTER
        lbl_cell.fill = KPI_BOX_FILL
        
        val_cell = ws_summary[start_v]
        val_cell.value = val
        val_cell.font = FONT_KPI_VAL
        val_cell.alignment = ALIGN_CENTER
        val_cell.fill = KPI_BOX_FILL

    ws_summary.row_dimensions[4].height = 18
    ws_summary.row_dimensions[5].height = 26

    # Cabeçalho da Tabela Principal de Políticas (Linha 7)
    headers_summary = [
        "Plano de Segurança",
        "Tipo do Plano",
        "Organização / Tenant",
        "Status do Plano",
        "Máquinas Protegidas",
        "Sucesso (OK)",
        "Avisos / Atenção",
        "Falhas",
        "Módulos Integrados",
        "Data de Atualização"
    ]

    header_row = 7
    ws_summary.row_dimensions[header_row].height = 28
    for col_idx, h_text in enumerate(headers_summary, start=1):
        c = ws_summary.cell(row=header_row, column=col_idx, value=h_text)
        c.font = FONT_TH
        c.fill = TABLE_HEADER_FILL
        c.alignment = ALIGN_CENTER
        c.border = BORDER_HEADER

    # Inserção das Linhas de Políticas (a partir da Linha 8)
    curr_row = 8
    for p in policies:
        ws_summary.row_dimensions[curr_row].height = 22
        is_stripe = (curr_row % 2 == 0)
        row_fill = STRIPE_FILL if is_stripe else WHITE_FILL

        name = p.get("name") or "Plano sem nome"
        p_type = p.get("type") or "policy.protection.total"
        # Organização: prioriza tenant da política ou organização padrão
        org = p.get("organization") or organization_name
        is_enabled = bool(p.get("enabled", True))
        status_label = "Ativo" if is_enabled else "Inativo"
        target_cnt = int(p.get("target_count", 0))
        
        sb = p.get("status_breakdown", {})
        succ_cnt = int(sb.get("success", target_cnt))
        warn_cnt = int(sb.get("warning", 0))
        fail_cnt = int(sb.get("failed", 0))
        
        mods = ", ".join(p.get("modules", [])) if p.get("modules") else "Backup, Active Protection"
        updated = format_iso_date(p.get("last_run_time") or p.get("updated_at") or p.get("created_at"))

        values = [
            (name, ALIGN_LEFT, FONT_CELL_BOLD, row_fill),
            (p_type, ALIGN_LEFT, FONT_CELL, row_fill),
            (org, ALIGN_LEFT, FONT_CELL, row_fill),
            (status_label, ALIGN_CENTER, SUCCESS_FONT if is_enabled else DANGER_FONT, SUCCESS_FILL if is_enabled else DANGER_FILL),
            (target_cnt, ALIGN_RIGHT, FONT_CELL_BOLD, row_fill),
            (succ_cnt, ALIGN_RIGHT, FONT_CELL, row_fill),
            (warn_cnt, ALIGN_RIGHT, FONT_CELL if warn_cnt == 0 else WARNING_FONT, row_fill if warn_cnt == 0 else WARNING_FILL),
            (fail_cnt, ALIGN_RIGHT, FONT_CELL if fail_cnt == 0 else DANGER_FONT, row_fill if fail_cnt == 0 else DANGER_FILL),
            (mods, ALIGN_WRAP, FONT_CELL, row_fill),
            (updated, ALIGN_CENTER, FONT_CELL, row_fill)
        ]

        for col_idx, (val, align, font, fill) in enumerate(values, start=1):
            cell = ws_summary.cell(row=curr_row, column=col_idx, value=val)
            cell.alignment = align
            cell.font = font
            cell.fill = fill
            cell.border = BORDER_ALL

        curr_row += 1

    # Adiciona Filtro Automático no Cabeçalho
    last_col_letter = get_column_letter(len(headers_summary))
    ws_summary.auto_filter.ref = f"A{header_row}:{last_col_letter}{curr_row - 1}"

    # Auto-dimensionamento elegante de Colunas com Padding
    for col in ws_summary.columns:
        max_len = 0
        col_letter = get_column_letter(col[0].column)
        for cell in col:
            # Pula títulos mesclados no cálculo de largura
            if cell.row in [1, 2, 4, 5]:
                continue
            if cell.value:
                val_str = str(cell.value)
                max_len = max(max_len, len(val_str))
        ws_summary.column_dimensions[col_letter].width = max(max_len + 4, 12)

    # -------------------------------------------------------------------------
    # ABA 2: DETALHAMENTO DE MÁQUINAS E COBERTURA
    # -------------------------------------------------------------------------
    ws_devices = wb.create_sheet(title="Dispositivos e Cobertura")
    ws_devices.views.sheetView[0].showGridLines = True

    # Banner de Título (Linhas 1 e 2)
    ws_devices.merge_cells("A1:J1")
    cell_dev_title = ws_devices["A1"]
    cell_dev_title.value = "DETALHAMENTO DE MÁQUINAS PROTEGIDAS & STATUS DE COBERTURA POR PLANO"
    cell_dev_title.font = FONT_TITLE
    cell_dev_title.fill = NAVY_HEADER_FILL
    cell_dev_title.alignment = ALIGN_CENTER
    ws_devices.row_dimensions[1].height = 36

    ws_devices.merge_cells("A2:J2")
    cell_dev_sub = ws_devices["A2"]
    cell_dev_sub.value = f"Inventário minucioso dos dispositivos vinculados e execução da proteção | Organização: {organization_name}"
    cell_dev_sub.font = FONT_SUBTITLE
    cell_dev_sub.fill = SUB_HEADER_FILL
    cell_dev_sub.alignment = ALIGN_CENTER
    ws_devices.row_dimensions[2].height = 22

    # Cabeçalho da Tabela de Dispositivos (Linha 4)
    headers_devices = [
        "Dispositivo / Hostname",
        "Endereço IP",
        "Sistema Operacional",
        "Organização / Tenant",
        "Plano de Segurança Vinculado",
        "Tipo do Plano",
        "Status da Proteção",
        "Nível de Risco do Ativo",
        "Data de Atualização",
        "ID do Dispositivo"
    ]

    dev_header_row = 4
    ws_devices.row_dimensions[dev_header_row].height = 28
    for col_idx, h_text in enumerate(headers_devices, start=1):
        c = ws_devices.cell(row=dev_header_row, column=col_idx, value=h_text)
        c.font = FONT_TH
        c.fill = TABLE_HEADER_FILL
        c.alignment = ALIGN_CENTER
        c.border = BORDER_HEADER

    dev_curr_row = 5
    for p in policies:
        p_name = p.get("name") or "Plano sem nome"
        p_type = p.get("type") or "policy.protection.total"
        p_org = p.get("organization") or organization_name
        p_updated = format_iso_date(p.get("last_run_time") or p.get("updated_at") or p.get("created_at"))

        machines = p.get("machines", [])
        if not machines:
            # Caso a política não liste máquinas individuais no array (ex: sumário agregado), registra a linha do plano
            ws_devices.row_dimensions[dev_curr_row].height = 20
            is_stripe = (dev_curr_row % 2 == 0)
            row_fill = STRIPE_FILL if is_stripe else WHITE_FILL

            row_data = [
                (f"Dispositivos sob {p_name} ({p.get('target_count', 0)} ativos)", ALIGN_LEFT, FONT_CELL_BOLD, row_fill),
                ("--", ALIGN_CENTER, FONT_CELL, row_fill),
                ("Vários", ALIGN_LEFT, FONT_CELL, row_fill),
                (p_org, ALIGN_LEFT, FONT_CELL, row_fill),
                (p_name, ALIGN_LEFT, FONT_CELL, row_fill),
                (p_type, ALIGN_LEFT, FONT_CELL, row_fill),
                ("Protegido", ALIGN_CENTER, SUCCESS_FONT, SUCCESS_FILL),
                ("Seguro", ALIGN_CENTER, SUCCESS_FONT, SUCCESS_FILL),
                (p_updated, ALIGN_CENTER, FONT_CELL, row_fill),
                (p.get("id", "--"), ALIGN_LEFT, FONT_CELL, row_fill)
            ]
            for col_idx, (val, align, font, fill) in enumerate(row_data, start=1):
                cell = ws_devices.cell(row=dev_curr_row, column=col_idx, value=val)
                cell.alignment = align
                cell.font = font
                cell.fill = fill
                cell.border = BORDER_ALL
            dev_curr_row += 1
            continue

        for m in machines:
            ws_devices.row_dimensions[dev_curr_row].height = 20
            is_stripe = (dev_curr_row % 2 == 0)
            row_fill = STRIPE_FILL if is_stripe else WHITE_FILL

            m_name = m.get("name") or f"Dispositivo-{str(m.get('id', ''))[:8]}"
            m_ip = m.get("ip") or "--"
            m_os = m.get("os") or "SO Não Identificado"
            m_org = m.get("organization") or p_org
            m_id = str(m.get("id", "N/A"))

            # Status de Proteção
            raw_st = str(m.get("status", "success")).lower()
            if raw_st in ["success", "ok", "protected"]:
                st_label = "Protegido (Sucesso)"
                st_font = SUCCESS_FONT
                st_fill = SUCCESS_FILL
            elif raw_st in ["warning", "warn", "attention"]:
                st_label = "Atenção (Alerta)"
                st_font = WARNING_FONT
                st_fill = WARNING_FILL
            else:
                st_label = "Falha de Execução"
                st_font = DANGER_FONT
                st_fill = DANGER_FILL

            # Nível de Risco
            raw_risk = str(m.get("risk_level", "safe")).lower()
            if raw_risk == "critical":
                risk_label = "Crítico"
                risk_font = DANGER_FONT
                risk_fill = DANGER_FILL
            elif raw_risk == "warning":
                risk_label = "Atenção"
                risk_font = WARNING_FONT
                risk_fill = WARNING_FILL
            else:
                risk_label = "Seguro"
                risk_font = SUCCESS_FONT
                risk_fill = SUCCESS_FILL

            m_date = format_iso_date(m.get("last_backup_time") or p_updated)

            row_data = [
                (m_name, ALIGN_LEFT, FONT_CELL_BOLD, row_fill),
                (m_ip, ALIGN_CENTER, FONT_CELL, row_fill),
                (m_os, ALIGN_LEFT, FONT_CELL, row_fill),
                (m_org, ALIGN_LEFT, FONT_CELL, row_fill),
                (p_name, ALIGN_LEFT, FONT_CELL, row_fill),
                (p_type, ALIGN_LEFT, FONT_CELL, row_fill),
                (st_label, ALIGN_CENTER, st_font, st_fill),
                (risk_label, ALIGN_CENTER, risk_font, risk_fill),
                (m_date, ALIGN_CENTER, FONT_CELL, row_fill),
                (m_id, ALIGN_LEFT, FONT_CELL, row_fill)
            ]

            for col_idx, (val, align, font, fill) in enumerate(row_data, start=1):
                cell = ws_devices.cell(row=dev_curr_row, column=col_idx, value=val)
                cell.alignment = align
                cell.font = font
                cell.fill = fill
                cell.border = BORDER_ALL

            dev_curr_row += 1

    # Filtro Automático na Aba 2
    dev_last_col_letter = get_column_letter(len(headers_devices))
    ws_devices.auto_filter.ref = f"A{dev_header_row}:{dev_last_col_letter}{dev_curr_row - 1}"

    # Auto-dimensionamento da Aba 2
    for col in ws_devices.columns:
        max_len = 0
        col_letter = get_column_letter(col[0].column)
        for cell in col:
            if cell.row in [1, 2]:
                continue
            if cell.value:
                val_str = str(cell.value)
                max_len = max(max_len, len(val_str))
        ws_devices.column_dimensions[col_letter].width = max(max_len + 4, 12)

    # Gera buffer em memória
    output = io.BytesIO()
    wb.save(output)
    output.seek(0)
    return output.getvalue()
