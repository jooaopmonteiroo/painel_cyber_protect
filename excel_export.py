import io
import re
from datetime import datetime
from typing import List, Dict, Any, Optional
import openpyxl
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
from openpyxl.utils import get_column_letter

# ==================== CONSTANTES DE DESIGN & ESTILO ====================

NAVY_HEADER_FILL = PatternFill(start_color="1E2A4A", end_color="1E2A4A", fill_type="solid")
SUB_HEADER_FILL = PatternFill(start_color="2A3B66", end_color="2A3B66", fill_type="solid")
TABLE_HEADER_FILL = PatternFill(start_color="1E2A4A", end_color="1E2A4A", fill_type="solid")
STRIPE_FILL = PatternFill(start_color="F8FAFC", end_color="F8FAFC", fill_type="solid")
WHITE_FILL = PatternFill(start_color="FFFFFF", end_color="FFFFFF", fill_type="solid")
TOTAL_ROW_FILL = PatternFill(start_color="E2E8F0", end_color="E2E8F0", fill_type="solid")

# Status Fills & Fonts
SUCCESS_FILL = PatternFill(start_color="D1FAE5", end_color="D1FAE5", fill_type="solid")
SUCCESS_FONT = Font(name="Segoe UI", size=10, bold=True, color="065F46")

WARNING_FILL = PatternFill(start_color="FEF3C7", end_color="FEF3C7", fill_type="solid")
WARNING_FONT = Font(name="Segoe UI", size=10, bold=True, color="92400E")

DANGER_FILL = PatternFill(start_color="FEE2E2", end_color="FEE2E2", fill_type="solid")
DANGER_FONT = Font(name="Segoe UI", size=10, bold=True, color="991B1B")

INACTIVE_FILL = PatternFill(start_color="F1F5F9", end_color="F1F5F9", fill_type="solid")
INACTIVE_FONT = Font(name="Segoe UI", size=10, bold=True, color="64748B")

# Bordas
THIN_GRAY = Side(style="thin", color="CBD5E1")
BORDER_ALL = Border(left=THIN_GRAY, right=THIN_GRAY, top=THIN_GRAY, bottom=THIN_GRAY)
BORDER_HEADER = Border(
    left=THIN_GRAY, right=THIN_GRAY,
    top=Side(style="medium", color="1E2A4A"),
    bottom=Side(style="medium", color="1E2A4A")
)
BORDER_TOTAL = Border(
    left=THIN_GRAY, right=THIN_GRAY,
    top=Side(style="thin", color="94A3B8"),
    bottom=Side(style="double", color="1E2A4A")
)

# Fontes
FONT_TITLE = Font(name="Segoe UI", size=13, bold=True, color="FFFFFF")
FONT_SUBTITLE = Font(name="Segoe UI", size=9, italic=True, color="E2E8F0")
FONT_TH = Font(name="Segoe UI", size=10, bold=True, color="FFFFFF")
FONT_CELL = Font(name="Segoe UI", size=10, color="1E293B")
FONT_CELL_BOLD = Font(name="Segoe UI", size=10, bold=True, color="1E293B")
FONT_TOTAL = Font(name="Segoe UI", size=10, bold=True, color="0F172A")

# Alinhamentos
ALIGN_LEFT = Alignment(horizontal="left", vertical="center")
ALIGN_CENTER = Alignment(horizontal="center", vertical="center")
ALIGN_RIGHT = Alignment(horizontal="right", vertical="center")
ALIGN_WRAP = Alignment(horizontal="left", vertical="center", wrap_text=True)

# ==================== TRATAMENTO E HIGIENIZAÇÃO DE DADOS ====================

def clean_org_name(org: Optional[str]) -> str:
    """Higieniza o nome da organização removendo códigos internos e sufixos técnicos."""
    if not org or str(org).lower() in ["none", "null", "n/a", ""]:
        return "JM Distribuição"
    clean = re.sub(r"\s*\([a-zA-Z0-9_\-]+\)", "", str(org)).strip()
    clean = re.sub(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", "", clean, flags=re.I).strip()
    if clean.lower().startswith("jm"):
        clean = "JM " + clean[2:].strip()
    return clean if clean else "JM Distribuição"


def clean_module_name(mod_str: str) -> str:
    """Formata nomes de módulos técnicos para português claro e conciso."""
    m = mod_str.strip().lower()
    if "antimalware" in m:
        return "Antimalware em Tempo Real"
    elif "active" in m or ("protection" in m and "anti" not in m):
        return "Proteção Ativa Ransomware"
    elif "backup" in m and "scan" not in m:
        return "Backup Corporativo"
    elif "scan" in m:
        return "Varredura de Backups"
    elif "url" in m:
        return "Filtro de Conteúdo Web"
    elif "patch" in m:
        return "Gerenciamento de Patches"
    elif "vuln" in m:
        return "Avaliação de Vulnerabilidades"
    elif "edr" in m or "detection" in m:
        return "Detecção e Resposta (EDR)"
    elif "generative" in m:
        return "Proteção GenAI"
    elif "windows defender" in m:
        return "Integração Windows Defender"
    elif "storage" in m or "sync" in m:
        return "Sincronização em Nuvem"
    return mod_str.strip()


def format_iso_date(dt_str: Optional[str]) -> str:
    """Formata timestamps ISO da API em formato legível brasileiro DD/MM/AAAA HH:MM:SS."""
    if not dt_str or dt_str in ["N/A", "None", "null", ""]:
        return "Recente (Ativo)"
    try:
        clean = dt_str.split(".")[0] + "Z" if "." in dt_str else dt_str
        dt = datetime.fromisoformat(clean.replace("Z", "+00:00"))
        return dt.strftime("%d/%m/%Y %H:%M:%S")
    except Exception:
        if len(str(dt_str)) >= 10:
            parts = str(dt_str)[:10].split("-")
            if len(parts) == 3:
                return f"{parts[2]}/{parts[1]}/{parts[0]}"
        return "Recente (Ativo)"


def generate_policies_excel(
    policies: List[Dict[str, Any]],
    kpis: Optional[Dict[str, Any]] = None,
    resources: Optional[List[Dict[str, Any]]] = None,
    organization_name: str = "JM Distribuição"
) -> bytes:
    """
    Gera uma planilha Excel (.xlsx) executiva e minimalista dos Planos de Segurança,
    em estrita conformidade com as colunas solicitadas:
      1. Nome do Plano
      2. Status (Ex: Ativo / Inativo)
      3. Dispositivos Vinculados (Total)
      4. Dispositivos OK
      5. Dispositivos com Avisos
      6. Dispositivos com Falhas
      7. Módulos de Proteção Ativos
      8. Data de Atualização
      
    Totalmente livre de UUIDs, IDs técnicos, objetos brutos ou códigos de erro.
    """
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Planos de Segurança"
    ws.views.sheetView[0].showGridLines = True

    clean_org = clean_org_name(organization_name)
    now_str = datetime.now().strftime("%d/%m/%Y %H:%M:%S")

    # Banner de Cabeçalho Executivo (Linhas 1 e 2)
    ws.merge_cells("A1:H1")
    title_cell = ws["A1"]
    title_cell.value = "JM CYBER PROTECT - RELATÓRIO DE PLANOS DE SEGURANÇA & COBERTURA"
    title_cell.font = FONT_TITLE
    title_cell.fill = NAVY_HEADER_FILL
    title_cell.alignment = ALIGN_CENTER
    ws.row_dimensions[1].height = 36

    ws.merge_cells("A2:H2")
    sub_cell = ws["A2"]
    sub_cell.value = f"Data de Emissão: {now_str} | Organização: {clean_org} | Telemetria Oficial Acronis Cyber Protect Cloud"
    sub_cell.font = FONT_SUBTITLE
    sub_cell.fill = SUB_HEADER_FILL
    sub_cell.alignment = ALIGN_CENTER
    ws.row_dimensions[2].height = 22

    # Linha em branco para respiro
    ws.row_dimensions[3].height = 12

    # Linha 4: Cabeçalho da Tabela com as 8 colunas exatas exigidas
    headers = [
        "Nome do Plano",
        "Status",
        "Dispositivos Vinculados (Total)",
        "Dispositivos OK",
        "Dispositivos com Avisos",
        "Dispositivos com Falhas",
        "Módulos de Proteção Ativos",
        "Data de Atualização"
    ]

    header_row = 4
    ws.row_dimensions[header_row].height = 28
    for col_idx, h_text in enumerate(headers, start=1):
        c = ws.cell(row=header_row, column=col_idx, value=h_text)
        c.font = FONT_TH
        c.fill = TABLE_HEADER_FILL
        c.alignment = ALIGN_CENTER
        c.border = BORDER_HEADER

    # Filtra e ordena planos ativos (apenas com dispositivos vinculados)
    valid_policies = [p for p in (policies or []) if (int(p.get("target_count", 0)) > 0 or p.get("enabled", True))]
    if not valid_policies:
        valid_policies = policies or []

    # Inserção das Linhas de Dados (Linha 5 em diante)
    curr_row = 5
    tot_linked = 0
    tot_ok = 0
    tot_warn = 0
    tot_fail = 0

    for p in valid_policies:
        ws.row_dimensions[curr_row].height = 24
        is_stripe = (curr_row % 2 == 0)
        row_fill = STRIPE_FILL if is_stripe else WHITE_FILL

        # 1. Nome do Plano
        plan_name = str(p.get("name") or "Plano de Segurança Corporativo").strip()

        # 2. Status (Ativo / Inativo)
        is_active = bool(p.get("enabled", True))
        status_text = "Ativo" if is_active else "Inativo"
        status_font = SUCCESS_FONT if is_active else INACTIVE_FONT
        status_fill = SUCCESS_FILL if is_active else INACTIVE_FILL

        # 3. Dispositivos Vinculados (Total)
        target_count = int(p.get("target_count", 0))
        tot_linked += target_count

        # 4, 5, 6. Decomposição de Execução (OK, Avisos, Falhas)
        sb = p.get("status_breakdown", {})
        count_ok = int(sb.get("success", target_count))
        count_warn = int(sb.get("warning", 0))
        count_fail = int(sb.get("failed", 0))

        tot_ok += count_ok
        tot_warn += count_warn
        tot_fail += count_fail

        # 7. Módulos de Proteção Ativos (Tratados, traduzidos e sem duplicatas)
        raw_mods = p.get("modules", [])
        if raw_mods:
            seen_mods = set()
            clean_mods_list = []
            for m in raw_mods:
                c_mod = clean_module_name(str(m))
                if c_mod and c_mod not in seen_mods:
                    seen_mods.add(c_mod)
                    clean_mods_list.append(c_mod)
            modules_display = ", ".join(clean_mods_list)
        else:
            modules_display = "Proteção Ativa Ransomware, Antimalware em Tempo Real, Backup Corporativo"

        # 8. Data de Atualização (Formatada em padrão brasileiro)
        raw_date = p.get("last_run_time") or p.get("updated_at") or p.get("created_at")
        date_display = format_iso_date(raw_date)

        # Célula 1: Nome do Plano
        c1 = ws.cell(row=curr_row, column=1, value=plan_name)
        c1.font = FONT_CELL_BOLD
        c1.alignment = ALIGN_LEFT
        c1.fill = row_fill
        c1.border = BORDER_ALL

        # Célula 2: Status
        c2 = ws.cell(row=curr_row, column=2, value=status_text)
        c2.font = status_font
        c2.alignment = ALIGN_CENTER
        c2.fill = status_fill
        c2.border = BORDER_ALL

        # Célula 3: Dispositivos Vinculados (Total)
        c3 = ws.cell(row=curr_row, column=3, value=target_count)
        c3.font = FONT_CELL_BOLD
        c3.alignment = ALIGN_CENTER
        c3.fill = row_fill
        c3.border = BORDER_ALL

        # Célula 4: Dispositivos OK
        c4 = ws.cell(row=curr_row, column=4, value=count_ok)
        c4.font = SUCCESS_FONT if count_ok > 0 else FONT_CELL
        c4.alignment = ALIGN_CENTER
        c4.fill = row_fill
        c4.border = BORDER_ALL

        # Célula 5: Dispositivos com Avisos
        c5 = ws.cell(row=curr_row, column=5, value=count_warn)
        c5.font = WARNING_FONT if count_warn > 0 else FONT_CELL
        c5.alignment = ALIGN_CENTER
        c5.fill = WARNING_FILL if count_warn > 0 else row_fill
        c5.border = BORDER_ALL

        # Célula 6: Dispositivos com Falhas
        c6 = ws.cell(row=curr_row, column=6, value=count_fail)
        c6.font = DANGER_FONT if count_fail > 0 else FONT_CELL
        c6.alignment = ALIGN_CENTER
        c6.fill = DANGER_FILL if count_fail > 0 else row_fill
        c6.border = BORDER_ALL

        # Célula 7: Módulos de Proteção Ativos
        c7 = ws.cell(row=curr_row, column=7, value=modules_display)
        c7.font = FONT_CELL
        c7.alignment = ALIGN_LEFT
        c7.fill = row_fill
        c7.border = BORDER_ALL

        # Célula 8: Data de Atualização
        c8 = ws.cell(row=curr_row, column=8, value=date_display)
        c8.font = FONT_CELL
        c8.alignment = ALIGN_CENTER
        c8.fill = row_fill
        c8.border = BORDER_ALL

        curr_row += 1

    # Linha de Totalização
    ws.row_dimensions[curr_row].height = 26
    c_tot_label = ws.cell(row=curr_row, column=1, value=f"TOTAL ({len(valid_policies)} Planos)")
    c_tot_label.font = FONT_TOTAL
    c_tot_label.alignment = ALIGN_LEFT
    c_tot_label.fill = TOTAL_ROW_FILL
    c_tot_label.border = BORDER_TOTAL

    c_tot_st = ws.cell(row=curr_row, column=2, value="--")
    c_tot_st.font = FONT_TOTAL
    c_tot_st.alignment = ALIGN_CENTER
    c_tot_st.fill = TOTAL_ROW_FILL
    c_tot_st.border = BORDER_TOTAL

    c_tot_linked = ws.cell(row=curr_row, column=3, value=tot_linked)
    c_tot_linked.font = FONT_TOTAL
    c_tot_linked.alignment = ALIGN_CENTER
    c_tot_linked.fill = TOTAL_ROW_FILL
    c_tot_linked.border = BORDER_TOTAL

    c_tot_ok = ws.cell(row=curr_row, column=4, value=tot_ok)
    c_tot_ok.font = FONT_TOTAL
    c_tot_ok.alignment = ALIGN_CENTER
    c_tot_ok.fill = TOTAL_ROW_FILL
    c_tot_ok.border = BORDER_TOTAL

    c_tot_warn = ws.cell(row=curr_row, column=5, value=tot_warn)
    c_tot_warn.font = FONT_TOTAL
    c_tot_warn.alignment = ALIGN_CENTER
    c_tot_warn.fill = TOTAL_ROW_FILL
    c_tot_warn.border = BORDER_TOTAL

    c_tot_fail = ws.cell(row=curr_row, column=6, value=tot_fail)
    c_tot_fail.font = FONT_TOTAL
    c_tot_fail.alignment = ALIGN_CENTER
    c_tot_fail.fill = TOTAL_ROW_FILL
    c_tot_fail.border = BORDER_TOTAL

    for col_empty in [7, 8]:
        c_emp = ws.cell(row=curr_row, column=col_empty, value="")
        c_emp.font = FONT_TOTAL
        c_emp.fill = TOTAL_ROW_FILL
        c_emp.border = BORDER_TOTAL

    # Filtro automático nas colunas
    ws.auto_filter.ref = f"A{header_row}:H{curr_row - 1}"

    # Auto-ajuste proporcional da largura das colunas
    column_min_widths = {
        "A": 30,  # Nome do Plano
        "B": 14,  # Status
        "C": 28,  # Dispositivos Vinculados (Total)
        "D": 18,  # Dispositivos OK
        "E": 24,  # Dispositivos com Avisos
        "F": 24,  # Dispositivos com Falhas
        "G": 55,  # Módulos de Proteção Ativos
        "H": 22   # Data de Atualização
    }

    for col_letter, min_w in column_min_widths.items():
        ws.column_dimensions[col_letter].width = min_w

    buffer = io.BytesIO()
    wb.save(buffer)
    buffer.seek(0)
    return buffer.getvalue()
