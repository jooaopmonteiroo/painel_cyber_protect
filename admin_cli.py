#!/usr/bin/env python3
"""
CLI de Gestão e Administração de Utilizadores - Painel JM Cyber Protect
Execução estritamente externa e isolada do site principal.
Permite listar, criar, aprovar, bloquear, redefinir senhas e excluir utilizadores.
"""

import sys
import argparse
import getpass
import auth

RESET = "\033[0m"
BOLD = "\033[1m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
CYAN = "\033[96m"
BLUE = "\033[94m"

def print_header():
    print(f"\n{BOLD}{CYAN}================================================================={RESET}")
    print(f"{BOLD}{BLUE}  JM CYBER PROTECT - MÓDULO ADMINISTRATIVO EXTERNO{RESET}")
    print(f"{BOLD}{CYAN}  Controle de Acesso, Aprovação e Liberação de Utilizadores{RESET}")
    print(f"{BOLD}{CYAN}================================================================={RESET}\n")

def cmd_list(args=None):
    users = auth.list_users()
    stats = auth.get_stats()
    
    print(f"{BOLD}Total de Utilizadores:{RESET} {stats['total_users']} | "
          f"{GREEN}{BOLD}Ativos/Liberados:{RESET} {stats['active_users']} | "
          f"{YELLOW}{BOLD}Pendentes:{RESET} {stats['pending_users']} | "
          f"{BLUE}{BOLD}Admins:{RESET} {stats['admin_users']}\n")

    if not users:
        print(f"{YELLOW}Nenhum utilizador encontrado no banco de dados.{RESET}")
        return

    col_id = "ID"
    col_user = "USUÁRIO"
    col_name = "NOME COMPLETO"
    col_email = "E-MAIL"
    col_role = "PAPEL"
    col_status = "STATUS"
    col_last = "ÚLTIMO ACESSO"

    print(f"{BOLD}{col_id:<4} {col_user:<15} {col_name:<24} {col_email:<28} {col_role:<10} {col_status:<16} {col_last:<18}{RESET}")
    print("-" * 120)

    for u in users:
        status_str = f"{GREEN}LIBERADO{RESET}" if u["is_active"] else f"{YELLOW}{BOLD}PENDENTE{RESET}"
        last_login = u["last_login"] or "Nunca acessou"
        full_name = (u["full_name"][:21] + "...") if len(u["full_name"]) > 24 else u["full_name"]
        email = (u["email"][:25] + "...") if len(u["email"]) > 28 else u["email"]
        print(f"{u['id']:<4} {u['username']:<15} {full_name:<24} {email:<28} {u['role']:<10} {status_str:<25} {last_login:<18}")
    print()

def cmd_approve(args):
    target = args.username_or_id
    success, msg = auth.approve_user(target, admin_actor="admin_cli", ip_address="127.0.0.1")
    if success:
        print(f"{GREEN}[✓] SUCESSO:{RESET} {msg}")
    else:
        print(f"{RED}[✗] ERRO:{RESET} {msg}")

def cmd_block(args):
    target = args.username_or_id
    success, msg = auth.block_user(target, admin_actor="admin_cli", ip_address="127.0.0.1")
    if success:
        print(f"{YELLOW}[✓] SUCESSO:{RESET} {msg}")
    else:
        print(f"{RED}[✗] ERRO:{RESET} {msg}")

def cmd_create(args):
    username = args.username
    email = args.email
    full_name = args.name
    password = args.password
    role = args.role or "operator"
    is_active = args.active

    if not username:
        username = input("Nome de Utilizador (login): ").strip()
    if not full_name:
        full_name = input("Nome Completo: ").strip()
    if not email:
        email = input("E-mail corporativo: ").strip()
    if not password:
        password = getpass.getpass("Senha de Acesso (mínimo 6 chars): ").strip()
    
    success, msg, user_id = auth.create_user(
        username=username,
        email=email,
        full_name=full_name,
        password=password,
        role=role,
        is_active=is_active,
        actor_admin="admin_cli",
        ip_address="127.0.0.1"
    )

    if success:
        print(f"{GREEN}[✓] SUCESSO:{RESET} {msg} (ID: {user_id})")
    else:
        print(f"{RED}[✗] ERRO:{RESET} {msg}")

def cmd_reset_pwd(args):
    target = args.username_or_id
    new_pwd = args.new_password
    if not new_pwd:
        new_pwd = getpass.getpass("Nova Senha (mínimo 6 chars): ").strip()

    success, msg = auth.reset_password(target, new_pwd, admin_actor="admin_cli", ip_address="127.0.0.1")
    if success:
        print(f"{GREEN}[✓] SUCESSO:{RESET} {msg}")
    else:
        print(f"{RED}[✗] ERRO:{RESET} {msg}")

def cmd_delete(args):
    target = args.username_or_id
    if not args.yes:
        confirm = input(f"Tem certeza que deseja EXCLUIR permanentemente o utilizador '{target}'? (s/N): ").strip().lower()
        if confirm not in ("s", "sim", "y", "yes"):
            print("Operação cancelada.")
            return

    success, msg = auth.delete_user(target, admin_actor="admin_cli", ip_address="127.0.0.1")
    if success:
        print(f"{GREEN}[✓] SUCESSO:{RESET} {msg}")
    else:
        print(f"{RED}[✗] ERRO:{RESET} {msg}")

def cmd_role(args):
    target = args.username_or_id
    new_role = args.new_role
    if not new_role:
        print(f"{BOLD}Escolha o novo papel:{RESET}")
        print("  1. admin (Administrador Pleno)")
        print("  2. operator (Operador de Sistema)")
        print("  3. viewer (Visualizador / Somente Leitura)")
        r_choice = input("Opção (1-3): ").strip()
        role_map = {"1": "admin", "2": "operator", "3": "viewer"}
        new_role = role_map.get(r_choice, "operator")

    success, msg = auth.update_user_role(target, new_role, admin_actor="admin_cli", ip_address="127.0.0.1")
    if success:
        print(f"{GREEN}[✓] SUCESSO:{RESET} {msg}")
    else:
        print(f"{RED}[✗] ERRO:{RESET} {msg}")

def cmd_audit(args):
    limit = args.limit or 25
    logs = auth.get_audit_logs(limit=limit)
    print(f"\n{BOLD}ÚLTIMOS {len(logs)} EVENTOS DE AUDITORIA DE ACESSO:{RESET}\n")
    print(f"{BOLD}{'DATA/HORA':<20} {'USUÁRIO':<16} {'AÇÃO':<28} {'IP':<15} {'DETALHES'}{RESET}")
    print("-" * 115)
    for log in logs:
        print(f"{log['timestamp']:<20} {log['username']:<16} {log['action']:<28} {log['ip_address']:<15} {log['details']}")
    print()

def cmd_interactive():
    print_header()
    while True:
        print(f"{BOLD}OPÇÕES DE ADMINISTRAÇÃO EXTERNA:{RESET}")
        print("  1. Listar Utilizadores e Status de Aprovação")
        print("  2. Aprovar / Liberar Utilizador Pendente")
        print("  3. Bloquear / Revogar Acesso de Utilizador")
        print("  4. Criar Novo Utilizador")
        print("  5. Redefinir Senha de Utilizador")
        print("  6. Excluir Utilizador")
        print("  7. Alterar Papel (Role) de Utilizador")
        print("  8. Ver Logs de Auditoria de Acesso")
        print("  0. Sair")

        choice = input(f"\n{BOLD}Escolha uma opção (0-8): {RESET}").strip()

        if choice == "1":
            cmd_list()
        elif choice == "2":
            user_input = input("Informe o Nome de Utilizador ou ID para APROVAR/LIBERAR: ").strip()
            if user_input:
                class Dummy: pass
                d = Dummy()
                d.username_or_id = user_input
                cmd_approve(d)
        elif choice == "3":
            user_input = input("Informe o Nome de Utilizador ou ID para BLOQUEAR: ").strip()
            if user_input:
                class Dummy: pass
                d = Dummy()
                d.username_or_id = user_input
                cmd_block(d)
        elif choice == "4":
            class Dummy: pass
            d = Dummy()
            d.username = None
            d.email = None
            d.name = None
            d.password = None
            d.role = input("Papel (operator/admin/viewer) [default: operator]: ").strip() or "operator"
            act_in = input("Liberar acesso imediatamente? (s/N): ").strip().lower()
            d.active = act_in in ("s", "sim", "y", "yes")
            cmd_create(d)
        elif choice == "5":
            user_input = input("Informe o Nome de Utilizador ou ID para redefinir senha: ").strip()
            if user_input:
                class Dummy: pass
                d = Dummy()
                d.username_or_id = user_input
                d.new_password = None
                cmd_reset_pwd(d)
        elif choice == "6":
            user_input = input("Informe o Nome de Utilizador ou ID para EXCLUIR: ").strip()
            if user_input:
                class Dummy: pass
                d = Dummy()
                d.username_or_id = user_input
                d.yes = False
                cmd_delete(d)
        elif choice == "7":
            user_input = input("Informe o Nome de Utilizador ou ID para alterar o papel: ").strip()
            if user_input:
                class Dummy: pass
                d = Dummy()
                d.username_or_id = user_input
                d.new_role = None
                cmd_role(d)
        elif choice == "8":
            class Dummy: pass
            d = Dummy()
            d.limit = 30
            cmd_audit(d)
        elif choice == "0":
            print(f"\n{GREEN}Encerrando console administrativo. Até logo!{RESET}\n")
            break
        else:
            print(f"{RED}Opção inválida.{RESET}")
        print("\n" + "="*70 + "\n")

def main():
    parser = argparse.ArgumentParser(
        description="Módulo Administrativo Externo de Utilizadores - JM Cyber Protect",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    subparsers = parser.add_subparsers(dest="command", help="Comando a executar")

    # list
    p_list = subparsers.add_parser("list", help="Lista todos os utilizadores e status de aprovação")
    p_list.set_defaults(func=cmd_list)

    # approve
    p_app = subparsers.add_parser("approve", help="Aprova e libera um utilizador para acessar o painel")
    p_app.add_argument("username_or_id", help="Nome de utilizador ou ID numérico")
    p_app.set_defaults(func=cmd_approve)

    # block
    p_blk = subparsers.add_parser("block", help="Bloqueia o acesso de um utilizador e derruba sessões ativas")
    p_blk.add_argument("username_or_id", help="Nome de utilizador ou ID numérico")
    p_blk.set_defaults(func=cmd_block)

    # create
    p_crt = subparsers.add_parser("create", help="Cadastra um novo utilizador no sistema")
    p_crt.add_argument("--username", "-u", help="Login de acesso")
    p_crt.add_argument("--name", "-n", help="Nome completo")
    p_crt.add_argument("--email", "-e", help="E-mail")
    p_crt.add_argument("--password", "-p", help="Senha")
    p_crt.add_argument("--role", "-r", choices=["admin", "operator", "viewer"], default="operator", help="Papel")
    p_crt.add_argument("--active", "-a", action="store_true", help="Se definido, o utilizador já nasce liberado")
    p_crt.set_defaults(func=cmd_create)

    # role
    p_rol = subparsers.add_parser("role", help="Altera o papel (role) de um utilizador cadastrado")
    p_rol.add_argument("username_or_id", help="Nome de utilizador ou ID numérico")
    p_rol.add_argument("new_role", choices=["admin", "operator", "viewer"], help="Novo papel (admin, operator, viewer)")
    p_rol.set_defaults(func=cmd_role)

    # reset-pwd
    p_rst = subparsers.add_parser("reset-pwd", help="Redefine a senha de um utilizador")
    p_rst.add_argument("username_or_id", help="Nome de utilizador ou ID")
    p_rst.add_argument("--new-password", "-p", help="Nova senha")
    p_rst.set_defaults(func=cmd_reset_pwd)

    # delete
    p_del = subparsers.add_parser("delete", help="Exclui definitivamente um utilizador")
    p_del.add_argument("username_or_id", help="Nome de utilizador ou ID")
    p_del.add_argument("--yes", "-y", action="store_true", help="Ignora confirmação interativa")
    p_del.set_defaults(func=cmd_delete)

    # audit
    p_aud = subparsers.add_parser("audit", help="Exibe os últimos logs de auditoria de autenticação e acesso")
    p_aud.add_argument("--limit", "-l", type=int, default=25, help="Quantidade de registros")
    p_aud.set_defaults(func=cmd_audit)

    # menu
    p_menu = subparsers.add_parser("menu", help="Abre o menu interativo no terminal")
    p_menu.set_defaults(func=lambda args: cmd_interactive())

    args = parser.parse_args()
    if not args.command:
        cmd_interactive()
    else:
        args.func(args)

if __name__ == "__main__":
    main()
