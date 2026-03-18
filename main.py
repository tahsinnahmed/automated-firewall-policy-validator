# main.py

from module.display import (
    show_logs,
    show_rules_by_site_vendor,
    show_collision_report,  # expects (existing_rules, new_rules)
)
from module.directory import (
    WELCOME_ANSI,
    README_ANSI,
    DEFAULT_RULES_CISCO,
    DEFAULT_RULES_PALOALTO,
)
from module.input import run_input_flow
from module.normalization import load_and_normalize_existing
from module.api import run_rest_api_login

import os
import sys
from pathlib import Path

RESET = "\033[0m"
FG_RED = "\033[31m"
FG_LIGHT_YELLOW = "\033[1;33m"


def _enable_windows_ansi():
    """Enable ANSI escape codes in Windows 10+ consoles without external libs."""
    if os.name != "nt":
        return
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        mode = ctypes.c_uint32()
        if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            kernel32.SetConsoleMode(handle, mode.value | 0x0004)  # ENABLE_VIRTUAL_TERMINAL_PROCESSING
    except Exception:
        pass


_enable_windows_ansi()


def _read_choice(prompt: str, valid: set[str]) -> str:
    """Read a choice that must be in 'valid'. Re-prompts until valid."""
    while True:
        choice = (input(prompt) or "").strip()
        if choice in valid:
            return choice
        sorted_valid = sorted(valid)
        hint = " or ".join(sorted_valid) if len(sorted_valid) == 2 else ", ".join(sorted_valid)
        print(f"{FG_RED}Invalid choice. Please enter {hint}.{RESET}\n")


def _load_existing_rules() -> list[dict]:
    """Load & normalize existing rules from default Cisco & PaloAlto sources if present."""
    rule_files: list[Path] = []
    try:
        if DEFAULT_RULES_CISCO and Path(DEFAULT_RULES_CISCO).exists():
            rule_files.append(Path(DEFAULT_RULES_CISCO))
    except Exception:
        pass

    try:
        if DEFAULT_RULES_PALOALTO and Path(DEFAULT_RULES_PALOALTO).exists():
            rule_files.append(Path(DEFAULT_RULES_PALOALTO))
    except Exception:
        pass

    if not rule_files:
        print(f"{FG_RED}Warning: No existing rules found under 'rules/'.{RESET}\n")
        return []

    return load_and_normalize_existing(rule_files)


def _view_rules_menu() -> None:
    """View rules by site/vendor via display.show_rules_by_site_vendor()."""
    print(f"\n{FG_LIGHT_YELLOW}Please select a site according to your task:{RESET}")
    print("1. DC1")
    print("2. DC2")
    print("3. DC3\n")
    s_choice = _read_choice("Enter choice: ", {"1", "2", "3"})
    site_map = {"1": "DC1", "2": "DC2", "3": "DC3"}
    site = site_map[s_choice]

    print(f"\n{FG_LIGHT_YELLOW}Please select a vendor according to your task:{RESET}")
    print("1. Cisco")
    print("2. PaloAlto\n")
    v_choice = _read_choice("Enter choice: ", {"1", "2"})
    vendor = "cisco" if v_choice == "1" else "paloalto"

    show_rules_by_site_vendor(site, vendor)


def _print_main_menu() -> None:
    print(f"{FG_LIGHT_YELLOW}Please select an option according to your task:{RESET}")
    print("1. Input rules")
    print("2. View rules")
    print("3. Readme")
    print("4. Rest API\n")


def main():
    # Show welcome screen first (without header/footer)
    if WELCOME_ANSI and Path(WELCOME_ANSI).exists():
        show_logs(WELCOME_ANSI, exit_on_missing=False, suppress_banner=True)

    # MAIN LOOP
    while True:
        _print_main_menu()
        choice = _read_choice("Enter choice: ", {"1", "2", "3", "4"})

        if choice == "2":
            _view_rules_menu()
            continue

        if choice == "3":
            if README_ANSI and Path(README_ANSI).exists():
                show_logs(README_ANSI, exit_on_missing=False)
            else:
                print(f"{FG_RED}README not found at: {README_ANSI}{RESET}\n")
            continue

        if choice == "4":
            run_rest_api_login()
            continue

        # choice == "1": Input Rules -> Collision Check -> Display
        new_rules = run_input_flow()
        if not new_rules:
            print(f"{FG_RED}No new rules were provided.{RESET}\n")
            continue

        existing_rules = _load_existing_rules()
        show_collision_report(existing_rules, new_rules)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"{FG_RED}\nAborted by user.{RESET}\n")
        try:
            sys.exit(130)
        except SystemExit:
            pass
















# # main.py
#
# from module.display import (
#     show_logs,
#     show_rules_by_site_vendor,
#     show_collision_report,  # expects (existing_rules, new_rules)
# )
# from module.directory import (
#     WELCOME_ANSI,
#     README_ANSI,
#     DEFAULT_RULES_CISCO,
#     DEFAULT_RULES_PALOALTO,
# )
# from module.input import run_input_flow
# from module.normalization import load_and_normalize_existing
# import os
# import sys
# from pathlib import Path
#
# RESET = "\033[0m"
# FG_RED = "\033[31m"
# FG_LIGHT_YELLOW = "\033[1;33m"
#
#
# def _enable_windows_ansi():
#     """Enable ANSI escape codes in Windows 10+ consoles without external libs."""
#     if os.name != "nt":
#         return
#     try:
#         import ctypes
#         kernel32 = ctypes.windll.kernel32
#         handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
#         mode = ctypes.c_uint32()
#         if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
#             kernel32.SetConsoleMode(handle, mode.value | 0x0004)  # ENABLE_VIRTUAL_TERMINAL_PROCESSING
#     except Exception:
#         pass
#
#
# _enable_windows_ansi()
#
#
# def _read_choice(prompt: str, valid: set[str]) -> str:
#     """
#     Read a choice that must be in 'valid'. Re-prompts until valid.
#     Shows a hint listing acceptable options.
#     """
#     while True:
#         choice = (input(prompt) or "").strip()
#         if choice in valid:
#             return choice
#         sorted_valid = sorted(valid)
#         hint = " or ".join(sorted_valid) if len(sorted_valid) == 2 else ", ".join(sorted_valid)
#         print(f"{FG_RED}Invalid choice. Please enter {hint}.{RESET}\n")
#
#
# def _load_existing_rules() -> list[dict]:
#     """
#     Load & normalize existing rules from default Cisco & PaloAlto sources if present.
#     Returns a unified list in canonical format.
#     """
#     rule_files: list[Path] = []
#     try:
#         if DEFAULT_RULES_CISCO and Path(DEFAULT_RULES_CISCO).exists():
#             rule_files.append(Path(DEFAULT_RULES_CISCO))
#     except Exception:
#         pass
#
#     try:
#         if DEFAULT_RULES_PALOALTO and Path(DEFAULT_RULES_PALOALTO).exists():
#             rule_files.append(Path(DEFAULT_RULES_PALOALTO))
#     except Exception:
#         pass
#
#     if not rule_files:
#         print(f"{FG_RED}Warning: No existing rules found under 'rules/'.{RESET}\n")
#         return []
#
#     return load_and_normalize_existing(rule_files)
#
#
# def _view_rules_menu() -> None:
#     """
#     View rules flow:
#       1) Select site (DC1/DC2/DC3)
#       2) Select vendor (Cisco/PaloAlto)
#       3) Display rules via display.show_rules_by_site_vendor()
#     """
#     # 1) Site selection
#     print(f"\n{FG_LIGHT_YELLOW}Please select a site according to your task:{RESET}")
#     print("1. DC1")
#     print("2. DC2")
#     print("3. DC3\n")
#     s_choice = _read_choice("Enter choice: ", {"1", "2", "3"})
#     site_map = {"1": "DC1", "2": "DC2", "3": "DC3"}
#     site = site_map[s_choice]
#
#     # 2) Vendor selection
#     print(f"\n{FG_LIGHT_YELLOW}Please select a vendor according to your task:{RESET}")
#     print("1. Cisco")
#     print("2. PaloAlto\n")
#     v_choice = _read_choice("Enter choice: ", {"1", "2"})
#     vendor = "cisco" if v_choice == "1" else "paloalto"
#
#     # 3) Display rules through display.py (header will show vendor only there)
#     show_rules_by_site_vendor(site, vendor)
#
#
# def _print_main_menu() -> None:
#     print(f"{FG_LIGHT_YELLOW}Please select an option according to your task:{RESET}")
#     print("1. Input rules")
#     print("2. View rules")
#     print("3. Readme\n")
#
#
# def main():
#     # Show welcome screen first (without header/footer)
#     if WELCOME_ANSI and Path(WELCOME_ANSI).exists():
#         show_logs(WELCOME_ANSI, exit_on_missing=False, suppress_banner=True)
#
#     # MAIN LOOP: Always return to the menu after completing any task
#     while True:
#         _print_main_menu()
#         choice = _read_choice("Enter choice: ", {"1", "2", "3"})
#
#         if choice == "2":
#             _view_rules_menu()
#             # Back to main menu
#             continue
#
#         if choice == "3":
#             # Show README (if exists) WITH header/footer (handled by display.py)
#             if README_ANSI and Path(README_ANSI).exists():
#                 show_logs(README_ANSI, exit_on_missing=False)
#             else:
#                 print(f"{FG_RED}README not found at: {README_ANSI}{RESET}\n")
#             # Back to main menu
#             continue
#
#         # choice == "1": Input Rules -> Collision Check -> Display via display.py
#         new_rules = run_input_flow()  # returns a list of normalized rules (canonical)
#         if not new_rules:
#             print(f"{FG_RED}No new rules were provided.{RESET}\n")
#             continue
#
#         existing_rules = _load_existing_rules()
#
#         # IMPORTANT: display.show_collision_report will compute collisions internally.
#         show_collision_report(existing_rules, new_rules)
#         # Loop continues to main menu
#
#
# if __name__ == "__main__":
#     try:
#         main()
#     except KeyboardInterrupt:
#         print(f"{FG_RED}\nAborted by user.{RESET}\n")
#         try:
#             sys.exit(130)  # standard exit code
#         except SystemExit:
#             pass