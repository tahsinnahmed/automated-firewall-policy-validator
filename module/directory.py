# module/directory.py

from pathlib import Path

# ---------------------------
# Project Root
# ---------------------------
PROJECT_ROOT = Path(__file__).resolve().parents[1]

# ---------------------------
# Rules Directory
# ---------------------------
RULES_DIR = PROJECT_ROOT / "rules"
DEFAULT_RULES_CISCO = RULES_DIR / "cisco_firewall_rules.json"
DEFAULT_RULES_PALOALTO = RULES_DIR / "paloalto_firewall_rules.xml"

# ---------------------------
# Guide
# ---------------------------
README_DIR = PROJECT_ROOT / "guide"
README_TXT = README_DIR / "readme.txt"
README_ANSI = README_DIR / "readme.ansi"
WELCOME_ANSI = README_DIR / "welcome.ansi"