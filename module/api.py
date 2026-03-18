# module/api.py

import os
import json
import base64
import urllib.request
import urllib.error
from dotenv import load_dotenv
from pathlib import Path
from urllib.parse import urlparse

RESET = "\033[0m"
FG_RED = "\033[31m"
FG_GREEN = "\033[32m"
FG_CYAN = "\033[36m"


# ------------------------------
# Load .env
# ------------------------------
def _load_env():
    base = Path(__file__).resolve().parent.parent
    env_path = base / "rules" / ".env"
    load_dotenv(dotenv_path=env_path, override=False)


# ------------------------------
# Helper
# ------------------------------
def _extract_origin(url: str) -> str:
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}" if p.scheme and p.netloc else ""


def _build_headers(url, method, auth_type, username, password):
    headers = {
        "Accept": "application/json",
        "User-Agent": "Mozilla/5.0"
    }

    origin = _extract_origin(url)
    if origin:
        headers["Origin"] = origin
        headers["Referer"] = url

    if method in {"POST", "GET", "PUT", "PATCH"}:
        headers["Content-Type"] = "application/json"

    if auth_type == "basic":
        token = base64.b64encode(f"{username}:{password}".encode()).decode()
        headers["Authorization"] = f"Basic {token}"

    return headers


# ------------------------------
# Main Function
# ------------------------------
def run_rest_api_login() -> None:
    _load_env()

    url = os.getenv("API_URL", "").strip()
    username = os.getenv("API_USERNAME", "").strip()
    password = os.getenv("API_PASSWORD", "").strip()

    method = os.getenv("HTTP_METHOD", "POST").strip().upper()
    auth_type = os.getenv("AUTH_TYPE", "body").strip().lower()

    username_field = os.getenv("USERNAME_FIELD", "username").strip()
    password_field = os.getenv("PASSWORD_FIELD", "password").strip()

    extra_raw = os.getenv("EXTRA_PAYLOAD", "{}")
    try:
        extra_payload = json.loads(extra_raw)
    except:
        extra_payload = {}

    if not url or not username or not password:
        print(f"{FG_RED}Missing API_URL/API_USERNAME/API_PASSWORD in .env{RESET}")
        return

    print(f"\n{FG_CYAN}Calling REST API...{RESET}\n")

    # Build body (only for non-basic POST/PUT/PATCH)
    if method in {"POST", "PUT", "PATCH"} and auth_type != "basic":
        body = {username_field: username, password_field: password}
        body.update(extra_payload)
        data = json.dumps(body).encode()
    else:
        data = None

    headers = _build_headers(url, method, auth_type, username, password)
    request = urllib.request.Request(url=url, data=data, method=method, headers=headers)

    try:
        with urllib.request.urlopen(request, timeout=30) as resp:
            charset = resp.headers.get_content_charset() or "utf-8"
            response_text = resp.read().decode(charset, errors="replace")
    except urllib.error.HTTPError as e:
        print(f"{FG_RED}HTTPError {e.code}: {e.reason}{RESET}")
        try:
            print(e.read().decode("utf-8", errors="replace"))
        except:
            pass
        return
    except Exception as e:
        print(f"{FG_RED}Error: {e}{RESET}")
        return

    # Try JSON
    try:
        parsed = json.loads(response_text)
        print(json.dumps(parsed, indent=2), "\n")
    except:
        print(f"{FG_GREEN}Response (non-JSON):{RESET}")
        print(response_text)