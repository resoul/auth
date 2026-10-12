#!/usr/bin/env python3
"""Run the HTTPS browser example with real SMTP settings from .env."""

import argparse
import os
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parent.parent
REQUIRED_SMTP = (
    "AIRLANCE_AUTH_SMTP_ADDR", "AIRLANCE_AUTH_SMTP_USERNAME", "AIRLANCE_AUTH_SMTP_PASSWORD",
    "AIRLANCE_AUTH_MAIL_FROM",
)


def load_env(path):
    """Read literal dotenv assignments; never evaluate commands or expand variables."""
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError):
        raise ValueError("cannot read the env file") from None
    values = {}
    for number, line in enumerate(lines, 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        match = re.fullmatch(r"(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)", line)
        if not match:
            raise ValueError("invalid env assignment at line %d" % number)
        key, value = match.groups()
        if value.startswith(("'", '"')):
            quoted = re.fullmatch(r"(['\"])(.*?)\1\s*(?:#.*)?", value)
            if not quoted:
                raise ValueError("invalid quoted env value at line %d" % number)
            value = quoted.group(2)
        else:
            value = re.split(r"\s+#", value, maxsplit=1)[0].rstrip()
        values[key] = value
    return values


def real_environment(path, inherited):
    """Apply project settings only, retaining the ordinary environment for child tools."""
    env = dict(inherited)
    for key, value in load_env(path).items():
        if key.startswith("AIRLANCE_AUTH_") or key == "CLOUDFLARED_TUNNEL_TOKEN":
            env[key] = value
    for key in REQUIRED_SMTP:
        if not env.get(key, "").strip():
            raise ValueError("%s is required for real SMTP" % key)
    env["AIRLANCE_AUTH_SMTP_TLS"] = env.get("AIRLANCE_AUTH_SMTP_TLS") or "starttls"
    if env["AIRLANCE_AUTH_SMTP_TLS"] not in ("starttls", "tls"):
        raise ValueError("AIRLANCE_AUTH_SMTP_TLS must be starttls or tls for real SMTP")
    return env


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--env-file", type=Path, default=ROOT / ".env")
    parser.add_argument("--check", action="store_true", help="validate settings without starting services or sending mail")
    args = parser.parse_args()
    try:
        env = real_environment(args.env_file, os.environ)
    except ValueError as err:
        sys.exit("real SMTP: %s" % err)
    if args.check:
        print("Real SMTP settings present; TLS enabled. No connection or delivery attempted.")
        return
    # The tunnel prepares the same HTTPS origin for page, cookies and passkeys. It keeps
    # the API on loopback and uses the local database unless explicitly configured.
    os.execve(str(ROOT / "scripts" / "tunnel.sh"), ["tunnel.sh", "--real-smtp"], env)


if __name__ == "__main__":
    main()
