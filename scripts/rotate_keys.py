#!/usr/bin/env python3
"""Rotate the keys of the keyring file without hand edits.

    rotate_keys.py status
    rotate_keys.py add otp|jwt
    rotate_keys.py activate otp|jwt KID [--cache-wait 10m]
    rotate_keys.py public-only KID
    rotate_keys.py retire otp|jwt KID [--access-ttl 1h] [--compromised] [--delete-file]

Every command changes the keyring file (AIRLANCE_AUTH_KEYRING_FILE or --keyring) atomically, keeps the
previous one as <file>.prev and appends what happened to <file>.history, which also remembers every
kid ever used: a kid is never given out twice. Nothing here restarts the service: a change takes
effect at the next start, and the runbook says when to restart. Key material is never printed.

The OTP check needs the database to know whether a flow still waits for an old key; it reads the
local Compose PostgreSQL like scripts/backup.py does (--database, --schema). Where there is no Docker
(a CI job with a PostgreSQL service), AIRLANCE_AUTH_PSQL_URL names the database and psql reaches it
directly; --database is then ignored.
"""
import argparse
import base64
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from urllib.parse import unquote, urlsplit

from backup import strict_object  # one strict JSON reader for the keyring in every script

ROOT = Path(__file__).resolve().parents[1]
# The stack to reach: the local one by default; AIRLANCE_AUTH_COMPOSE_FILE names another (deploy/compose.prod.yaml).
COMPOSE_FILE = os.environ.get("AIRLANCE_AUTH_COMPOSE_FILE") or str(ROOT / "deploy/compose.yaml")
COMPOSE = ["docker", "compose", "-f", COMPOSE_FILE, "exec", "-T", "postgres"]
PURPOSES = {"otp": "otp_hmac", "jwt": "jwt_signing", "oidc": "oidc_signing"}
PREFIX = {"otp": "otp", "jwt": "sign", "oidc": "oidc"}
# The purposes whose keys are PEM signing keys: the /v1 API signs with ES256, the OpenID Provider with RS256.
SIGNING = ("jwt", "oidc")
# oidc_signing is optional: a service without the OpenID Provider has no such group.
REQUIRED_GROUPS = {"otp_hmac", "jwt_signing"}
KID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
# The access token lifetime is at most an hour (internal/config); this is the safe default for retiring a JWT key.
DEFAULT_ACCESS_TTL = "1h"
# A verifier that cached the key set before the new key was published must refresh it before the key signs.
DEFAULT_CACHE_WAIT = "10m"
CLOCK_SKEW = timedelta(seconds=60)


class Refusal(Exception):
    """An expected refusal: the message is safe to print."""


def now():
    return datetime.now(timezone.utc)


def duration(text):
    match = re.fullmatch(r"(\d+)([smh])", text)
    if not match:
        raise argparse.ArgumentTypeError("a duration looks like 30s, 10m or 1h")
    return timedelta(**{{"s": "seconds", "m": "minutes", "h": "hours"}[match.group(2)]: int(match.group(1))})


def read_ring(path):
    try:
        ring = json.loads(path.read_bytes(), object_pairs_hook=strict_object)
    except (OSError, json.JSONDecodeError, UnicodeDecodeError, ValueError):
        raise Refusal("the keyring file is missing or is not valid JSON") from None
    if not isinstance(ring, dict) or not {"format_version", *REQUIRED_GROUPS} <= set(ring) <= {"format_version", *PURPOSES.values()} or ring["format_version"] != 1:
        raise Refusal("unsupported keyring schema")
    for group in (ring[name] for name in PURPOSES.values() if name in ring):
        if not isinstance(group, dict) or set(group) != {"active_kid", "keys"} or group["active_kid"] not in group["keys"]:
            raise Refusal("invalid keyring group")
        for entry in group["keys"].values():
            if not isinstance(entry, dict) or set(entry) != {"key_file"}:
                raise Refusal("invalid keyring key reference")
    return ring


def resolve(reference):
    # The service resolves a relative path from its working directory, which is the repository root here.
    path = Path(reference)
    return path if path.is_absolute() else ROOT / path


def write_atomically(path, data, mode=0o600):
    descriptor, temporary = tempfile.mkstemp(dir=str(path.parent), prefix=path.name + ".")
    try:
        os.chmod(temporary, mode)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def save_ring(path, ring):
    previous = path.read_bytes()
    write_atomically(path.with_name(path.name + ".prev"), previous)
    write_atomically(path, (json.dumps(ring, indent=2) + "\n").encode())


class History:
    """Append-only record of key events: what was ever used, and when a key stopped being active."""

    def __init__(self, ring_path):
        self.path = ring_path.with_name(ring_path.name + ".history")

    def events(self):
        if not self.path.exists():
            return []
        try:
            return [json.loads(line) for line in self.path.read_text().splitlines() if line.strip()]
        except ValueError:
            raise Refusal("the key history file is damaged; restore it from a backup") from None

    def used(self, purpose):
        return {event["kid"] for event in self.events() if event["purpose"] == purpose}

    def when(self, purpose, kid, event):
        times = [datetime.fromisoformat(e["at"]) for e in self.events() if (e["purpose"], e["kid"], e["event"]) == (purpose, kid, event)]
        return max(times) if times else None

    def record(self, purpose, kid, event):
        line = json.dumps({"purpose": purpose, "kid": kid, "event": event, "at": now().isoformat()}) + "\n"
        existing = self.path.read_bytes() if self.path.exists() else b""
        write_atomically(self.path, existing + line.encode())


class Compose:
    """The local PostgreSQL of deploy/compose.yaml, reached the way scripts/backup.py reaches it."""

    def __init__(self, database="airlance_auth", schema="public"):
        if not re.fullmatch(r"[a-z][a-z0-9_]{0,62}", database) or not re.fullmatch(r"[a-z][a-z0-9_]{0,62}", schema):
            raise Refusal("database and schema must be lowercase names")
        self.database, self.schema = database, schema

    def command(self, kid):
        """The psql command and its environment: through the Compose service, or straight to AIRLANCE_AUTH_PSQL_URL.
        The URL goes to psql through PG* variables, so a password never shows in the process list."""
        psql = ["psql", "-X", "-qAt", "-v", "ON_ERROR_STOP=1", "-v", "kid=" + kid]
        url = os.environ.get("AIRLANCE_AUTH_PSQL_URL")
        if not url:
            return COMPOSE + psql + ["-U", "airlance_auth", "-d", self.database], None
        parts = urlsplit(url)
        env = dict(os.environ, PGHOST=parts.hostname or "", PGPORT=str(parts.port or 5432), PGUSER=unquote(parts.username or ""),
                   PGDATABASE=parts.path.lstrip("/"))
        if parts.password is not None:
            env["PGPASSWORD"] = unquote(parts.password)
        if "sslmode=" in parts.query:
            env["PGSSLMODE"] = dict(q.split("=", 1) for q in parts.query.split("&") if q.startswith("sslmode="))["sslmode"]
        return psql, env

    def run(self, sql, kid):
        command, env = self.command(kid)
        try:
            done = subprocess.run(command, input=f"SET search_path TO {self.schema};\n{sql}", text=True, check=True, env=env,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
            # PostgreSQL errors can quote rows; say nothing about them.
            raise Refusal("the database check failed; is `make up` running, and are --database and --schema right?") from None
        return [line for line in done.stdout.splitlines() if line and line != "SET"]

    def waiting_flows(self, kid):
        """Flows that can still be proven and need the OTP key kid."""
        rows = self.run("SELECT count(*) FROM auth_flows WHERE key_id = :'kid' AND state = 'pending' AND expires_at > now();", kid)
        return int(rows[-1])

    def expire_flows(self, kid):
        """Close every flow that waits for the key, so none of its codes can be proven or sent any more."""
        rows = self.run("WITH closed AS (UPDATE auth_flows SET state = 'expired', salt = NULL WHERE key_id = :'kid' AND state = 'pending' "
                        "RETURNING 1) SELECT count(*) FROM closed;", kid)
        return int(rows[-1])


def kid_argument(value):
    if not KID.fullmatch(value):
        raise argparse.ArgumentTypeError("a kid is 1 to 64 letters, digits, dots, dashes or underscores")
    return value


def group_of(ring, purpose):
    if PURPOSES[purpose] not in ring:
        raise Refusal(f"this keyring has no {PURPOSES[purpose]} keys: the {purpose} purpose is not in use")
    return ring[PURPOSES[purpose]]


def key_path(ring, purpose, kid):
    group = group_of(ring, purpose)
    if kid not in group["keys"]:
        raise Refusal(f"{purpose} key {kid} is not in the keyring")
    return resolve(group["keys"][kid]["key_file"])


def check_private_jwt(path):
    text = path.read_text(errors="replace")
    if "BEGIN PRIVATE KEY" not in text:
        raise Refusal("this key has no private part; only a key with one can sign")


def check_otp_file(path):
    try:
        raw = base64.b64decode(path.read_text().strip(), validate=True)
    except (ValueError, OSError):
        raise Refusal("the key file is not base64") from None
    if len(raw) != 32:
        raise Refusal("an OTP key is 32 random bytes")


def new_kid(ring, history, purpose, database):
    taken = set(group_of(ring, purpose)["keys"]) | history.used(purpose)
    stamp = now().strftime("%Y%m%d")
    for n in range(1, 100):
        kid = f"{PREFIX[purpose]}-{stamp}" + ("" if n == 1 else f"-{n}")
        if kid in taken:
            continue
        if purpose == "otp" and database is not None:
            # A kid left in old flows would make them look like they use the new key.
            if database.run("SELECT count(*) FROM auth_flows WHERE key_id = :'kid';", kid)[-1] != "0":
                continue
        return kid
    raise Refusal("no free kid for today")


def openssl(*args, data=None):
    try:
        return subprocess.run(["openssl", *args], input=data, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30).stdout
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
        raise Refusal("openssl failed; is it installed?") from None


def reference_for(ring, purpose, path):
    """Write the path in the form the active key uses: relative to the repository, or absolute."""
    active = group_of(ring, purpose)["keys"][group_of(ring, purpose)["active_kid"]]["key_file"]
    if Path(active).is_absolute():
        return str(path)
    return os.path.relpath(path, ROOT)


def cmd_status(args, ring, history, database):
    for purpose in (p for p in PURPOSES if PURPOSES[p] in ring):
        group = group_of(ring, purpose)
        print(f"{purpose}: active {group['active_kid']}")
        for kid, entry in group["keys"].items():
            path = resolve(entry["key_file"])
            line = [f"  {kid}", "active" if kid == group["active_kid"] else "not active"]
            line.append("file ok" if path.is_file() else "FILE MISSING")
            if purpose in SIGNING and path.is_file():
                line.append("private" if "BEGIN PRIVATE KEY" in path.read_text(errors="replace") else "public only")
            added, left = history.when(purpose, kid, "added"), history.when(purpose, kid, "deactivated")
            if added:
                line.append("added " + added.strftime("%Y-%m-%d %H:%M UTC"))
            if left:
                line.append("stopped signing " + left.strftime("%Y-%m-%d %H:%M UTC"))
            if purpose == "otp" and database is not None:
                try:
                    line.append(f"{database.waiting_flows(kid)} flows wait for it")
                except Refusal:
                    line.append("flows waiting for it: unknown, the database is not reachable")
            print(" | ".join(line))


def cmd_add(args, ring, history, database):
    purpose = args.purpose
    kid = new_kid(ring, history, purpose, database)
    active_file = key_path(ring, purpose, group_of(ring, purpose)["active_kid"])
    path = active_file.parent / (kid + (".pem" if purpose in SIGNING else ""))
    if purpose == "otp":
        material = (base64.b64encode(os.urandom(32)) + b"\n")
    elif purpose == "oidc":
        material = openssl("genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:3072")
    else:
        material = openssl("genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256")
    with path.open("xb") as handle:  # never overwrites an existing file
        os.chmod(path, 0o600)
        handle.write(material)
    group_of(ring, purpose)["keys"][kid] = {"key_file": reference_for(ring, purpose, path)}
    save_ring(args.keyring, ring)
    history.record(purpose, kid, "added")
    print(f"added {purpose} key {kid} (not active). Restart the service so that it is loaded"
          + (" and published in the key set." if purpose in SIGNING else "."))


def cmd_activate(args, ring, history, database):
    purpose, kid = args.purpose, args.kid
    group = group_of(ring, purpose)
    path = key_path(ring, purpose, kid)
    if group["active_kid"] == kid:
        raise Refusal(f"{kid} is already active")
    if purpose in SIGNING:
        check_private_jwt(path)
        added = history.when(purpose, kid, "added")
        if added is None and not args.assume_published:
            raise Refusal("this key was not added by this script: pass --assume-published once you are sure verifiers have seen it")
        if added is not None and now() - added < args.cache_wait and not args.assume_published:
            wait = (args.cache_wait - (now() - added)).total_seconds()
            raise Refusal(f"wait {int(wait)} more seconds: verifiers may still hold a key set without {kid}")
    else:
        check_otp_file(path)
    previous = group["active_kid"]
    group["active_kid"] = kid
    save_ring(args.keyring, ring)
    history.record(purpose, previous, "deactivated")
    history.record(purpose, kid, "activated")
    print(f"{kid} is now the active {purpose} key (was {previous}). Restart the service to start using it.")


def cmd_public_only(args, ring, history, database):
    kid, purpose = args.kid, args.purpose
    group = group_of(ring, purpose)
    path = key_path(ring, purpose, kid)
    if group["active_kid"] == kid:
        raise Refusal("the active key signs: it keeps its private part")
    check_private_jwt(path)
    public = openssl("pkey", "-pubout", data=path.read_bytes())
    write_atomically(path, public)
    print(f"{kid} keeps only its public part now: it still verifies tokens it signed and signs nothing.")


def cmd_retire(args, ring, history, database):
    purpose, kid = args.purpose, args.kid
    group = group_of(ring, purpose)
    path = key_path(ring, purpose, kid)
    if group["active_kid"] == kid:
        raise Refusal("the active key cannot be retired: activate another one first")
    if purpose in SIGNING and not args.compromised:
        left = history.when(purpose, kid, "deactivated")
        if left is None and not args.assume_elapsed:
            raise Refusal("this key was not deactivated by this script: pass --assume-elapsed once its tokens have expired")
        if left is not None and not args.assume_elapsed and now() - left < args.access_ttl + CLOCK_SKEW:
            wait = (args.access_ttl + CLOCK_SKEW - (now() - left)).total_seconds()
            raise Refusal(f"wait {int(wait)} more seconds: tokens signed with {kid} can still be valid")
    if purpose == "otp":
        if database is None:
            raise Refusal("the OTP check needs the database")
        if args.compromised:
            closed = database.expire_flows(kid)
            print(f"closed {closed} open flows that waited for {kid}: their codes are void, those users start again")
        elif database.waiting_flows(kid):
            raise Refusal(f"{database.waiting_flows(kid)} flows still wait for {kid}; wait for them to end (10 minutes) or use --compromised")
    del group["keys"][kid]
    save_ring(args.keyring, ring)
    history.record(purpose, kid, "retired")
    deleted = args.delete_file or args.compromised
    if deleted:
        try:
            path.unlink()
        except FileNotFoundError:
            pass
    print(f"{kid} is out of the keyring" + ("; its file is deleted." if deleted else f"; delete {path} when no backup restore needs it.")
          + " Restart the service.")


def build_parser():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0], formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--keyring", type=Path, default=os.environ.get("AIRLANCE_AUTH_KEYRING_FILE"), help="default: AIRLANCE_AUTH_KEYRING_FILE")
    parser.add_argument("--database", default="airlance_auth")
    parser.add_argument("--schema", default="public")
    parser.add_argument("--no-database", action="store_true", help="skip every database check (a refusal for OTP retire)")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("status")
    add = sub.add_parser("add")
    add.add_argument("purpose", choices=PURPOSES)
    activate = sub.add_parser("activate")
    activate.add_argument("purpose", choices=PURPOSES)
    activate.add_argument("kid", type=kid_argument)
    activate.add_argument("--cache-wait", type=duration, default=duration(DEFAULT_CACHE_WAIT))
    activate.add_argument("--assume-published", action="store_true")
    public = sub.add_parser("public-only")
    public.add_argument("kid", type=kid_argument)
    public.add_argument("--purpose", choices=SIGNING, default="jwt", help="the signing purpose of the key (default: jwt)")
    retire = sub.add_parser("retire")
    retire.add_argument("purpose", choices=PURPOSES)
    retire.add_argument("kid", type=kid_argument)
    retire.add_argument("--access-ttl", type=duration, default=duration(DEFAULT_ACCESS_TTL), help="the service's AIRLANCE_AUTH_ACCESS_TTL")
    retire.add_argument("--assume-elapsed", action="store_true")
    retire.add_argument("--compromised", action="store_true", help="remove now: no waiting, and open OTP flows are closed")
    retire.add_argument("--delete-file", action="store_true")
    return parser


COMMANDS = {"status": cmd_status, "add": cmd_add, "activate": cmd_activate, "public-only": cmd_public_only, "retire": cmd_retire}


def main(argv=None):
    args = build_parser().parse_args(argv)
    if args.keyring is None:
        print("keyring: set AIRLANCE_AUTH_KEYRING_FILE or pass --keyring", file=sys.stderr)
        return 2
    args.keyring = Path(args.keyring)
    try:
        ring = read_ring(args.keyring)
        database = None if args.no_database else Compose(args.database, args.schema)
        COMMANDS[args.command](args, ring, History(args.keyring), database)
    except Refusal as refusal:
        print(f"keyring: {refusal}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
