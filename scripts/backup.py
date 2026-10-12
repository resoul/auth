#!/usr/bin/env python3
"""Local Compose PostgreSQL + complete keyring backup; restore only to a new DB."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import uuid

ROOT = Path(__file__).resolve().parents[1]
# The stack to reach: the local one by default; AIRLANCE_AUTH_COMPOSE_FILE names another (deploy/compose.prod.yaml).
COMPOSE_FILE = os.environ.get("AIRLANCE_AUTH_COMPOSE_FILE") or str(ROOT / "deploy/compose.yaml")
COMPOSE = ["docker", "compose", "-f", COMPOSE_FILE, "exec", "-T", "postgres"]
COUNTS_SQL = r"""SELECT format('SELECT %L, count(*) FROM %I.%I;', tablename, schemaname, tablename)
FROM pg_tables WHERE schemaname = 'public' ORDER BY tablename
\gexec
"""


def database_name(value):
    if not re.fullmatch(r"[a-z][a-z0-9_]{0,62}", value) or value in {"postgres", "template0", "template1"}:
        raise ValueError("database name must be a lowercase application name (max 63 characters)")
    return value


def run(args, **kwargs):
    if kwargs.pop("capture_output", False):
        kwargs["stdout"] = subprocess.PIPE
    try:
        return subprocess.run(COMPOSE + args, check=True, stderr=subprocess.PIPE, timeout=300, **kwargs)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        # PostgreSQL errors can include rows/SQL. Never echo diagnostics containing account data.
        raise ValueError(f"{args[0]} failed; check local Compose PostgreSQL and database selection") from None


def psql(database):
    return ["psql", "-X", "-qAt", "-v", "ON_ERROR_STOP=1", "-U", "airlance_auth", "-d", database]


def parse_counts(lines):
    result = {}
    for line in lines:
        name, count = line.strip().split("|")
        if name in result:
            raise ValueError("duplicate table count")
        result[name] = int(count)
    if not result:
        raise ValueError("database has no public tables; migrate it before backup")
    return result


def counts(database):
    return parse_counts(run(psql(database), input=COUNTS_SQL, capture_output=True, text=True).stdout.splitlines())


def strict_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON field")
        result[key] = value
    return result


def read_json(path):
    try:
        return json.loads(path.read_bytes(), object_pairs_hook=strict_object)
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise ValueError("invalid JSON file") from None


def keyring_files(path):
    ring = read_json(path)
    if set(ring) != {"format_version", "otp_hmac", "jwt_signing"} or ring["format_version"] != 1:
        raise ValueError("unsupported keyring schema")
    files = {"keyring.json": path.read_bytes()}
    portable = json.loads(files["keyring.json"])
    index = 0
    for purpose in ("otp_hmac", "jwt_signing"):
        group = ring[purpose]
        if set(group) != {"active_kid", "keys"} or group["active_kid"] not in group["keys"]:
            raise ValueError("invalid keyring group")
        for kid, entry in group["keys"].items():
            if set(entry) != {"key_file"}:
                raise ValueError("invalid keyring key reference")
            original = Path(entry["key_file"])
            if not original.is_absolute():
                original = ROOT / original  # Same working directory as make real / the service.
            if not original.is_file() or original.stat().st_size > 16384:
                raise ValueError("missing or oversized key file")
            relative = f"keys/{index:04d}"
            index += 1
            files[relative] = original.read_bytes()
            portable[purpose]["keys"][kid]["key_file"] = relative
    files["keyring.json"] = (json.dumps(portable, indent=2) + "\n").encode()
    return files


def write_private(path, data):
    with path.open("xb") as handle:
        os.chmod(path, 0o600)
        handle.write(data)


def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def create(source, keyring, output):
    database_name(source)
    material = keyring_files(keyring)
    output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    output.mkdir(mode=0o700)  # Existing backup is never overwritten.
    try:
        (output / "keys").mkdir(mode=0o700)
        for name, data in material.items():
            write_private(output / name, data)
        # Keep the exporting transaction alive until dump AND counts use its snapshot.
        with subprocess.Popen(COMPOSE + psql(source), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                              stderr=subprocess.DEVNULL, text=True) as session:
            try:
                session.stdin.write("SET statement_timeout = '30s';\nBEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;\nSELECT pg_export_snapshot();\n")
                session.stdin.flush()
                snapshot = session.stdout.readline().strip()
                if not re.fullmatch(r"[0-9A-Fa-f]+-[0-9A-Fa-f]+-[0-9]+", snapshot):
                    raise ValueError("could not export PostgreSQL snapshot")
                with (output / "database.dump").open("xb") as dump:
                    os.chmod(output / "database.dump", 0o600)
                    run(["pg_dump", "-U", "airlance_auth", "-d", source, "--format=custom", "--no-owner", "--no-acl", "--lock-wait-timeout=30s",
                         "--snapshot=" + snapshot], stdout=dump)
                session.stdin.write(COUNTS_SQL + "\\echo COUNTS_END\n")
                session.stdin.flush()
                lines = []
                while True:
                    line = session.stdout.readline()
                    if not line:
                        raise ValueError("snapshot table count failed")
                    if line.strip() == "COUNTS_END":
                        break
                    lines.append(line)
                expected = parse_counts(lines)
                session.stdin.write("ROLLBACK;\n\\q\n")
                session.stdin.flush()
                if session.wait(timeout=30):
                    raise ValueError("snapshot transaction failed")
            finally:
                if session.poll() is None:
                    session.kill()
                    session.wait()
        if keyring_files(keyring) != material:
            raise ValueError("keyring changed during backup; repeat after rotation finishes")
        version = run(["pg_dump", "--version"], capture_output=True, text=True).stdout.strip()
        manifest = {"format_version": 1, "created_at": datetime.now(timezone.utc).isoformat(),
                    "source_database": source, "pg_dump_version": version, "table_counts": expected,
                    "sha256": {name: digest(output / name) for name in ["database.dump", *material]}}
        write_private(output / "manifest.json", (json.dumps(manifest, indent=2) + "\n").encode())
    except BaseException:
        shutil.rmtree(output)
        raise
    return output


def validate(bundle):
    if bundle.is_symlink() or (bundle / "manifest.json").is_symlink():
        raise ValueError("backup symlinks are not allowed")
    manifest = read_json(bundle / "manifest.json")
    if manifest.get("format_version") != 1:
        raise ValueError("unsupported backup version")
    database_name(manifest["source_database"])
    expected_counts = manifest["table_counts"]
    if not isinstance(expected_counts, dict) or not expected_counts or any(
            not isinstance(name, str) or type(value) is not int or value < 0
            for name, value in expected_counts.items()):
        raise ValueError("invalid backup table counts")
    hashes = manifest["sha256"]
    if not {"database.dump", "keyring.json"}.issubset(hashes):
        raise ValueError("backup missing database or keyring")
    for name, expected in hashes.items():
        if name not in {"database.dump", "keyring.json"} and not re.fullmatch(r"keys/[0-9]{4}", name):
            raise ValueError("unsafe backup filename")
        path = bundle / name
        if path.is_symlink() or path.parent.is_symlink() or not path.is_file() or digest(path) != expected:
            raise ValueError("backup checksum mismatch or missing file")
    ring = read_json(bundle / "keyring.json")
    if set(ring) != {"format_version", "otp_hmac", "jwt_signing"} or ring["format_version"] != 1:
        raise ValueError("unsupported backup keyring schema")
    for purpose in ("otp_hmac", "jwt_signing"):
        group = ring[purpose]
        if set(group) != {"active_kid", "keys"} or group["active_kid"] not in group["keys"]:
            raise ValueError("missing active key")
        for entry in group["keys"].values():
            if set(entry) != {"key_file"} or not re.fullmatch(r"keys/[0-9]{4}", entry["key_file"]) or entry["key_file"] not in hashes:
                raise ValueError("keyring reference outside backup")
    return manifest, ring


def restore(bundle, target, destination):
    database_name(target)
    manifest, ring = validate(bundle)
    if target == manifest["source_database"]:
        raise ValueError("restore target must differ from source database")
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    destination.mkdir(mode=0o700)
    created = False
    try:
        # createdb refuses an existing target. Never clean, overwrite, or migrate the source.
        run(["createdb", "-U", "airlance_auth", "--maintenance-db=postgres", target], capture_output=True)
        created = True
        with (bundle / "database.dump").open("rb") as dump:
            run(["pg_restore", "-U", "airlance_auth", "-d", target, "--single-transaction", "--exit-on-error",
                 "--no-owner", "--no-acl"], stdin=dump, stdout=subprocess.DEVNULL)
        if counts(target) != manifest["table_counts"]:
            raise ValueError("restored table counts differ from the backup snapshot")
        (destination / "keys").mkdir(mode=0o700)
        for name in manifest["sha256"]:
            if name.startswith("keys/"):
                write_private(destination / name, (bundle / name).read_bytes())
        for purpose in ("otp_hmac", "jwt_signing"):
            for entry in ring[purpose]["keys"].values():
                entry["key_file"] = str(destination / entry["key_file"])
        write_private(destination / "keyring.json", (json.dumps(ring, indent=2) + "\n").encode())
    except BaseException:
        if created:
            run(["dropdb", "-U", "airlance_auth", "--maintenance-db=postgres", target], capture_output=True)
        shutil.rmtree(destination)
        raise
    return manifest


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    backup = commands.add_parser("create")
    backup.add_argument("--source-db", default="airlance_auth")
    backup.add_argument("--keyring", type=Path, default=ROOT / ".secrets/real/keyring.json")
    backup.add_argument("--output", type=Path)
    for command in ("restore", "check"):
        child = commands.add_parser(command)
        child.add_argument("--backup", type=Path, required=True)
        if command == "restore":
            child.add_argument("--database", required=True)
            child.add_argument("--keys-output", type=Path)
    args = parser.parse_args()
    try:
        if args.command == "create":
            output = args.output or ROOT / ".secrets/backups" / (datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8])
            result = create(args.source_db, args.keyring.resolve(), output.resolve())
            print(f"Backup saved: {result}")
        else:
            target = args.database if args.command == "restore" else "airlance_auth_check_" + uuid.uuid4().hex
            destination = (getattr(args, "keys_output", None) or ROOT / ".secrets/restored" / target).resolve()
            manifest = restore(args.backup.resolve(), target, destination)
            if args.command == "check":
                try:
                    run(["dropdb", "-U", "airlance_auth", "--maintenance-db=postgres", target], capture_output=True)
                finally:
                    shutil.rmtree(destination)
                print(f"Restore check passed: {len(manifest['table_counts'])} tables; snapshot counts and file checksums match; test copy removed")
            else:
                print(f"Restored into new local Compose database: {target}\nKeyring: {destination / 'keyring.json'}\nService was not started.")
        return 0
    except (ValueError, OSError, KeyError, TypeError, subprocess.TimeoutExpired) as err:
        message = str(err) if isinstance(err, ValueError) else "backup operation failed; check files and Docker availability"
        print("ERROR: " + message, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
