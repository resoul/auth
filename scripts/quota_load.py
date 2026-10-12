#!/usr/bin/env python3
"""Run opt-in PostgreSQL quota load tests and save a report without account data."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import uuid

ROOT = Path(__file__).resolve().parents[1]
SCENARIOS = (
    "passkey_ip", "passkey_ref_rotating_ip", "passkey_ipv6_64", "passkey_unknown_ip",
    "passkey_distributed", "email_change_new_address", "email_change_shared_ip",
    "email_change_distributed", "email_verify_rotating_clients",
)


def positive_list(value):
    try:
        workers = [int(part) for part in value.split(",")]
    except ValueError:
        raise argparse.ArgumentTypeError("workers must be comma-separated integers") from None
    if not workers or len(set(workers)) != len(workers) or any(worker < 1 or worker > 256 for worker in workers):
        raise argparse.ArgumentTypeError("workers must be distinct integers from 1 to 256")
    return workers


def parse_result(line):
    if "QUOTA_LOAD " not in line:
        return None
    result = json.loads(line.split("QUOTA_LOAD ", 1)[1])
    if result["admitted"] + result["refused"] != result["requests"]:
        raise ValueError("inconsistent load result")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--requests", type=int, default=1000)
    parser.add_argument("--workers", type=positive_list, default=[1, 8, 32])
    parser.add_argument("--pool", type=int, default=8)
    parser.add_argument("--scenarios", default=",".join(SCENARIOS))
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    scenarios = args.scenarios.split(",")
    if not 100 <= args.requests <= 100000 or not 1 <= args.pool <= 64:
        parser.error("requests must be 100..100000 and pool 1..64")
    if len(set(scenarios)) != len(scenarios) or any(item not in SCENARIOS for item in scenarios):
        parser.error("unknown or duplicate scenario")
    if not os.environ.get("AIRLANCE_AUTH_TEST_DATABASE_URL"):
        parser.error("AIRLANCE_AUTH_TEST_DATABASE_URL is required; use make quota-load")
    output = args.output or ROOT / ".secrets/load" / (datetime.now(timezone.utc).strftime("quota-%Y%m%dT%H%M%SZ-") + uuid.uuid4().hex[:8] + ".json")
    os.umask(0o077)
    output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    # Reserve before doing any work; never overwrite an earlier report.
    try:
        report_file = output.open("x", encoding="utf-8")
    except OSError:
        print("ERROR: report destination unavailable or already exists", file=sys.stderr)
        return 1
    env = dict(os.environ, AIRLANCE_AUTH_QUOTA_LOAD="1", AIRLANCE_AUTH_QUOTA_LOAD_REQUESTS=str(args.requests),
               AIRLANCE_AUTH_QUOTA_LOAD_WORKERS=",".join(map(str, args.workers)), AIRLANCE_AUTH_QUOTA_LOAD_POOL=str(args.pool),
               AIRLANCE_AUTH_QUOTA_LOAD_SCENARIOS=",".join(scenarios))
    command = ["go", "test", "-count=1", "-tags=integration", "-run", "^TestQuotaLoad$", "-v", "-timeout=40m", "./internal/adapter/postgres"]
    results = []
    status = 1
    try:
        with subprocess.Popen(command, cwd=ROOT, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True) as process:
            for line in process.stdout:
                # Do not relay Go/DB diagnostics which could contain connection details.
                result = parse_result(line)
                if result is not None:
                    results.append(result)
                    p95 = result["latency"]["p95_ms"]
                    print(f"{result['scenario']} workers={result['workers']}: admitted={result['admitted']}, "
                          f"refused={result['refused']}, {result['transactions_per_second']:.0f} tx/s, p95={p95:.2f} ms", flush=True)
            status = process.wait()
        if len(results) != len(scenarios) * len(args.workers):
            status = 1
    except (OSError, ValueError):
        status = 1
    finally:
        report = {"created_at": datetime.now(timezone.utc).isoformat(), "passed": status == 0,
                  "measurement": "PostgreSQL limiter transactions; no HTTP, SMTP or WebAuthn verification",
                  "host": {"system": platform.system(), "machine": platform.machine(), "cpu_count": os.cpu_count()},
                  "requests_per_case": args.requests, "pool_connections": args.pool, "results": results}
        with report_file:
            json.dump(report, report_file, indent=2)
            report_file.write("\n")
    print(f"Report: {output}")
    if status:
        print("ERROR: load suite failed or incomplete; rerun the integration test directly for diagnostics", file=sys.stderr)
    return status


if __name__ == "__main__":
    sys.exit(main())
