from __future__ import annotations

import argparse
import ipaddress
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path


def split_endpoint(value: str) -> tuple[str, str]:
    """Split ss local endpoint into host and port; supports bracketed IPv6."""
    value = value.strip()
    if value.startswith("[") and "]:" in value:
        host, port = value[1:].rsplit("]:", 1)
        return host, port
    if ":" not in value:
        return value, ""
    host, port = value.rsplit(":", 1)
    return host, port


def classify_host(host: str) -> str:
    host = host.strip()
    if host in ("*", "0.0.0.0", "::", "[::]"):
        return "wildcard"
    normalized = host.split("%", 1)[0]
    try:
        address = ipaddress.ip_address(normalized)
    except ValueError:
        return "hostname_or_unknown"
    if address.is_loopback:
        return "loopback"
    if address.is_link_local:
        return "link_local"
    if address.is_private:
        return "private"
    if address.is_unspecified:
        return "wildcard"
    if address.is_global:
        return "public"
    return "reserved_or_special"


def parse_ss_output(text: str) -> dict:
    entries = []
    malformed = 0
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.lower().startswith("netid "):
            continue
        # Split into the six standard ss columns; process details remain intact.
        parts = re.split(r"\s+", line, maxsplit=5)
        if len(parts) < 5:
            malformed += 1
            continue

        netid, state, recv_q, send_q, local, peer = parts[:6] if len(parts) >= 6 else (*parts, "")
        host, port = split_endpoint(local)
        if not host or not port:
            malformed += 1
            continue

        entries.append({
            "protocol": netid.lower(),
            "state": state.upper(),
            "recv_queue": recv_q,
            "send_queue": send_q,
            "local_address": local,
            "local_host": host,
            "local_port": port,
            "peer_address": peer,
            "bind_scope": classify_host(host),
            "wildcard_bind": classify_host(host) == "wildcard",
            "process": parts[5] if len(parts) >= 6 else None,
        })

    return {
        "socket_count": len(entries),
        "wildcard_bind_count": sum(item["wildcard_bind"] for item in entries),
        "sockets": entries,
        "malformed_lines_ignored": malformed,
        "note": "Local inventory only. Wildcard binds need contextual review; no remote probing or configuration changes occur.",
    }


def collect_local() -> str:
    executable = shutil.which("ss")
    if not executable:
        raise FileNotFoundError("The 'ss' command was not found. Install iproute2 or use --input with saved ss output.")
    result = subprocess.run(
        [executable, "-lntup"],
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "ss command failed").strip()
        raise RuntimeError(detail)
    return result.stdout


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Inventory local Linux TCP/UDP listening sockets using ss; no remote scans are performed."
    )
    parser.add_argument("--input", help="Saved output from 'ss -lntup'. Omit to collect a local inventory.")
    parser.add_argument("--output", help="Optional JSON report output path.")
    args = parser.parse_args()

    try:
        raw = Path(args.input).read_text(encoding="utf-8", errors="replace") if args.input else collect_local()
    except (OSError, RuntimeError) as exc:
        print(json.dumps({"error": str(exc)}, indent=2), file=sys.stderr)
        return 2

    report = parse_ss_output(raw)
    rendered = json.dumps(report, indent=2)
    if args.output:
        Path(args.output).write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
