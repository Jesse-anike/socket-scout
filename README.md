# SOCKET SCOUT — Local Listening Socket Inventory

A defensive local inventory tool for Linux listening TCP/UDP sockets. It reads the output of `ss -lntup` or parses a saved export, then classifies local bind addresses to help administrators identify services listening on wildcard interfaces.

## Features
- Inventories TCP and UDP listening/unconnected sockets from `ss`.
- Highlights wildcard binds such as `0.0.0.0`, `::`, and `*`.
- Distinguishes loopback, private, link-local, public, and unclassified local addresses.
- Includes the reported process field when available.
- Supports saved `ss` output for offline analysis.
- Does not scan remote hosts or change firewall/service configuration.

## Requirements
- Python 3.10+
- Linux with `ss` (iproute2) for live local inventory.
- Python standard library only.

## Run a local inventory
```bash
python main.py
```

Run against saved output:
```bash
ss -lntup > sockets.txt
python main.py --input sockets.txt
```

Save a JSON report:
```bash
python main.py --output socket-inventory.json
```

## Tests
```bash
python -m unittest discover -s tests -v
python main.py --help
```

## Security and privacy
Run only on systems you own or are authorized to administer. The process column may include process names and PIDs; review and redact reports before sharing. A wildcard bind is a review signal, not proof of internet exposure: host firewall rules, cloud security groups, NAT, routing, and network namespaces affect reachability. This tool does not probe any address, kill processes, or update security controls.

## Portfolio context
Built for Anike-Moses Melie Jesse's defensive cybersecurity portfolio, demonstrating Linux network service visibility, TCP/UDP fundamentals, address classification, subprocess safety, and JSON-based security reporting.
