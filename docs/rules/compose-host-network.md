# compose-host-network: Host network mode

**Severity:** CRITICAL &nbsp;·&nbsp; **Rule ID:** `compose-host-network`

## What it catches

A service sets `network_mode: host`.

## Example

```yaml
services:
  api:
    image: myapi
    network_mode: host   # <- shares the host network namespace
```

## Why it matters

With host networking the container shares the host's network namespace outright. Every port
the process opens is bound on the host, including ports it opens dynamically and ones you never
published. Network isolation between services is gone, and a service that binds 0.0.0.0 inside the
container is now doing so on the host's real interfaces.

## How to fix it

Use a defined network and publish only the ports required:

```yaml
services:
  api:
    image: myapi
    ports:
      - "127.0.0.1:8080:8080"
    networks:
      - backend
networks:
  backend:
```

## When you might keep it

A service that must observe or manipulate host traffic - a network monitor, a VPN
endpoint, or a service needing very high packet throughput where the NAT layer is a measured
bottleneck. Document why, because the next reader will assume it is an accident.

## Suppressing this rule

Permanently, for the whole repository:

```yaml
# .docksec.yml
rules:
  disabled:
    - compose-host-network
```

Or per finding, with a reason and an expiry that keeps the decision auditable:

```yaml
# .docksec-ignore.yml
ignores:
  - id: compose-host-network
    reason: "why this is accepted here"
    expires: 2027-01-01
```

## References

- Implementation: [`docksec/compose_scanner.py`](../../docksec/compose_scanner.py)
- [All compose rules](README.md) · [Exploit chains](../exploit-chains.md)
