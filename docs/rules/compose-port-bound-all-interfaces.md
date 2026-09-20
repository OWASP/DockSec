# compose-port-bound-all-interfaces: Sensitive port bound to all interfaces

**Severity:** HIGH &nbsp;·&nbsp; **Rule ID:** `compose-port-bound-all-interfaces`

## What it catches

A database, cache, broker, or admin port is published with no host IP, so it binds 0.0.0.0.

## Example

```yaml
services:
  db:
    image: postgres:16
    ports:
      - "5432:5432"   # <- reachable from any host that can route to this machine
```

## Why it matters

`"5432:5432"` binds every interface, not just localhost. On a cloud VM or any host with a
public address, the database is now exposed to the internet - a fact that is easy to miss because
the compose file looks the same as a local-only one.

Only ports that indicate a directly attackable service are flagged: databases, caches, brokers,
admin interfaces, and the Docker API. Ordinary web ports are not, because publishing those is
usually the point.

## How to fix it

Bind to localhost, or do not publish the port at all - services on the same compose network
reach each other without publishing:

```yaml
services:
  db:
    image: postgres:16
    expose:
      - "5432"        # reachable by other services, not from the host
    # or, if the host genuinely needs access:
    # ports:
    #   - "127.0.0.1:5432:5432"
```

## When you might keep it

A managed database that is intentionally exposed and protected by a firewall or security
group outside the compose file. The rule cannot see that layer, so suppress it with a
[waiver](../../README.md#ignoring-findings-waivers) recording where the protection lives.

## Suppressing this rule

Permanently, for the whole repository:

```yaml
# .docksec.yml
rules:
  disabled:
    - compose-port-bound-all-interfaces
```

Or per finding, with a reason and an expiry that keeps the decision auditable:

```yaml
# .docksec-ignore.yml
ignores:
  - id: compose-port-bound-all-interfaces
    reason: "why this is accepted here"
    expires: 2027-01-01
```

## References

- Implementation: [`docksec/compose_scanner.py`](../../docksec/compose_scanner.py)
- [All compose rules](README.md) · [Exploit chains](../exploit-chains.md)
