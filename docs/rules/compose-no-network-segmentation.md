# compose-no-network-segmentation: No network segmentation

**Severity:** LOW &nbsp;·&nbsp; **Rule ID:** `compose-no-network-segmentation`

## What it catches

No service defines a `networks:` key, so every service sits on the default network.

## Example

```yaml
services:
  web:
    image: nginx
    ports: ["80:80"]
  db:
    image: postgres   # <- same default network as web
```

## Why it matters

Compose puts every service on one default network when none is specified, so any service can
reach any other. On its own this is minor. It becomes the connectivity half of a
[lateral movement chain](../exploit-chains.md): an internet-facing service that is compromised can
then reach a database it never needed to talk to.

## How to fix it

Define networks and connect only the services that must communicate:

```yaml
services:
  web:
    image: nginx
    networks: [frontend]
  api:
    image: myapi
    networks: [frontend, backend]
  db:
    image: postgres
    networks: [backend]     # unreachable from web
networks:
  frontend:
  backend:
```

## When you might keep it

A two-service stack where both services must talk to each other anyway, or a local
development environment. The benefit grows with the number of services.

## Suppressing this rule

Permanently, for the whole repository:

```yaml
# .docksec.yml
rules:
  disabled:
    - compose-no-network-segmentation
```

Or per finding, with a reason and an expiry that keeps the decision auditable:

```yaml
# .docksec-ignore.yml
ignores:
  - id: compose-no-network-segmentation
    reason: "why this is accepted here"
    expires: 2027-01-01
```

## References

- Implementation: [`docksec/compose_scanner.py`](../../docksec/compose_scanner.py)
- [All compose rules](README.md) · [Exploit chains](../exploit-chains.md)
