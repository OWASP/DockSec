# compose-no-resource-limits: No resource limits

**Severity:** LOW &nbsp;·&nbsp; **Rule ID:** `compose-no-resource-limits`

## What it catches

A service sets neither `deploy.resources.limits` nor `mem_limit`/`cpu_limit`.

## Example

```yaml
services:
  app:
    image: myapp   # <- can consume all host memory and CPU
```

## Why it matters

Without limits, one service can exhaust the host's memory or CPU and take down every other
service on it. That makes a bug or a denial-of-service attack against one container an outage for
the whole stack. Limits also make the kernel's OOM killer target the offending container rather than
choosing for itself.

## How to fix it

```yaml
services:
  app:
    image: myapp
    deploy:
      resources:
        limits:
          cpus: "1.0"
          memory: 512M
```

Note that `deploy.resources` only applies with `docker compose` v2 or Swarm; for older `docker-compose`
use the top-level `mem_limit` and `cpus` keys.

## When you might keep it

A development stack where limits would just get in the way, or an orchestrator that applies
limits outside the compose file (Kubernetes, Nomad). In the second case, waive it.

## Suppressing this rule

Permanently, for the whole repository:

```yaml
# .docksec.yml
rules:
  disabled:
    - compose-no-resource-limits
```

Or per finding, with a reason and an expiry that keeps the decision auditable:

```yaml
# .docksec-ignore.yml
ignores:
  - id: compose-no-resource-limits
    reason: "why this is accepted here"
    expires: 2027-01-01
```

## References

- Implementation: [`docksec/compose_scanner.py`](../../docksec/compose_scanner.py)
- [All compose rules](README.md) · [Exploit chains](../exploit-chains.md)
