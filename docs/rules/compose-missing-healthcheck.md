# compose-missing-healthcheck: Missing healthcheck

**Severity:** LOW &nbsp;·&nbsp; **Rule ID:** `compose-missing-healthcheck`

## What it catches

A service has no `healthcheck:` block.

## Example

```yaml
services:
  app:
    image: myapp   # <- Docker only knows whether the process is running
```

## Why it matters

Without a healthcheck, Docker knows only whether the main process exited - not whether the
service is actually working. A container that has deadlocked, lost its database connection, or is
returning 500s to everything counts as healthy, so restart policies never fire and dependent
services start against a backend that cannot serve them.

This is a reliability control more than a security one, which is why it is LOW.

## How to fix it

```yaml
services:
  app:
    image: myapp
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/health"]
      interval: 30s
      timeout: 5s
      retries: 3
      start_period: 10s
```

## When you might keep it

Short-lived and batch containers that exit when their work is done - a healthcheck is
meaningless there. Many teams also disable this rule wholesale when health is managed by an
orchestrator; that is a reasonable use of
[`rules.disabled`](../../README.md#disabling-rules).

## Suppressing this rule

Permanently, for the whole repository:

```yaml
# .docksec.yml
rules:
  disabled:
    - compose-missing-healthcheck
```

Or per finding, with a reason and an expiry that keeps the decision auditable:

```yaml
# .docksec-ignore.yml
ignores:
  - id: compose-missing-healthcheck
    reason: "why this is accepted here"
    expires: 2027-01-01
```

## References

- Implementation: [`docksec/compose_scanner.py`](../../docksec/compose_scanner.py)
- [All compose rules](README.md) · [Exploit chains](../exploit-chains.md)
