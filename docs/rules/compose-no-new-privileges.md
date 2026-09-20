# compose-no-new-privileges: Missing no-new-privileges

**Severity:** LOW &nbsp;·&nbsp; **Rule ID:** `compose-no-new-privileges`

## What it catches

`security_opt` does not include `no-new-privileges:true`.

## Example

```yaml
services:
  app:
    image: myapp   # <- setuid binaries can still escalate
```

## Why it matters

Without this flag, a process in the container can gain privileges through setuid binaries.
An attacker with a shell as an unprivileged user can look for a setuid root binary in the image and
use it to become root inside the container - undoing the benefit of running as a non-root user.

## How to fix it

```yaml
services:
  app:
    image: myapp
    security_opt:
      - no-new-privileges:true
```

This is close to free: almost no containerized workload legitimately needs to escalate privileges
after starting.

## When you might keep it

An image that deliberately uses a setuid helper - `sudo` in a development container, or
certain ping implementations. Rare in production images.

## Suppressing this rule

Permanently, for the whole repository:

```yaml
# .docksec.yml
rules:
  disabled:
    - compose-no-new-privileges
```

Or per finding, with a reason and an expiry that keeps the decision auditable:

```yaml
# .docksec-ignore.yml
ignores:
  - id: compose-no-new-privileges
    reason: "why this is accepted here"
    expires: 2027-01-01
```

## References

- Implementation: [`docksec/compose_scanner.py`](../../docksec/compose_scanner.py)
- [All compose rules](README.md) · [Exploit chains](../exploit-chains.md)
