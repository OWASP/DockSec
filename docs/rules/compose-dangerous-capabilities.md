# compose-dangerous-capabilities: Dangerous capability added

**Severity:** CRITICAL &nbsp;·&nbsp; **Rule ID:** `compose-dangerous-capabilities`

## What it catches

`cap_add` includes `SYS_ADMIN`, `NET_ADMIN`, `SYS_PTRACE`, or `ALL`.

## Example

```yaml
services:
  app:
    image: myapp
    cap_add:
      - SYS_ADMIN   # <- close to privileged
```

## Why it matters

`SYS_ADMIN` is broad enough to be near-equivalent to privileged: it permits mount
operations, which opens several documented escape paths. `SYS_PTRACE` lets the container inspect and
modify the memory of other processes it can see. `NET_ADMIN` allows reconfiguring interfaces and
firewall rules. `ALL` grants everything.

## How to fix it

Grant the specific capability the workload needs, and drop the rest:

```yaml
services:
  app:
    image: myapp
    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE   # only what is required, e.g. to bind port 80
```

## When you might keep it

`NET_ADMIN` is legitimate for VPN and networking containers; `SYS_PTRACE` for debuggers
and profilers. `SYS_ADMIN` and `ALL` rarely survive scrutiny - if one is needed, the workload
probably belongs outside a container.

## Suppressing this rule

Permanently, for the whole repository:

```yaml
# .docksec.yml
rules:
  disabled:
    - compose-dangerous-capabilities
```

Or per finding, with a reason and an expiry that keeps the decision auditable:

```yaml
# .docksec-ignore.yml
ignores:
  - id: compose-dangerous-capabilities
    reason: "why this is accepted here"
    expires: 2027-01-01
```

## References

- Implementation: [`docksec/compose_scanner.py`](../../docksec/compose_scanner.py)
- [All compose rules](README.md) · [Exploit chains](../exploit-chains.md)
