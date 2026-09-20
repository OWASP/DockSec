# compose-disabled-security-opt: Security profile disabled

**Severity:** HIGH &nbsp;·&nbsp; **Rule ID:** `compose-disabled-security-opt`

## What it catches

`security_opt` sets `apparmor:unconfined` or `seccomp:unconfined`.

## Example

```yaml
services:
  app:
    image: myapp
    security_opt:
      - seccomp:unconfined   # <- every syscall available
```

## Why it matters

Docker's default seccomp profile blocks around 44 syscalls that container workloads do not
need and that have been used in kernel exploits. AppArmor adds file and capability restrictions on
top. Setting either to `unconfined` removes a layer that costs nothing when it is working, and turns
a kernel vulnerability that would have been blocked into one that is reachable.

## How to fix it

Remove the entry. If a specific syscall is genuinely required, ship a custom profile that
allows exactly that syscall rather than disabling the whole profile:

```yaml
services:
  app:
    image: myapp
    security_opt:
      - seccomp:./custom-seccomp.json
```

## When you might keep it

Debugging sessions using `ptrace` or `perf`, and some language runtimes with unusual
syscall needs. A custom profile is almost always achievable and is a much smaller concession.

## Suppressing this rule

Permanently, for the whole repository:

```yaml
# .docksec.yml
rules:
  disabled:
    - compose-disabled-security-opt
```

Or per finding, with a reason and an expiry that keeps the decision auditable:

```yaml
# .docksec-ignore.yml
ignores:
  - id: compose-disabled-security-opt
    reason: "why this is accepted here"
    expires: 2027-01-01
```

## References

- Implementation: [`docksec/compose_scanner.py`](../../docksec/compose_scanner.py)
- [All compose rules](README.md) · [Exploit chains](../exploit-chains.md)
