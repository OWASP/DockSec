# compose-privileged: Privileged container

**Severity:** CRITICAL &nbsp;·&nbsp; **Rule ID:** `compose-privileged`

## What it catches

A service sets `privileged: true`.

## Example

```yaml
services:
  worker:
    image: busybox
    privileged: true   # <- all capabilities, all devices, no seccomp/AppArmor
```

## Why it matters

`privileged: true` is not "a few more permissions". It grants every Linux capability,
disables seccomp and AppArmor, and exposes all host devices. A privileged container can load kernel
modules, access raw block devices, and mount the host filesystem - so escaping it is trivial by
design rather than a bug.

## How to fix it

Remove the flag and add back only what is actually needed:

```yaml
services:
  worker:
    image: busybox
    cap_add:
      - NET_ADMIN       # only the capability the workload needs
```

If the service needs a specific device, map it explicitly with `devices:` rather than granting all
of them.

## When you might keep it

A container that genuinely manages host hardware - a storage or networking agent in a
controlled environment. Even then, prefer specific `cap_add` and `devices:` entries; `privileged`
is rarely the minimum that works.

## Suppressing this rule

Permanently, for the whole repository:

```yaml
# .docksec.yml
rules:
  disabled:
    - compose-privileged
```

Or per finding, with a reason and an expiry that keeps the decision auditable:

```yaml
# .docksec-ignore.yml
ignores:
  - id: compose-privileged
    reason: "why this is accepted here"
    expires: 2027-01-01
```

## References

- Implementation: [`docksec/compose_scanner.py`](../../docksec/compose_scanner.py)
- [All compose rules](README.md) · [Exploit chains](../exploit-chains.md)
