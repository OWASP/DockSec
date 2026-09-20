# compose-sensitive-host-mount: Sensitive host directory mounted

**Severity:** CRITICAL &nbsp;·&nbsp; **Rule ID:** `compose-sensitive-host-mount`

## What it catches

A service bind-mounts `/`, `/etc`, `/root`, `/var/run`, `/proc`, or `/sys`.

## Example

```yaml
services:
  backup:
    image: alpine
    volumes:
      - /:/host        # <- the entire host filesystem, writable
```

## Why it matters

Mounting a sensitive host path hands the container the contents of the host. `/etc` exposes
`shadow`, SSH host keys, and every service credential on the box. `/` writable means the container
can modify systemd units or `authorized_keys` and take over the host at the next boot or login.
`/proc` and `/sys` expose kernel interfaces that can be used to affect the host directly.

## How to fix it

Mount the narrowest path that works, read-only where possible:

```yaml
services:
  backup:
    image: alpine
    volumes:
      - /srv/appdata:/data:ro   # one directory, read-only
```

## When you might keep it

Backup and monitoring agents sometimes need broad read access. Use `:ro`, scope to the
specific subtree, and never mount `/` writable.

## Suppressing this rule

Permanently, for the whole repository:

```yaml
# .docksec.yml
rules:
  disabled:
    - compose-sensitive-host-mount
```

Or per finding, with a reason and an expiry that keeps the decision auditable:

```yaml
# .docksec-ignore.yml
ignores:
  - id: compose-sensitive-host-mount
    reason: "why this is accepted here"
    expires: 2027-01-01
```

## References

- Implementation: [`docksec/compose_scanner.py`](../../docksec/compose_scanner.py)
- [All compose rules](README.md) · [Exploit chains](../exploit-chains.md)
