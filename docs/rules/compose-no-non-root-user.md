# compose-no-non-root-user: No non-root user

**Severity:** MEDIUM &nbsp;·&nbsp; **Rule ID:** `compose-no-non-root-user`

## What it catches

A service has no `user:` directive, so it runs as whatever the image defaults to - usually root.

## Example

```yaml
services:
  app:
    image: myapp   # <- no user: directive
```

## Why it matters

A process running as root inside the container is uid 0 on the host. If it escapes - through
a kernel bug, a writable bind mount, or a misconfiguration elsewhere in this list - it does so with
root privileges. Running as an unprivileged user does not prevent escape, but it removes the easiest
paths and limits the damage of the ones that remain.

## How to fix it

Set a non-root user:

```yaml
services:
  app:
    image: myapp
    user: "1000:1000"
```

Better still, set `USER` in the Dockerfile so the image is safe by default wherever it runs.

## When you might keep it

An init container that must chown a volume before the main service starts, or an image
whose entrypoint drops privileges itself after binding a low port. In the second case the finding is
a false positive worth waiving with a note.

## Suppressing this rule

Permanently, for the whole repository:

```yaml
# .docksec.yml
rules:
  disabled:
    - compose-no-non-root-user
```

Or per finding, with a reason and an expiry that keeps the decision auditable:

```yaml
# .docksec-ignore.yml
ignores:
  - id: compose-no-non-root-user
    reason: "why this is accepted here"
    expires: 2027-01-01
```

## References

- Implementation: [`docksec/compose_scanner.py`](../../docksec/compose_scanner.py)
- [All compose rules](README.md) · [Exploit chains](../exploit-chains.md)
