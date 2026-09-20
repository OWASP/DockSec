# compose-writable-root-fs: Writable root filesystem

**Severity:** LOW &nbsp;·&nbsp; **Rule ID:** `compose-writable-root-fs`

## What it catches

A service does not set `read_only: true`.

## Example

```yaml
services:
  app:
    image: myapp   # <- container filesystem is writable
```

## Why it matters

A writable root filesystem lets an attacker who achieves code execution persist: dropping a
binary, modifying an interpreter's startup file, or replacing a script that runs later. A read-only
root turns many footholds into temporary ones that vanish when the container restarts.

## How to fix it

Make the root read-only and grant tmpfs for the paths that genuinely need writes:

```yaml
services:
  app:
    image: myapp
    read_only: true
    tmpfs:
      - /tmp
      - /run
```

## When you might keep it

Services that write to their own filesystem by design - databases with local storage,
applications with embedded caches. Use a named volume for the data path and keep the rest read-only
where you can.

## Suppressing this rule

Permanently, for the whole repository:

```yaml
# .docksec.yml
rules:
  disabled:
    - compose-writable-root-fs
```

Or per finding, with a reason and an expiry that keeps the decision auditable:

```yaml
# .docksec-ignore.yml
ignores:
  - id: compose-writable-root-fs
    reason: "why this is accepted here"
    expires: 2027-01-01
```

## References

- Implementation: [`docksec/compose_scanner.py`](../../docksec/compose_scanner.py)
- [All compose rules](README.md) · [Exploit chains](../exploit-chains.md)
