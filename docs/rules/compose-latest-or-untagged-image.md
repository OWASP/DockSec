# compose-latest-or-untagged-image: Mutable image tag

**Severity:** MEDIUM &nbsp;·&nbsp; **Rule ID:** `compose-latest-or-untagged-image`

## What it catches

`image:` uses `:latest` or has no tag at all.

## Example

```yaml
services:
  web:
    image: nginx   # <- resolves to :latest, which moves
```

## Why it matters

`:latest` is a moving pointer. The image you tested and the image that deploys next week can
differ, so a stack that passed review can ship different code without any change to the compose
file. It also makes incidents hard to reason about: "which version was running" has no answer.

For security specifically, it means a scan result has a short shelf life - it describes whatever
`:latest` resolved to at scan time.

## How to fix it

Pin to an explicit version, or to a digest for full reproducibility:

```yaml
services:
  web:
    image: nginx:1.27.3-alpine
    # strongest: image: nginx@sha256:...
```

## When you might keep it

A local development stack where always getting the newest image is the point. Do not let it
reach a deployed environment.

## Suppressing this rule

Permanently, for the whole repository:

```yaml
# .docksec.yml
rules:
  disabled:
    - compose-latest-or-untagged-image
```

Or per finding, with a reason and an expiry that keeps the decision auditable:

```yaml
# .docksec-ignore.yml
ignores:
  - id: compose-latest-or-untagged-image
    reason: "why this is accepted here"
    expires: 2027-01-01
```

## References

- Implementation: [`docksec/compose_scanner.py`](../../docksec/compose_scanner.py)
- [All compose rules](README.md) · [Exploit chains](../exploit-chains.md)
