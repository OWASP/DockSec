# compose-plaintext-secret-env: Plaintext secret in environment

**Severity:** HIGH &nbsp;·&nbsp; **Rule ID:** `compose-plaintext-secret-env`

## What it catches

An `environment` entry whose key names a credential carries a literal value.

## Example

```yaml
services:
  db:
    image: postgres:16
    environment:
      POSTGRES_PASSWORD: hunter2   # <- committed to version control
```

## Why it matters

A value here is committed to the repository, so it is in every clone, every fork, and the
full git history - rotating it later does not remove it from the past. It is also visible to anyone
who can run `docker inspect`, and it appears in the process environment where any process in the
container can read it.

Combined with an exposed port, this becomes an [exploit chain](../exploit-chains.md): the service
is reachable and the password to it is public.

## How to fix it

Use a Docker secret and the `_FILE` convention most official images support:

```yaml
services:
  db:
    image: postgres:16
    environment:
      POSTGRES_PASSWORD_FILE: /run/secrets/db_password
    secrets:
      - db_password
secrets:
  db_password:
    file: ./db_password.txt   # gitignored, or an external secret
```

Interpolation (`POSTGRES_PASSWORD: ${DB_PASSWORD}`) also satisfies this rule, since the value then
comes from the environment rather than the file.

## When you might keep it

A throwaway value in a local development stack that is never deployed and never reachable
from outside the machine. Even then, prefer interpolation - it costs nothing and removes the risk of
the file being copied into a real deployment.

## Suppressing this rule

Permanently, for the whole repository:

```yaml
# .docksec.yml
rules:
  disabled:
    - compose-plaintext-secret-env
```

Or per finding, with a reason and an expiry that keeps the decision auditable:

```yaml
# .docksec-ignore.yml
ignores:
  - id: compose-plaintext-secret-env
    reason: "why this is accepted here"
    expires: 2027-01-01
```

## References

- Implementation: [`docksec/compose_scanner.py`](../../docksec/compose_scanner.py)
- [All compose rules](README.md) · [Exploit chains](../exploit-chains.md)
