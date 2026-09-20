# compose-env-file-secret-risk: env_file may carry secrets

**Severity:** MEDIUM &nbsp;·&nbsp; **Rule ID:** `compose-env-file-secret-risk`

## What it catches

A service uses `env_file:`.

## Example

```yaml
services:
  app:
    image: myapp
    env_file: .env   # <- is this gitignored?
```

## Why it matters

`env_file` is not itself a vulnerability - it is usually better than inlining values. It is
flagged because the referenced file frequently contains credentials and is frequently committed by
accident. Once committed it is in the git history permanently.

## How to fix it

Confirm the file is gitignored, and prefer Docker secrets for anything genuinely sensitive:

```bash
grep -q '^\.env$' .gitignore || echo '.env' >> .gitignore
git ls-files --error-unmatch .env 2>/dev/null && echo "WARNING: .env is tracked"
```

## When you might keep it

Routinely - `env_file` is a normal pattern. Waive it once you have confirmed the file is
not tracked; this rule is a prompt to check, not a defect.

## Suppressing this rule

Permanently, for the whole repository:

```yaml
# .docksec.yml
rules:
  disabled:
    - compose-env-file-secret-risk
```

Or per finding, with a reason and an expiry that keeps the decision auditable:

```yaml
# .docksec-ignore.yml
ignores:
  - id: compose-env-file-secret-risk
    reason: "why this is accepted here"
    expires: 2027-01-01
```

## References

- Implementation: [`docksec/compose_scanner.py`](../../docksec/compose_scanner.py)
- [All compose rules](README.md) · [Exploit chains](../exploit-chains.md)
