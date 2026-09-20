# DockSec as a pre-commit hook

Catching a hardcoded secret before it reaches the repository is worth far more
than catching it in CI, because once it is committed it is in the history
permanently.

## Setup

Add to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/OWASP/DockSec
    rev: v2026.8.19       # pin a tag
    hooks:
      - id: docksec
```

Then:

```bash
pre-commit install
```

The hook runs whenever a `Dockerfile` or `Containerfile` is staged. It needs
Trivy and Hadolint on the PATH:

```bash
brew install trivy hadolint          # macOS
python -m docksec.setup_external_tools   # or let DockSec install them
```

## Hooks

| Hook | Gates on | Use when |
| --- | --- | --- |
| `docksec` | CRITICAL | Default. Blocks committed secrets and container-escape misconfigurations, stays quiet otherwise. |
| `docksec-strict` | HIGH | A team that has already cleared its HIGH findings and wants to keep it that way. |

The default is deliberately CRITICAL-only. A pre-commit hook that is slow or
noisy gets bypassed with `--no-verify`, and a bypassed hook protects nothing.

## Stricter configuration

```yaml
repos:
  - repo: https://github.com/OWASP/DockSec
    rev: v2026.8.19
    hooks:
      - id: docksec-strict
        args: ['--scan-only', '--quiet', '--fail-on', 'high', '--no-epss']
```

`--no-epss` skips the exploitation-likelihood lookup, which removes the only
network call and makes the hook faster and usable offline. The ranking is less
informative, but a pre-commit hook is a gate rather than a triage surface.

## Why there is no compose hook

Scanning a compose stack means scanning each service's image, and on a developer
machine those images are usually not pulled. DockSec reports that as an
incomplete scan and exits `3` - correctly, since it cannot claim a stack is clean
when it never inspected the images. That would make the hook fail on clean input,
so it is not shipped.

Compose scanning belongs in CI, where the images are built. See
[Jenkins](jenkins.md), [GitLab](gitlab.md), or
[Azure Pipelines](azure-pipelines.md).

You can still run it by hand:

```bash
docksec --compose docker-compose.yml --scan-only
```

## Skipping a commit

```bash
git commit --no-verify        # skip all hooks
SKIP=docksec git commit       # skip just this one
```

If you find yourself doing this routinely, the threshold is wrong for your
project. Lower the gate or add a [waiver](../../README.md#ignoring-findings-waivers)
rather than training yourself to bypass it.

## Running against everything

The hook only sees staged files. To scan the whole repository:

```bash
pre-commit run docksec --all-files
```

Worth doing once when you adopt it, so you know what the backlog is.

## Speed

A Dockerfile-only scan takes roughly two seconds - Hadolint and `trivy config`
both read the file without pulling anything, and most of that is process
startup. Results are cached for 24 hours, so repeated commits against an
unchanged file are faster.

If the hook feels slow, it is almost always the Trivy database refresh on first
use. Prime it once:

```bash
trivy image --download-db-only
```
