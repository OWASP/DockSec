# Evaluating DockSec in 15 minutes

Written for a security or platform engineer deciding whether this belongs in
their pipeline. It covers what DockSec does that the tools it wraps do not, and
states plainly where it does not add anything.

No API key is needed for any of it. Everything below runs locally.

## 0. Install (2 minutes)

```bash
docker run --rm -v "$PWD:/github/workspace" \
  -e INPUT_DOCKERFILE=Dockerfile -e INPUT_SCAN_ONLY=true \
  ghcr.io/owasp/docksec:latest
```

The image bundles pinned Trivy and Hadolint. If you prefer a local install:

```bash
pip install docksec
python -m docksec.setup_external_tools   # installs Trivy and Hadolint
```

## 1. The honest comparison first (3 minutes)

DockSec wraps Trivy, so the first question worth answering is what it adds.
Start with what Trivy alone gives you:

```bash
trivy config .
```

That already finds the root user, the missing HEALTHCHECK, and secrets in `ENV`.
If that output is enough for your team, you do not need DockSec, and this guide
has saved you an afternoon.

Now the same file through DockSec:

```bash
docksec Dockerfile --scan-only
```

The differences to look for:

- Findings from Hadolint *and* `trivy config`, deduplicated - each catches rules
  the other does not.
- A priority tier per CVE, combining severity with EPSS exploitation likelihood.
- Copy-and-run fix commands, and a statement of how many findings they resolve.
- A Coverage block stating what the scan could **not** determine.

## 2. The thing Trivy cannot do (5 minutes)

This is the part worth your attention. Clone the repository and scan the
deliberately insecure example:

```bash
git clone https://github.com/OWASP/DockSec
cd DockSec
docksec --compose examples/compose/docker-compose-insecure.yml --scan-only
```

Look at the **Exploit chains** section:

```text
[HIGH] 'db' is internet-facing and can reach 'web' with a committed credential
    services: db, web
    combines: compose-plaintext-secret-env, compose-no-network-segmentation
```

That finding does not exist in any per-service view. `web` has no credential, so
it looks low-value. `db` is not exposed, so it looks contained. Compose puts both
on the default network, so compromising one yields authenticated access to the
other.

Chain detection is rule-based, so it works offline and returns the same answer
every run. See [exploit chains](exploit-chains.md) for the full list, including
what is **not** yet detected.

Now the hardened example:

```bash
docksec --compose examples/compose/docker-compose-secure.yml --scan-only
```

Zero chains, and a score above 85. A signal that fires on everything is not a
signal, so this run matters as much as the previous one.

## 3. CI behavior (3 minutes)

```bash
docksec Dockerfile --scan-only --fail-on high ; echo "exit: $?"
```

Exit codes: `0` clean, `1` findings at or above the threshold, `2` usage error,
`3` the scan could not complete. The distinction between `1` and `3` is
deliberate - a gate that cannot tell "found problems" from "could not look" is
not a gate.

Test that:

```bash
docksec --compose examples/compose/docker-compose-insecure.yml \
  --scan-only --incomplete-policy fail ; echo "exit: $?"
```

Exit `3`, because the example's images are not pulled locally so the per-service
scans could not run. DockSec says so rather than reporting a clean result.

Machine-readable output:

```bash
docksec Dockerfile --scan-only --json | jq '{
  score: .scan_info.analysis_score,
  complete: .scan_info.completeness.complete,
  priorities: .priority_counts
}'
```

## 4. Fixing rather than reporting (2 minutes)

```bash
docksec Dockerfile --scan-only --fix --dry-run
```

Prints a unified diff without writing anything. Apply it:

```bash
docksec Dockerfile --scan-only --fix
```

The original is kept as `.bak`, the file is re-scanned, and the before/after
finding counts are reported. It refuses to edit a file with uncommitted changes
unless `--force`.

Note what it does **not** change: it will not pick a base image version for you,
will not move a secret, and will not edit a compose file. Those are listed under
"Needs review" instead. The conservatism is deliberate - an auto-fix that breaks
a build gets switched off.

## 5. Data flow (1 minute)

The question a security review asks first. What leaves the machine:

| Mode | Leaves your network |
| --- | --- |
| `--scan-only` | CVE IDs only, to the EPSS API for exploitation scores |
| `--scan-only --no-epss` | Nothing |
| `--offline` | Nothing |
| Default (AI enabled) | The above, plus the secret-redacted file content to the LLM provider you configure |
| `--provider ollama` | Nothing - the model runs locally |

Redaction applies to the AI path only, because that is the only path that sends
file content anywhere. `--scan-only` sends no content at all, so nothing needs
masking. Verify the masking itself without a provider:

```bash
python3 -c "
from docksec.redact import redact_content
content, masked = redact_content(
    'FROM alpine\nENV AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n'
)
print(content)
print(f'{masked} value(s) masked')
"
```

The key name stays visible so the model can still flag an exposed credential;
the secret itself is replaced. With a provider configured, a real run reports
the count:

```text
info  Masked 1 secret-looking value(s) before AI analysis (--no-redact to disable)
```

There is no telemetry. DockSec makes no outbound call other than those listed
above.

## What DockSec does not do

Stated so you do not discover it in week three:

- It does not prove exploitability or runtime reachability. A finding means the
  vulnerable version is present, not that the code path is invoked.
- It does not scan Kubernetes manifests or Helm charts. Trivy does; DockSec does
  not wrap that yet.
- It does not detect malicious packages, only known advisories.
- Chain detection covers compose stacks only, and not chains spanning a
  Dockerfile and a compose file.
- The AI layer is optional and adds explanation and ranking. Every gate, score,
  and chain works without it.

## Deciding

DockSec is probably worth adopting if:

- You run multi-service compose stacks and want cross-service analysis.
- You want a merge gate that distinguishes "found problems" from "could not
  scan".
- You need everything to run inside your own network.

It is probably not worth adopting if:

- You scan single images in CI and `trivy image --exit-code 1` already does what
  you need.
- Your workloads are Kubernetes-first; the chain analysis does not cover them yet.

Questions, or a case where it got something wrong:
[open an issue](https://github.com/OWASP/DockSec/issues). A scan that produced a
false positive is the most useful bug report this project can get.
