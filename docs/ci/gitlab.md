# DockSec in GitLab CI

## Minimal job

```yaml
container-security:
  stage: test
  image: python:3.12-slim
  before_script:
    - pip install --quiet docksec
    - |
      curl -fsSL -o /tmp/trivy.tar.gz \
        "https://github.com/aquasecurity/trivy/releases/download/v0.74.0/trivy_0.74.0_Linux-64bit.tar.gz"
      tar -xzf /tmp/trivy.tar.gz -C /usr/local/bin trivy
      curl -fsSL -o /usr/local/bin/hadolint \
        "https://github.com/hadolint/hadolint/releases/download/v2.15.1/hadolint-Linux-x86_64"
      chmod +x /usr/local/bin/hadolint
  script:
    - docksec Dockerfile --scan-only --fail-on high
```

## Using the published image

Shorter, and the scanner versions are pinned for you:

```yaml
container-security:
  stage: test
  image:
    name: ghcr.io/owasp/docksec:latest
    entrypoint: [""]   # the default entrypoint expects GitHub Action inputs
  script:
    - docksec Dockerfile --scan-only --fail-on high
```

Pin the tag (`ghcr.io/owasp/docksec:2026.8`) in a pipeline you depend on.

## Merge request annotations with Code Quality

GitLab renders Code Quality reports inline on the merge request diff. DockSec
emits SARIF, which converts cleanly:

```yaml
container-security:
  stage: test
  image:
    name: ghcr.io/owasp/docksec:latest
    entrypoint: [""]
  script:
    - docksec Dockerfile --scan-only --sarif --output-dir reports || true
    - |
      python3 - <<'PY'
      import glob, hashlib, json

      sarif_files = glob.glob("reports/*.sarif")
      issues = []
      for path in sarif_files:
          with open(path) as handle:
              sarif = json.load(handle)
          for run in sarif.get("runs", []):
              for result in run.get("results", []):
                  location = (result.get("locations") or [{}])[0]
                  physical = location.get("physicalLocation", {})
                  uri = physical.get("artifactLocation", {}).get("uri", "Dockerfile")
                  line = physical.get("region", {}).get("startLine", 1)
                  message = result.get("message", {}).get("text", "")
                  severity = {
                      "error": "major", "warning": "minor", "note": "info",
                  }.get(result.get("level", "warning"), "minor")
                  issues.append({
                      "description": message,
                      "check_name": result.get("ruleId", "docksec"),
                      "fingerprint": hashlib.sha256(
                          f"{result.get('ruleId')}{uri}{line}".encode()
                      ).hexdigest(),
                      "severity": severity,
                      "location": {"path": uri, "lines": {"begin": line}},
                  })

      with open("gl-code-quality-report.json", "w") as handle:
          json.dump(issues, handle)
      print(f"wrote {len(issues)} findings")
      PY
    - docksec Dockerfile --scan-only --fail-on high
  artifacts:
    when: always
    reports:
      codequality: gl-code-quality-report.json
    paths:
      - reports/
```

The scan runs twice here - once to produce the report, once to gate - so the
report is written even when the gate fails. `|| true` on the first run and
`when: always` on the artifact are both load-bearing.

## Scanning a built image

```yaml
container-security:
  stage: test
  image: docker:27
  services:
    - docker:27-dind
  variables:
    DOCKER_TLS_CERTDIR: "/certs"
  before_script:
    - apk add --no-cache python3 py3-pip
    - pip install --quiet --break-system-packages docksec
    - wget -qO- "https://github.com/aquasecurity/trivy/releases/download/v0.74.0/trivy_0.74.0_Linux-64bit.tar.gz" | tar -xz -C /usr/local/bin trivy
  script:
    - docker build -t "$CI_REGISTRY_IMAGE:$CI_COMMIT_SHA" .
    - docksec Dockerfile -i "$CI_REGISTRY_IMAGE:$CI_COMMIT_SHA" --scan-only --fail-on high
```

## Adopting on an existing project

Gate on new findings only, so a backlog does not block every merge request:

```yaml
container-security:
  script:
    - docksec Dockerfile --scan-only --fail-on high --baseline .docksec-baseline.json
```

Create the baseline once and commit it:

```bash
docksec Dockerfile --scan-only --baseline .docksec-baseline.json --update-baseline
```

## Air-gapped runners

```yaml
container-security:
  script:
    - docksec Dockerfile --scan-only --offline --fail-on high
```

`--offline` skips every network call, including the EPSS lookup, and uses the
Trivy database already on the runner. Refresh that database on a schedule.

## Caching

Scan results are cached by image digest for 24 hours. Persisting the cache
across jobs saves a re-scan of unchanged images:

```yaml
container-security:
  cache:
    key: docksec-$CI_COMMIT_REF_SLUG
    paths:
      - .docksec-cache/
  variables:
    DOCKSEC_RESULTS_DIR: .docksec-cache
```
