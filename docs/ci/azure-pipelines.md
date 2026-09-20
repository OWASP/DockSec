# DockSec in Azure Pipelines

## Minimal job

```yaml
- job: ContainerSecurity
  displayName: Container security
  pool:
    vmImage: ubuntu-latest
  steps:
    - task: UsePythonVersion@0
      inputs:
        versionSpec: '3.12'

    - script: |
        set -euo pipefail
        pip install --quiet docksec
        curl -fsSL -o /tmp/trivy.tar.gz \
          "https://github.com/aquasecurity/trivy/releases/download/v0.74.0/trivy_0.74.0_Linux-64bit.tar.gz"
        sudo tar -xzf /tmp/trivy.tar.gz -C /usr/local/bin trivy
        sudo curl -fsSL -o /usr/local/bin/hadolint \
          "https://github.com/hadolint/hadolint/releases/download/v2.15.1/hadolint-Linux-x86_64"
        sudo chmod +x /usr/local/bin/hadolint
      displayName: Install DockSec and scanners

    - script: docksec Dockerfile --scan-only --fail-on high
      displayName: Scan Dockerfile
```

A non-zero exit fails the step, so `--fail-on` gates the pipeline without any
extra wiring.

## Using the published image

```yaml
- job: ContainerSecurity
  pool:
    vmImage: ubuntu-latest
  container:
    image: ghcr.io/owasp/docksec:latest
    options: --entrypoint=""
  steps:
    - script: docksec Dockerfile --scan-only --fail-on high
      displayName: Scan Dockerfile
```

Pin the tag in a pipeline you depend on: `ghcr.io/owasp/docksec:2026.8`.

## Publishing the report

```yaml
- script: |
    docksec Dockerfile -i "$(imageName):$(Build.BuildId)" \
      --fail-on high \
      --format json,html \
      --output-dir "$(Build.ArtifactStagingDirectory)/docksec"
  displayName: Scan
  continueOnError: false

- task: PublishBuildArtifacts@1
  displayName: Publish DockSec report
  condition: always()
  inputs:
    pathToPublish: '$(Build.ArtifactStagingDirectory)/docksec'
    artifactName: docksec-report
```

`condition: always()` matters: without it the report is not published on the
runs where the gate fires, which is when you most want it.

## Adopting on an existing project

```yaml
- script: |
    docksec Dockerfile --scan-only --fail-on high \
      --baseline .docksec-baseline.json
  displayName: Scan (new findings only)
```

Generate the baseline once and commit it:

```bash
docksec Dockerfile --scan-only --baseline .docksec-baseline.json --update-baseline
```

## Self-hosted and air-gapped agents

```yaml
- script: docksec Dockerfile --scan-only --offline --fail-on high
  displayName: Scan (offline)
```

`--offline` makes no network calls at all, including the EPSS lookup, and uses
the Trivy database already present on the agent.

## Failing on an incomplete scan

By default a scanner that could not run is reported as a coverage gap and the
pipeline continues. To treat that as a failure instead:

```yaml
- script: docksec Dockerfile --scan-only --fail-on high --incomplete-policy fail
  displayName: Scan (strict)
```

## Multi-stage pipeline example

```yaml
trigger:
  - main

stages:
  - stage: Build
    jobs:
      - job: BuildImage
        pool:
          vmImage: ubuntu-latest
        steps:
          - task: Docker@2
            inputs:
              command: build
              repository: myapp
              tags: $(Build.BuildId)

  - stage: Security
    dependsOn: Build
    jobs:
      - job: ContainerSecurity
        pool:
          vmImage: ubuntu-latest
        container:
          image: ghcr.io/owasp/docksec:2026.8
          options: --entrypoint=""
        steps:
          - script: |
              docksec Dockerfile -i "myapp:$(Build.BuildId)" \
                --fail-on high \
                --format json,html \
                --output-dir "$(Build.ArtifactStagingDirectory)/docksec"
            displayName: Scan image and Dockerfile
          - task: PublishBuildArtifacts@1
            condition: always()
            inputs:
              pathToPublish: '$(Build.ArtifactStagingDirectory)/docksec'
              artifactName: docksec-report
```
