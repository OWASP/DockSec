# DockSec in Jenkins

A declarative pipeline stage that scans a Dockerfile and fails the build on
HIGH-or-worse findings.

## Minimal stage

```groovy
pipeline {
    agent any

    stages {
        stage('Container security') {
            steps {
                sh '''
                    pip install --quiet docksec
                    docksec Dockerfile --scan-only --fail-on high
                '''
            }
        }
    }
}
```

DockSec exits `1` when it finds something at or above the threshold, which fails
the stage. Exit codes are `0` clean, `1` gated findings, `2` usage error,
`3` the scan could not complete.

## Using the container image instead

Avoids installing Python and the scanners on the agent. The image ships pinned
Trivy and Hadolint:

```groovy
pipeline {
    agent {
        docker {
            image 'ghcr.io/owasp/docksec:latest'
            args '--entrypoint='   // the image's entrypoint expects Action inputs
        }
    }

    stages {
        stage('Container security') {
            steps {
                sh 'docksec Dockerfile --scan-only --fail-on high'
            }
        }
    }
}
```

Pin the tag (`ghcr.io/owasp/docksec:2026.8`) rather than using `latest` in CI, so
a scan result does not change because of a release you did not choose.

## Publishing results

Jenkins reads JSON and HTML; the HTML report is the one reviewers will actually
open.

```groovy
stage('Container security') {
    steps {
        sh '''
            docksec Dockerfile -i "myapp:${BUILD_NUMBER}" \
                --fail-on high \
                --format json,html \
                --output-dir reports
        '''
    }
    post {
        always {
            archiveArtifacts artifacts: 'reports/**', allowEmptyArchive: true
            publishHTML(target: [
                reportDir: 'reports',
                reportFiles: '*.html',
                reportName: 'DockSec',
                keepAll: true
            ])
        }
    }
}
```

`post { always { ... } }` matters: without it the archive step is skipped
whenever the gate fails, which is exactly when you want the report.

## Adopting on an existing project

A project with pre-existing findings will fail on the first run. Baseline mode
lets you gate on new findings only:

```groovy
stage('Container security') {
    steps {
        sh '''
            docksec Dockerfile -i "myapp:${BUILD_NUMBER}" \
                --fail-on high \
                --baseline .docksec-baseline.json
        '''
    }
}
```

Generate and commit the baseline once:

```bash
docksec Dockerfile -i myapp:latest --baseline .docksec-baseline.json --update-baseline
git add .docksec-baseline.json && git commit -m "chore: baseline container findings"
```

From then on the build fails only on findings introduced after that point.

## Air-gapped agents

`--offline` uses the Trivy database already on the agent and skips every network
call, including the EPSS lookup:

```groovy
sh 'docksec Dockerfile --scan-only --offline --fail-on high'
```

The Trivy database must have been downloaded at least once. Refresh it on a
schedule, or bake it into the agent image.

## Not failing the build yet

To report without gating while a team gets used to the output, drop `--fail-on`
and let the stage pass:

```groovy
sh 'docksec Dockerfile --scan-only --format html --output-dir reports || true'
```

Add `--incomplete-policy fail` once you do gate, so a scan that could not run is
treated as a failure rather than a pass.

## Shared library function

For an organization standardising across many pipelines:

```groovy
// vars/dockSecScan.groovy
def call(Map config = [:]) {
    def dockerfile = config.get('dockerfile', 'Dockerfile')
    def image      = config.get('image', '')
    def failOn     = config.get('failOn', 'high')
    def reportDir  = config.get('reportDir', 'docksec-reports')

    def command = "docksec ${dockerfile} --fail-on ${failOn} " +
                  "--format json,html --output-dir ${reportDir}"
    if (image) {
        command += " -i ${image}"
    } else {
        command += " --scan-only"
    }

    sh "pip install --quiet docksec"
    sh command
}
```

Used as:

```groovy
stage('Container security') {
    steps {
        dockSecScan(image: "myapp:${BUILD_NUMBER}", failOn: 'critical')
    }
}
```

## Troubleshooting

**"Missing required tools: trivy"** - the agent does not have Trivy installed.
Install it, or use the container image above, which bundles it.

**The build fails but the report is missing** - add `post { always { ... } }`
around the archive step.

**Scans are slow** - results are cached for 24 hours by image digest. On
ephemeral agents the cache is lost each run; mount `~/.docksec` as a persistent
volume, or accept the cost.

**No findings on a Dockerfile you expect to be flagged** - check the Coverage
block in the output. If a scanner failed, DockSec reports a detection gap rather
than claiming the file is clean.
