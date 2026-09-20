# CI integration

Copy-pasteable configurations for the common CI systems. Every example is built
on the same three things, so adapting one to a system not listed here is
straightforward:

- **Exit codes.** `0` clean, `1` findings at or above `--fail-on`, `2` usage
  error, `3` the scan could not complete. Any CI system fails a step on a
  non-zero exit, so `--fail-on` is all the wiring a gate needs.
- **`--json`** for anything that needs to consume results programmatically.
- **`--sarif`** for platforms that render findings inline on a pull request.

| System | Guide |
| --- | --- |
| GitHub Actions | [README](../../README.md#5-or-run-the-container-image-nothing-to-install) |
| Jenkins | [jenkins.md](jenkins.md) |
| GitLab CI | [gitlab.md](gitlab.md) |
| Azure Pipelines | [azure-pipelines.md](azure-pipelines.md) |
| pre-commit | [pre-commit.md](pre-commit.md) |

## Choosing a threshold

`--fail-on high` is the usual starting point: CRITICAL and HIGH are the levels
where DockSec is confident enough that blocking a merge is defensible.

On an existing project with a backlog, gate on new findings only rather than
lowering the bar:

```bash
# once, committed to the repository
docksec Dockerfile --scan-only --baseline .docksec-baseline.json --update-baseline

# in CI from then on
docksec Dockerfile --scan-only --fail-on high --baseline .docksec-baseline.json
```

## Committing the policy instead of the flags

Repeating flags across pipelines drifts. A `.docksec.yml` at the repository root
applies to every run:

```yaml
severity: CRITICAL,HIGH
fail_on: HIGH
formats: [json, html]
output_dir: ./security-reports
```

CI then needs only `docksec Dockerfile`. Flags still override the file when you
need them to; see [Configuration file](../../README.md#configuration-file).

## Incomplete scans

If a scanner cannot run, DockSec reports a detection gap rather than claiming
the target is clean - but by default the run still succeeds. To treat an
incomplete scan as a failure:

```bash
docksec Dockerfile --fail-on high --incomplete-policy fail
```

Worth turning on once a pipeline is stable. Until then it can be noisy on
runners with intermittent network.

## Air-gapped environments

```bash
docksec Dockerfile --scan-only --offline --fail-on high
```

`--offline` makes no network calls, including the EPSS lookup, and uses the
Trivy database already on the runner. Refresh that database on a schedule -
a stale vulnerability database is a silent source of wrong results, and
`docksec doctor` reports its age.

## Keeping the report when the gate fires

The most common mistake across all of these: the step that publishes the report
is skipped exactly when the gate fails, because CI stops on the first failing
step. Every guide here shows the fix for its system - `post { always { ... } }`
in Jenkins, `when: always` in GitLab, `condition: always()` in Azure,
`if: always()` in GitHub Actions.
