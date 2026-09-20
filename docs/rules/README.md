# Compose rule reference

Every Docker Compose rule DockSec applies, what it catches, why it matters, and when you might
reasonably keep the pattern it flags.

Each rule ID is stable and can be used to suppress a finding, either permanently with
[`rules.disabled`](../../README.md#disabling-rules) or per-finding with an auditable
[waiver](../../README.md#ignoring-findings-waivers).

Several of these rules also combine into [exploit chains](../exploit-chains.md) - cases where two
findings that look minor individually form one exploitable path.

| Rule | Severity | Catches |
| --- | --- | --- |
| [`compose-dangerous-capabilities`](compose-dangerous-capabilities.md) | CRITICAL | `cap_add` includes `SYS_ADMIN`, `NET_ADMIN`, `SYS_PTRACE`, or `ALL`. |
| [`compose-disabled-security-opt`](compose-disabled-security-opt.md) | HIGH | `security_opt` sets `apparmor:unconfined` or `seccomp:unconfined`. |
| [`compose-docker-socket-mount`](compose-docker-socket-mount.md) | CRITICAL | A service bind-mounts `/var/run/docker.sock`. |
| [`compose-env-file-secret-risk`](compose-env-file-secret-risk.md) | MEDIUM | A service uses `env_file:`. |
| [`compose-host-namespace`](compose-host-namespace.md) | CRITICAL | A service sets `pid: host` or `ipc: host`. |
| [`compose-host-network`](compose-host-network.md) | CRITICAL | A service sets `network_mode: host`. |
| [`compose-latest-or-untagged-image`](compose-latest-or-untagged-image.md) | MEDIUM | `image:` uses `:latest` or has no tag at all. |
| [`compose-missing-healthcheck`](compose-missing-healthcheck.md) | LOW | A service has no `healthcheck:` block. |
| [`compose-no-network-segmentation`](compose-no-network-segmentation.md) | LOW | No service defines a `networks:` key, so every service sits on the default network. |
| [`compose-no-new-privileges`](compose-no-new-privileges.md) | LOW | `security_opt` does not include `no-new-privileges:true`. |
| [`compose-no-non-root-user`](compose-no-non-root-user.md) | MEDIUM | A service has no `user:` directive, so it runs as whatever the image defaults to - usually root. |
| [`compose-no-resource-limits`](compose-no-resource-limits.md) | LOW | A service sets neither `deploy.resources.limits` nor `mem_limit`/`cpu_limit`. |
| [`compose-plaintext-secret-env`](compose-plaintext-secret-env.md) | HIGH | An `environment` entry whose key names a credential carries a literal value. |
| [`compose-port-bound-all-interfaces`](compose-port-bound-all-interfaces.md) | HIGH | A database, cache, broker, or admin port is published with no host IP, so it binds 0.0.0.0. |
| [`compose-privileged`](compose-privileged.md) | CRITICAL | A service sets `privileged: true`. |
| [`compose-sensitive-host-mount`](compose-sensitive-host-mount.md) | CRITICAL | A service bind-mounts `/`, `/etc`, `/root`, `/var/run`, `/proc`, or `/sys`. |
| [`compose-writable-root-fs`](compose-writable-root-fs.md) | LOW | A service does not set `read_only: true`. |
