# compose-host-namespace: Host PID or IPC namespace

**Severity:** CRITICAL &nbsp;·&nbsp; **Rule ID:** `compose-host-namespace`

## What it catches

A service sets `pid: host` or `ipc: host`.

## Example

```yaml
services:
  debug:
    image: alpine
    pid: host   # <- sees and can signal every host process
```

## Why it matters

`pid: host` lets the container see every process on the host, read their `/proc` entries -
which can include command-line arguments carrying secrets - and send them signals. `ipc: host`
shares System V IPC and POSIX message queues with the host, so the container can read shared memory
belonging to other processes. Both remove a boundary that container isolation otherwise provides.

## How to fix it

Remove the setting. If the service needs to inspect another container's processes, target
that container's namespace specifically rather than the host's:

```yaml
services:
  debug:
    image: alpine
    pid: "service:app"   # scoped to one service, not the host
```

## When you might keep it

Monitoring and profiling agents (APM collectors, `perf`-based tools) often require
`pid: host` to see the processes they measure. That is a real use case; it just should be a
deliberate one.

## Suppressing this rule

Permanently, for the whole repository:

```yaml
# .docksec.yml
rules:
  disabled:
    - compose-host-namespace
```

Or per finding, with a reason and an expiry that keeps the decision auditable:

```yaml
# .docksec-ignore.yml
ignores:
  - id: compose-host-namespace
    reason: "why this is accepted here"
    expires: 2027-01-01
```

## References

- Implementation: [`docksec/compose_scanner.py`](../../docksec/compose_scanner.py)
- [All compose rules](README.md) · [Exploit chains](../exploit-chains.md)
