# compose-docker-socket-mount: Docker socket mount

**Severity:** CRITICAL &nbsp;·&nbsp; **Rule ID:** `compose-docker-socket-mount`

## What it catches

A service bind-mounts `/var/run/docker.sock`.

## Example

```yaml
services:
  web:
    image: nginx
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock   # <- full control of the host daemon
```

## Why it matters

The Docker socket is the daemon's full control API. A process that can write to it can start a
new container with the host filesystem mounted, and read or modify anything on the host as root.
There is no privilege boundary left: the container is effectively running as host root, and a
remote code execution bug in this service becomes a host compromise rather than a contained one.

This is the single most consequential misconfiguration in a compose file, which is why it is also
a component of the [exploit chains](../exploit-chains.md) DockSec reports.

## How to fix it

Remove the mount. If the service genuinely needs to talk to Docker - a CI runner, a
reverse proxy doing service discovery - put a scoped socket proxy in front of it so only the
specific API calls it needs are reachable:

```yaml
services:
  socket-proxy:
    image: tecnativa/docker-socket-proxy
    environment:
      CONTAINERS: 1      # allow only what is needed
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
  web:
    image: nginx
    environment:
      DOCKER_HOST: tcp://socket-proxy:2375
```

## When you might keep it

Almost never in production. A local development stack for a tool that manages containers
(Portainer, a CI agent, Traefik's Docker provider) is the legitimate case - and even then, mount
it read-only and prefer the proxy above.

## Suppressing this rule

Permanently, for the whole repository:

```yaml
# .docksec.yml
rules:
  disabled:
    - compose-docker-socket-mount
```

Or per finding, with a reason and an expiry that keeps the decision auditable:

```yaml
# .docksec-ignore.yml
ignores:
  - id: compose-docker-socket-mount
    reason: "why this is accepted here"
    expires: 2027-01-01
```

## References

- Implementation: [`docksec/compose_scanner.py`](../../docksec/compose_scanner.py)
- [All compose rules](README.md) · [Exploit chains](../exploit-chains.md)
