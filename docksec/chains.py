"""Cross-service exploit chains in a Compose stack.

A per-artifact scanner sees findings one at a time. A stack is not a list of
services, and the risk is often in the relationships: a database with a default
password is one finding, a database published on 0.0.0.0 is another, and a
database that is both *and* shares a network with an internet-facing service is
a single exploitable path that neither finding describes.

This is the capability a per-file scanner cannot copy, so it is built
deterministically here and only *explained* by the model. Chain detection is a
graph query over the topology - exposure, credentials, connectivity, privilege -
not an inference problem. Keeping it in rules means the flagship output survives
``--scan-only``, works offline, and returns the same answer twice.

The AI pass still adds value on top: ranking chains against each other, catching
the shapes these rules miss, and explaining impact in context. It is not load
bearing for the detection itself.
"""

from typing import Dict, List, Optional

from docksec.enums import Severity

# Ports whose exposure means the service speaks a protocol worth attacking
# directly: databases, caches, brokers, admin interfaces.
SENSITIVE_SERVICE_PORTS = {
    22: "SSH", 1433: "MSSQL", 1521: "Oracle", 2375: "Docker API",
    2376: "Docker API (TLS)", 2379: "etcd", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5984: "CouchDB", 6379: "Redis", 8086: "InfluxDB",
    8500: "Consul", 9092: "Kafka", 9200: "Elasticsearch", 11211: "memcached",
    15672: "RabbitMQ admin", 27017: "MongoDB",
}

# Environment keys that name a credential rather than a path to one.
CREDENTIAL_KEY_HINTS = ("password", "passwd", "secret", "token", "api_key",
                        "apikey", "access_key", "private_key", "auth")

LOCAL_ADDRESSES = {"127.0.0.1", "localhost", "::1"}


def _parse_port(entry) -> tuple:
    """Return (host_ip, published_port) for a compose port entry."""
    if isinstance(entry, dict):
        published = entry.get("published") or entry.get("target")
        try:
            return entry.get("host_ip"), int(str(published))
        except (TypeError, ValueError):
            return entry.get("host_ip"), None

    text = str(entry).split("/")[0]
    parts = text.rsplit(":", 2)
    host_ip, published = None, None
    if len(parts) == 3:
        host_ip, published = parts[0], parts[1]
    elif len(parts) == 2:
        published = parts[0]
    else:
        published = parts[0]
    try:
        return host_ip, int(str(published))
    except (TypeError, ValueError):
        return host_ip, None


def _service_networks(config: Dict) -> List[str]:
    """Networks a service is attached to; the implicit default counts."""
    networks = config.get("networks")
    if not networks:
        return ["default"]
    if isinstance(networks, dict):
        return list(networks)
    if isinstance(networks, list):
        return [str(n) for n in networks]
    return [str(networks)]


def _plaintext_credentials(config: Dict) -> List[str]:
    """Credential-named environment keys carrying a literal value.

    ``${VAR}`` interpolation and ``*_FILE`` indirection are both excluded: the
    first defers the value, the second points at a Docker secret, and flagging
    either would penalize the recommended patterns.
    """
    env = config.get("environment")
    if not env:
        return []

    pairs = []
    if isinstance(env, dict):
        pairs = [(str(k), str(v)) for k, v in env.items()]
    elif isinstance(env, list):
        for item in env:
            text = str(item)
            if "=" in text:
                key, value = text.split("=", 1)
                pairs.append((key, value))

    found = []
    for key, value in pairs:
        lowered = key.lower()
        if lowered.endswith(("_file", "_path", "_filepath")):
            continue
        if not any(hint in lowered for hint in CREDENTIAL_KEY_HINTS):
            continue
        if not value or value.startswith("${"):
            continue
        found.append(key)
    return found


def _is_internet_facing(config: Dict) -> bool:
    """A service is internet-facing when it publishes a port on all interfaces."""
    if config.get("network_mode") == "host":
        return True
    for entry in config.get("ports") or []:
        host_ip, _ = _parse_port(entry)
        if host_ip is None or str(host_ip) not in LOCAL_ADDRESSES:
            return True
    return False


def _chain(chain_id, title, severity, services, finding_ids, narrative, fix) -> Dict:
    return {
        "chain_id": chain_id,
        "title": title,
        "severity": severity,
        "services": services,
        "finding_ids": finding_ids,
        "narrative": narrative,
        "fix": fix,
        "source": "rules",
    }


def detect(compose_data: Optional[Dict], findings: Optional[List[Dict]] = None) -> List[Dict]:
    """Find exploit chains in a compose stack.

    Returns chains most severe first. Each names the services involved, the
    findings that combine, the path in order, and the single change that breaks
    it most effectively.
    """
    if not compose_data:
        return []

    services = compose_data.get("services") or {}
    if not isinstance(services, dict) or not services:
        return []

    # Build a view of each service once; the rules below are queries over it.
    view = {}
    for name, config in services.items():
        if not isinstance(config, dict):
            continue
        exposed_sensitive = []
        for entry in config.get("ports") or []:
            host_ip, port = _parse_port(entry)
            if port in SENSITIVE_SERVICE_PORTS:
                bound_locally = host_ip and str(host_ip) in LOCAL_ADDRESSES
                exposed_sensitive.append({
                    "port": port,
                    "service_type": SENSITIVE_SERVICE_PORTS[port],
                    "public": not bound_locally,
                })
        view[name] = {
            "config": config,
            "networks": set(_service_networks(config)),
            "credentials": _plaintext_credentials(config),
            "sensitive_ports": exposed_sensitive,
            "internet_facing": _is_internet_facing(config),
            "privileged": bool(config.get("privileged")),
            "socket_mounted": any(
                "/var/run/docker.sock" in str(v) for v in (config.get("volumes") or [])
            ),
            "root_user": "user" not in config,
        }

    chains: List[Dict] = []

    for name, data in view.items():
        # Chain 1: a credentialed datastore reachable from outside the host.
        for port in data["sensitive_ports"]:
            if port["public"] and data["credentials"]:
                chains.append(_chain(
                    "chain-exposed-credentialed-datastore",
                    f"{port['service_type']} on '{name}' is reachable from any host "
                    f"and its credential is in the compose file",
                    Severity.CRITICAL.value,
                    [name],
                    ["compose-port-bound-all-interfaces", "compose-plaintext-secret-env"],
                    f"Port {port['port']} is published with no host IP, so it binds "
                    f"0.0.0.0 and accepts connections from outside the host. The "
                    f"credential in {', '.join(data['credentials'])} is committed "
                    f"alongside it, so anyone who can read the repository can "
                    f"authenticate to the datastore directly - no application "
                    f"vulnerability required.",
                    f"Bind the port to 127.0.0.1 (or drop it and use 'expose'), and "
                    f"move {data['credentials'][0]} to a Docker secret.",
                ))

        # Chain 2: container escape reachable through an exposed service.
        if (data["privileged"] or data["socket_mounted"]) and data["internet_facing"]:
            mechanism = (
                "mounts the Docker socket" if data["socket_mounted"]
                else "runs privileged"
            )
            escape_finding = (
                "compose-docker-socket-mount" if data["socket_mounted"]
                else "compose-privileged"
            )
            chains.append(_chain(
                "chain-exposed-escape-path",
                f"'{name}' publishes a port and {mechanism}",
                Severity.CRITICAL.value,
                [name],
                [escape_finding, "compose-port-bound-all-interfaces"],
                f"'{name}' is reachable from outside the host and {mechanism}. Any "
                f"remote code execution in this service is a host compromise rather "
                f"than a container one: the escape path is already open, so the "
                f"container boundary provides no containment.",
                f"Remove the {'socket mount' if data['socket_mounted'] else 'privileged flag'} "
                f"first - it is what turns a service compromise into a host compromise.",
            ))

    # Chain 3: lateral movement. An internet-facing service shares a network
    # with a credentialed datastore that is not itself exposed. Each service
    # looks acceptable alone; together they are a path.
    for entry_name, entry in view.items():
        if not entry["internet_facing"]:
            continue
        for target_name, target in view.items():
            if target_name == entry_name:
                continue
            if not target["credentials"]:
                continue
            shared = entry["networks"] & target["networks"]
            if not shared:
                continue
            # Already covered by chain 1 when the datastore is itself public.
            if any(p["public"] for p in target["sensitive_ports"]):
                continue
            network_note = (
                "the default network, which every service joins when none is "
                "specified" if shared == {"default"}
                else f"network '{sorted(shared)[0]}'"
            )
            chains.append(_chain(
                "chain-lateral-to-datastore",
                f"'{entry_name}' is internet-facing and can reach '{target_name}' "
                f"with a committed credential",
                Severity.HIGH.value,
                [entry_name, target_name],
                ["compose-plaintext-secret-env", "compose-no-network-segmentation"],
                f"'{entry_name}' accepts connections from outside the host and shares "
                f"{network_note} with '{target_name}'. '{target_name}' is not exposed "
                f"directly, but its credential ({', '.join(target['credentials'])}) is "
                f"in the compose file, so compromising '{entry_name}' yields "
                f"authenticated access to it. Neither service looks critical on its "
                f"own.",
                f"Put '{target_name}' on its own network that '{entry_name}' does not "
                f"join, or move {target['credentials'][0]} to a Docker secret so a "
                f"compromise of '{entry_name}' does not hand over the password.",
            ))

    chains.sort(key=lambda c: -Severity.rank(c["severity"]))
    return chains


def to_ai_shape(chains: List[Dict]) -> List[Dict]:
    """Render rule-detected chains in the same shape the model returns them.

    Lets the renderer and the reports treat both sources uniformly.
    """
    return [
        {
            "title": chain["title"],
            "severity": chain["severity"],
            "finding_ids": chain["finding_ids"],
            "services": chain["services"],
            "narrative": chain["narrative"],
            "fix": chain["fix"],
            "source": "rules",
        }
        for chain in chains
    ]
