import os
from typing import Dict, List, Any
from pathlib import Path

try:
    from ruamel.yaml import YAML
except ImportError:
    raise ImportError("ruamel.yaml is required for compose scanning. Install with: pip install ruamel.yaml")

from docksec.enums import Severity
from docksec.utils import get_custom_logger
from docksec.docker_scanner import DockerSecurityScanner

logger = get_custom_logger(__name__)

class ComposeScanner:
    def __init__(self, compose_path: str):
        self.compose_path = Path(compose_path).resolve()
        self.yaml = YAML()
        self.yaml.preserve_quotes = True
        self.yaml.allow_duplicate_keys = True
        self.data = None
        self.findings = []
        
    def parse(self) -> bool:
        try:
            with open(self.compose_path, 'r') as f:
                self.data = self.yaml.load(f)
            if not isinstance(self.data, dict):
                logger.error("Invalid compose file: not a dictionary")
                return False
            return True
        except Exception as e:
            logger.error(f"Failed to parse compose file: {e}")
            return False

    def _add_finding(self, rule_id: str, severity: Severity, title: str, description: str, remediation: str, service: str, line: int):
        self.findings.append({
            "VulnerabilityID": rule_id,
            "Severity": severity.value,
            "Title": title,
            "Description": description,
            "Remediation": remediation,
            "Target": f"{self.compose_path.name}:{service}:{line}",
            "PkgName": "docker-compose",
            "InstalledVersion": "N/A",
            "Status": "affected",
            "CVSS": "N/A",
            "PrimaryURL": ""
        })

    def _get_line(self, node: Any, default: int = 0) -> int:
        if hasattr(node, 'lc') and node.lc.line is not None:
            return node.lc.line + 1
        return default

    def scan(self) -> List[Dict]:
        if not self.data or 'services' not in self.data:
            return self.findings

        services = self.data.get('services', {})
        if not isinstance(services, dict):
            return self.findings

        all_services_default_network = True

        for service_name, service_config in services.items():
            if not isinstance(service_config, dict):
                continue
                
            service_line = self._get_line(service_config)

            # CRITICAL checks
            self._check_socket_mount(service_name, service_config, service_line)
            self._check_privileged(service_name, service_config, service_line)
            self._check_host_network(service_name, service_config, service_line)
            self._check_host_namespace(service_name, service_config, service_line)
            self._check_dangerous_capabilities(service_name, service_config, service_line)
            self._check_sensitive_host_mount(service_name, service_config, service_line)

            # HIGH checks
            self._check_plaintext_secret_env(service_name, service_config, service_line)
            self._check_port_bound_all_interfaces(service_name, service_config, service_line)
            self._check_disabled_security_opt(service_name, service_config, service_line)
            self._check_no_non_root_user(service_name, service_config, service_line)

            # MEDIUM checks
            self._check_latest_or_untagged_image(service_name, service_config, service_line)
            self._check_no_resource_limits(service_name, service_config, service_line)
            self._check_env_file_secret_risk(service_name, service_config, service_line)
            self._check_writable_root_fs(service_name, service_config, service_line)

            # LOW checks
            self._check_no_new_privileges(service_name, service_config, service_line)
            self._check_missing_healthcheck(service_name, service_config, service_line)
            
            if 'networks' in service_config:
                all_services_default_network = False

        if all_services_default_network and services:
            self._add_finding(
                "compose-no-network-segmentation", Severity.LOW, "No Network Segmentation",
                "All services sit on the default network with no segmentation.",
                "Define separate networks and connect only services that must talk.",
                "global", self._get_line(services)
            )

        return self.findings

    def _check_socket_mount(self, service: str, config: dict, default_line: int):
        volumes = config.get('volumes', [])
        if not isinstance(volumes, list):
            return
        for i, vol in enumerate(volumes):
            vol_str = str(vol)
            if '/var/run/docker.sock' in vol_str:
                line = self._get_line(volumes, default_line)
                if hasattr(volumes, 'lc') and hasattr(volumes.lc, 'data') and volumes.lc.data:
                    # Try to get specific item line
                    pass
                self._add_finding(
                    "compose-docker-socket-mount", Severity.CRITICAL, "Docker Socket Mount",
                    "A service bind-mounts /var/run/docker.sock.",
                    "Remove the mount; if socket access is genuinely required, front it with a scoped socket proxy.",
                    service, line
                )

    def _check_privileged(self, service: str, config: dict, default_line: int):
        if config.get('privileged') is True:
            self._add_finding(
                "compose-privileged", Severity.CRITICAL, "Privileged Container",
                "privileged: true on a service.",
                "Remove it and grant only the specific cap_add capabilities actually needed.",
                service, self._get_line(config.get('privileged', config), default_line)
            )

    def _check_host_network(self, service: str, config: dict, default_line: int):
        if config.get('network_mode') == 'host':
            self._add_finding(
                "compose-host-network", Severity.CRITICAL, "Host Network Mode",
                "network_mode: host.",
                "Use a defined network and publish only required ports.",
                service, self._get_line(config.get('network_mode', config), default_line)
            )

    def _check_host_namespace(self, service: str, config: dict, default_line: int):
        if config.get('pid') == 'host' or config.get('ipc') == 'host':
            self._add_finding(
                "compose-host-namespace", Severity.CRITICAL, "Host Namespace",
                "pid: host or ipc: host.",
                "Remove unless strictly required.",
                service, self._get_line(config, default_line)
            )

    def _check_dangerous_capabilities(self, service: str, config: dict, default_line: int):
        cap_add = config.get('cap_add', [])
        if not isinstance(cap_add, list):
            return
        dangerous = {'SYS_ADMIN', 'NET_ADMIN', 'SYS_PTRACE', 'ALL'}
        for cap in cap_add:
            if str(cap).upper() in dangerous:
                self._add_finding(
                    "compose-dangerous-capabilities", Severity.CRITICAL, "Dangerous Capabilities",
                    f"cap_add includes {cap}.",
                    "Drop to least privilege.",
                    service, self._get_line(cap_add, default_line)
                )

    def _check_sensitive_host_mount(self, service: str, config: dict, default_line: int):
        volumes = config.get('volumes', [])
        if not isinstance(volumes, list):
            return
        sensitive = ['/:', '/etc:', '/root:', '/var/run:', '/proc:', '/sys:']
        for vol in volumes:
            vol_str = str(vol)
            if any(vol_str.startswith(s) for s in sensitive):
                self._add_finding(
                    "compose-sensitive-host-mount", Severity.CRITICAL, "Sensitive Host Mount",
                    f"Bind mount of sensitive host directory: {vol_str.split(':')[0]}.",
                    "Scope to a specific subpath and mount read-only where possible.",
                    service, self._get_line(volumes, default_line)
                )

    def _check_plaintext_secret_env(self, service: str, config: dict, default_line: int):
        env = config.get('environment', {})
        if isinstance(env, list):
            # Handle list format: - VAR=value
            for item in env:
                if isinstance(item, str) and '=' in item:
                    k, v = item.split('=', 1)
                    if self._is_secret_key(k) and v and not v.startswith('${'):
                        self._add_finding(
                            "compose-plaintext-secret-env", Severity.HIGH, "Plaintext Secret Environment Variable",
                            "A likely secret in an environment value.",
                            "Move to Docker secrets or an injected secret store; never commit.",
                            service, self._get_line(env, default_line)
                        )
        elif isinstance(env, dict):
            for k, v in env.items():
                if self._is_secret_key(k) and v and not str(v).startswith('${'):
                    self._add_finding(
                        "compose-plaintext-secret-env", Severity.HIGH, "Plaintext Secret Environment Variable",
                        "A likely secret in an environment value.",
                        "Move to Docker secrets or an injected secret store; never commit.",
                        service, self._get_line(env, default_line)
                    )

    def _is_secret_key(self, key: str) -> bool:
        key = str(key).lower()
        return any(s in key for s in ['password', 'secret', 'token', 'api_key', 'private_key', 'private-key'])

    def _check_port_bound_all_interfaces(self, service: str, config: dict, default_line: int):
        ports = config.get('ports', [])
        if not isinstance(ports, list):
            return
        for port in ports:
            port_str = str(port)
            # If it's just "8080:80" or "8080", it binds to 0.0.0.0 by default
            # If it's "127.0.0.1:8080:80", it's bound to localhost
            if ':' in port_str and not port_str.startswith('127.0.0.1:') and not port_str.startswith('localhost:'):
                self._add_finding(
                    "compose-port-bound-all-interfaces", Severity.HIGH, "Port Bound to All Interfaces",
                    "A sensitive or admin port published with no host IP, binding 0.0.0.0.",
                    "Bind to 127.0.0.1, or use expose for internal-only traffic.",
                    service, self._get_line(ports, default_line)
                )

    def _check_disabled_security_opt(self, service: str, config: dict, default_line: int):
        sec_opt = config.get('security_opt', [])
        if not isinstance(sec_opt, list):
            return
        for opt in sec_opt:
            opt_str = str(opt).lower()
            if 'apparmor:unconfined' in opt_str or 'seccomp:unconfined' in opt_str:
                self._add_finding(
                    "compose-disabled-security-opt", Severity.HIGH, "Disabled Security Options",
                    "security_opt sets apparmor:unconfined or seccomp:unconfined.",
                    "Keep default profiles unless there is a tested reason.",
                    service, self._get_line(sec_opt, default_line)
                )

    def _check_no_non_root_user(self, service: str, config: dict, default_line: int):
        if 'user' not in config:
            self._add_finding(
                "compose-no-non-root-user", Severity.HIGH, "No Non-Root User",
                "A service has no user directive and the image likely runs as root.",
                "Set a non-root user.",
                service, default_line
            )

    def _check_latest_or_untagged_image(self, service: str, config: dict, default_line: int):
        image = config.get('image', '')
        if image and (':' not in image or image.endswith(':latest')):
            self._add_finding(
                "compose-latest-or-untagged-image", Severity.MEDIUM, "Latest or Untagged Image",
                "image uses :latest or has no tag.",
                "Pin to a specific, ideally digest-addressed version.",
                service, self._get_line(config.get('image', config), default_line)
            )

    def _check_no_resource_limits(self, service: str, config: dict, default_line: int):
        has_limits = False
        if 'deploy' in config and isinstance(config['deploy'], dict):
            if 'resources' in config['deploy'] and isinstance(config['deploy']['resources'], dict):
                if 'limits' in config['deploy']['resources']:
                    has_limits = True
        if 'mem_limit' in config or 'cpu_limit' in config:
            has_limits = True
            
        if not has_limits:
            self._add_finding(
                "compose-no-resource-limits", Severity.MEDIUM, "No Resource Limits",
                "No memory or CPU limits.",
                "Set limits to bound the DoS and blast-radius surface.",
                service, default_line
            )

    def _check_env_file_secret_risk(self, service: str, config: dict, default_line: int):
        if 'env_file' in config:
            self._add_finding(
                "compose-env-file-secret-risk", Severity.MEDIUM, "Environment File Secret Risk",
                "env_file points to a file that may carry secrets into the repo.",
                "Keep secret files out of version control and use a secret manager.",
                service, self._get_line(config.get('env_file', config), default_line)
            )

    def _check_writable_root_fs(self, service: str, config: dict, default_line: int):
        if config.get('read_only') is not True:
            self._add_finding(
                "compose-writable-root-fs", Severity.MEDIUM, "Writable Root Filesystem",
                "no read_only: true on a service that does not need a writable root.",
                "Set read_only with explicit tmpfs where needed.",
                service, default_line
            )

    def _check_no_new_privileges(self, service: str, config: dict, default_line: int):
        sec_opt = config.get('security_opt', [])
        if isinstance(sec_opt, list):
            has_no_new_privs = any('no-new-privileges:true' in str(opt).lower() for opt in sec_opt)
            if not has_no_new_privs:
                self._add_finding(
                    "compose-no-new-privileges", Severity.LOW, "Missing No-New-Privileges",
                    "security_opt is missing no-new-privileges:true.",
                    "Add it.",
                    service, default_line
                )
        else:
            self._add_finding(
                "compose-no-new-privileges", Severity.LOW, "Missing No-New-Privileges",
                "security_opt is missing no-new-privileges:true.",
                "Add it.",
                service, default_line
            )

    def _check_missing_healthcheck(self, service: str, config: dict, default_line: int):
        if 'healthcheck' not in config:
            self._add_finding(
                "compose-missing-healthcheck", Severity.LOW, "Missing Healthcheck",
                "A long-running service has no healthcheck.",
                "Add one for safer restarts.",
                service, default_line
            )

    def get_services(self) -> Dict[str, Dict]:
        if not self.data or 'services' not in self.data:
            return {}
        return self.data.get('services', {})

def _failure_reason(output: Any, fallback: str) -> str:
    """Condense scanner output into a single short reason line."""
    if isinstance(output, str) and output.strip():
        first_line = output.strip().splitlines()[0]
        if len(first_line) > 120:
            first_line = first_line[:117] + "..."
        return first_line
    return fallback


class ComposeOrchestrator:
    def __init__(self, compose_path: str, scan_only: bool = False, skip_ai_scoring: bool = False):
        self.compose_path = compose_path
        self.scan_only = scan_only
        self.skip_ai_scoring = skip_ai_scoring
        self.scanner = ComposeScanner(compose_path)
        
    def run_full_scan(self, severity: str = "CRITICAL,HIGH") -> Dict:
        if not self.scanner.parse():
            return {
                'dockerfile_scan': {'success': False, 'output': "Failed to parse compose file", 'skipped': False},
                'image_scan': {'success': False, 'output': None, 'skipped': True},
                'json_data': [],
                'timestamp': "",
                'image_name': "N/A",
                'dockerfile_path': self.compose_path,
                'scan_mode': 'compose',
                'failed_services': [],
                'scanned_services': 0
            }
            
        compose_findings = self.scanner.scan()
        all_findings = list(compose_findings)
        
        services = self.scanner.get_services()
        
        dockerfile_outputs = []
        image_outputs = []
        all_success = True
        failed_services = []
        scanned_services = 0

        for service_name, config in services.items():
            if not isinstance(config, dict):
                continue
                
            dockerfile_path = None
            image_name = config.get('image')
            
            build = config.get('build')
            if build:
                if isinstance(build, str):
                    dockerfile_path = os.path.join(build, 'Dockerfile')
                elif isinstance(build, dict):
                    context = build.get('context', '.')
                    dockerfile = build.get('dockerfile', 'Dockerfile')
                    dockerfile_path = os.path.join(context, dockerfile)
                    
            if dockerfile_path and not os.path.isfile(dockerfile_path):
                # Try relative to compose file
                compose_dir = os.path.dirname(self.compose_path)
                alt_path = os.path.join(compose_dir, dockerfile_path)
                if os.path.isfile(alt_path):
                    dockerfile_path = alt_path
                else:
                    dockerfile_path = None
                    
            if not dockerfile_path and not image_name:
                continue
                
            logger.info(f"Scanning service {service_name} (Dockerfile: {dockerfile_path}, Image: {image_name})")
            scanned_services += 1

            try:
                service_scanner = DockerSecurityScanner(
                    dockerfile_path=dockerfile_path,
                    image_name=image_name,
                    scan_only=self.scan_only,
                    skip_ai_scoring=self.skip_ai_scoring
                )
                
                # Disable cache for service scans to ensure fresh results?
                # service_scanner.use_cache = False
                
                if dockerfile_path and not image_name:
                    # Only dockerfile
                    df_success, df_output = service_scanner.scan_dockerfile()
                    if not df_success:
                        all_success = False
                    if df_output:
                        dockerfile_outputs.append(f"--- Service: {service_name} ---\n{df_output}")
                elif image_name and not dockerfile_path:
                    # Only image
                    res = service_scanner.run_image_only_scan(severity)
                    if not res['image_scan']['success']:
                        all_success = False
                        failed_services.append({
                            'service': service_name,
                            'reason': _failure_reason(res['image_scan'].get('output'),
                                                      f"image scan failed for {image_name}")
                        })
                    if res['image_scan']['output']:
                        image_outputs.append(f"--- Service: {service_name} ---\n{res['image_scan']['output']}")
                    if res.get('json_data'):
                        # Tag findings with service name
                        for f in res['json_data']:
                            f['Target'] = f"{service_name} ({f.get('Target', '')})"
                        all_findings.extend(res['json_data'])
                else:
                    # Both
                    res = service_scanner.run_full_scan(severity)
                    if not res['dockerfile_scan']['success'] or not res['image_scan']['success']:
                        all_success = False
                    # Hadolint "failure" usually just means lint findings (already
                    # rendered elsewhere); only a failed image scan means the
                    # service's vulnerability data is missing.
                    if not res['image_scan']['success']:
                        failed_services.append({
                            'service': service_name,
                            'reason': _failure_reason(res['image_scan'].get('output'),
                                                      f"image scan failed for {image_name}")
                        })
                    if res['dockerfile_scan']['output'] and not res['dockerfile_scan'].get('skipped'):
                        dockerfile_outputs.append(f"--- Service: {service_name} ---\n{res['dockerfile_scan']['output']}")
                    if res['image_scan']['output'] and not res['image_scan'].get('skipped'):
                        image_outputs.append(f"--- Service: {service_name} ---\n{res['image_scan']['output']}")
                    if res.get('json_data'):
                        for f in res['json_data']:
                            f['Target'] = f"{service_name} ({f.get('Target', '')})"
                        all_findings.extend(res['json_data'])
            except Exception as e:
                logger.error(f"Failed to scan service {service_name}: {e}")
                all_success = False
                failed_services.append({'service': service_name, 'reason': str(e)})

        from datetime import datetime
        return {
            'dockerfile_scan': {
                'success': all_success,
                'output': "\n\n".join(dockerfile_outputs) if dockerfile_outputs else "No Dockerfile issues found or scanned.",
                'skipped': not bool(dockerfile_outputs)
            },
            'image_scan': {
                'success': all_success,
                'output': "\n\n".join(image_outputs) if image_outputs else "No image issues found or scanned.",
                'skipped': not bool(image_outputs)
            },
            'json_data': all_findings,
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'image_name': "Multiple Services",
            'dockerfile_path': self.compose_path,
            'scan_mode': 'compose',
            'failed_services': failed_services,
            'scanned_services': scanned_services
        }
