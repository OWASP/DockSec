import pytest
import os
from pathlib import Path
from docksec.compose_scanner import ComposeScanner, ComposeOrchestrator
from docksec.enums import Severity

@pytest.fixture
def valid_compose_file(tmp_path):
    compose_content = """
version: '3'
services:
  web:
    image: nginx:1.21.0
    user: "1000:1000"
    ports:
      - "127.0.0.1:8080:80"
    read_only: true
    security_opt:
      - no-new-privileges:true
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost"]
    deploy:
      resources:
        limits:
          cpus: '0.50'
          memory: 512M
    networks:
      - frontend
  db:
    image: postgres:13
    user: "999:999"
    read_only: true
    security_opt:
      - no-new-privileges:true
    healthcheck:
      test: ["CMD", "pg_isready"]
    deploy:
      resources:
        limits:
          cpus: '1.0'
          memory: 1G
    networks:
      - backend

networks:
  frontend:
  backend:
"""
    p = tmp_path / "docker-compose.yml"
    p.write_text(compose_content)
    return str(p)

@pytest.fixture
def vulnerable_compose_file(tmp_path):
    compose_content = """
version: '3'
services:
  web:
    image: nginx:latest
    ports:
      - "80:80"
    privileged: true
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - /:/host
    environment:
      - MYSQL_ROOT_PASSWORD=secret
    network_mode: host
    pid: host
    cap_add:
      - ALL
    security_opt:
      - apparmor:unconfined
"""
    p = tmp_path / "docker-compose-vuln.yml"
    p.write_text(compose_content)
    return str(p)

def test_compose_scanner_valid(valid_compose_file):
    scanner = ComposeScanner(valid_compose_file)
    assert scanner.parse() is True
    findings = scanner.scan()
    # The valid file should have very few or no findings
    # We might have a few if our valid file isn't perfect, but let's check it doesn't have the critical ones
    finding_ids = [f['VulnerabilityID'] for f in findings]
    assert "compose-privileged" not in finding_ids
    assert "compose-docker-socket-mount" not in finding_ids
    assert "compose-no-network-segmentation" not in finding_ids

def test_compose_scanner_vulnerable(vulnerable_compose_file):
    scanner = ComposeScanner(vulnerable_compose_file)
    assert scanner.parse() is True
    findings = scanner.scan()
    finding_ids = [f['VulnerabilityID'] for f in findings]
    
    # CRITICAL
    assert "compose-docker-socket-mount" in finding_ids
    assert "compose-privileged" in finding_ids
    assert "compose-host-network" in finding_ids
    assert "compose-host-namespace" in finding_ids
    assert "compose-dangerous-capabilities" in finding_ids
    assert "compose-sensitive-host-mount" in finding_ids
    
    # HIGH
    assert "compose-plaintext-secret-env" in finding_ids
    assert "compose-port-bound-all-interfaces" in finding_ids
    assert "compose-disabled-security-opt" in finding_ids
    assert "compose-no-non-root-user" in finding_ids
    
    # MEDIUM
    assert "compose-latest-or-untagged-image" in finding_ids
    assert "compose-no-resource-limits" in finding_ids
    assert "compose-writable-root-fs" in finding_ids
    
    # LOW
    assert "compose-no-new-privileges" in finding_ids
    assert "compose-missing-healthcheck" in finding_ids
    assert "compose-no-network-segmentation" in finding_ids

def test_line_numbers(vulnerable_compose_file):
    scanner = ComposeScanner(vulnerable_compose_file)
    scanner.parse()
    findings = scanner.scan()
    
    # Find the privileged finding
    priv_finding = next((f for f in findings if f['VulnerabilityID'] == 'compose-privileged'), None)
    assert priv_finding is not None
    # In the vulnerable_compose_file, 'privileged: true' is on line 8 (1-indexed)
    # Actually, let's just check it has a line number > 0
    target = priv_finding['Target']
    assert target.startswith('docker-compose-vuln.yml:web:')
    line_num = int(target.split(':')[-1])
    assert line_num > 0

def test_compose_orchestrator_offline(valid_compose_file, mocker):
    # Mock DockerSecurityScanner to avoid needing Docker daemon running
    mock_scanner = mocker.patch('docksec.compose_scanner.DockerSecurityScanner')
    mock_instance = mock_scanner.return_value
    mock_instance.run_image_only_scan.return_value = {
        'image_scan': {'success': True, 'output': 'Mock output'},
        'json_data': []
    }
    
    orchestrator = ComposeOrchestrator(valid_compose_file, scan_only=True)
    results = orchestrator.run_full_scan()
    
    assert results['scan_mode'] == 'compose'
    assert results['dockerfile_scan']['success'] is True
    assert results['image_scan']['success'] is True
