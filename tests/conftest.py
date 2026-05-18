"""Pytest configuration and fixtures."""

import os
import shutil
import tempfile

import pytest


@pytest.fixture
def temp_dir():
    """Create a temporary directory for tests."""
    test_dir = tempfile.mkdtemp()
    yield test_dir
    shutil.rmtree(test_dir)


@pytest.fixture
def sample_dockerfile(temp_dir):
    """Create a sample Dockerfile for testing."""
    dockerfile_path = os.path.join(temp_dir, "Dockerfile")
    with open(dockerfile_path, "w") as f:
        f.write("FROM ubuntu:latest\nRUN echo 'test'\n")
    return dockerfile_path


@pytest.fixture
def sample_vulnerabilities():
    return [
        {
            "VulnerabilityID": "CVE-2023-1234",
            "Severity": "CRITICAL",
            "PkgName": "openssl",
            "InstalledVersion": "1.0.0",
            "Title": "Buffer overflow in openssl",
            "CVSS": 9.8,
            "Status": "fixed",
            "Target": "python:3.9-slim",
            "PrimaryURL": "https://nvd.nist.gov/vuln/detail/CVE-2023-1234",
        }
    ]


@pytest.fixture
def sample_scan_info():
    return {
        "image": "python:3.9-slim",
        "scan_date": "2024-01-01T00:00:00",
        "scanner": "trivy",
    }
