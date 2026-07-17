from docksec.ignore import (
    apply_ignores,
    find_default_ignore_file,
    load_ignore_file,
    DEFAULT_IGNORE_FILE,
)


def _write(tmp_path, content, name=DEFAULT_IGNORE_FILE):
    p = tmp_path / name
    p.write_text(content)
    return str(p)


def test_load_valid_ignore_file(tmp_path):
    path = _write(tmp_path, (
        "ignores:\n"
        "  - id: CVE-2023-45853\n"
        "    reason: not reachable\n"
        "  - id: compose-missing-healthcheck\n"
        "    reason: platform handles healthchecks\n"
        "    expires: 2099-12-31\n"
    ))
    entries, warnings = load_ignore_file(path)
    assert len(entries) == 2
    assert warnings == []


def test_expired_entry_dropped_with_warning(tmp_path):
    path = _write(tmp_path, (
        "ignores:\n"
        "  - id: CVE-2020-0001\n"
        "    reason: old waiver\n"
        "    expires: 2020-01-01\n"
    ))
    entries, warnings = load_ignore_file(path)
    assert entries == []
    assert any("expired" in w for w in warnings)


def test_missing_reason_warns_but_applies(tmp_path):
    path = _write(tmp_path, "ignores:\n  - id: CVE-2024-1111\n")
    entries, warnings = load_ignore_file(path)
    assert len(entries) == 1
    assert any("reason" in w for w in warnings)


def test_invalid_file_shape(tmp_path):
    path = _write(tmp_path, "not_ignores: []\n")
    entries, warnings = load_ignore_file(path)
    assert entries == []
    assert len(warnings) == 1


def test_apply_ignores_filters_case_insensitive():
    findings = [
        {"VulnerabilityID": "CVE-2024-1111", "Severity": "HIGH"},
        {"VulnerabilityID": "cve-2024-2222", "Severity": "LOW"},
        {"VulnerabilityID": "CVE-2024-3333", "Severity": "CRITICAL"},
    ]
    entries = [{"id": "cve-2024-1111"}, {"id": "CVE-2024-2222"}]
    kept, suppressed = apply_ignores(findings, entries)
    assert suppressed == 2
    assert [f["VulnerabilityID"] for f in kept] == ["CVE-2024-3333"]


def test_apply_ignores_noop_without_entries():
    findings = [{"VulnerabilityID": "CVE-2024-1111"}]
    kept, suppressed = apply_ignores(findings, [])
    assert kept == findings and suppressed == 0


def test_find_default_ignore_file(tmp_path):
    assert find_default_ignore_file(str(tmp_path)) is None
    _write(tmp_path, "ignores: []\n")
    assert find_default_ignore_file(str(tmp_path)) is not None
