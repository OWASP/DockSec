"""Tests for cross-service exploit chain detection.

Chains are detected by rules rather than by the model so the flagship output
survives --scan-only, works offline, and returns the same answer twice.
"""

import unittest

from docksec import chains


def _stack(services):
    return {"services": services}


class TestExposedCredentialedDatastore(unittest.TestCase):
    """A datastore that is both reachable and has its password committed."""

    def test_public_port_plus_credential_is_critical(self):
        found = chains.detect(_stack({
            "db": {
                "image": "postgres:16",
                "ports": ["5432:5432"],
                "environment": {"POSTGRES_PASSWORD": "hunter2"},
            }
        }))
        self.assertTrue(found)
        self.assertEqual(found[0]["severity"], "CRITICAL")
        self.assertIn("PostgreSQL", found[0]["title"])

    def test_localhost_binding_is_not_a_chain(self):
        """Bound to 127.0.0.1 the datastore is not remotely reachable, so the
        credential alone is a finding rather than a path."""
        found = chains.detect(_stack({
            "db": {
                "image": "postgres:16",
                "ports": ["127.0.0.1:5432:5432"],
                "environment": {"POSTGRES_PASSWORD": "hunter2"},
            }
        }))
        self.assertEqual(found, [])

    def test_no_credential_is_not_this_chain(self):
        found = chains.detect(_stack({
            "db": {"image": "postgres:16", "ports": ["5432:5432"]}
        }))
        chain_ids = [c["chain_id"] for c in found]
        self.assertNotIn("chain-exposed-credentialed-datastore", chain_ids)

    def test_secret_file_indirection_is_not_a_credential(self):
        """POSTGRES_PASSWORD_FILE points at a Docker secret - the recommended
        pattern - and must not be read as a committed password."""
        found = chains.detect(_stack({
            "db": {
                "image": "postgres:16",
                "ports": ["5432:5432"],
                "environment": {"POSTGRES_PASSWORD_FILE": "/run/secrets/db"},
            }
        }))
        self.assertEqual(found, [])

    def test_interpolated_value_is_not_a_committed_credential(self):
        found = chains.detect(_stack({
            "db": {
                "image": "postgres:16",
                "ports": ["5432:5432"],
                "environment": {"POSTGRES_PASSWORD": "${DB_PASSWORD}"},
            }
        }))
        self.assertEqual(found, [])

    def test_list_style_environment_is_handled(self):
        found = chains.detect(_stack({
            "db": {
                "image": "postgres:16",
                "ports": ["5432:5432"],
                "environment": ["POSTGRES_PASSWORD=hunter2"],
            }
        }))
        self.assertTrue(found)


class TestExposedEscapePath(unittest.TestCase):
    """An exposed service that can already escape the container."""

    def test_socket_mount_plus_exposure_is_critical(self):
        found = chains.detect(_stack({
            "web": {
                "image": "nginx",
                "ports": ["80:80"],
                "volumes": ["/var/run/docker.sock:/var/run/docker.sock"],
            }
        }))
        self.assertTrue(any(c["chain_id"] == "chain-exposed-escape-path" for c in found))
        self.assertIn("Docker socket", found[0]["title"])

    def test_privileged_plus_exposure_is_critical(self):
        found = chains.detect(_stack({
            "web": {"image": "nginx", "ports": ["80:80"], "privileged": True}
        }))
        self.assertTrue(any(c["chain_id"] == "chain-exposed-escape-path" for c in found))

    def test_escape_path_without_exposure_is_not_a_chain(self):
        """Still a serious finding, but not a remotely reachable path - the
        compose rules report it on its own."""
        found = chains.detect(_stack({
            "worker": {"image": "busybox", "privileged": True}
        }))
        self.assertEqual(found, [])

    def test_host_network_counts_as_exposure(self):
        found = chains.detect(_stack({
            "web": {"image": "nginx", "network_mode": "host", "privileged": True}
        }))
        self.assertTrue(found)


class TestLateralMovement(unittest.TestCase):
    """The chain no per-service view can see: each service looks acceptable,
    the pair is a path."""

    def test_internet_facing_service_reaching_a_credentialed_datastore(self):
        found = chains.detect(_stack({
            "web": {"image": "nginx", "ports": ["80:80"]},
            "db": {
                "image": "postgres:16",
                "environment": {"POSTGRES_PASSWORD": "hunter2"},
            },
        }))
        lateral = [c for c in found if c["chain_id"] == "chain-lateral-to-datastore"]
        self.assertEqual(len(lateral), 1)
        self.assertEqual(sorted(lateral[0]["services"]), ["db", "web"])

    def test_network_segmentation_breaks_the_chain(self):
        found = chains.detect(_stack({
            "web": {"image": "nginx", "ports": ["80:80"], "networks": ["front"]},
            "db": {
                "image": "postgres:16", "networks": ["back"],
                "environment": {"POSTGRES_PASSWORD": "hunter2"},
            },
        }))
        self.assertEqual(
            [c for c in found if c["chain_id"] == "chain-lateral-to-datastore"], []
        )

    def test_default_network_is_shared_implicitly(self):
        """Services with no networks key all join the default network - the
        reason this chain is so common."""
        found = chains.detect(_stack({
            "web": {"image": "nginx", "ports": ["80:80"]},
            "db": {"image": "postgres", "environment": {"POSTGRES_PASSWORD": "x"}},
        }))
        lateral = [c for c in found if c["chain_id"] == "chain-lateral-to-datastore"]
        self.assertTrue(lateral)
        self.assertIn("default network", lateral[0]["narrative"])

    def test_publicly_exposed_datastore_is_not_double_reported(self):
        """That case is the stronger chain-1; reporting both would be noise."""
        found = chains.detect(_stack({
            "web": {"image": "nginx", "ports": ["80:80"]},
            "db": {
                "image": "postgres", "ports": ["5432:5432"],
                "environment": {"POSTGRES_PASSWORD": "x"},
            },
        }))
        self.assertEqual(
            [c for c in found if c["chain_id"] == "chain-lateral-to-datastore"], []
        )


class TestChainQuality(unittest.TestCase):
    def test_chains_are_ordered_most_severe_first(self):
        found = chains.detect(_stack({
            "web": {"image": "nginx", "ports": ["80:80"]},
            "db": {
                "image": "postgres", "ports": ["5432:5432"],
                "environment": {"POSTGRES_PASSWORD": "x"},
            },
            "cache": {"image": "redis", "environment": {"REDIS_PASSWORD": "y"}},
        }))
        severities = [c["severity"] for c in found]
        ranked = sorted(severities, key=lambda s: {"CRITICAL": 0, "HIGH": 1}.get(s, 2))
        self.assertEqual(severities, ranked)

    def test_every_chain_names_a_concrete_fix(self):
        found = chains.detect(_stack({
            "web": {"image": "nginx", "ports": ["80:80"], "privileged": True},
            "db": {"image": "postgres", "environment": {"POSTGRES_PASSWORD": "x"}},
        }))
        self.assertTrue(found)
        for chain in found:
            self.assertTrue(chain["fix"], f"{chain['chain_id']} has no fix")
            self.assertTrue(chain["narrative"])
            self.assertTrue(chain["finding_ids"])

    def test_detection_is_deterministic(self):
        stack = _stack({
            "web": {"image": "nginx", "ports": ["80:80"]},
            "db": {"image": "postgres", "environment": {"POSTGRES_PASSWORD": "x"}},
        })
        first = chains.detect(stack)
        for _ in range(4):
            self.assertEqual(chains.detect(stack), first)


class TestEdgeCases(unittest.TestCase):
    def test_empty_and_malformed_input(self):
        for data in (None, {}, {"services": {}}, {"services": "not a dict"}):
            with self.subTest(data=data):
                self.assertEqual(chains.detect(data), [])

    def test_non_dict_service_config_is_skipped(self):
        self.assertEqual(chains.detect(_stack({"web": "nope"})), [])

    def test_long_syntax_ports_are_parsed(self):
        found = chains.detect(_stack({
            "db": {
                "image": "postgres",
                "ports": [{"target": 5432, "published": 5432, "protocol": "tcp"}],
                "environment": {"POSTGRES_PASSWORD": "x"},
            }
        }))
        self.assertTrue(found)


class TestBundledExamples(unittest.TestCase):
    """End-to-end on the examples an evaluator runs first."""

    def _load(self, name):
        from ruamel.yaml import YAML
        with open(f"examples/compose/{name}") as handle:
            return YAML(typ="safe").load(handle)

    def test_insecure_example_has_chains(self):
        found = chains.detect(self._load("docker-compose-insecure.yml"))
        self.assertGreaterEqual(len(found), 2)
        self.assertTrue(any(c["severity"] == "CRITICAL" for c in found))

    def test_secure_example_has_none(self):
        """A hardened stack must produce no chains, or the signal is noise."""
        self.assertEqual(chains.detect(self._load("docker-compose-secure.yml")), [])


if __name__ == "__main__":
    unittest.main()


class TestRuleDocumentation(unittest.TestCase):
    """Every compose rule must have a documentation page.

    A rule that exists only as a string in a Python file gives a reviewer no way
    to judge whether a finding is real, and nothing for a search engine to find.
    """

    def _rule_ids(self):
        import re
        from pathlib import Path

        source = Path("docksec/compose_scanner.py").read_text()
        return set(re.findall(r'"(compose-[a-z-]+)"', source))

    def _tracked_pages(self):
        """Rule pages as git sees them, not as the working tree does.

        Checking the filesystem alone passed locally while CI failed: the page
        for compose-latest-or-untagged-image existed on disk but was matched by
        an unanchored `*TEST*.md` ignore rule ("latest" contains "test"), so it
        was never committed. A doc-coverage guard that cannot see that is not
        guarding much.
        """
        import subprocess

        result = subprocess.run(
            ["git", "ls-files", "docs/rules/compose-*.md"],
            capture_output=True, text=True, check=False,
        )
        if result.returncode != 0:
            self.skipTest("not a git checkout")
        return {
            line.rsplit("/", 1)[-1].removesuffix(".md")
            for line in result.stdout.splitlines() if line.strip()
        }

    def test_every_rule_has_a_page(self):
        from pathlib import Path

        documented = {p.stem for p in Path("docs/rules").glob("compose-*.md")}
        missing = self._rule_ids() - documented
        self.assertFalse(missing, f"rules with no documentation page: {sorted(missing)}")

    def test_every_rule_page_is_committed(self):
        """A page that exists only in the working tree ships to nobody."""
        missing = self._rule_ids() - self._tracked_pages()
        self.assertFalse(
            missing,
            f"rule pages exist on disk but are not tracked by git (check "
            f".gitignore): {sorted(missing)}",
        )

    def test_no_orphan_pages(self):
        """A page for a rule that no longer exists is worse than none: it
        documents behaviour the tool does not have."""
        from pathlib import Path

        documented = {p.stem for p in Path("docs/rules").glob("compose-*.md")}
        orphans = documented - self._rule_ids()
        self.assertFalse(orphans, f"pages for rules that no longer exist: {sorted(orphans)}")

    def test_pages_carry_the_required_sections(self):
        from pathlib import Path

        required = [
            "## What it catches",
            "## Why it matters",
            "## How to fix it",
            "## When you might keep it",
        ]
        for page in Path("docs/rules").glob("compose-*.md"):
            text = page.read_text()
            for section in required:
                with self.subTest(page=page.name, section=section):
                    self.assertIn(section, text)

    def test_index_lists_every_rule(self):
        from pathlib import Path

        index = Path("docs/rules/README.md").read_text()
        for rule_id in self._rule_ids():
            with self.subTest(rule=rule_id):
                self.assertIn(rule_id, index)
