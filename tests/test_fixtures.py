"""Each fixture must get its expected verdict from real inventory and real scanner output.

tests/data/cisco holds reports recorded from cisco-ai-skill-scanner 2.3.2 with
policy/cisco-strict.yaml. self-test.yml re-runs the scanner live.
"""

import json
import os
import pathlib

import pytest

import inventory
import verdict

TESTS = pathlib.Path(__file__).parent
FIXTURES = TESTS / "fixtures"

EXPECTED = {
    "benign-skill": ("PASS", set()),
    "injection-skill": ("FAIL", {"PROMPT_INJECTION_IGNORE_INSTRUCTIONS", "PROMPT_INJECTION_CONCEALMENT"}),
    "exfil-skill": ("FAIL", {"DATA_EXFIL_HTTP_POST", "BEHAVIOR_CREDENTIAL_FILE_ACCESS"}),
    "hook-plugin": ("REVIEW", {"HOOK"}),
    "mcp-plugin": ("REVIEW", {"MCP_SERVER"}),
    "postinstall-plugin": ("REVIEW", {"LIFECYCLE_SCRIPT"}),
    "symlink-escape": ("FAIL", {"SYMLINK_ESCAPE"}),
    "bypass-settings": ("FAIL", {"BYPASS_PERMISSIONS"}),
}


def judge(name):
    inv = inventory.build_inventory(str(FIXTURES / name))
    report = json.loads((TESTS / "data" / "cisco" / f"{name}.json").read_text(encoding="utf-8"))
    return verdict.decide(inv, report, None, snyk_requested=False, target=f"/fx/{name}")


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_fixture_gets_expected_verdict(name):
    result, _ = judge(name)
    assert result == EXPECTED[name][0]


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_fixture_verdict_has_expected_reasons(name):
    _, reasons = judge(name)
    assert EXPECTED[name][1] <= {r["rule"] for r in reasons}


def test_every_fixture_has_an_expectation():
    assert {p.name for p in FIXTURES.iterdir() if p.is_dir()} == set(EXPECTED)


def test_no_fixture_is_executable():
    for directory, _, names in os.walk(FIXTURES):
        for name in names:
            path = os.path.join(directory, name)
            if not os.path.islink(path):
                assert not os.stat(path).st_mode & 0o111, path
