#!/usr/bin/env python3
"""Merge the inventory and scanner reports into a PASS / REVIEW / FAIL verdict.

FAIL beats REVIEW and REVIEW beats PASS. Scanner trouble fails closed. Everything
read from the reports is influenced by the scanned repo, so it is treated as
untrusted when written to the job summary or workflow commands.
"""

import argparse
import datetime
import html
import json
import os
import re
import sys
import unicodedata

REQUIRED_ANALYZERS = {"static_analyzer", "behavioral_analyzer", "osv_analyzer"}
SEVERITY_LEVELS = {"CRITICAL": "FAIL", "HIGH": "FAIL", "MEDIUM": "REVIEW", "LOW": None, "INFO": None}

# Snyk reports 0-1000 scores, not severities. These are the boundaries of the
# risk bands in its printer: 300-599, 600-999 and 1000.
SNYK_REVIEW_SCORE = 300
SNYK_FAIL_SCORE = 600
SNYK_CRITICAL_SCORE = 1000

REVIEW_ITEMS = (
    ("hooks", "HOOK"),
    ("mcp_servers", "MCP_SERVER"),
    ("lifecycle", "LIFECYCLE_SCRIPT"),
    ("binaries", "BINARY_OR_ARCHIVE"),
    ("exec_surfaces", "EXECUTABLE_SURFACE"),
    ("unparseable", "LOW_ANALYZABILITY"),
)
INVENTORY_LISTS = (
    "skills",
    "prompts",
    "hooks",
    "mcp_servers",
    "scripts",
    "lifecycle",
    "binaries",
    "symlinks",
    "bypass_settings",
    "prompt_injection",
    "exec_surfaces",
    "unparseable",
)
COUNT_LABELS = (
    ("skills", "skills"),
    ("prompts", "commands/agents"),
    ("hooks", "hooks"),
    ("mcp_servers", "MCP servers"),
    ("exec_surfaces", "other executable surfaces"),
    ("lifecycle", "lifecycle scripts"),
    ("scripts", "scripts"),
    ("binaries", "binaries/archives"),
    ("symlinks", "symlinks"),
)
VERDICT_ICONS = {"PASS": "✅", "REVIEW": "⚠️", "FAIL": "❌"}

MAX_REASON_ROWS = 30
MAX_COMMAND_BLOCKS = 20
MAX_BLOCK_CHARS = 2000
MAX_ANNOTATION_REASONS = 10

SHA_RE = re.compile(r"[0-9a-f]{40}")
REPO_RE = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
SUBPATH_RE = re.compile(r"[A-Za-z0-9_./-]*")


def reason(level, severity, rule, location, source, detail=""):
    return {"level": level, "severity": severity, "rule": rule, "location": location, "source": source, "detail": detail}


def scanner_error(detail, source="cisco"):
    return reason("FAIL", "ERROR", "SCANNER_ERROR", source, source, detail)


def location_of(item):
    return f"{item['file']}:{item['line']}" if item.get("line") else item["file"]


def inventory_is_usable(inventory):
    return (
        isinstance(inventory, dict)
        and inventory.get("schema") == 1
        and isinstance(inventory.get("totals"), dict)
        and all(isinstance(inventory.get(key), list) for key in INVENTORY_LISTS)
    )


def inventory_reasons(inventory):
    reasons = []
    for item in inventory["symlinks"]:
        if item["escapes"]:
            reasons.append(reason("FAIL", "FAIL", "SYMLINK_ESCAPE", item["file"], "inventory", item["target"]))
        else:
            reasons.append(reason("REVIEW", "REVIEW", "INTERNAL_SYMLINK", f"{item['file']} -> {item['target']}", "inventory"))
    for item in inventory["bypass_settings"]:
        reasons.append(reason("FAIL", "FAIL", "BYPASS_PERMISSIONS", location_of(item), "inventory", item["setting"]))
    for item in inventory["prompt_injection"]:
        reasons.append(reason("FAIL", "HIGH", item["rule"], location_of(item), "inventory", item["snippet"]))
    for field, rule in REVIEW_ITEMS:
        for item in inventory[field]:
            reasons.append(reason("REVIEW", "REVIEW", rule, location_of(item), "inventory"))
    for item in [*inventory["skills"], *inventory["prompts"]]:
        if item.get("unrestricted_tools"):
            reasons.append(reason("REVIEW", "REVIEW", "UNRESTRICTED_TOOLS", location_of(item), "inventory"))
        if item.get("frontmatter_error"):
            reasons.append(reason("REVIEW", "REVIEW", "LOW_ANALYZABILITY", location_of(item), "inventory", "unreadable frontmatter"))
    if inventory["totals"].get("too_large"):
        reasons.append(reason("REVIEW", "REVIEW", "TOO_LARGE", "repository", "inventory", "too large to analyze"))
    return reasons


def relative_to_target(path, target):
    root = target.rstrip("/")
    if path == root or path.startswith(root + "/"):
        return os.path.relpath(path, root)
    return path


def cisco_location(finding, skill_dir, target):
    file_path = finding.get("file_path")
    if not file_path:
        return skill_dir if skill_dir else "(cross-skill)"
    if os.path.isabs(file_path):
        location = relative_to_target(file_path, target)
    else:
        location = os.path.normpath(os.path.join(skill_dir or "", file_path))
    line = finding.get("line_number")
    return f"{location}:{line}" if line else location


def finding_reason(finding, skill_dir, target):
    severity = finding.get("severity")
    severity = severity.upper() if isinstance(severity, str) else severity
    if not isinstance(severity, str) or severity not in SEVERITY_LEVELS:
        return scanner_error(f"unknown severity on {finding.get('rule_id')}")
    level = SEVERITY_LEVELS[severity]
    if level is None:
        return None
    return reason(level, severity, str(finding.get("rule_id")), cisco_location(finding, skill_dir, target), "cisco")


def cisco_shape_problem(report):
    if not isinstance(report, dict) or not isinstance(report.get("summary"), dict):
        return "report has no summary"
    results = report.get("results")
    if not isinstance(results, list):
        return "report has no results list"
    for result in results:
        if not isinstance(result, dict) or not isinstance(result.get("skill_path"), str):
            return "result has no skill path"
        findings = result.get("findings")
        if not isinstance(findings, list) or not all(isinstance(f, dict) for f in findings):
            return "result has no findings list"
        analyzers = result.get("analyzers_used")
        if not isinstance(analyzers, list) or not REQUIRED_ANALYZERS <= set(analyzers):
            return f"required analyzer did not run on {result['skill_path']}"
    cross = report.get("cross_skill_findings", [])
    if not isinstance(cross, list) or not all(isinstance(f, dict) for f in cross):
        return "cross-skill findings are malformed"
    return None


def cisco_reasons(report, inventory, target):
    if report is None:
        if inventory["totals"].get("too_large"):
            return []
        if not inventory["skills"]:
            return [reason("REVIEW", "REVIEW", "LOW_ANALYZABILITY", "repository", "cisco", "no SKILL.md for the scanner to read")]
        return [scanner_error("report is missing or unparseable")]

    problem = cisco_shape_problem(report)
    if problem:
        return [scanner_error(problem)]

    reasons = []
    if report["summary"].get("skills_skipped"):
        reasons.append(scanner_error("scanner skipped a skill it could not load"))

    analyzed = set()
    for result in report["results"]:
        skill_dir = relative_to_target(result["skill_path"], target)
        analyzed.add(skill_dir)
        reasons.extend(finding_reason(f, skill_dir, target) for f in result["findings"])
    reasons.extend(finding_reason(f, None, target) for f in report.get("cross_skill_findings", []))

    for skill in inventory["skills"]:
        if (os.path.dirname(skill["file"]) or ".") not in analyzed:
            reasons.append(reason("REVIEW", "REVIEW", "LOW_ANALYZABILITY", skill["file"], "cisco", "scanner did not analyze this skill"))
    if not inventory["skills"] and not report["results"]:
        reasons.append(reason("REVIEW", "REVIEW", "LOW_ANALYZABILITY", "repository", "cisco", "no SKILL.md for the scanner to read"))
    return [r for r in reasons if r is not None]


def snyk_failed(entry):
    error = entry.get("error")
    return bool(error) and error.get("is_failure", True)


def snyk_risk_reason(index, risk, name):
    score = risk["score"]
    if isinstance(score, bool) or not isinstance(score, int):
        raise TypeError("score is not an integer")
    if score >= SNYK_CRITICAL_SCORE:
        return reason("FAIL", "CRITICAL", index, name, "snyk")
    if score >= SNYK_FAIL_SCORE:
        return reason("FAIL", "HIGH", index, name, "snyk")
    if score >= SNYK_REVIEW_SCORE:
        return reason("REVIEW", "MEDIUM", index, name, "snyk")
    return None


def snyk_reasons(report, inventory):
    if report is None:
        return [scanner_error("report is missing or unparseable", "snyk")]
    reasons = []
    skills_analyzed = 0
    try:
        paths = report["scan_path_responses"]
        if not isinstance(paths, list) or not paths:
            raise TypeError("no scan results")
        for path in paths:
            if snyk_failed(path):
                reasons.append(scanner_error("scanner reported a failure", "snyk"))
            skills_analyzed += len(path["skill_risks"])
            for component in [*path["server_risks"], *path["skill_risks"]]:
                if snyk_failed(component):
                    reasons.append(scanner_error("scanner reported a failure", "snyk"))
                for index, risk in component.get("risk_indexes", {}).items():
                    if risk is not None:
                        reasons.append(snyk_risk_reason(index, risk, str(component.get("name"))))
    except (KeyError, TypeError, AttributeError):
        return [scanner_error("report is malformed", "snyk")]
    if skills_analyzed < len(inventory["skills"]):
        reasons.append(reason("REVIEW", "REVIEW", "LOW_ANALYZABILITY", "repository", "snyk", "scanner did not analyze every skill"))
    return [r for r in reasons if r is not None]


def decide(inventory, cisco, snyk, snyk_requested, target):
    if not inventory_is_usable(inventory):
        return "FAIL", [reason("FAIL", "ERROR", "INVENTORY_ERROR", "inventory.json", "inventory", "inventory is missing or malformed")]
    reasons = inventory_reasons(inventory) + cisco_reasons(cisco, inventory, target)
    if snyk_requested:
        reasons += snyk_reasons(snyk, inventory)
    reasons.sort(key=lambda r: r["level"] != "FAIL")
    if any(r["level"] == "FAIL" for r in reasons):
        return "FAIL", reasons
    return ("REVIEW", reasons) if reasons else ("PASS", reasons)


def visible(text):
    """Show control and invisible characters as escapes, so what is printed is what would run."""
    out = []
    for char in str(text):
        category = unicodedata.category(char)
        hidden = category[0] == "C" or category in ("Zl", "Zp")
        out.append(f"\\u{ord(char):04x}" if hidden and char not in "\n\t" else char)
    return "".join(out)


def cell(value, limit=120):
    text = visible(" ".join(str(value).split()))[:limit]
    return re.sub(r"([\\`*_\[\]|~])", r"\\\1", html.escape(text, quote=False))


def code_block(text):
    shown = visible(text)
    note = ""
    if len(shown) > MAX_BLOCK_CHARS:
        shown = shown[:MAX_BLOCK_CHARS]
        note = "\n\n_truncated; the full text is in the reports artifact_"
    longest = max((len(run) for run in re.findall(r"`+", shown)), default=0)
    fence = "`" * max(3, longest + 1)
    return f"{fence}\n{shown}\n{fence}{note}"


def command_entries(inventory):
    entries = []
    for hook in inventory["hooks"]:
        entries.append((f"hook {hook['event']}", location_of(hook), hook["command"]))
    for server in inventory["mcp_servers"]:
        text = server.get("url") or " ".join(str(part) for part in [server.get("command"), *server.get("args", [])] if part)
        entries.append((f"MCP {server['name']}", location_of(server), text))
    for item in inventory["lifecycle"]:
        entries.append((f"lifecycle {item['kind']}", location_of(item), item.get("command") or item["file"]))
    for item in inventory["exec_surfaces"]:
        entries.append((item["kind"], location_of(item), item["detail"]))
    return entries


def render_summary(doc, inventory):
    result = doc["verdict"]
    lines = [f"## {VERDICT_ICONS[result]} {result} · {doc['sha'][:7]}", "", cell(doc["repo"] + (f" / {doc['subpath']}" if doc["subpath"] else "")), ""]

    reasons = doc["reasons"]
    if reasons:
        lines += ["| Severity | Rule | Location |", "| --- | --- | --- |"]
        for item in reasons[:MAX_REASON_ROWS]:
            lines.append(f"| {cell(item['severity'])} | {cell(item['rule'])} | {cell(item['location'])} |")
        if len(reasons) > MAX_REASON_ROWS:
            lines += ["", f"...and {len(reasons) - MAX_REASON_ROWS} more in the reports artifact"]
        lines.append("")

    if inventory_is_usable(inventory):
        lines += [" · ".join(f"{label}: {len(inventory[field])}" for field, label in COUNT_LABELS), ""]
        entries = command_entries(inventory)
        for title, location, text in entries[:MAX_COMMAND_BLOCKS]:
            lines += [f"**{cell(title)}** · {cell(location)}", "", code_block(text), ""]
        if len(entries) > MAX_COMMAND_BLOCKS:
            lines += [f"...and {len(entries) - MAX_COMMAND_BLOCKS} more in the reports artifact", ""]
    return "\n".join(lines)


def workflow_annotation(reasons):
    listed = "; ".join(f"{r['rule']} {r['location']}" for r in reasons[:MAX_ANNOTATION_REASONS])
    text = visible(f"REVIEW: {listed}")
    return "::warning::" + text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def load_json(path):
    try:
        with open(path, encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, ValueError, RecursionError):
        return None


def append_to_env_file(variable, text):
    path = os.environ.get(variable)
    if path:
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(text)


def arguments_are_valid(args):
    if not SHA_RE.fullmatch(args.sha):
        return False
    if not REPO_RE.fullmatch(args.repo) or any(part in (".", "..") for part in args.repo.split("/")):
        return False
    return bool(SUBPATH_RE.fullmatch(args.subpath)) and not args.subpath.startswith("/") and ".." not in args.subpath.split("/")


def parse_args(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", required=True)
    parser.add_argument("--cisco", required=True)
    parser.add_argument("--snyk")
    parser.add_argument("--target", required=True)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--sha", required=True)
    parser.add_argument("--subpath", default="")
    parser.add_argument("--cisco-version", required=True)
    parser.add_argument("--snyk-version")
    parser.add_argument("--out", required=True)
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    if not arguments_are_valid(args):
        print("invalid --repo, --sha or --subpath", file=sys.stderr)
        return 2

    inventory = load_json(args.inventory)
    cisco = load_json(args.cisco)
    snyk = load_json(args.snyk) if args.snyk else None
    result, reasons = decide(inventory, cisco, snyk, snyk_requested=bool(args.snyk), target=args.target)

    doc = {
        "repo": args.repo,
        "sha": args.sha,
        "subpath": args.subpath,
        "kind": inventory.get("kind", "unknown") if isinstance(inventory, dict) else "unknown",
        "verdict": result,
        "reasons": reasons,
        "scanner_versions": {"cisco": args.cisco_version, "snyk": args.snyk_version},
        "scanned_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    with open(args.out, "w", encoding="utf-8") as handle:
        json.dump(doc, handle, indent=2)
        handle.write("\n")

    append_to_env_file("GITHUB_STEP_SUMMARY", render_summary(doc, inventory) + "\n")
    append_to_env_file("GITHUB_OUTPUT", f"verdict={result}\nsha={args.sha}\n")
    if result == "REVIEW":
        print(workflow_annotation(reasons))
    return 0


if __name__ == "__main__":
    sys.exit(main())
