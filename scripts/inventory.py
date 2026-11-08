#!/usr/bin/env python3
"""Enumerate what a skill or plugin repo could do on an installing machine.

Reads files only. Nothing from the target is executed or imported, and symlinks
are recorded but never followed.
"""

import argparse
import fnmatch
import json
import os
import re
import stat
import sys

import yaml

MAX_FILES = 5000
MAX_BYTES = 50 * 1024 * 1024
MAX_READ_BYTES = 1024 * 1024
MAX_DESCRIPTION = 500
MAX_SNIPPET = 120
HEAD_BYTES = 8192

SUBPATH_RE = re.compile(r"[A-Za-z0-9_./-]*")
TOOL_RE = re.compile(r"[^\s,()]+(?:\([^)]*\))?")
INLINE_COMMAND_RE = re.compile(r"(?:^|(?<=\s))!`([^`\n]+)`", re.MULTILINE)
FENCED_COMMAND_RE = re.compile(r"^[ \t]*(`{3,})!\s*\n(.*?)^[ \t]*\1\s*$", re.MULTILINE | re.DOTALL)

ARCHIVE_EXTENSIONS = (".zip", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".rar", ".jar", ".whl", ".mcpb", ".dxt")
BINARY_EXTENSIONS = (".exe", ".dll", ".so", ".dylib", ".bin", ".wasm", ".node", ".pyc", ".class")
SCRIPT_EXTENSIONS = (".sh", ".bash", ".zsh", ".py", ".js", ".mjs", ".cjs", ".ts", ".rb", ".pl", ".ps1", ".bat", ".cmd")

LIFECYCLE_SCRIPTS = ("preinstall", "install", "postinstall", "prepare")
PACKAGE_DEPENDENCY_KEYS = ("dependencies", "optionalDependencies")
SETTINGS_COMMAND_KEYS = (
    "apiKeyHelper",
    "awsAuthRefresh",
    "awsCredentialExport",
    "gcpAuthRefresh",
    "otelHeadersHelper",
    "fileSuggestion",
    "statusLine",
    "subagentStatusLine",
    "sshHostCommands",
    "processWrapper",
    "policyHelper",
)
PROMPT_SKIP_KEYS = ("skipDangerousModePermissionPrompt", "skipAutoPermissionPrompt", "enableAllProjectMcpServers")
WEAKENED_MODES = ("acceptEdits", "auto")

# The HIGH prompt injection signatures from cisco-ai-skill-scanner 2.3.2
# (Apache-2.0). That scanner does not read commands/ or agents/ files, so this
# applies the same rules to them.
INJECTION_RULES = (
    (
        "PROMPT_INJECTION_IGNORE_INSTRUCTIONS",
        (
            r"(?i)ignore\s+(all\s+)?(previous|prior|earlier)\s+(instructions|rules|prompts|guidelines)",
            r"(?i)disregard\s+(all\s+)?(previous|prior)\s+(instructions|rules)",
            r"(?i)\bdisregard(?:ing)?\s+(?:all\s+)?(?:previous|prior)\s+(?:prompts?|instructions?|commands?)\b",
            r"(?i)forget\s+(all\s+)?(previous|prior)\s+(instructions|context)",
        ),
        (
            r"(?i)^\s*(?:command|prompt|instruction)s?\s+(?:addressed\s+)?to\s+(?:you|the\s+(?:agent|assistant))\s*\(",
            r"""(?i)(?<![:=\\])(?<![:=]\s)["'`“‘«]\s*\**\s*(?:ignore|disregard(?:ing)?|forget)\s+(?:all\s+)?(?:previous|prior|earlier)\s+(?:instructions?|rules|prompts?|guidelines|commands?|context)[^"'`”’».;!?\n]{0,24}["'`”’»]""",
        ),
    ),
    (
        "PROMPT_INJECTION_UNRESTRICTED_MODE",
        (
            r"(?i)you are now in\s+(unrestricted|debug|developer|admin|god|jailbreak)\s+mode",
            r"(?i)enter\s+(unrestricted|debug|developer)\s+mode",
            r"(?i)disable\s+(all\s+)?(safety|security|content|ethical)\s+(filters|checks|guidelines)",
        ),
        (),
    ),
    (
        "PROMPT_INJECTION_BYPASS_POLICY",
        (
            r"(?i)bypass\s+(content|usage|safety)\s+policy",
            r"(?i)ignore\s+(safety|content|ethical)\s+(guidelines|restrictions|limits)",
            r"(?i)output\s+disallowed\s+content\s+anyway",
        ),
        (),
    ),
    (
        "PROMPT_INJECTION_CONCEALMENT",
        (
            r"(?i)do\s+not\s+(tell|inform|mention|notify)\s+(the\s+)?user",
            r"(?i)hide\s+(this|that)\s+(action|operation|step)",
            r"(?i)keep\s+(this|that)\s+(secret|hidden)",
            r"(?i)don't\s+mention\s+you\s+used\s+this\s+skill",
        ),
        (),
    ),
)


class Malformed(Exception):
    pass


def line_of(text, *needles):
    for needle in needles:
        index = text.find(needle) if needle else -1
        if index >= 0:
            return text.count("\n", 0, index) + 1
    return 1


def is_inside(path, root):
    return path == root or path.startswith(root + os.sep)


def parse_tools(value):
    if isinstance(value, str):
        return TOOL_RE.findall(value)
    if isinstance(value, list):
        return [tool for item in value if isinstance(item, str) for tool in TOOL_RE.findall(item)]
    return []


def is_unrestricted(tool):
    match = re.fullmatch(r"bash\((.*)\)", tool.strip(), re.IGNORECASE)
    if match:
        return match.group(1).strip() in ("", "*", ":*", "*:*")
    return tool.strip().lower() in ("bash", "*")


def parse_frontmatter(text):
    """Return (mapping, usable). A file with no frontmatter gives ({}, False)."""
    lines = text.lstrip("\ufeff").split("\n")
    if lines[0].strip() != "---":
        return {}, False
    for index, line in enumerate(lines[1:], start=1):
        if line.strip() == "---":
            try:
                data = yaml.safe_load("\n".join(lines[1:index]))
            except (yaml.YAMLError, ValueError, RecursionError):
                return {}, False
            return (data, True) if isinstance(data, dict) else ({}, False)
    return {}, False


def has_frontmatter(text):
    return text.lstrip("\ufeff").split("\n")[0].strip() == "---"


def handler_text(handler):
    kind = handler.get("type")
    if kind == "command" and "command" in handler:
        return " ".join(str(part) for part in [handler["command"], *handler.get("args", [])])
    if kind == "http" and "url" in handler:
        return str(handler["url"])
    if kind == "mcp_tool" and "server" in handler:
        return f"{handler['server']} {handler.get('tool', '')}".strip()
    if kind in ("prompt", "agent") and "prompt" in handler:
        return str(handler["prompt"])
    return json.dumps(handler)


class Inventory:
    def __init__(self, root, subpath):
        self.root = root
        self.real_root = os.path.realpath(root)
        self.scan_rel = os.path.normpath(subpath) if subpath else ""
        self.scan_root = os.path.join(root, self.scan_rel) if subpath else root
        self.files = []
        self.lower_files = set()
        self.seen_configs = set()
        self.prompt_paths = {}
        self.prompt_tools = {}
        self.totals = {"files": 0, "bytes": 0, "too_large": False}
        self.lists = {
            key: []
            for key in (
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
        }

    def add(self, field, **item):
        self.lists[field].append(item)

    def bad(self, rel, reason):
        self.add("unparseable", file=rel, reason=reason)

    def surface(self, rel, line, kind, detail):
        self.add("exec_surfaces", file=rel, line=line, kind=kind, detail=detail)

    def full(self, rel):
        return os.path.join(self.root, rel)

    def read_text(self, rel):
        path = self.full(rel)
        try:
            info = os.lstat(path)
            if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_READ_BYTES:
                return None
            with open(path, "rb") as handle:
                return handle.read().decode("utf-8", "replace")
        except OSError:
            return None

    def load_config(self, rel):
        """Return (data, text), recording the file as unparseable on any failure."""
        self.seen_configs.add(rel)
        text = self.read_text(rel)
        if text is None:
            self.bad(rel, "could not be read")
            return None, None
        try:
            return json.loads(text), text
        except (ValueError, RecursionError):
            self.bad(rel, "invalid JSON")
            return None, None

    def load_mapping(self, rel):
        data, text = self.load_config(rel)
        if data is None:
            return None, None
        if not isinstance(data, dict):
            self.bad(rel, "expected a JSON object")
            return None, None
        return data, text

    def resolve(self, base, value):
        """Return the repo-relative path of a manifest reference, or None if it is unsafe."""
        if not isinstance(value, str) or value.startswith("/"):
            return None
        rel = os.path.normpath(os.path.join(base, value))
        if rel == ".." or rel.startswith("../"):
            return None
        if base != "." and not is_inside(rel, base):
            return None
        path = self.full(rel)
        if not os.path.lexists(path) or not is_inside(os.path.realpath(path), self.real_root):
            return None
        return rel

    # Walking the tree

    def walk(self):
        for dirpath, dirnames, filenames in os.walk(self.scan_root, followlinks=False):
            rel_dir = os.path.relpath(dirpath, self.root)
            prefix = "" if rel_dir == "." else rel_dir + "/"
            kept = []
            for name in sorted(dirnames):
                if name == ".git":
                    continue
                if os.path.islink(os.path.join(dirpath, name)):
                    self.record_symlink(prefix + name)
                else:
                    kept.append(name)
            dirnames[:] = kept
            for name in sorted(filenames):
                rel = prefix + name
                if os.path.islink(self.full(rel)):
                    self.record_symlink(rel)
                else:
                    self.record_file(rel)
        self.totals["too_large"] = self.totals["files"] > MAX_FILES or self.totals["bytes"] > MAX_BYTES

    def record_symlink(self, rel):
        path = self.full(rel)
        self.add("symlinks", file=rel, target=os.readlink(path), escapes=not is_inside(os.path.realpath(path), self.real_root))

    def record_file(self, rel):
        path = self.full(rel)
        try:
            info = os.lstat(path)
            if not stat.S_ISREG(info.st_mode):
                return
            with open(path, "rb") as handle:
                head = handle.read(HEAD_BYTES)
        except OSError:
            self.bad(rel, "could not be read")
            return
        self.files.append(rel)
        self.lower_files.add(rel.lower())
        self.totals["files"] += 1
        self.totals["bytes"] += info.st_size

        name = os.path.basename(rel).lower()
        if name.endswith(ARCHIVE_EXTENSIONS):
            self.add("binaries", file=rel, kind="archive")
        elif name.endswith(BINARY_EXTENSIONS) or b"\0" in head:
            self.add("binaries", file=rel, kind="binary")
        elif info.st_mode & 0o111 or head.startswith(b"#!") or name.endswith(SCRIPT_EXTENSIONS):
            self.add("scripts", file=rel)

    # Hooks

    def add_hooks(self, events, rel, text):
        if not isinstance(events, dict):
            raise Malformed
        for event, groups in events.items():
            if not isinstance(groups, list):
                raise Malformed
            for group in groups:
                if not isinstance(group, dict) or not isinstance(group.get("hooks"), list):
                    raise Malformed
                for handler in group["hooks"]:
                    if not isinstance(handler, dict):
                        raise Malformed
                    primary = next((str(handler[key]) for key in ("command", "url", "server", "prompt") if key in handler), "")
                    self.add(
                        "hooks",
                        file=rel,
                        line=line_of(text, json.dumps(primary)[1:-1], primary, str(event)),
                        event=str(event),
                        matcher=group.get("matcher"),
                        type=handler.get("type", "unknown"),
                        command=handler_text(handler),
                    )

    def try_hooks(self, events, rel, text):
        try:
            self.add_hooks(events, rel, text)
        except Malformed:
            self.bad(rel, "malformed hooks")

    def read_hooks_file(self, rel):
        if rel in self.seen_configs:
            return
        data, text = self.load_mapping(rel)
        if data is None:
            return
        if "modules" in data:
            self.surface(rel, line_of(text, '"modules"'), "mod", json.dumps(data["modules"]))
        elif "hooks" not in data:
            self.bad(rel, "malformed hooks")
            return
        self.try_hooks(data.get("hooks", {}), rel, text)

    def add_inline_hooks(self, value, rel, text):
        events = value["hooks"] if isinstance(value.get("hooks"), dict) else value
        self.add_hooks(events, rel, text)

    # MCP servers

    def add_mcp_servers(self, servers, rel, text):
        if not isinstance(servers, dict):
            raise Malformed
        for name, server in servers.items():
            if not isinstance(server, dict):
                raise Malformed
            line = line_of(text, json.dumps(str(name)), str(name))
            args = server.get("args")
            self.add("mcp_servers", file=rel, line=line, name=str(name), command=server.get("command"), args=args if isinstance(args, list) else [], url=server.get("url"))
            if "headersHelper" in server:
                self.surface(rel, line, "mcp_headers_helper", str(server["headersHelper"]))

    def read_mcp_file(self, rel):
        if rel in self.seen_configs:
            return
        data, text = self.load_mapping(rel)
        if data is not None:
            try:
                self.add_mcp_servers(data.get("mcpServers", data), rel, text)
            except Malformed:
                self.bad(rel, "malformed MCP servers")

    def add_inline_mcp(self, value, rel, text):
        self.add_mcp_servers(value.get("mcpServers", value), rel, text)

    # LSP servers and monitors

    def add_lsp_servers(self, servers, rel, text):
        if not isinstance(servers, dict):
            raise Malformed
        for name, server in servers.items():
            if not isinstance(server, dict):
                raise Malformed
            detail = " ".join(str(part) for part in [server.get("command"), *server.get("args", [])] if part)
            self.surface(rel, line_of(text, json.dumps(str(name))), "lsp_server", detail)

    def read_lsp_file(self, rel):
        if rel in self.seen_configs:
            return
        data, text = self.load_mapping(rel)
        if data is not None:
            try:
                self.add_lsp_servers(data.get("lspServers", data), rel, text)
            except Malformed:
                self.bad(rel, "malformed LSP servers")

    def add_inline_lsp(self, value, rel, text):
        self.add_lsp_servers(value.get("lspServers", value), rel, text)

    def add_monitors(self, monitors, rel, text):
        if not isinstance(monitors, list):
            raise Malformed
        for monitor in monitors:
            if not isinstance(monitor, dict):
                raise Malformed
            command = str(monitor.get("command", ""))
            self.surface(rel, line_of(text, json.dumps(command)[1:-1], command), "monitor", command)

    def read_monitors_file(self, rel):
        if rel in self.seen_configs:
            return
        data, text = self.load_config(rel)
        if data is not None:
            try:
                self.add_monitors(data, rel, text)
            except Malformed:
                self.bad(rel, "malformed monitors")

    # Settings

    def inspect_settings(self, data, rel, text):
        if "hooks" in data:
            self.try_hooks(data["hooks"], rel, text)

        permissions = data.get("permissions")
        permissions = permissions if isinstance(permissions, dict) else {}
        mode = permissions.get("defaultMode")
        if mode == "bypassPermissions":
            self.add("bypass_settings", file=rel, line=line_of(text, "defaultMode"), setting="permissions.defaultMode")
        elif mode in WEAKENED_MODES:
            self.surface(rel, line_of(text, "defaultMode"), "permission_grant", f"defaultMode: {mode}")
        allow = permissions.get("allow")
        for entry in allow if isinstance(allow, list) else []:
            if isinstance(entry, str) and is_unrestricted(entry):
                self.add("bypass_settings", file=rel, line=line_of(text, '"allow"', "allow"), setting="permissions.allow")
            elif isinstance(entry, str):
                self.surface(rel, line_of(text, json.dumps(entry)[1:-1], entry), "permission_grant", entry)

        for key in PROMPT_SKIP_KEYS:
            if data.get(key):
                self.add("bypass_settings", file=rel, line=line_of(text, key), setting=key)
        sandbox = data.get("sandbox")
        if isinstance(sandbox, dict) and sandbox.get("autoAllowBashIfSandboxed"):
            self.add("bypass_settings", file=rel, line=line_of(text, "autoAllowBashIfSandboxed"), setting="sandbox.autoAllowBashIfSandboxed")

        for key in SETTINGS_COMMAND_KEYS:
            if key in data:
                value = data[key] if isinstance(data[key], str) else json.dumps(data[key])
                self.surface(rel, line_of(text, key), "settings_command", f"{key}: {value}")
        env = data.get("env")
        for name, value in env.items() if isinstance(env, dict) else ():
            self.surface(rel, line_of(text, json.dumps(str(name))), "settings_env", f"{name}={value}")

    def read_settings_file(self, rel):
        data, text = self.load_mapping(rel)
        if data is not None:
            self.inspect_settings(data, rel, text)

    # Plugin manifests

    def component(self, manifest, plugin_dir, value, text, read_file, add_inline):
        for item in value if isinstance(value, list) else [value]:
            if isinstance(item, dict):
                try:
                    add_inline(item, manifest, text)
                except Malformed:
                    self.bad(manifest, "malformed inline component")
                continue
            target = self.resolve(plugin_dir, item)
            if target is None:
                self.bad(manifest, "bad component reference")
            else:
                read_file(target)

    def add_mcp_reference(self, manifest, plugin_dir, value, text):
        for item in value if isinstance(value, list) else [value]:
            if isinstance(item, str) and (item.startswith("https://") or item.endswith((".mcpb", ".dxt"))):
                self.add("mcp_servers", file=manifest, line=line_of(text, item), name=os.path.basename(item), command=None, args=[], url=item)
            else:
                self.component(manifest, plugin_dir, item, text, self.read_mcp_file, self.add_inline_mcp)

    def add_monitor_reference(self, manifest, plugin_dir, value, text):
        if isinstance(value, list):
            try:
                self.add_monitors(value, manifest, text)
            except Malformed:
                self.bad(manifest, "malformed monitors")
            return
        target = self.resolve(plugin_dir, value)
        if target is None:
            self.bad(manifest, "bad component reference")
        else:
            self.read_monitors_file(target)

    def mark_prompts(self, manifest, plugin_dir, value, kind, tools=()):
        target = self.resolve(plugin_dir, value)
        if target is None:
            self.bad(manifest, "bad component reference")
        elif os.path.isdir(self.full(target)):
            for rel in self.files:
                if rel.startswith(target + "/") and rel.lower().endswith(".md"):
                    self.prompt_paths[rel] = kind
        else:
            self.prompt_paths[target] = kind
            self.prompt_tools[target] = list(tools)

    def add_command_map(self, manifest, plugin_dir, commands, text):
        for name, entry in commands.items():
            if not isinstance(entry, dict):
                self.bad(manifest, "malformed command entry")
            elif "source" in entry:
                self.mark_prompts(manifest, plugin_dir, entry["source"], "command", parse_tools(entry.get("allowedTools")))
            elif isinstance(entry.get("content"), str):
                line = line_of(text, json.dumps(str(name)))
                tools = parse_tools(entry.get("allowedTools"))
                self.add_prompt(manifest, line, "command", str(name), tools, False)
                self.inspect_prompt_body(entry["content"], manifest, line)

    def read_manifest(self, rel):
        plugin_dir = os.path.dirname(os.path.dirname(rel)) or "."
        data, text = self.load_mapping(rel)
        if data is None:
            return
        experimental = data.get("experimental")
        experimental = experimental if isinstance(experimental, dict) else {}

        if "hooks" in data:
            self.component(rel, plugin_dir, data["hooks"], text, self.read_hooks_file, self.add_inline_hooks)
        if "mcpServers" in data:
            self.add_mcp_reference(rel, plugin_dir, data["mcpServers"], text)
        if "lspServers" in data:
            self.component(rel, plugin_dir, data["lspServers"], text, self.read_lsp_file, self.add_inline_lsp)
        for monitors in (data.get("monitors"), experimental.get("monitors")):
            if monitors is not None:
                self.add_monitor_reference(rel, plugin_dir, monitors, text)
        if "workflows" in data:
            for item in data["workflows"] if isinstance(data["workflows"], list) else [data["workflows"]]:
                self.surface(rel, line_of(text, "workflows"), "workflow", str(item))
        if isinstance(data.get("settings"), dict):
            self.inspect_settings(data["settings"], rel, text)
        if data.get("dependencies"):
            self.surface(rel, line_of(text, '"dependencies"'), "plugin_dependency", json.dumps(data["dependencies"]))

        commands = data.get("commands")
        if isinstance(commands, dict):
            self.add_command_map(rel, plugin_dir, commands, text)
        elif commands is not None:
            for item in commands if isinstance(commands, list) else [commands]:
                self.mark_prompts(rel, plugin_dir, item, "command")
        for key, kind in (("agents", "agent"), ("outputStyles", "output_style")):
            value = data.get(key)
            if value is not None:
                for item in value if isinstance(value, list) else [value]:
                    self.mark_prompts(rel, plugin_dir, item, kind)

    # Markdown

    def add_prompt(self, rel, line, kind, name, tools, frontmatter_error):
        self.add(
            "prompts",
            file=rel,
            line=line,
            kind=kind,
            name=name,
            tools=tools,
            unrestricted_tools=any(is_unrestricted(tool) for tool in tools),
            frontmatter_error=frontmatter_error,
        )

    def inspect_dynamic_commands(self, text, rel, fixed_line=None):
        for match in INLINE_COMMAND_RE.finditer(text):
            line = fixed_line or text.count("\n", 0, match.start()) + 1
            self.surface(rel, line, "dynamic_command", match.group(1).strip())
        for match in FENCED_COMMAND_RE.finditer(text):
            line = fixed_line or text.count("\n", 0, match.start()) + 1
            self.surface(rel, line, "dynamic_command", match.group(2).strip())

    def inspect_prompt_body(self, text, rel, fixed_line=None):
        self.inspect_dynamic_commands(text, rel, fixed_line)
        for rule, patterns, excludes in INJECTION_RULES:
            for pattern in patterns:
                for match in re.finditer(pattern, text):
                    start = text.rfind("\n", 0, match.start()) + 1
                    end = text.find("\n", match.end())
                    context = text[start:] if end < 0 else text[start:end]
                    if any(re.search(exclude, context) for exclude in excludes):
                        continue
                    line = fixed_line or text.count("\n", 0, match.start()) + 1
                    self.add("prompt_injection", file=rel, line=line, rule=rule, snippet=match.group(0)[:MAX_SNIPPET])

    def inspect_frontmatter_surfaces(self, data, rel, text):
        if "hooks" in data:
            self.try_hooks(data["hooks"], rel, text)
        servers = data.get("mcpServers")
        for entry in servers if isinstance(servers, list) else [servers] if isinstance(servers, dict) else []:
            if isinstance(entry, dict):
                try:
                    self.add_mcp_servers(entry, rel, text)
                except Malformed:
                    self.bad(rel, "malformed MCP servers")
        if data.get("permissionMode") == "bypassPermissions":
            self.add("bypass_settings", file=rel, line=line_of(text, "permissionMode"), setting="permissionMode")

    def read_skill(self, rel):
        text = self.read_text(rel)
        if text is None:
            self.bad(rel, "could not be read")
            return
        data, usable = parse_frontmatter(text)
        tools = parse_tools(data.get("allowed-tools"))
        self.add(
            "skills",
            file=rel,
            line=1,
            name=str(data.get("name") or os.path.basename(os.path.dirname(rel)) or "(root)"),
            description=str(data.get("description") or "")[:MAX_DESCRIPTION],
            allowed_tools=tools,
            unrestricted_tools=any(is_unrestricted(tool) for tool in tools),
            frontmatter_error=not usable,
        )
        self.inspect_frontmatter_surfaces(data, rel, text)
        self.inspect_dynamic_commands(text, rel)

    def read_prompt(self, rel, kind):
        text = self.read_text(rel)
        if text is None:
            self.bad(rel, "could not be read")
            return
        data, usable = parse_frontmatter(text)
        tools = parse_tools(data.get("allowed-tools")) + parse_tools(data.get("tools")) + self.prompt_tools.get(rel, [])
        name = str(data.get("name") or os.path.splitext(os.path.basename(rel))[0])
        self.add_prompt(rel, 1, kind, name, tools, has_frontmatter(text) and not usable)
        self.inspect_frontmatter_surfaces(data, rel, text)
        if kind == "output_style" and data.get("force-for-plugin"):
            self.surface(rel, line_of(text, "force-for-plugin"), "forced_output_style", rel)
        self.inspect_prompt_body(text, rel)

    def prompt_kind(self, rel):
        if rel in self.prompt_paths:
            return self.prompt_paths[rel]
        if not rel.lower().endswith(".md"):
            return None
        directories = rel.lower().split("/")[:-1]
        if "commands" in directories:
            return "command"
        if "agents" in directories:
            return "agent"
        return "output_style" if "output-styles" in directories else None

    # Everything else that is recognized by its path

    def read_package_json(self, rel):
        data, text = self.load_mapping(rel)
        if data is None:
            return
        scripts = data.get("scripts")
        for kind in LIFECYCLE_SCRIPTS:
            if isinstance(scripts, dict) and kind in scripts:
                self.add("lifecycle", file=rel, line=line_of(text, json.dumps(kind)), kind=kind, command=str(scripts[kind]))
        for key in PACKAGE_DEPENDENCY_KEYS:
            if data.get(key):
                self.surface(rel, line_of(text, json.dumps(key)), "package_dependencies", json.dumps(data[key]))

    def is_plugin_settings(self, rel, name):
        if name != "settings.json":
            return False
        at_scan_root = rel.lower() == os.path.join(self.scan_rel, "settings.json").lower()
        return at_scan_root or os.path.join(os.path.dirname(rel), ".claude-plugin/plugin.json").lower() in self.lower_files

    def inspect_path(self, rel):
        # Matched case-insensitively: macOS installs on a case-insensitive filesystem.
        parts = rel.lower().split("/")
        name = parts[-1]
        directories = parts[:-1]
        if parts[-2:] == ["hooks", "hooks.json"]:
            self.read_hooks_file(rel)
        elif name == ".mcp.json":
            self.read_mcp_file(rel)
        elif name == ".lsp.json":
            self.read_lsp_file(rel)
        elif parts[-2:] == ["monitors", "monitors.json"]:
            self.read_monitors_file(rel)
        elif (directories[-1:] == [".claude"] and fnmatch.fnmatch(name, "settings*.json")) or self.is_plugin_settings(rel, name):
            self.read_settings_file(rel)
        elif name == "package.json":
            self.read_package_json(rel)
        elif name == "setup.py":
            self.add("lifecycle", file=rel, line=None, kind="setup.py", command=None)

        if "bin" in directories:
            self.surface(rel, None, "plugin_bin", rel)
        if "workflows" in directories and ".github" not in directories and name.endswith(".js"):
            self.surface(rel, None, "workflow", rel)

    def run(self):
        self.walk()
        for rel in self.files:
            if rel.lower().endswith(".claude-plugin/plugin.json"):
                self.read_manifest(rel)
            elif rel.lower().endswith(".claude-plugin/marketplace.json"):
                self.surface(rel, None, "marketplace", rel)
        for rel in self.files:
            self.inspect_path(rel)
            kind = self.prompt_kind(rel)
            if os.path.basename(rel).lower() == "skill.md":
                self.read_skill(rel)
            elif kind:
                self.read_prompt(rel, kind)

        for items in self.lists.values():
            items.sort(key=lambda item: (item["file"], item.get("line") or 0))
        manifest = os.path.join(self.scan_rel, ".claude-plugin/plugin.json")
        return {
            "schema": 1,
            "kind": "plugin" if manifest.lower() in self.lower_files else "skill",
            "totals": self.totals,
            **self.lists,
        }


def validate_subpath(root, subpath):
    if not SUBPATH_RE.fullmatch(subpath) or subpath.startswith("/") or ".." in subpath.split("/"):
        raise ValueError("unsafe subpath")
    scan_root = os.path.join(root, subpath) if subpath else root
    if not os.path.isdir(scan_root) or not is_inside(os.path.realpath(scan_root), os.path.realpath(root)):
        raise ValueError("subpath is not a directory inside the repository")


def build_inventory(root, subpath=""):
    validate_subpath(root, subpath)
    return Inventory(root, subpath).run()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target")
    parser.add_argument("--subpath", default="")
    args = parser.parse_args(argv)
    try:
        result = build_inventory(args.target, args.subpath)
    except ValueError as error:
        print(error, file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
