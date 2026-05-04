"""SkillBom analyzer - detect malicious patterns in agent supply chain assets."""
from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

from xbom.analyzers.base import BaseAnalyzer
from xbom.models.bom_types import BomEntry, BomType, ComponentType

logger = logging.getLogger(__name__)

_SEVERITY_ORDER = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1}

# --- Pattern Definitions ---

_PATTERNS: list[dict[str, Any]] = [
    {
        "category": "shell_execution",
        "severity": "HIGH",
        "patterns": [
            re.compile(r'\b(?:Bash|bash)\b.*(?:tool|run|exec)', re.IGNORECASE),
            re.compile(r'\b(?:subprocess|os\.system|exec|eval)\s*\('),
            re.compile(r'`[^`]*(?:rm\s+-rf|curl\s.*\|.*sh|wget\s.*\|.*sh)[^`]*`'),
            re.compile(r'\bcurl\s+.*\|\s*(?:sh|bash)\b'),
        ],
    },
    {
        "category": "data_exfiltration",
        "severity": "CRITICAL",
        "patterns": [
            re.compile(r'curl\s+.*-X\s*POST\s+https?://'),
            re.compile(r'https?://[^\s]*(?:ngrok|webhook\.site|requestbin|pipedream|hookbin)', re.IGNORECASE),
            re.compile(r'https?://[^\s]*(?:pastebin|paste\.ee|hastebin|dpaste)', re.IGNORECASE),
            re.compile(r'curl\s+.*--data.*https?://'),
        ],
    },
    {
        "category": "prompt_injection",
        "severity": "CRITICAL",
        "patterns": [
            re.compile(r'ignore\s+(?:previous|prior|above|all)\s+instructions', re.IGNORECASE),
            re.compile(r'you\s+are\s+now\s+(?:a|an|DAN)', re.IGNORECASE),
            re.compile(r'disregard\s+(?:all|any|your)\s+(?:previous|prior)', re.IGNORECASE),
            re.compile(r'(?:system|admin)\s*:\s*(?:override|new\s+instructions)', re.IGNORECASE),
            re.compile(r'<!--.*(?:ignore|override|disregard).*-->', re.IGNORECASE | re.DOTALL),
        ],
    },
    {
        "category": "credential_access",
        "severity": "HIGH",
        "patterns": [
            re.compile(r'~/\.(?:ssh|aws|gnupg|config/gcloud)'),
            re.compile(r'\b(?:API_KEY|SECRET_KEY|PRIVATE_KEY|ACCESS_TOKEN)\b'),
            re.compile(r'\.env\b(?!\w)'),
            re.compile(r'(?:keychain|credential\s*store|vault\s+read)', re.IGNORECASE),
        ],
    },
    {
        "category": "file_system_overreach",
        "severity": "HIGH",
        "patterns": [
            re.compile(r'(?:write|append|echo\s+.*>>?)\s+.*(?:/etc/|~/\.bashrc|~/\.zshrc|~/\.profile)'),
            re.compile(r'\bchmod\s+(?:777|a\+[rwx])'),
            re.compile(r'~/\.(?:bashrc|zshrc|bash_profile|profile)\b'),
            re.compile(r'(?:write|modify|edit)\s+.*(?:/etc/hosts|/etc/passwd)', re.IGNORECASE),
        ],
    },
    {
        "category": "network_tunneling",
        "severity": "CRITICAL",
        "patterns": [
            re.compile(r'\bngrok\b'),
            re.compile(r'\bnc\s+-[lp]'),
            re.compile(r'reverse\s+shell', re.IGNORECASE),
            re.compile(r'ssh\s+-R\s+\d+'),
            re.compile(r'\bsocat\b.*TCP'),
        ],
    },
    {
        "category": "permission_escalation",
        "severity": "MEDIUM",
        "patterns": [
            re.compile(r'dangerouslySkipPermissions', re.IGNORECASE),
            re.compile(r'bypassPermissions', re.IGNORECASE),
            re.compile(r'--no-verify\b'),
            re.compile(r'dangerouslyDisableSandbox', re.IGNORECASE),
        ],
    },
    {
        "category": "obfuscation",
        "severity": "HIGH",
        "patterns": [
            re.compile(r'base64\s+-d\s*\|\s*(?:sh|bash)'),
            re.compile(r'echo\s+[A-Za-z0-9+/]{20,}=*\s*\|\s*base64'),
            re.compile(r'\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){4,}'),
            re.compile(r'eval\s*\(\s*(?:atob|Buffer\.from)\s*\('),
        ],
    },
    {
        "category": "typosquatting_signal",
        "severity": "MEDIUM",
        "patterns": [
            re.compile(r'\b(?:c0mmit|comm1t|giit|glt)\b', re.IGNORECASE),
            re.compile(r'\b(?:eslint-confg|prettir|webpck)\b', re.IGNORECASE),
        ],
    },
]

_FILE_TYPE_MAP = {
    "skill.md": "skill_md",
    "plugin.json": "plugin",
    "plugin.yaml": "plugin",
    ".mcp.json": "mcp_config",
    "mcp.json": "mcp_config",
    "action.yml": "action",
    "action.yaml": "action",
    "agents.md": "agent_instruction",
    "claude.md": "agent_instruction",
    "gemini.md": "agent_instruction",
}


def _detect_file_type(file_path: Path) -> str:
    name_lower = file_path.name.lower()
    if name_lower in _FILE_TYPE_MAP:
        return _FILE_TYPE_MAP[name_lower]
    if name_lower.startswith("mcp-config"):
        return "mcp_config"
    if name_lower.endswith(".md"):
        return "skill_md"
    if name_lower.endswith((".json", ".yaml", ".yml")):
        return "plugin"
    return "unknown"


def _extract_skill_name(content: str, file_path: Path) -> str:
    name_match = re.search(r'^name:\s*(.+)$', content, re.MULTILINE)
    if name_match:
        return name_match.group(1).strip().strip('"\'')
    heading_match = re.search(r'^#\s+(.+)$', content, re.MULTILINE)
    if heading_match:
        return heading_match.group(1).strip()
    json_name = re.search(r'"name"\s*:\s*"([^"]+)"', content)
    if json_name:
        return json_name.group(1)
    return file_path.stem


class SkillBomAnalyzer(BaseAnalyzer):
    """Detect malicious patterns in agent supply chain assets."""

    @property
    def name(self) -> str:
        return "skillbom"

    def analyze(
        self,
        extracted_dir: Path,
        classified_files: dict[str, list[Path]],
    ) -> list[BomEntry]:
        skill_files = classified_files.get("skills", [])
        if not skill_files:
            return []

        entries: list[BomEntry] = []
        for file_path in skill_files:
            try:
                content = file_path.read_text(errors="ignore")
            except OSError:
                continue

            findings = self._scan_patterns(content)
            max_sev = self._max_severity(findings)
            skill_name = _extract_skill_name(content, file_path)

            try:
                rel_path = str(file_path.relative_to(extracted_dir))
            except ValueError:
                rel_path = str(file_path)

            entries.append(BomEntry(
                bom_type=BomType.SKILLBOM,
                component_type=ComponentType.SKILL,
                name=skill_name,
                version=None,
                metadata={
                    "file_path": rel_path,
                    "file_type": _detect_file_type(file_path),
                    "findings": findings,
                    "finding_count": len(findings),
                    "max_severity": max_sev,
                    "execution_graph": None,
                    "ecosystem": None,
                },
            ))

        logger.info("SkillBom: found %d skill files, %d with findings",
                     len(entries),
                     sum(1 for e in entries if e.metadata["finding_count"] > 0))
        return entries

    def _scan_patterns(self, content: str) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        lines = content.splitlines()

        for pattern_def in _PATTERNS:
            category = pattern_def["category"]
            severity = pattern_def["severity"]
            for regex in pattern_def["patterns"]:
                for line_num, line in enumerate(lines, start=1):
                    if regex.search(line):
                        findings.append({
                            "category": category,
                            "severity": severity,
                            "pattern": regex.pattern[:80],
                            "line": line_num,
                        })
                        break  # One match per regex per file

        return findings

    @staticmethod
    def _max_severity(findings: list[dict[str, Any]]) -> str | None:
        if not findings:
            return None
        return max(findings, key=lambda f: _SEVERITY_ORDER.get(f["severity"], 0))["severity"]
