from __future__ import annotations

import enum
import json
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any


class Severity(enum.IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def from_str(cls, name: str) -> "Severity":
        return cls[name.upper()]

    def __str__(self) -> str:
        return self.name


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: Severity
    message: str
    file: Path
    line: int | None = None
    column: int | None = None
    snippet: str | None = None
    incident_ref: str | None = None
    remediation: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.name
        d["file"] = str(self.file)
        return d


@dataclass
class RuleContext:
    """Everything a Rule needs to inspect one parsed file (PKGBUILD, .install, or
    a source=() patch/diff)."""

    file: Path
    source: str
    ast: Any | None  # bashlex AST root node, or None if parsing failed
    parse_error: str | None = None

    # True for a RuleContext built from a .patch/.diff file (see
    # parser/patch.py) -- `source` there is not bash, it's a unified diff with
    # everything except added-line content blanked out (see
    # parser/patch.py:extract_added_lines), so ast/functions/module_scope are
    # always empty/None and AST-walking rules correctly find nothing. Lets a
    # rule that specifically targets patch content (see rules/patch.py) avoid
    # double-reporting the same construct an AST-based rule already covers
    # precisely when scanning a real PKGBUILD/.install.
    is_patch: bool = False

    # Structured fields extracted by parser/pkgbuild.py or parser/install_script.py.
    pkgname: str | None = None
    pkgver: str | None = None
    sources: list[str] = field(default_factory=list)
    # (start, end) character offsets in `source`, one per source=()/source_<arch>=()
    # array-literal occurrence -- lets a rule locate a specific source entry's
    # real line by searching only within these spans. See
    # rules/integrity.py:_line_for_source_entry.
    source_spans: list[tuple[int, int]] = field(default_factory=list)
    checksums: dict[str, list[str]] = field(default_factory=dict)  # e.g. {"sha256sums": [...]}

    # A sibling .SRCINFO's pkgbase-level source/checksum arrays, if the file
    # exists next to this PKGBUILD -- see rules/integrity.py:INT006. Not
    # populated for .install contexts (.SRCINFO describes the PKGBUILD, not
    # install scripts).
    srcinfo_present: bool = False
    srcinfo_sources: list[str] = field(default_factory=list)
    srcinfo_checksums: dict[str, list[str]] = field(default_factory=dict)

    # function name -> function body AST node (or None if not present)
    functions: dict[str, Any] = field(default_factory=dict)

    # top-level statements not inside any function (executes immediately when
    # PKGBUILD/.install is sourced) -- see parser/bash_ast.py:ModuleScopeNode
    module_scope: Any = None
    # `source` with every function body masked out, for regex-based rules that need
    # to search "everything outside a function" as plain text
    module_scope_source: str = ""


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    # The parsed PKGBUILD RuleContext scan() already built, exposed so callers
    # that also need structured PKGBUILD data (e.g. diffscan.py's function/
    # source diffing) can reuse it instead of parsing the same file again.
    pkgbuild_ctx: RuleContext | None = None

    @property
    def overall_verdict(self) -> Severity:
        if not self.findings:
            return Severity.INFO
        return max(f.severity for f in self.findings)

    def findings_at_or_above(self, threshold: Severity) -> list[Finding]:
        return [f for f in self.findings if f.severity >= threshold]

    def to_json(self, severity_min: Severity | None = None) -> str:
        shown = self.findings if severity_min is None else self.findings_at_or_above(severity_min)
        return json.dumps(
            {
                # overall_verdict always reflects ALL findings, not just what's shown,
                # so a severity_min filter can't make a scan look cleaner than it is.
                "overall_verdict": self.overall_verdict.name,
                "findings": [f.to_dict() for f in shown],
            },
            indent=2,
        )
