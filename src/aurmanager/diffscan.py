from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from .engine import scan
from .loader import resolve
from .model import Finding, RuleContext, ScanResult, Severity
from .rules.base import Rule


def _fingerprint(f: Finding) -> tuple[str, str | None]:
    """A Finding's identity independent of line number -- line numbers shift
    between package versions even when the underlying issue is unchanged, so
    diffing findings must key on rule_id + the actual flagged text, not location."""
    return (f.rule_id, f.snippet)


def _source_checksum_coverage(ctx: RuleContext) -> dict[str, bool]:
    """For each declared source, whether at least one checksum array has a real
    (non-SKIP) entry at its index -- same coverage logic INT003 uses, reused here
    to detect a source that was checksummed before and isn't anymore."""
    coverage: dict[str, bool] = {}
    for idx, src in enumerate(ctx.sources):
        entries = [
            checksum_list[idx] for checksum_list in ctx.checksums.values() if idx < len(checksum_list)
        ]
        coverage[src] = bool(entries) and any(e.strip().upper() != "SKIP" for e in entries)
    return coverage


@dataclass
class DiffResult:
    old: ScanResult
    new: ScanResult
    new_findings: list[Finding] = field(default_factory=list)
    resolved_findings: list[Finding] = field(default_factory=list)
    carried_findings: list[Finding] = field(default_factory=list)
    new_functions: list[str] = field(default_factory=list)
    removed_functions: list[str] = field(default_factory=list)
    new_sources: list[str] = field(default_factory=list)
    removed_sources: list[str] = field(default_factory=list)
    weakened_checksum_sources: list[str] = field(default_factory=list)

    @property
    def diff_verdict(self) -> Severity:
        """Verdict driven only by what's *new* in this update -- a finding that was
        already present in the previous (presumably already-reviewed) version
        shouldn't by itself fail a diff-mode check the way it would a fresh scan."""
        if not self.new_findings:
            return Severity.INFO
        return max(f.severity for f in self.new_findings)

    def to_json(self, severity_min: Severity | None = None) -> str:
        def shown(findings: list[Finding]) -> list[Finding]:
            return findings if severity_min is None else [f for f in findings if f.severity >= severity_min]

        return json.dumps(
            {
                # diff_verdict always reflects ALL new findings, not just what's
                # shown, so a severity_min filter can't make a diff look cleaner
                # than it is -- same contract as ScanResult.to_json.
                "diff_verdict": self.diff_verdict.name,
                "new_findings": [f.to_dict() for f in shown(self.new_findings)],
                "carried_findings": [f.to_dict() for f in shown(self.carried_findings)],
                "resolved_findings": [f.to_dict() for f in shown(self.resolved_findings)],
                "new_functions": self.new_functions,
                "removed_functions": self.removed_functions,
                "new_sources": self.new_sources,
                "removed_sources": self.removed_sources,
                "weakened_checksum_sources": self.weakened_checksum_sources,
            },
            indent=2,
        )


def diff_scan(old_path: Path, new_path: Path, rules: list[type[Rule]] | None = None) -> DiffResult:
    """Compare two versions of the same package (e.g. the previous and current
    commit of an AUR package's git checkout) and separate findings into what's
    newly introduced by this update vs. what was already present.

    A previously-clean package suddenly gaining a rule-triggering construct in an
    update is a stronger signal than the same construct in a package nobody has
    vetted yet -- most real AUR compromises rely on trust already established by
    an earlier, clean version (maintainer account takeover, orphan adoption),
    not a brand-new malicious package. See README's incident traceability table.
    """
    old_files = resolve(old_path)
    new_files = resolve(new_path)
    old_result = scan(old_files, rules=rules)
    new_result = scan(new_files, rules=rules)

    old_fp = {_fingerprint(f) for f in old_result.findings}
    new_fp = {_fingerprint(f) for f in new_result.findings}

    new_findings = [f for f in new_result.findings if _fingerprint(f) not in old_fp]
    resolved_findings = [f for f in old_result.findings if _fingerprint(f) not in new_fp]
    carried_findings = [f for f in new_result.findings if _fingerprint(f) in old_fp]

    # scan() already parsed each PKGBUILD once to build its RuleContext (needed
    # to run rules against it) -- reuse that instead of parsing both files a
    # second time just for function/source diffing.
    old_ctx = old_result.pkgbuild_ctx
    new_ctx = new_result.pkgbuild_ctx

    old_functions = set(old_ctx.functions)
    new_functions_set = set(new_ctx.functions)
    old_sources = set(old_ctx.sources)
    new_sources_set = set(new_ctx.sources)

    old_coverage = _source_checksum_coverage(old_ctx)
    new_coverage = _source_checksum_coverage(new_ctx)
    weakened = [
        src
        for src in old_sources & new_sources_set
        if old_coverage.get(src) and not new_coverage.get(src)
    ]

    return DiffResult(
        old=old_result,
        new=new_result,
        new_findings=new_findings,
        resolved_findings=resolved_findings,
        carried_findings=carried_findings,
        new_functions=sorted(new_functions_set - old_functions),
        removed_functions=sorted(old_functions - new_functions_set),
        new_sources=sorted(new_sources_set - old_sources),
        removed_sources=sorted(old_sources - new_sources_set),
        weakened_checksum_sources=sorted(weakened),
    )
