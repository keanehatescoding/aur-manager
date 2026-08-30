from __future__ import annotations

from .loader import PackageFiles
from .model import Finding, RuleContext, ScanResult
from .parser.install_script import parse_install_script
from .parser.patch import parse_patch
from .parser.pkgbuild import parse_pkgbuild
from .rules import ALL_RULES
from .rules.base import Rule


def scan(files: PackageFiles, rules: list[type[Rule]] | None = None) -> ScanResult:
    pkgbuild_ctx = parse_pkgbuild(files.pkgbuild)
    contexts: list[RuleContext] = [pkgbuild_ctx]
    for install_path in files.install_scripts:
        contexts.append(parse_install_script(install_path))
    for patch_path in files.patches:
        contexts.append(parse_patch(patch_path))

    active_rules = ALL_RULES if rules is None else rules

    findings: list[Finding] = []
    for ctx in contexts:
        for rule_cls in active_rules:
            findings.extend(rule_cls().check(ctx))

    return ScanResult(findings=findings, pkgbuild_ctx=pkgbuild_ctx)
