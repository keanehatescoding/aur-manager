from __future__ import annotations

import re
from typing import Iterable

from ..model import Finding, RuleContext, Severity
from ..parser.bash_ast import command_name, command_words, line_and_snippet, walk
from ..parser.pkgbuild import CHECKSUM_KEYS
from .base import Rule

_PACKAGE_MANAGERS = {
    "npm", "pip", "pip3", "go", "bun", "yarn", "pnpm",
    "cargo", "gem", "composer", "luarocks",
}
_INSTALL_VERBS = {"install", "add", "get", "require"}
_INSTALL_HOOKS = ("post_install", "post_upgrade")

# pip's `==1.2.3`, npm/go's `@1.2.3` or `@v1.2.3` -- deliberately excludes npm/go
# "pins" like `@latest`/`@next` that aren't actually pinned to a fixed version.
_VERSION_PIN_RE = re.compile(r"(==\S|@=?v?\d)")

# Options that take a following value -- that value must not be mistaken for a
# package spec when checking whether every installed package is version-pinned.
_FLAGS_WITH_VALUE = {
    "--registry", "--tag", "--prefix",  # npm
    "--index-url", "--extra-index-url", "--find-links", "--target", "-i", "-f", "-t",  # pip
}


def _package_specs(words: list[str]) -> list[str]:
    specs = []
    i = 0
    while i < len(words):
        w = words[i]
        if w.startswith("-"):
            i += 2 if w in _FLAGS_WITH_VALUE else 1
            continue
        specs.append(w)
        i += 1
    return specs

_NETWORK_COMMANDS = {"curl", "wget"}
_GIT_NETWORK_SUBCOMMANDS = {"ls-remote", "fetch", "pull", "clone"}

# Scheme allows RFC 3986's letter/digit/+/-/. so compound VCS schemes like
# git+https:// and hg+ssh:// match, not just plain http(s)/ftp.
_URL_RE = re.compile(r"^(?:[\w+.-]+::)?([a-zA-Z][a-zA-Z0-9+.-]*)://(?:[^/@\s]+@)?([^/\s]+)")
_IP_LITERAL_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?$")
_PASTE_HOSTS = {
    "pastebin.com",
    "paste.ee",
    "hastebin.com",
    "transfer.sh",
    "0x0.st",
    "ix.io",
    "termbin.com",
    "file.io",
    "ghostbin.com",
    "dpaste.com",
}


def _line_for_source_entry(ctx: RuleContext, src: str) -> tuple[int | None, str | None]:
    """Search only within the real source=()/source_<arch>=() array-literal
    spans, not the whole file -- a plain ctx.source.find(src) can match an
    earlier, unrelated occurrence of the same string (e.g. quoted in a
    comment or a changelog block above source=()), reporting the wrong line
    to a reviewer even though detection itself is unaffected."""
    for start, end in ctx.source_spans:
        idx = ctx.source.find(src, start, end)
        if idx != -1:
            return line_and_snippet(idx, ctx.source)
    return None, None


class INT001PkgverNetworkCall(Rule):
    """pkgver() is meant to derive a version string from sources already fetched by
    makepkg (e.g. `git describe` against an already-cloned checkout) -- it should
    never itself reach out over the network. A pkgver() that does (curl/wget, or
    `git ls-remote`/`fetch`/`pull`/`clone`) runs on every single invocation of
    makepkg, pacman -Syu, or any AUR helper that checks for updates, not just when
    actually building. No specific AUR incident is known to have used this exact
    mechanism (verified via web search); this is a generic heuristic, not
    incident-grounded like the other integrity rules."""

    rule_id = "INT001"
    category = "integrity"
    default_severity = Severity.MEDIUM

    def check(self, ctx: RuleContext) -> Iterable[Finding]:
        fn_node = ctx.functions.get("pkgver")
        if fn_node is None:
            return []
        findings: list[Finding] = []
        for node in walk(fn_node):
            if getattr(node, "kind", None) != "command":
                continue
            words = command_words(node)
            if not words:
                continue
            name = words[0]
            is_network = name in _NETWORK_COMMANDS or (
                name == "git" and len(words) > 1 and words[1] in _GIT_NETWORK_SUBCOMMANDS
            )
            if not is_network:
                continue
            line, snippet = line_and_snippet(node.pos[0], ctx.source)
            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    severity=self.default_severity,
                    message=(
                        f"pkgver() makes a network call ('{name}'), which runs on every "
                        f"makepkg/AUR-helper version check, not just when actually building."
                    ),
                    file=ctx.file,
                    line=line,
                    snippet=snippet,
                    remediation=(
                        "Derive the version from sources already fetched into $srcdir "
                        "(e.g. `git describe` against the checkout), not a live network call."
                    ),
                )
            )
        return findings


class INT002SuspiciousSourceHost(Rule):
    """A source=() URL pointing at a raw IP address or a known paste/ephemeral-file
    host (pastebin.com, transfer.sh, ...) instead of a recognizable upstream project
    host is a red flag -- legitimate upstream releases don't live on paste sites.
    Generalizes the disguise pattern from the 2025 Chaos RAT packages (an
    attacker-controlled host masquerading as a legitimate source), though this
    specific IP-literal/paste-host check isn't itself tied to a single cited
    incident."""

    rule_id = "INT002"
    category = "integrity"
    default_severity = Severity.MEDIUM

    def check(self, ctx: RuleContext) -> Iterable[Finding]:
        findings: list[Finding] = []
        for src in ctx.sources:
            m = _URL_RE.match(src)
            if not m:
                continue
            host = m.group(2).split(":")[0]
            reason = None
            if _IP_LITERAL_RE.match(m.group(2)):
                reason = "a raw IP address"
            elif host.lower() in _PASTE_HOSTS:
                reason = f"a paste/ephemeral-file host ({host})"
            if reason is None:
                continue
            line, snippet = _line_for_source_entry(ctx, src)
            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    severity=self.default_severity,
                    message=f"source=() entry points at {reason} instead of a recognizable upstream project host: {src}",
                    file=ctx.file,
                    line=line,
                    snippet=snippet,
                    remediation="Source URLs should point at the actual upstream project's release infrastructure.",
                )
            )
        return findings


class INT003SkippedChecksumOnNetworkSource(Rule):
    """`SKIP` is a legitimate checksum entry for local files shipped alongside the
    PKGBUILD in the AUR git repo (already covered by AUR's own integrity) and for
    VCS sources (git+/svn+/hg+/bzr+ -- there's no fixed content to checksum, the VCS
    itself provides integrity), but for a plain network download it means makepkg
    will happily build from a tampered file with no integrity check at all."""

    rule_id = "INT003"
    category = "integrity"
    default_severity = Severity.MEDIUM

    def check(self, ctx: RuleContext) -> Iterable[Finding]:
        if not ctx.checksums or not ctx.sources:
            return []
        findings: list[Finding] = []
        for idx, src in enumerate(ctx.sources):
            url_part = src.split("::", 1)[-1]
            is_local = "://" not in url_part
            is_vcs = bool(re.match(r"^(?:git|svn|hg|bzr)\+", url_part))
            if is_local or is_vcs:
                continue
            # makepkg verifies every declared checksum array that has an entry at
            # this index -- a source is only unprotected if ALL of them are SKIP
            # (or none cover this index at all). Checking just the first-declared
            # array (e.g. b2sums=('SKIP')) would both false-positive when a later
            # array (e.g. sha256sums) actually protects the source, and, via a
            # shared break, silently stop checking every source after the first
            # array ran out of entries.
            entries = [
                checksum_list[idx] for checksum_list in ctx.checksums.values() if idx < len(checksum_list)
            ]
            # Protected only if at least one declared array actually has a real
            # (non-SKIP) entry at this index. No entries at all (every declared
            # array is too short to cover this source) is just as unprotected as
            # every entry being SKIP -- makepkg builds from an unverified download
            # either way.
            if entries and any(e.strip().upper() != "SKIP" for e in entries):
                continue
            if entries:
                reason = "Checksum is SKIP for a network source"
            else:
                reason = "No checksum entry covers this network source"
            line, snippet = _line_for_source_entry(ctx, src)
            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    severity=self.default_severity,
                    message=f"{reason} ({src}) -- makepkg will build from a tampered download with no integrity check.",
                    file=ctx.file,
                    line=line,
                    snippet=snippet,
                    remediation="Provide a real checksum for any source fetched over the network.",
                )
            )
        return findings


class INT005InstallHookPullsUnpinnedDeps(Rule):
    """A post_install/post_upgrade hook silently running a package manager to pull
    down more code at install time bypasses the AUR review process entirely for
    whatever that dependency turns out to be -- exactly how the 2026 Atomic Arch
    campaign's `.install` hooks pulled the malicious `atomic-lockfile`/`js-digest`
    npm packages that dropped the actual infostealer/rootkit payload. See
    tests/fixtures/incidents/2026_atomic_arch_install_hook_and_obfuscation/
    SOURCE.md."""

    rule_id = "INT005"
    category = "integrity"
    default_severity = Severity.HIGH
    incident_refs = ("AUR-2026-atomic-arch",)

    def check(self, ctx: RuleContext) -> Iterable[Finding]:
        findings: list[Finding] = []
        for fn_name, fn_node in ctx.functions.items():
            if fn_name not in _INSTALL_HOOKS:
                continue
            for node in walk(fn_node):
                if getattr(node, "kind", None) != "command":
                    continue
                name = command_name(node)
                if name not in _PACKAGE_MANAGERS:
                    continue
                words = command_words(node)
                if len(words) < 2 or words[1] not in _INSTALL_VERBS:
                    continue

                specs = _package_specs(words[2:])
                all_pinned = bool(specs) and all(_VERSION_PIN_RE.search(s) for s in specs)

                line, snippet = line_and_snippet(node.pos[0], ctx.source)
                if all_pinned:
                    detail = "pins a specific version, but still fetches unaudited third-party code"
                else:
                    detail = "pulls additional, unpinned code"
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        severity=self.default_severity,
                        message=(
                            f"'{fn_name}()' runs '{name} {words[1]}' to {detail} at install "
                            f"time -- this bypasses AUR review for whatever that dependency "
                            f"resolves to."
                        ),
                        file=ctx.file,
                        line=line,
                        snippet=snippet,
                        incident_ref=self.incident_refs[0],
                        remediation=(
                            "Package the actual runtime dependency properly (depends=()) "
                            "instead of fetching it via a package manager at install time."
                        ),
                    )
                )
        return findings


class INT006SrcinfoPkgbuildMismatch(Rule):
    """.SRCINFO is committed alongside every real AUR PKGBUILD -- it's what the
    AUR website displays and what some tooling reads without executing the
    PKGBUILD (paru's own docs note it deliberately does *not* trust a
    committed .SRCINFO for dependency resolution, regenerating it fresh from
    the real PKGBUILD instead, precisely because a committed one can go
    stale or be wrong). If a PKGBUILD's own checksums or source count don't
    match its sibling .SRCINFO, either the maintainer edited the PKGBUILD
    without regenerating .SRCINFO (the ArchWiki-documented workflow requires
    doing so after every PKGBUILD change), or the mismatch is deliberate: the
    metadata a reviewer sees doesn't reflect what the script actually
    declares. Generic heuristic, not tied to one specific incident.

    Deliberately does not compare source *URLs* directly: .SRCINFO is fully
    variable-resolved by makepkg (source=("$pkgname-$pkgver.tar.gz::...")
    becomes a literal string in .SRCINFO), while ctx.sources is the
    PKGBUILD's raw, unexpanded text -- verified empirically by running
    `makepkg --printsrcinfo` against a real PKGBUILD. A naive string
    comparison would false-positive on nearly every real-world PKGBUILD,
    which almost universally templates $pkgname/$pkgver into source URLs.
    Checksums and array counts are never templated with bash variables, so
    comparing those is unambiguous without needing to resolve them."""

    rule_id = "INT006"
    category = "integrity"
    default_severity = Severity.MEDIUM

    def check(self, ctx: RuleContext) -> Iterable[Finding]:
        if not ctx.srcinfo_present:
            return []
        findings: list[Finding] = []

        if len(ctx.sources) != len(ctx.srcinfo_sources):
            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    severity=self.default_severity,
                    message=(
                        f"PKGBUILD declares {len(ctx.sources)} source(s) but the sibling "
                        f".SRCINFO declares {len(ctx.srcinfo_sources)} -- .SRCINFO is stale "
                        f"or was hand-edited and no longer reflects this PKGBUILD."
                    ),
                    file=ctx.file,
                    line=None,
                    snippet=None,
                    remediation="Run `makepkg --printsrcinfo > .SRCINFO` and commit the result.",
                )
            )

        for key in CHECKSUM_KEYS:
            pkgbuild_sums = ctx.checksums.get(key, [])
            srcinfo_sums = ctx.srcinfo_checksums.get(key, [])
            # Compares even when only one side declares this key at all -- a
            # checksum array present in .SRCINFO but entirely removed from
            # PKGBUILD (or vice versa) is exactly as much a mismatch as
            # differing values would be; `[] != []` for a key neither side
            # uses keeps that case correctly silent.
            if pkgbuild_sums != srcinfo_sums:
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        severity=self.default_severity,
                        message=(
                            f"'{key}' in PKGBUILD does not match the sibling .SRCINFO -- the "
                            f"checksums a reviewer sees in .SRCINFO don't match what makepkg "
                            f"will actually verify downloads against."
                        ),
                        file=ctx.file,
                        line=None,
                        snippet=None,
                        remediation="Run `makepkg --printsrcinfo > .SRCINFO` and commit the result.",
                    )
                )
        return findings
