from __future__ import annotations

import re
from pathlib import Path

from ..model import RuleContext
from .bash_ast import build_module_scope, extract_functions, mask_function_bodies, parse_script
from .srcinfo import parse_srcinfo_fields

_SCALAR_RE = re.compile(
    r'^\s*(pkgname|pkgver|pkgrel|pkgbase)=(["\']?)(.*?)\2\s*$', re.MULTILINE
)

CHECKSUM_KEYS = (
    "cksums",
    "md5sums",
    "sha1sums",
    "sha224sums",
    "sha256sums",
    "sha384sums",
    "sha512sums",
    "b2sums",
)

# makepkg supports architecture-specific overrides for source and every
# checksum array (source_x86_64=(), sha256sums_aarch64=(), ...) -- makepkg
# builds the effective array for the current CARCH as base + arch-suffixed,
# so a source hidden only in an arch-specific array is just as real as one in
# the base array, but was previously invisible to every rule that reads
# ctx.sources/ctx.checksums (RCE004, INT002, INT003), regardless of which
# architecture a reviewer's machine happens to be. We don't know CARCH
# statically and don't need to: every arch suffix the PKGBUILD itself
# declares in arch=() is merged in, so nothing hidden behind any of them
# goes unseen.
#
# Suffix candidates are restricted to values actually declared in arch=()
# (not just any array named source_<word>): makepkg itself only ever treats
# source_<arch>/<checksum>_<arch> as a real override when <arch> matches a
# declared architecture, so an unrelated array that happens to be named e.g.
# source_notes or sha256sums_backup is not something makepkg would ever
# consume as source data, and merging it in would inject non-source content
# into ctx.sources/ctx.checksums.


def _merge_arch_variants(arrays: dict[str, list[str]], base_key: str, arch_suffixes: list[str]) -> list[str]:
    combined = list(arrays.get(base_key, []))
    for arch in arch_suffixes:
        combined += arrays.get(f"{base_key}_{arch}", [])
    return combined


def _merge_arch_variant_spans(
    array_spans: dict[str, list[tuple[int, int]]], base_key: str, arch_suffixes: list[str]
) -> list[tuple[int, int]]:
    """Same merge as _merge_arch_variants(), but over the base/arch arrays' raw
    source-character spans rather than their parsed element values -- gives
    rules/integrity.py the real on-disk locations of source=()/source_<arch>=()
    to search within, instead of the whole file."""
    combined = list(array_spans.get(base_key, []))
    for arch in arch_suffixes:
        combined += array_spans.get(f"{base_key}_{arch}", [])
    return combined


def parse_pkgbuild(path: Path) -> RuleContext:
    source = path.read_text(errors="replace")
    parsed = parse_script(source)

    scalars: dict[str, str] = {}
    for m in _SCALAR_RE.finditer(source):
        key, _, value = m.group(1), m.group(2), m.group(3)
        scalars.setdefault(key, value)

    # Split packages declare pkgname=('a' 'b') as an array; a single pkgname=foo
    # scalar is only meaningful when there's no array form. Checking the array
    # first also sidesteps a quirk of _SCALAR_RE: against `pkgname=(...)`  it still
    # matches (the empty quote-group case), capturing the literal text "(...)"  as
    # if it were a scalar value, which would be wrong for split packages.
    array_names = parsed.arrays.get("pkgname")
    pkgname = array_names[0] if array_names else scalars.get("pkgname")

    # Sorted for a deterministic merge order, applied identically to `source`
    # and every checksum key -- this preserves index alignment between a
    # source and its checksum entries (an invariant makepkg itself requires:
    # each arch block's source/checksum arrays must be the same length),
    # since both are built by appending the same arch suffixes in the same
    # order.
    arch_suffixes = sorted(set(parsed.arrays.get("arch", [])))

    sources = _merge_arch_variants(parsed.arrays, "source", arch_suffixes)
    source_spans = _merge_arch_variant_spans(parsed.array_spans, "source", arch_suffixes)
    checksums = {
        key: merged
        for key in CHECKSUM_KEYS
        if (merged := _merge_arch_variants(parsed.arrays, key, arch_suffixes))
    }
    functions = extract_functions(parsed.ast_nodes)
    module_scope = build_module_scope(parsed.ast_nodes, source)
    module_scope_source = mask_function_bodies(parsed.ast_nodes, source)

    # .SRCINFO is committed alongside every real AUR PKGBUILD and is what the
    # AUR website displays and some tooling reads without executing the
    # PKGBUILD -- see rules/integrity.py:INT006. Sibling file, not always
    # present (e.g. a bare snapshot tarball rather than a git checkout), so
    # its absence is not itself a finding.
    srcinfo_path = path.parent / ".SRCINFO"
    srcinfo_present = srcinfo_path.is_file()
    srcinfo_sources: list[str] = []
    srcinfo_checksums: dict[str, list[str]] = {}
    if srcinfo_present:
        srcinfo_fields = parse_srcinfo_fields(srcinfo_path)
        srcinfo_arch_suffixes = sorted(set(srcinfo_fields.get("arch", [])))
        srcinfo_sources = _merge_arch_variants(srcinfo_fields, "source", srcinfo_arch_suffixes)
        srcinfo_checksums = {
            key: merged
            for key in CHECKSUM_KEYS
            if (merged := _merge_arch_variants(srcinfo_fields, key, srcinfo_arch_suffixes))
        }

    return RuleContext(
        file=path,
        source=source,
        ast=parsed.ast_nodes,
        parse_error=parsed.parse_error,
        pkgname=pkgname,
        pkgver=scalars.get("pkgver"),
        sources=sources,
        source_spans=source_spans,
        checksums=checksums,
        functions=functions,
        module_scope=module_scope,
        module_scope_source=module_scope_source,
        srcinfo_present=srcinfo_present,
        srcinfo_sources=srcinfo_sources,
        srcinfo_checksums=srcinfo_checksums,
    )
