from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Iterator

import bashlex
from bashlex import errors as bashlex_errors

_ARRAY_ASSIGN_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)\+?=\(")


def strip_array_literals(source: str) -> tuple[str, dict[str, str]]:
    """bashlex cannot parse bash array-literal assignments (`name=(...)`) anywhere in
    a script, and a single occurrence aborts parsing of the *entire* file rather than
    just that statement (verified empirically: bashlex.parse() is all-or-nothing).
    PKGBUILDs rely on arrays pervasively (source=(), sha256sums=(), depends=(), and
    often `local` arrays inside build()/package()), so an unmodified real-world
    PKGBUILD fails to parse essentially every time.

    This masks each array-literal statement in place (every character replaced with
    a space, newlines left as newlines) before the remainder is handed to bashlex for
    real AST parsing of control flow. Masking rather than deleting keeps the cleaned
    string exactly the same length as the original, so every bashlex node's character
    offset lines up 1:1 with an offset into the original source -- callers can use
    line_of(node.pos[0], original_source) directly. The raw inner text of each array
    is returned separately, to be split into elements by split_array_elements() --
    array contents are declarative data, not control flow, so they don't need a full
    bash AST.
    """
    extracted: dict[str, str] = {}
    out: list[str] = []
    n = len(source)
    last = 0
    while True:
        m = _ARRAY_ASSIGN_RE.search(source, last)
        if not m:
            out.append(source[last:])
            break
        out.append(source[last : m.start()])
        name = m.group(1)
        is_append = m.group(0).startswith(f"{name}+=")
        j = m.end()  # position just after the opening '('
        depth = 1
        in_squote = in_dquote = False
        # Bash only starts a `#` comment when the `#` is the first character
        # of a word (preceded by whitespace, or at the very start of the
        # array) -- a `#` glued onto other text, e.g. an element like
        # `foo#bar` or a quoted `"...#tag=v1"` git-source fragment, is just
        # part of that word. Tracked so an unbalanced paren inside a real
        # comment (e.g. a ":)" smiley) doesn't perturb depth, while a mid-word
        # `#` is correctly NOT treated as a comment (verified against real
        # bash: `a=(foo#bar baz)` keeps "foo#bar" as one element).
        at_word_start = True
        start_inner = j
        while j < n and depth > 0:
            c = source[j]
            if in_squote:
                if c == "'":
                    in_squote = False
                j += 1
                continue
            if in_dquote:
                if c == "\\":
                    j += 1
                elif c == '"':
                    in_dquote = False
                j += 1
                continue
            if c in " \t\n":
                at_word_start = True
                j += 1
                continue
            if c == "#" and at_word_start:
                nl = source.find("\n", j)
                j = nl if nl != -1 else n
                continue
            at_word_start = False
            if c == "'":
                in_squote = True
            elif c == '"':
                in_dquote = True
            elif c == "(":
                depth += 1
            elif c == ")":
                depth -= 1
            j += 1
        if depth > 0:
            # Ran off the end of the file without a matching ')' -- e.g. an
            # unterminated quote inside the array literal ate the rest of the
            # source. Masking to EOF here would silently blind every rule to
            # everything after this point with no parse error surfaced, so
            # this must fail loudly and let parse_script() report it instead.
            raise ValueError(
                f"unterminated array literal '{name}=(' starting at line "
                f"{source.count(chr(10), 0, m.start()) + 1}"
            )
        inner = source[start_inner : j - 1]
        if is_append and name in extracted:
            # depends+=('foo') should append to the array, not replace it -- common
            # in PKGBUILDs for arch-conditional dependency lists.
            extracted[name] = extracted[name] + " " + inner
        else:
            extracted[name] = inner
        replaced_span = source[m.start() : j]
        out.append("".join(ch if ch == "\n" else " " for ch in replaced_span))
        last = j
    return "".join(out), extracted


def split_array_elements(inner: str) -> list[str]:
    """Quote-aware whitespace split of an array literal's inner text into elements,
    stripping quotes but leaving embedded $var references as literal text (this is
    static analysis, not evaluation)."""
    elements: list[str] = []
    buf: list[str] = []
    in_squote = in_dquote = False
    # Same word-boundary rule as strip_array_literals() above: `#` only starts
    # a comment as the first character of a word, not glued onto other text
    # (e.g. `foo#bar` is one element, not `foo` followed by a comment).
    at_word_start = True
    i = 0
    n = len(inner)
    while i < n:
        c = inner[i]
        if in_squote:
            if c == "'":
                in_squote = False
            else:
                buf.append(c)
            i += 1
            continue
        if in_dquote:
            if c == "\\" and i + 1 < n:
                buf.append(inner[i + 1])
                i += 2
                continue
            if c == '"':
                in_dquote = False
                i += 1
                continue
            buf.append(c)
            i += 1
            continue
        if c.isspace():
            if buf:
                elements.append("".join(buf))
                buf = []
            at_word_start = True
            i += 1
            continue
        if c == "#" and at_word_start:
            nl = inner.find("\n", i)
            if nl == -1:
                break
            i = nl
            continue
        at_word_start = False
        if c == "'":
            in_squote = True
            i += 1
            continue
        if c == '"':
            in_dquote = True
            i += 1
            continue
        buf.append(c)
        i += 1
    if buf:
        elements.append("".join(buf))
    return elements


@dataclass
class ParsedScript:
    source: str
    ast_nodes: list[Any]
    arrays: dict[str, list[str]]
    parse_error: str | None


def parse_script(source: str) -> ParsedScript:
    try:
        cleaned, raw_arrays = strip_array_literals(source)
        arrays = {name: split_array_elements(inner) for name, inner in raw_arrays.items()}
    except Exception as e:
        # e.g. an unterminated quote inside an array literal. Must degrade to a
        # reported parse_error (surfaced by rules/meta.py), never mask the rest
        # of the file to whitespace and report a silent clean scan.
        return ParsedScript(
            source=source, ast_nodes=[], arrays={}, parse_error=f"{type(e).__name__}: {e}"
        )

    try:
        nodes = list(bashlex.parse(cleaned))
        return ParsedScript(source=source, ast_nodes=nodes, arrays=arrays, parse_error=None)
    except bashlex_errors.ParsingError as e:
        return ParsedScript(source=source, ast_nodes=[], arrays=arrays, parse_error=str(e))
    except Exception as e:
        # bashlex doesn't only raise ParsingError for unsupported input -- e.g.
        # arithmetic expansion $((...)) raises a bare NotImplementedError from deep
        # inside its substitution module. This is a security scanner parsing
        # adversarial/malformed input by design: any parse failure must degrade to
        # a reported parse_error (surfaced by rules/meta.py), never crash the scan.
        return ParsedScript(
            source=source, ast_nodes=[], arrays=arrays, parse_error=f"{type(e).__name__}: {e}"
        )


def line_of(offset: int, source: str) -> int:
    return source.count("\n", 0, offset) + 1


def line_and_snippet(offset: int, source: str) -> tuple[int, str | None]:
    """1-indexed line number and stripped source text of that line for a given
    character offset -- the (line_of() + splitlines()[line-1].strip()) idiom every
    rule needs when reporting a Finding, in one place."""
    line = line_of(offset, source)
    snippet = source.splitlines()[line - 1].strip() if line else None
    return line, snippet


def walk(node: Any) -> Iterator[Any]:
    """Depth-first walk over a bashlex AST subtree."""
    yield node
    children: list[Any] = []
    parts = getattr(node, "parts", None)
    if parts:
        children.extend(parts)
    lst = getattr(node, "list", None)
    if lst:
        children.extend(lst)
    # ProcesssubstitutionNode (<(...) / >(...)) holds its inner command here,
    # not in .parts/.list.
    command = getattr(node, "command", None)
    if command is not None:
        children.append(command)
    for child in children:
        yield from walk(child)


def extract_functions(ast_nodes: list[Any]) -> dict[str, Any]:
    """Every function defined in the script, keyed by name. Extracting all of them
    (rather than filtering to a fixed name list) means split-package override
    functions like package_foo-doc() are picked up automatically -- makepkg calls
    package_<pkgname>() instead of package() for split packages, and a fixed name
    list would make any malicious code hidden there invisible to every rule."""
    functions: dict[str, Any] = {}
    for node in ast_nodes:
        if getattr(node, "kind", None) == "function":
            fname = node.parts[0].word
            functions[fname] = node
    return functions


class ModuleScopeNode:
    """Synthetic pseudo-node bundling every top-level statement that is NOT inside a
    function definition, so AST-walking rules can inspect it the same way they
    inspect a function body via walk(). This matters because PKGBUILD is *sourced*
    by makepkg: top-level statements execute immediately when the file is loaded,
    before any function is ever called -- code placed outside build()/package() is
    not somehow safer, and rules that only walk ctx.functions would otherwise miss
    it entirely."""

    kind = "module_scope"

    def __init__(self, statements: list[Any], pos: tuple[int, int]):
        self.parts = statements
        self.pos = pos


def build_module_scope(ast_nodes: list[Any], source: str) -> ModuleScopeNode | None:
    statements = [n for n in ast_nodes if getattr(n, "kind", None) != "function"]
    if not statements:
        return None
    return ModuleScopeNode(statements, pos=(0, len(source)))


def mask_function_bodies(ast_nodes: list[Any], source: str) -> str:
    """Source text with every function body blanked out (space-filled, newlines
    preserved -- same technique as strip_array_literals), leaving only module/
    top-level-scope text. Used by regex-based rules that need to search "everything
    outside a function" as plain text rather than walking the AST."""
    chars = list(source)
    for node in ast_nodes:
        if getattr(node, "kind", None) != "function":
            continue
        start, end = node.pos
        for i in range(start, end):
            if chars[i] != "\n":
                chars[i] = " "
    return "".join(chars)


def describe_scope(name: str) -> str:
    if name == "<module scope>":
        return "top-level code (runs immediately when the file is sourced)"
    return f"'{name}()'"


def iter_scopes(ctx: Any) -> Iterator[tuple[str, Any]]:
    """Yield (label, node) for every function in ctx.functions plus, if present, the
    module/top-level scope -- the standard iteration rules should use instead of
    `ctx.functions.items()` directly, so top-level code isn't silently skipped."""
    yield from ctx.functions.items()
    if ctx.module_scope is not None:
        yield ("<module scope>", ctx.module_scope)


def node_text(node: Any, source: str) -> str:
    """Slice of the original source text spanned by an AST node. Safe to use on any
    node returned by parse_script() since offsets are preserved 1:1 with the original
    source (see strip_array_literals)."""
    start, end = node.pos
    return source[start:end]


def command_words(cmd_node: Any) -> list[str]:
    """All plain `.word` values on a CommandNode's parts, in order (command name plus
    its arguments, skipping parts like redirects that don't carry a `.word`)."""
    return [w for p in getattr(cmd_node, "parts", []) if (w := getattr(p, "word", None)) is not None]


DOWNLOADERS = {"curl", "wget"}

# Matches a short-option cluster ending in -o/-O (e.g. curl's -fsSLo, wget's -qO),
# optionally with the output path attached directly (e.g. wget's -O-, -O/path).
_BUNDLED_OUTPUT_FLAG_RE = re.compile(r"^-[a-zA-Z]*([oO])(.*)$")

# curl and wget give -o/-O opposite meanings, so which flags actually name a
# *content* download target differs per tool:
#   curl: -o/--output <file> writes content there (takes a value).
#         -O/--remote-name derives the local filename from the URL itself --
#         no explicit path to compare against, so it's not tracked as a target.
#   wget: -O/--output-document <file> writes content there (takes a value).
#         -o/--output-file <file> is wget's own *log* file, not a content
#         target -- treating it as one would be a false positive (a package
#         redirecting wget's log chatter to /tmp/systemd-fake isn't dropping a
#         disguised binary there).
_CONTENT_TARGET_FLAGS = {
    "curl": {"-o", "--output"},
    "wget": {"-O", "--output-document"},
}
_BUNDLED_TARGET_LETTER = {"curl": "o", "wget": "O"}


def normalize_path(p: str) -> str:
    return p[2:] if p.startswith("./") else p


def download_output_targets(tool: str, words: list[str]) -> list[str]:
    """Every path a curl/wget invocation actually writes downloaded *content* to --
    tool-aware because curl and wget assign opposite meanings to -o/-O (see
    _CONTENT_TARGET_FLAGS). Handles bundled short flags (curl's -fsSLo), attached
    forms (wget's -O-), and --flag=value long-option syntax."""
    value_flags = _CONTENT_TARGET_FLAGS.get(tool, {"-o", "-O", "--output", "--output-document"})
    bundled_letter = _BUNDLED_TARGET_LETTER.get(tool)

    targets: list[str] = []
    i = 0
    n = len(words)
    while i < n:
        w = words[i]
        if w == "--":
            break
        if w in value_flags:
            if i + 1 < n:
                targets.append(words[i + 1])
            i += 2
            continue
        if "=" in w and w.split("=", 1)[0] in value_flags:
            targets.append(w.split("=", 1)[1])
            i += 1
            continue
        if bundled_letter and w not in ("-o", "-O"):
            m = _BUNDLED_OUTPUT_FLAG_RE.match(w)
            if m and m.group(1) == bundled_letter:
                attached = m.group(2)
                if attached:
                    targets.append(attached)
                elif i + 1 < n:
                    targets.append(words[i + 1])
        i += 1
    return targets


def command_name(cmd_node: Any) -> str | None:
    """Best-effort command name of a bashlex CommandNode: the first part that carries
    a plain `.word` (skips redirects etc.)."""
    for p in getattr(cmd_node, "parts", []):
        w = getattr(p, "word", None)
        if w is not None:
            return w
    return None
