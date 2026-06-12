# mcp-bytesmith — pure-Python MCP server for encoding, hashing, and crypto-primitives.
# Copyright (C) 2026  Laszlo Pere
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""TODO 12.3 / plan §2.3.3 / §1.4.10-12, §1.5.1-2 — string_escape.

Covers each of the 11 styles: the backslash family (json/js/python/c/backslash),
the entity styles (html/xml), and the codec styles (unicode_escape,
quoted_printable, mime_word, shell), plus control-char handling and the
style-validation rejection."""

import asyncio
import base64
import json as _json

import pytest

from mcp_bytesmith.core import string_escape as SE  # noqa: E402
from mcp_bytesmith.server import mcp  # noqa: E402


def r(text, style):
    out = SE(text, style)
    assert out["style"] == style
    return out["result"]


# --- backslash family ----------------------------------------------------------
def test_json_escapes_quote_backslash_controls():
    # bare content, no wrapping quotes; \v becomes  (JSON has no \v).
    assert r('a"b\\c\n\t', "json") == 'a\\"b\\\\c\\n\\t'
    assert r("\v", "json") == "\\u000b"


def test_json_keeps_printable_unicode():
    assert r("café", "json") == "café"


def test_js_escapes_all_quote_kinds_and_line_separators():
    assert r("'\"`", "js") == "\\'\\\"\\`"
    assert r("  ", "js") == "\\u2028\\u2029"


def test_python_escapes_both_quotes():
    assert r("a'b\"c", "python") == "a\\'b\\\"c"
    assert r("\x01", "python") == "\\x01"


def test_c_uses_octal_for_control_and_names_bell():
    assert r("\a", "c") == "\\a"
    assert r("\x01", "c") == "\\001"  # octal, unambiguous before a digit
    assert r('"', "c") == '\\"'
    assert r("'", "c") == "'"  # apostrophe needs no escape in a C "..." literal


def test_backslash_escapes_controls_not_quotes():
    assert r("a\"'b\n", "backslash") == "a\"'b\\n"
    assert r("\x7f", "backslash") == "\\x7f"


def test_backslash_doubles_existing_backslash():
    assert r("\\n", "backslash") == "\\\\n"  # literal backslash + n, not newline


# --- entity styles -------------------------------------------------------------
def test_html_escapes_markup_and_quotes():
    assert r('<a href="x">&\'', "html") == "&lt;a href=&quot;x&quot;&gt;&amp;&#x27;"


def test_xml_uses_apos_for_apostrophe():
    assert r("<x>&'\"", "xml") == "&lt;x&gt;&amp;&apos;&quot;"


# --- codec styles --------------------------------------------------------------
def test_unicode_escape_escapes_non_ascii():
    assert r("é☃", "unicode_escape") == "\\xe9\\u2603"
    assert r("ab", "unicode_escape") == "ab"


def test_quoted_printable_encodes_high_bytes():
    # 'é' is UTF-8 C3 A9 -> =C3=A9
    assert r("é", "quoted_printable") == "=C3=A9"


def test_mime_word_is_base64_encoded_word():
    out = r("café", "mime_word")
    assert out.startswith("=?UTF-8?B?") and out.endswith("?=")
    body = out[len("=?UTF-8?B?") : -len("?=")]
    assert base64.b64decode(body).decode("utf-8") == "café"


def test_shell_single_quotes_dangerous_input():
    assert r("a b; rm -rf /", "shell") == "'a b; rm -rf /'"
    assert r("plain", "shell") == "plain"  # safe tokens pass through unquoted


def test_shell_handles_embedded_single_quote():
    assert r("it's", "shell") == "'it'\"'\"'s'"


# --- empty / identity ----------------------------------------------------------
def test_empty_string_each_style():
    for style in (
        "json",
        "js",
        "python",
        "c",
        "backslash",
        "html",
        "xml",
        "unicode_escape",
        "quoted_printable",
    ):
        assert r("", style) == ""


# --- validation ----------------------------------------------------------------
def test_unknown_style_rejected():
    with pytest.raises(ValueError, match="unknown style"):
        SE("x", "rust")


# --- app wiring ----------------------------------------------------------------
def test_registered_with_style_enum():
    tool = next(t for t in asyncio.run(mcp.list_tools()) if t.name == "string_escape")
    styles = tool.inputSchema["properties"]["style"]["enum"]
    assert set(styles) == {
        "json",
        "js",
        "python",
        "c",
        "shell",
        "html",
        "xml",
        "backslash",
        "unicode_escape",
        "quoted_printable",
        "mime_word",
    }


def test_callable_through_app():
    async def go():
        return await mcp.call_tool("string_escape", {"text": "a\nb", "style": "json"})

    result = asyncio.run(go())
    contents = result[0] if isinstance(result, tuple) else result
    payload = _json.loads(contents[0].text)
    assert payload == {"style": "json", "result": "a\\nb"}
