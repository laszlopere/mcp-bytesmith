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

"""TODO 12.4 / plan §2.3.4 / §1.4.10-12, §1.5.1-2 — string_unescape.

The style-for-style inverse of string_escape. Covers each style's decode, the
backslash-sequence forms (\\xNN, \\uXXXX, octal, \\u{...}), escaped-quote
recovery, malformed-sequence rejection, and a full escape->unescape round trip
across all 11 styles."""

import asyncio
import json as _json

import pytest

from mcp_bytesmith.core import string_escape as SE  # noqa: E402
from mcp_bytesmith.core import string_unescape as SU  # noqa: E402
from mcp_bytesmith.server import mcp  # noqa: E402

ALL_STYLES = [
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
]


def r(text, style):
    out = SU(text, style)
    assert out["style"] == style
    return out["result"]


# --- backslash family ----------------------------------------------------------
def test_json_decodes_escapes():
    assert r('a\\"b\\\\c\\n\\t', "json") == 'a"b\\c\n\t'
    assert r("\\u000b", "json") == "\v"


def test_js_decodes_quotes_hex_unicode():
    assert r("\\'\\\"\\`", "js") == "'\"`"
    assert r("\\x41\\u0042", "js") == "AB"
    assert r("\\u{1f600}", "js") == "\U0001f600"


def test_python_decodes_hex_octal_and_wide_unicode():
    assert r("\\x01", "python") == "\x01"
    assert r("\\101", "python") == "A"  # octal
    assert r("\\U0001f600", "python") == "\U0001f600"


def test_c_greedy_hex_and_octal():
    assert r("\\x41", "c") == "A"
    assert r("\\001", "c") == "\x01"
    assert r("\\a", "c") == "\a"


def test_backslash_decodes_hex_and_unknown_drops_slash():
    assert r("a\\x7fb", "backslash") == "a\x7fb"
    assert r('\\"', "backslash") == '"'  # unknown escape -> drop backslash


def test_backslash_collapses_double_backslash():
    assert r("\\\\n", "backslash") == "\\n"  # -> literal backslash + n


# --- entity styles -------------------------------------------------------------
def test_html_decodes_entities():
    assert r("&lt;a&gt;&amp;&quot;&#x27;", "html") == "<a>&\"'"


def test_xml_decodes_apos():
    assert r("&lt;x&gt;&amp;&apos;&quot;", "xml") == "<x>&'\""


# --- codec styles --------------------------------------------------------------
def test_unicode_escape_decodes():
    assert r("\\xe9\\u2603", "unicode_escape") == "é☃"


def test_quoted_printable_decodes():
    assert r("=C3=A9", "quoted_printable") == "é"


def test_mime_word_decodes_b_and_q():
    assert r("=?UTF-8?B?Y2Fmw6k=?=", "mime_word") == "café"
    assert r("=?UTF-8?Q?caf=C3=A9?=", "mime_word") == "café"  # Q-encoding too


def test_shell_unquotes():
    assert r("'a b; rm -rf /'", "shell") == "a b; rm -rf /"
    assert r("'it'\"'\"'s'", "shell") == "it's"  # concatenated segments


# --- malformed sequences -------------------------------------------------------
def test_truncated_hex_rejected():
    with pytest.raises(ValueError):
        SU("\\x4", "python")


def test_truncated_unicode_rejected():
    with pytest.raises(ValueError):
        SU("\\u12", "js")


def test_unterminated_brace_rejected():
    with pytest.raises(ValueError):
        SU("\\u{1f600", "js")


def test_c_greedy_hex_needs_a_digit():
    # C's greedy \x must be followed by at least one hex digit.
    with pytest.raises(ValueError, match=r"\\x needs at least one hex digit"):
        SU("\\xZ", "c")


def test_python_wide_unicode_truncated_rejected():
    # \U requires exactly eight hex digits.
    with pytest.raises(ValueError, match=r"\\U needs eight hex digits"):
        SU("\\U0001F60", "python")


def test_trailing_backslash_kept_literal():
    assert r("ab\\", "backslash") == "ab\\"


# --- round trip with string_escape ---------------------------------------------
@pytest.mark.parametrize("style", ALL_STYLES)
@pytest.mark.parametrize(
    "sample",
    [
        "",
        "plain text",
        "quotes \" ' ` mixed",
        "controls \t \n \r \x00 \x07 \x7f",
        "unicode café ☃ é ﬁ",
        "back\\slash and \\n literal",
        '<a href="x">&\'</a>',
    ],
)
def test_round_trip(style, sample):
    escaped = SE(sample, style)["result"]
    assert SU(escaped, style)["result"] == sample


# --- validation / app ----------------------------------------------------------
def test_unknown_style_rejected():
    with pytest.raises(ValueError, match="unknown style"):
        SU("x", "rust")


def test_registered_with_style_enum():
    tool = next(t for t in asyncio.run(mcp.list_tools()) if t.name == "string_unescape")
    styles = tool.inputSchema["properties"]["style"]["enum"]
    assert set(styles) == set(ALL_STYLES)


def test_callable_through_app():
    async def go():
        return await mcp.call_tool(
            "string_unescape", {"text": "a\\nb", "style": "json"}
        )

    result = asyncio.run(go())
    contents = result[0] if isinstance(result, tuple) else result
    payload = _json.loads(contents[0].text)
    assert payload == {"style": "json", "result": "a\nb"}
