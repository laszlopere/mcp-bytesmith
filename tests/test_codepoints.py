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

"""TODO 12.5 / plan §2.3.5 / §1.5.3 — codepoints.

Covers the per-scalar breakdown (codepoint/name/utf8/utf16/utf32), astral
characters staying whole, combining sequences, the <category> name fallback for
unnamed scalars, count vs len, and the empty-string edge."""

import asyncio
import json

from mcp_bytesmith.core import codepoints as CP  # noqa: E402
from mcp_bytesmith.server import mcp  # noqa: E402


# --- plain ASCII ---------------------------------------------------------------
def test_ascii_letter():
    out = CP("A")
    assert out["count"] == 1
    assert out["chars"] == [
        {
            "char": "A",
            "codepoint": "U+0041",
            "name": "LATIN CAPITAL LETTER A",
            "utf8": "41",
            "utf16": "0041",
            "utf32": "00000041",
        }
    ]


def test_multiple_chars_in_order():
    out = CP("Hi")
    assert out["count"] == 2
    assert [c["codepoint"] for c in out["chars"]] == ["U+0048", "U+0069"]


# --- multi-byte BMP ------------------------------------------------------------
def test_accented_char_byte_views():
    # é = U+00E9: utf-8 c3a9, utf-16-be 00e9, utf-32-be 000000e9.
    out = CP("é")
    c = out["chars"][0]
    assert c["codepoint"] == "U+00E9"
    assert c["name"] == "LATIN SMALL LETTER E WITH ACUTE"
    assert c["utf8"] == "c3a9"
    assert c["utf16"] == "00e9"
    assert c["utf32"] == "000000e9"


# --- astral / surrogate-pair character -----------------------------------------
def test_astral_emoji_stays_whole():
    # 😀 = U+1F600, a single code point above the BMP.
    out = CP("😀")
    assert out["count"] == 1
    c = out["chars"][0]
    assert c["char"] == "😀"
    assert c["codepoint"] == "U+1F600"
    assert c["name"] == "GRINNING FACE"
    assert c["utf8"] == "f09f9880"
    assert c["utf16"] == "d83dde00"  # surrogate pair, big-endian
    assert c["utf32"] == "0001f600"


def test_count_is_codepoints_not_len_quirks():
    # Two astral chars -> count 2 even though each is a surrogate pair internally.
    out = CP("😀😀")
    assert out["count"] == 2


# --- combining sequence --------------------------------------------------------
def test_combining_mark_is_separate_codepoint():
    # "e" + combining acute (U+0301) is two code points, not one.
    out = CP("é")
    assert out["count"] == 2
    assert out["chars"][1]["codepoint"] == "U+0301"
    assert out["chars"][1]["name"] == "COMBINING ACUTE ACCENT"


# --- unnamed scalars get a <category> placeholder ------------------------------
def test_control_char_name_fallback():
    out = CP("\x00")
    c = out["chars"][0]
    assert c["codepoint"] == "U+0000"
    assert c["name"] == "<control>"
    assert c["utf8"] == "00"


def test_private_use_name_fallback():
    out = CP("")  # start of the BMP private-use area
    assert out["chars"][0]["name"] == "<private-use>"


# --- empty input ---------------------------------------------------------------
def test_empty_string():
    assert CP("") == {"count": 0, "chars": []}


# --- app wiring ----------------------------------------------------------------
def test_registered_on_app():
    names = {t.name for t in asyncio.run(mcp.list_tools())}
    assert "codepoints" in names


def test_callable_through_app():
    async def go():
        return await mcp.call_tool("codepoints", {"text": "é"})

    result = asyncio.run(go())
    contents = result[0] if isinstance(result, tuple) else result
    payload = json.loads(contents[0].text)
    assert payload["count"] == 1
    assert payload["chars"][0]["utf8"] == "c3a9"
