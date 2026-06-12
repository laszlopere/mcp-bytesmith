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

"""TODO 12.2 / plan §2.3.2 / §1.5.6 — charset_transcode.

Covers the mojibake-repair round trip (cp1252 <-> utf-8), the hex fallback when
target bytes aren't valid text, the `errors` handlers (strict/replace/ignore),
and the charset/handler validation rejections."""

import asyncio
import json

import pytest

from mcp_bytesmith.core import charset_transcode as TC  # noqa: E402
from mcp_bytesmith.server import mcp  # noqa: E402


# --- mojibake repair (the headline use case) -----------------------------------
def test_repairs_cp1252_misread_utf8():
    # "café" stored as utf-8, then mis-decoded as cp1252, shows as "cafÃ©".
    out = TC("cafÃ©", from_charset="cp1252", to_charset="utf-8")
    assert out == {
        "from_charset": "cp1252",
        "to_charset": "utf-8",
        "result": "café",
        "output_format": "text",
    }


def test_forward_produces_mojibake():
    # The inverse: utf-8 bytes of "café" reinterpreted as cp1252.
    out = TC("café", from_charset="utf-8", to_charset="cp1252")
    assert out["result"] == "cafÃ©"
    assert out["output_format"] == "text"


def test_round_trip_is_inverse():
    once = TC("café", from_charset="utf-8", to_charset="cp1252")["result"]
    back = TC(once, from_charset="cp1252", to_charset="utf-8")
    assert back["result"] == "café"


# --- latin-1 <-> utf-8 ---------------------------------------------------------
def test_latin1_to_utf8():
    out = TC("Ã¥Ã¸", from_charset="latin-1", to_charset="utf-8")
    assert out["result"] == "åø"
    assert out["output_format"] == "text"


# --- hex fallback when target can't decode -------------------------------------
def test_hex_fallback_on_undecodable_target():
    # utf-8 bytes of "café" (63 61 66 c3 a9) are not valid ASCII.
    out = TC("café", from_charset="utf-8", to_charset="ascii")
    assert out == {
        "from_charset": "utf-8",
        "to_charset": "ascii",
        "result": "636166c3a9",
        "output_format": "hex",
    }


# --- error handlers ------------------------------------------------------------
def test_replace_handler_substitutes_on_decode():
    out = TC("café", from_charset="utf-8", to_charset="ascii", errors="replace")
    assert out["output_format"] == "text"
    assert out["result"].startswith("caf")
    assert "�" in out["result"]


def test_ignore_handler_drops_unencodable_source():
    # "☃" has no cp1252 byte; ignore drops it instead of raising.
    out = TC("ab☃c", from_charset="cp1252", to_charset="cp1252", errors="ignore")
    assert out["result"] == "abc"


def test_strict_rejects_unencodable_source():
    with pytest.raises(ValueError):
        TC("snowman ☃", from_charset="ascii", to_charset="utf-8")


# --- identity / empty ----------------------------------------------------------
def test_ascii_identity():
    out = TC("hello", from_charset="utf-8", to_charset="utf-8")
    assert out == {
        "from_charset": "utf-8",
        "to_charset": "utf-8",
        "result": "hello",
        "output_format": "text",
    }


def test_empty_string():
    out = TC("", from_charset="utf-8", to_charset="utf-8")
    assert out["result"] == ""
    assert out["output_format"] == "text"


# --- validation ----------------------------------------------------------------
def test_unknown_from_charset_rejected():
    with pytest.raises(ValueError, match="unknown charset"):
        TC("x", from_charset="bogus-codec", to_charset="utf-8")


def test_unknown_to_charset_rejected():
    with pytest.raises(ValueError, match="unknown charset"):
        TC("x", from_charset="utf-8", to_charset="bogus-codec")


def test_unknown_errors_handler_rejected():
    with pytest.raises(ValueError, match="errors handler"):
        TC("x", from_charset="utf-8", to_charset="utf-8", errors="nonsense")


# --- app wiring ----------------------------------------------------------------
def test_registered_on_app():
    names = {t.name for t in asyncio.run(mcp.list_tools())}
    assert "charset_transcode" in names


def test_callable_through_app():
    async def go():
        return await mcp.call_tool(
            "charset_transcode",
            {"text": "cafÃ©", "from_charset": "cp1252", "to_charset": "utf-8"},
        )

    result = asyncio.run(go())
    contents = result[0] if isinstance(result, tuple) else result
    payload = json.loads(contents[0].text)
    assert payload["result"] == "café"
    assert payload["output_format"] == "text"
