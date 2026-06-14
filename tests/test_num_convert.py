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

"""TODO 18.4 / plan §2.9.4 / §1.4.15 — num_convert (big-int radix convert).

A stdlib (always-on) tool — no extra required, so no importorskip guard."""

import asyncio
import json

import pytest

from mcp_bytesmith.core import num_convert  # noqa: E402
from mcp_bytesmith.server import mcp  # noqa: E402


def _r(*args, **kwargs):
    return num_convert(*args, **kwargs)["result"]


# --- round trips / basic conversions -------------------------------------------
def test_hex_to_dec():
    out = num_convert("0x1a", "hex", "dec")
    assert out == {
        "value": "0x1a",
        "from_base": "hex",
        "to_base": "dec",
        "result": "26",
    }


def test_dec_to_hex_is_prefixed():
    assert _r("26", "dec", "hex") == "0x1a"


def test_bin_and_oct():
    assert _r("0b1010", "bin", "hex") == "0xa"
    assert _r("0xa", "hex", "bin") == "0b1010"
    assert _r("255", "dec", "oct") == "0o377"
    assert _r("0o377", "oct", "dec") == "255"


def test_rpc_hex_to_decimal():
    # 1 gwei as an RPC quantity.
    assert _r("0x3b9aca00", "hex", "dec") == "1000000000"


def test_hex_input_accepts_bare_and_prefixed():
    assert _r("ff", "hex", "dec") == _r("0xff", "hex", "dec") == "255"


def test_same_base_is_normalized():
    # hex -> hex re-emits the canonical prefixed form.
    assert _r("0X1A", "hex", "hex") == "0x1a"


# --- big integers --------------------------------------------------------------
def test_uint256_max_round_trips_losslessly():
    big_hex = "0x" + "f" * 64
    dec = _r(big_hex, "hex", "dec")
    assert dec == str(2**256 - 1)
    assert _r(dec, "dec", "hex", pad_bytes=32) == big_hex


# --- negative values -----------------------------------------------------------
def test_negative_hex_to_dec():
    assert _r("-0xff", "hex", "dec") == "-255"


def test_negative_dec_to_hex_keeps_sign_before_prefix():
    assert _r("-255", "dec", "hex") == "-0xff"


# --- padding -------------------------------------------------------------------
def test_pad_bytes_hex():
    assert _r("26", "dec", "hex", pad_bytes=2) == "0x001a"


def test_pad_bytes_bin_is_bit_aligned():
    assert _r("5", "dec", "bin", pad_bytes=1) == "0b00000101"  # 8 bits


def test_pad_bytes_does_not_truncate_wider_values():
    # 0xffff needs 2 bytes; padding to 1 must not lose data.
    assert _r("0xffff", "hex", "hex", pad_bytes=1) == "0xffff"


def test_pad_zero():
    assert _r("0", "dec", "hex", pad_bytes=4) == "0x00000000"


# --- error paths ---------------------------------------------------------------
def test_invalid_value_raises():
    with pytest.raises(ValueError):
        num_convert("zz", "hex", "dec")


def test_pad_bytes_rejected_for_decimal():
    with pytest.raises(ValueError):
        num_convert("5", "dec", "dec", pad_bytes=1)


def test_pad_bytes_must_be_positive():
    with pytest.raises(ValueError):
        num_convert("5", "dec", "hex", pad_bytes=0)


def test_unknown_from_base_raises():
    # Literal-typed at the schema boundary, but the function still guards a bad
    # base name passed directly.
    with pytest.raises(ValueError, match="unknown from_base"):
        num_convert("1", "base57", "dec")


def test_unknown_to_base_raises():
    with pytest.raises(ValueError, match="unknown to_base"):
        num_convert("1", "dec", "base57")


# --- app registration / schema -------------------------------------------------
def test_registered_with_enum_schema():
    tool = next(t for t in asyncio.run(mcp.list_tools()) if t.name == "num_convert")
    props = tool.inputSchema["properties"]
    assert props["from_base"]["enum"] == ["hex", "dec", "bin", "oct"]
    assert props["to_base"]["enum"] == ["hex", "dec", "bin", "oct"]


def test_callable_through_app():
    async def go():
        return await mcp.call_tool(
            "num_convert", {"value": "0x1a", "from_base": "hex", "to_base": "dec"}
        )

    result = asyncio.run(go())
    contents = result[0] if isinstance(result, tuple) else result
    payload = json.loads(contents[0].text)
    assert payload["result"] == "26"
