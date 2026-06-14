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

"""TODO 18.5 / §2.9.5 — byte_order (host<->network endianness codec).

A stdlib (always-on) tool — no extra required, so no importorskip guard."""

import asyncio
import base64
import json
import sys

import pytest

from mcp_bytesmith.core import byte_order
from mcp_bytesmith.server import mcp


def _r(*args, **kwargs):
    return byte_order(*args, **kwargs)["result"]


# --- basic swaps (htons/htonl/ntohs/ntohl shapes) ------------------------------
def test_htons_2_byte_swap():
    # little -> big reverses the two bytes: 0x1234 -> 0x3412.
    assert _r("0x1234", "little", "big", width=2) == "3412"


def test_htonl_4_byte_swap():
    assert _r("0x12345678", "little", "big", width=4) == "78563412"


def test_8_byte_swap():
    assert _r("0x0102030405060708", "big", "little", width=8) == "0807060504030201"


def test_swap_is_symmetric_big_little():
    # ntohs is the same byte reversal as htons (orders just differ in name).
    assert _r("0x1234", "big", "little", width=2) == _r(
        "0x1234", "little", "big", width=2
    )


# --- no-op when source and target orders agree ---------------------------------
def test_same_order_is_noop():
    assert _r("0x12345678", "big", "big", width=4) == "12345678"
    assert _r("0x12345678", "little", "little", width=4) == "12345678"


def test_host_to_host_is_noop():
    assert _r("0xdeadbeef", "host", "host") == "deadbeef"


# --- network / host aliases ----------------------------------------------------
def test_network_is_alias_for_big():
    assert _r("0x1234", "little", "network", width=2) == _r(
        "0x1234", "little", "big", width=2
    )
    assert _r("0x1234", "network", "little", width=2) == _r(
        "0x1234", "big", "little", width=2
    )


def test_host_resolves_to_platform_byteorder():
    # On a little-endian box host->network swaps; on a big-endian box it is a no-op.
    out = _r("0x1234", "host", "network", width=2)
    assert out == ("3412" if sys.byteorder == "little" else "1234")


# --- width: left-pad a short value ---------------------------------------------
def test_width_left_pads_short_value():
    # 0x1234 padded to 4 bytes (0x00001234) then reversed -> 0x34120000.
    assert _r("0x1234", "big", "little", width=4) == "34120000"


def test_width_pad_noop_order_still_pads():
    # equal orders skip the reversal but width normalization still applies.
    assert _r("0x1234", "big", "big", width=4) == "00001234"


# --- width: array of fixed-size fields -----------------------------------------
def test_width_groups_into_independent_fields():
    # width 2 over 4 bytes: [1234][5678] -> [3412][7856].
    assert _r("0x12345678", "little", "big", width=2) == "34127856"


def test_no_width_swaps_whole_buffer():
    assert _r("0x12345678", "little", "big") == "78563412"


# --- formats -------------------------------------------------------------------
def test_input_format_text():
    # "AB" -> bytes 0x41 0x42; swap width 2 -> 0x42 0x41.
    assert _r("AB", "little", "big", input_format="text", width=2) == "4241"


def test_output_format_base64():
    out = _r("0x1234", "little", "big", width=2, output_format="base64")
    assert out == base64.b64encode(bytes.fromhex("3412")).decode("ascii")


def test_empty_input():
    assert _r("", "big", "little") == ""


# --- full payload + reported width ---------------------------------------------
def test_full_payload():
    assert byte_order("0x1234", "little", "big", width=2) == {
        "result": "3412",
        "from_order": "little",
        "to_order": "big",
        "width": 2,
        "output_format": "hex",
    }


def test_width_defaults_to_data_length():
    out = byte_order("0x12345678", "little", "big")
    assert out["width"] == 4


# --- error paths ---------------------------------------------------------------
def test_unknown_order_raises():
    with pytest.raises(ValueError):
        byte_order("0x12", "weird", "big")


def test_width_must_be_positive():
    with pytest.raises(ValueError):
        byte_order("0x1234", "little", "big", width=0)


def test_length_not_multiple_of_width_raises():
    # 3 bytes is longer than width 2 but not a multiple of it.
    with pytest.raises(ValueError):
        byte_order("0x123456", "big", "little", width=2)


def test_invalid_hex_raises():
    with pytest.raises(ValueError):
        byte_order("0xZZ", "little", "big")


# --- app registration / schema -------------------------------------------------
def test_registered_with_enum_schema():
    tool = next(t for t in asyncio.run(mcp.list_tools()) if t.name == "byte_order")
    props = tool.inputSchema["properties"]
    assert props["from_order"]["enum"] == ["host", "little", "big", "network"]
    assert props["to_order"]["enum"] == ["host", "little", "big", "network"]


def test_callable_through_app():
    async def go():
        return await mcp.call_tool(
            "byte_order",
            {"data": "0x12345678", "from_order": "little", "to_order": "big"},
        )

    result = asyncio.run(go())
    contents = result[0] if isinstance(result, tuple) else result
    payload = json.loads(contents[0].text)
    assert payload["result"] == "78563412"
