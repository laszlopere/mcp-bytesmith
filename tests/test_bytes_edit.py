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

"""TODO 11.8 / plan §2.2.8 / §1.5.8 — bytes_edit (byte-field glue).

Covers each action (pad/trim/slice/concat/size/prefix), the address <-> 32-byte
topic round-trip that motivates the tool, and the input-validation rejections."""

import asyncio
import json

import pytest

from mcp_bytesmith.core import bytes_edit as BE  # noqa: E402
from mcp_bytesmith.server import mcp  # noqa: E402

# A 20-byte address and its 32-byte left-padded log-topic form.
ADDR = "0x" + "ab" * 20
TOPIC = "0x" + "00" * 12 + "ab" * 20


# --- pad -----------------------------------------------------------------------
def test_pad_left_to_32_makes_topic():
    out = BE("pad", ADDR, length=32)  # side defaults to left
    assert out == {"action": "pad", "result": TOPIC, "size": 32}


def test_pad_right_appends_fill():
    out = BE("pad", "0x1234", length=4, side="right")
    assert out["result"] == "0x12340000"
    assert out["size"] == 4


def test_pad_custom_fill_byte():
    out = BE("pad", "0xbeef", length=4, side="left", fill="ff")
    assert out["result"] == "0xffffbeef"


def test_pad_never_truncates_when_already_wider():
    out = BE("pad", "0x11223344", length=2)
    assert out["result"] == "0x11223344"
    assert out["size"] == 4


def test_pad_requires_length():
    with pytest.raises(ValueError):
        BE("pad", "0x1234")


def test_pad_rejects_negative_length():
    with pytest.raises(ValueError):
        BE("pad", "0x1234", length=-1)


def test_pad_rejects_oversize_length():
    # An unbounded target width allocates gigabytes of fill bytes (CR.5).
    with pytest.raises(ValueError):
        BE("pad", "0x1234", length=2_000_000)


# --- trim ----------------------------------------------------------------------
def test_trim_left_strips_leading_zeros():
    out = BE("trim", TOPIC)  # side defaults to left
    assert out["result"] == ADDR
    assert out["size"] == 20


def test_trim_right_strips_trailing_zeros():
    out = BE("trim", "0x12340000", side="right")
    assert out["result"] == "0x1234"
    assert out["size"] == 2


def test_trim_custom_fill():
    out = BE("trim", "0xffff1234", side="left", fill="ff")
    assert out["result"] == "0x1234"


def test_trim_all_zeros_to_empty():
    out = BE("trim", "0x000000")
    assert out["result"] == "0x"
    assert out["size"] == 0


# --- slice ---------------------------------------------------------------------
def test_slice_topic_back_to_address():
    out = BE("slice", TOPIC, start=12)  # last 20 bytes
    assert out["result"] == ADDR
    assert out["size"] == 20


def test_slice_start_end():
    out = BE("slice", "0xdeadbeefcafe", start=1, end=3)
    assert out["result"] == "0xadbe"


def test_slice_negative_index():
    out = BE("slice", "0xdeadbeefcafe", start=-2)
    assert out["result"] == "0xcafe"


# --- concat --------------------------------------------------------------------
def test_concat_appends_parts():
    out = BE("concat", "0x1234", parts=["0x5678", "abcd"])
    assert out["result"] == "0x12345678abcd"
    assert out["size"] == 6


def test_concat_no_parts_is_identity():
    out = BE("concat", "0x1234")
    assert out["result"] == "0x1234"


# --- size ----------------------------------------------------------------------
def test_size_reports_length_unchanged():
    out = BE("size", ADDR)
    assert out["size"] == 20
    assert out["result"] == ADDR


# --- prefix --------------------------------------------------------------------
def test_prefix_add():
    out = BE("prefix", "1234", side="left")
    assert out["result"] == "0x1234"
    assert out["size"] == 2


def test_prefix_strip():
    out = BE("prefix", "0x1234", side="right")
    assert out["result"] == "1234"
    assert out["size"] == 2


# --- errors / app --------------------------------------------------------------
def test_invalid_hex_rejected():
    with pytest.raises(ValueError):
        BE("size", "0xnothex")


def test_invalid_fill_rejected():
    with pytest.raises(ValueError):
        BE("pad", "0x12", length=4, fill="zz")


def test_multibyte_fill_rejected():
    with pytest.raises(ValueError):
        BE("pad", "0x12", length=4, fill="0011")


def test_unknown_action_raises():
    with pytest.raises(ValueError):
        BE("frobnicate", "0x12")


def test_registered_with_action_enum():
    tool = next(t for t in asyncio.run(mcp.list_tools()) if t.name == "bytes_edit")
    actions = tool.inputSchema["properties"]["action"]["enum"]
    assert set(actions) == {"pad", "trim", "slice", "concat", "size", "prefix"}


def test_callable_through_app():
    async def go():
        return await mcp.call_tool(
            "bytes_edit", {"action": "pad", "data": ADDR, "length": 32}
        )

    result = asyncio.run(go())
    contents = result[0] if isinstance(result, tuple) else result
    payload = json.loads(contents[0].text)
    assert payload["result"] == TOPIC
    assert payload["size"] == 32
