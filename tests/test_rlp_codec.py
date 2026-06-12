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

"""TODO 11.5 / plan §2.2.5 / §1.13.5 — rlp_codec.

Vectors are the canonical ones from the Ethereum RLP spec (the "dog"/"cat,dog",
empty string/list, integer, and nested-set examples), cross-checked by
round-tripping encode <-> decode."""

import asyncio
import json

import pytest

pytest.importorskip("Crypto", reason="ethereum extra (pycryptodome) not installed")

from mcp_bytesmith.eth import rlp_codec  # noqa: E402
from mcp_bytesmith.server import mcp  # noqa: E402


def _enc(data):
    return rlp_codec("encode", data)["encoded"]


def _dec(data):
    return rlp_codec("decode", data)["decoded"]


# --- encode: byte-string leaves ------------------------------------------------
def test_encode_single_byte_is_itself():
    # 0x00..0x7f encode to themselves.
    assert _enc("0x00") == "0x00"
    assert _enc("0x7f") == "0x7f"


def test_encode_dog():
    # "dog" = 0x646f67 -> 0x83 646f67.
    assert _enc("0x646f67") == "0x83646f67"


def test_encode_empty_string():
    assert _enc("0x") == "0x80"


def test_encode_byte_above_0x7f_gets_prefix():
    # 0x80 is not < 0x80, so it becomes a length-1 string: 0x81 80.
    assert _enc("0x80") == "0x8180"


def test_encode_long_string_uses_length_of_length():
    # 56 bytes -> long form: 0xb8, length 0x38 (56), then the payload.
    out = _enc("0x" + "61" * 56)
    assert out == "0xb838" + "61" * 56


# --- encode: integer leaves ----------------------------------------------------
def test_encode_zero_is_empty_string():
    assert _enc(0) == "0x80"


def test_encode_small_int_is_single_byte():
    assert _enc(15) == "0x0f"


def test_encode_int_1024():
    assert _enc(1024) == "0x820400"


# --- encode: lists -------------------------------------------------------------
def test_encode_empty_list():
    assert _enc([]) == "0xc0"


def test_encode_cat_dog_list():
    # ["cat", "dog"] = [0x636174, 0x646f67] -> 0xc8 83636174 83646f67.
    assert _enc(["0x636174", "0x646f67"]) == "0xc88363617483646f67"


def test_encode_nested_set_theoretic():
    # The "set theoretical representation of three" vector:
    # [ [], [[]], [ [], [[]] ] ] -> 0xc7c0c1c0c3c0c1c0.
    assert _enc([[], [[]], [[], [[]]]]) == "0xc7c0c1c0c3c0c1c0"


def test_encode_array_as_json_string():
    # A client that stringifies the array still works.
    assert _enc('["0x636174", "0x646f67"]') == "0xc88363617483646f67"


# --- decode --------------------------------------------------------------------
def test_decode_dog():
    assert _dec("0x83646f67") == "0x646f67"


def test_decode_single_byte():
    assert _dec("0x00") == "0x00"


def test_decode_empty_string_and_list():
    assert _dec("0x80") == "0x"
    assert _dec("0xc0") == []


def test_decode_cat_dog_list():
    assert _dec("0xc88363617483646f67") == ["0x636174", "0x646f67"]


def test_decode_nested_set_theoretic():
    assert _dec("0xc7c0c1c0c3c0c1c0") == [[], [[]], [[], [[]]]]


def test_decode_long_string():
    assert _dec("0xb838" + "61" * 56) == "0x" + "61" * 56


# --- round trips ---------------------------------------------------------------
def test_roundtrip_nested_structure():
    structure = ["0x12", ["0x", "0xdeadbeef"], "0x" + "ab" * 100]
    assert _dec(_enc(structure)) == structure


def test_roundtrip_typical_tx_fields():
    # nonce, gasprice, gaslimit, to, value, data, v, r, s (as hex leaves).
    fields = [
        "0x09",
        "0x04a817c800",
        "0x5208",
        "0x3535353535353535353535353535353535353535",
        "0x0de0b6b3a7640000",
        "0x",
        "0x25",
        "0x" + "ab" * 32,
        "0x" + "cd" * 32,
    ]
    assert _dec(_enc(fields)) == fields


# --- error paths ---------------------------------------------------------------
def test_decode_trailing_bytes_raises():
    # Two concatenated empty lists — the second is trailing garbage.
    with pytest.raises(ValueError):
        rlp_codec("decode", "0xc0c0")


def test_decode_truncated_raises():
    # Claims a 3-byte string but only 2 bytes follow.
    with pytest.raises(ValueError):
        rlp_codec("decode", "0x83646f")


def test_decode_empty_input_raises():
    with pytest.raises(ValueError):
        rlp_codec("decode", "0x")


def test_decode_non_string_raises():
    with pytest.raises(ValueError):
        rlp_codec("decode", [1, 2, 3])


def test_encode_negative_int_raises():
    with pytest.raises(ValueError):
        rlp_codec("encode", -1)


def test_encode_bool_raises():
    with pytest.raises(ValueError):
        rlp_codec("encode", True)


def test_unknown_action_raises():
    with pytest.raises(ValueError):
        rlp_codec("frobnicate", "0x00")


# --- app registration ----------------------------------------------------------
def test_registered_and_callable_through_app():
    names = {t.name for t in asyncio.run(mcp.list_tools())}
    assert "rlp_codec" in names

    async def go():
        return await mcp.call_tool(
            "rlp_codec",
            {"action": "encode", "data": ["0x636174", "0x646f67"]},
        )

    result = asyncio.run(go())
    contents = result[0] if isinstance(result, tuple) else result
    payload = json.loads(contents[0].text)
    assert payload["encoded"] == "0xc88363617483646f67"
