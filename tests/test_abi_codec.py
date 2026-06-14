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

"""TODO 11.6 / plan §2.6.5 / §1.13.3, §1.13.6 — abi_codec.

Standard ABI vectors are the canonical ones from the Solidity ABI spec
(hand-verified head/tail layout); packed vectors follow abi.encodePacked's
tight, no-padding rules. Decode is checked by round-tripping and against the
known string vector."""

import asyncio
import json

import pytest

pytest.importorskip("Crypto", reason="ethereum extra (pycryptodome) not installed")

from mcp_bytesmith.eth import abi_codec  # noqa: E402
from mcp_bytesmith.server import mcp  # noqa: E402

W = "0" * 64  # an all-zero 32-byte word in hex


def _enc(types, values, mode="standard"):
    return abi_codec("encode", types, values=values, mode=mode)["encoded"]


def _dec(types, data):
    return abi_codec("decode", types, data=data)["values"]


# --- standard encode: static scalars -------------------------------------------
def test_encode_uint256():
    assert _enc(["uint256"], [1]) == "0x" + W[:-1] + "1"


def test_encode_bool_and_uint():
    # bool true, then uint8(69) — both static, packed head, no tail.
    out = _enc(["bool", "uint8"], [True, 69])
    assert out == "0x" + W[:-1] + "1" + W[:-2] + "45"


def test_encode_address_right_aligned():
    addr = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
    out = _enc(["address"], [addr])
    assert out == "0x" + "0" * 24 + addr[2:].lower()


def test_encode_negative_int_twos_complement():
    out = _enc(["int256"], [-1])
    assert out == "0x" + "f" * 64


def test_encode_bytes32_left_aligned():
    out = _enc(["bytes4"], ["0xdeadbeef"])
    assert out == "0xdeadbeef" + "0" * 56


def test_uint_alias_normalizes_to_uint256():
    assert _enc(["uint"], [7]) == _enc(["uint256"], [7])


# --- standard encode: dynamic types --------------------------------------------
def test_encode_string_vector():
    # Canonical Solidity vector for the string "Hello, world!".
    out = _enc(["string"], ["Hello, world!"])
    expect = (
        "0x"
        "0000000000000000000000000000000000000000000000000000000000000020"
        "000000000000000000000000000000000000000000000000000000000000000d"
        "48656c6c6f2c20776f726c642100000000000000000000000000000000000000"
    )
    assert out == expect


def test_encode_dynamic_uint_array():
    out = _enc(["uint256[]"], [[1, 2, 3]])
    expect = (
        "0x"
        + "0" * 62
        + "20"  # offset to the array
        + "0" * 63
        + "3"  # length 3
        + W[:-1]
        + "1"
        + W[:-1]
        + "2"
        + W[:-1]
        + "3"
    )
    assert out == expect


def test_encode_static_then_dynamic_offsets():
    # uint256(1) is inline; string offset points past both head words.
    out = _enc(["uint256", "string"], [1, "abc"])
    expect = (
        "0x"
        + W[:-1]
        + "1"  # head: uint = 1
        + "0" * 62
        + "40"  # head: offset 0x40 to the string tail
        + "0" * 63
        + "3"  # tail: length 3
        + "616263"
        + "0" * 58  # tail: "abc" padded
    )
    assert out == expect


def test_encode_fixed_array_of_static_is_inline():
    out = _enc(["uint256[2]"], [[1, 2]])
    assert out == "0x" + W[:-1] + "1" + W[:-1] + "2"


# --- tuples --------------------------------------------------------------------
def test_encode_static_tuple_inline():
    out = _enc(["(uint256,bool)"], [[5, True]])
    assert out == "0x" + W[:-1] + "5" + W[:-1] + "1"


def test_roundtrip_dynamic_tuple():
    types = ["(string,uint256)"]
    values = [["hi", 7]]
    assert _dec(types, _enc(types, values)) == [["hi", "7"]]


# --- packed (encodePacked) -----------------------------------------------------
def test_packed_drops_padding():
    assert _enc(["uint16"], [0x1234], mode="packed") == "0x1234"
    assert _enc(["uint8"], [1], mode="packed") == "0x01"


def test_packed_address_is_20_bytes():
    addr = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
    assert _enc(["address"], [addr], mode="packed") == "0x" + addr[2:].lower()


def test_packed_string_and_bytes_unprefixed():
    # abi.encodePacked("abc") == 0x616263, no length, no padding.
    assert _enc(["string"], ["abc"], mode="packed") == "0x616263"
    assert _enc(["bytes"], ["0xdeadbeef"], mode="packed") == "0xdeadbeef"


def test_packed_concatenation():
    # encodePacked(uint8(1), uint16(2)) -> 0x01 0002.
    assert _enc(["uint8", "uint16"], [1, 2], mode="packed") == "0x010002"


def test_packed_array_elements_are_padded():
    # array elements are padded to 32 bytes even in packed mode.
    out = _enc(["uint8[]"], [[1, 2]], mode="packed")
    assert out == "0x" + W[:-1] + "1" + W[:-1] + "2"


# --- decode --------------------------------------------------------------------
def test_decode_string_vector():
    data = (
        "0x"
        "0000000000000000000000000000000000000000000000000000000000000020"
        "000000000000000000000000000000000000000000000000000000000000000d"
        "48656c6c6f2c20776f726c642100000000000000000000000000000000000000"
    )
    assert _dec(["string"], data) == ["Hello, world!"]


def test_decode_uint_is_decimal_string():
    assert _dec(["uint256"], _enc(["uint256"], [12345])) == ["12345"]


def test_decode_negative_int():
    assert _dec(["int256"], _enc(["int256"], [-42])) == ["-42"]


def test_decode_address_is_checksummed():
    addr = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
    assert _dec(["address"], _enc(["address"], [addr])) == [addr]


def test_decode_bool():
    assert _dec(["bool"], _enc(["bool"], [True])) == [True]


def test_roundtrip_dynamic_array_of_strings():
    types = ["string[]"]
    values = [["a", "bb", "ccc"]]
    assert _dec(types, _enc(types, values)) == [["a", "bb", "ccc"]]


def test_roundtrip_mixed():
    types = ["uint256", "address", "string", "bool"]
    addr = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
    values = [99, addr, "ok", False]
    assert _dec(types, _enc(types, values)) == ["99", addr, "ok", False]


# --- argument handling ---------------------------------------------------------
def test_types_and_values_accept_json_strings():
    out = abi_codec("encode", json.dumps(["uint256"]), values=json.dumps([1]))
    assert out["encoded"] == "0x" + W[:-1] + "1"


# --- static fixed-arrays / static tuples (head-region sizing) ------------------
def test_decode_fixed_array_of_static():
    # uint256[2] is static and inline; decode returns decimal strings.
    data = "0x" + "00" * 31 + "01" + "00" * 31 + "02"
    assert _dec(["uint256[2]"], data) == [["1", "2"]]


def test_roundtrip_static_tuple_with_fixed_array():
    # A static tuple containing a fixed array exercises _abi_static_size's
    # array and tuple branches when sizing the head region.
    types = ["(uint256[2],bool)", "uint256"]
    values = [[[1, 2], True], 9]
    assert _dec(types, _enc(types, values)) == [[["1", "2"], True], "9"]


def test_decode_bytes4_left_aligned():
    assert _dec(["bytes4"], "0xdeadbeef" + "00" * 28) == ["0xdeadbeef"]


# --- more packed scalars -------------------------------------------------------
def test_packed_bool():
    assert _enc(["bool"], [True], mode="packed") == "0x01"
    assert _enc(["bool"], [False], mode="packed") == "0x00"


def test_packed_bytesN_right_padded():
    # bytesN packs to exactly N bytes (right-padded if short).
    assert _enc(["bytes4"], ["0xdeadbeef"], mode="packed") == "0xdeadbeef"
    assert _enc(["bytes4"], ["0xdead"], mode="packed") == "0xdead0000"


def test_packed_signed_int_twos_complement():
    # int16(-1) packs to its 2-byte two's-complement form.
    assert _enc(["int16"], [-1], mode="packed") == "0xffff"


# --- error paths ---------------------------------------------------------------
def test_encode_bytesN_too_long_raises():
    with pytest.raises(ValueError):
        abi_codec("encode", ["bytes4"], values=["0xdeadbeef00"])


def test_encode_unsupported_scalar_type_raises():
    with pytest.raises(ValueError):
        abi_codec("encode", ["foo"], values=[1])


def test_encode_fixed_array_wrong_length_raises():
    with pytest.raises(ValueError):
        abi_codec("encode", ["uint256[2]"], values=[[1, 2, 3]])


def test_encode_tuple_arity_mismatch_raises():
    with pytest.raises(ValueError):
        abi_codec("encode", ["(uint256,bool)"], values=[[1]])


def test_packed_bytesN_too_long_raises():
    with pytest.raises(ValueError):
        abi_codec("encode", ["bytes4"], values=["0xdeadbeef00"], mode="packed")


def test_packed_unsupported_scalar_type_raises():
    with pytest.raises(ValueError):
        abi_codec("encode", ["foo"], values=[1], mode="packed")


def test_packed_fixed_array_wrong_length_raises():
    with pytest.raises(ValueError):
        abi_codec("encode", ["uint8[2]"], values=[[1, 2, 3]], mode="packed")


def test_decode_unsupported_scalar_type_raises():
    with pytest.raises(ValueError):
        abi_codec("decode", ["foo"], data="0x" + W)


def test_types_not_a_list_raises():
    # A JSON string that parses to a non-list `types` is rejected.
    with pytest.raises(ValueError):
        abi_codec("encode", json.dumps("uint256"), values=[1])


def test_packed_decode_rejected():
    with pytest.raises(ValueError):
        abi_codec("decode", ["uint256"], data="0x" + W, mode="packed")


def test_encode_without_values_raises():
    with pytest.raises(ValueError):
        abi_codec("encode", ["uint256"])


def test_decode_rejects_oversize_array_length():
    # Untrusted length word: offset 0x20 -> length 2**256-1, no element data.
    # Pre-allocating [base] * length would hang/OOM (CR.6).
    offset = "0" * 62 + "20"
    length = "f" * 64
    with pytest.raises(ValueError):
        abi_codec("decode", ["uint256[]"], data="0x" + offset + length)


def test_decode_without_data_raises():
    with pytest.raises(ValueError):
        abi_codec("decode", ["uint256"])


def test_packed_tuple_rejected():
    with pytest.raises(ValueError):
        abi_codec("encode", ["(uint256,bool)"], values=[[1, True]], mode="packed")


def test_packed_dynamic_array_rejected():
    with pytest.raises(ValueError):
        abi_codec("encode", ["string[]"], values=[["a"]], mode="packed")


def test_length_mismatch_raises():
    with pytest.raises(ValueError):
        abi_codec("encode", ["uint256", "bool"], values=[1])


def test_unknown_action_raises():
    with pytest.raises(ValueError):
        abi_codec("frobnicate", ["uint256"], values=[1])


def test_unknown_mode_raises():
    with pytest.raises(ValueError):
        abi_codec("encode", ["uint256"], values=[1], mode="loose")


# --- app registration ----------------------------------------------------------
def test_registered_and_callable_through_app():
    names = {t.name for t in asyncio.run(mcp.list_tools())}
    assert "abi_codec" in names

    async def go():
        return await mcp.call_tool(
            "abi_codec",
            {"action": "encode", "types": ["uint256"], "values": [1]},
        )

    result = asyncio.run(go())
    contents = result[0] if isinstance(result, tuple) else result
    payload = json.loads(contents[0].text)
    assert payload["encoded"] == "0x" + W[:-1] + "1"
