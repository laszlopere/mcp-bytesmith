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

"""TODO 13.5 / plan §2.4.5 / §1.15.4 — eth_storage_slot.

The mapping/array slot formulas are Solidity's storage layout rules; vectors
are cross-checked against the keccak preimage built by hand (the keccak itself
is already verified in test_eth_hash)."""

import asyncio
import json

import pytest

pytest.importorskip("Crypto", reason="ethereum extra (pycryptodome) not installed")

from mcp_bytesmith.eth import _keccak256, eth_storage_slot  # noqa: E402
from mcp_bytesmith.server import mcp  # noqa: E402


def _ref(preimage: bytes) -> str:
    return "0x" + _keccak256(preimage).hex()


# --- mappings ------------------------------------------------------------------
def test_mapping_uint_key():
    # Canonical Solidity vector: mapping(uint=>uint) at slot 2, key 1.
    out = eth_storage_slot({"kind": "mapping", "slot": 2, "key_type": "uint256"}, key=1)
    expect = _ref((1).to_bytes(32, "big") + (2).to_bytes(32, "big"))
    assert out["slot_hex"] == expect
    assert out["slot"] == str(int(expect, 16))


def test_mapping_address_key():
    addr = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
    out = eth_storage_slot(
        {"kind": "mapping", "slot": 0, "key_type": "address"}, key=addr
    )
    expect = _ref(int(addr, 16).to_bytes(32, "big") + (0).to_bytes(32, "big"))
    assert out["slot_hex"] == expect


def test_mapping_key_type_defaults_to_uint256():
    a = eth_storage_slot({"kind": "mapping", "slot": 7}, key=42)
    b = eth_storage_slot({"kind": "mapping", "slot": 7, "key_type": "uint256"}, key=42)
    assert a == b


def test_mapping_string_key_is_unpadded():
    out = eth_storage_slot(
        {"kind": "mapping", "slot": 3, "key_type": "string"}, key="hello"
    )
    assert out["slot_hex"] == _ref(b"hello" + (3).to_bytes(32, "big"))


def test_nested_mapping_chains_keys():
    # mapping(address => mapping(address => uint)) at slot 1 (ERC-20 allowances).
    a1 = "0x1111111111111111111111111111111111111111"
    a2 = "0x2222222222222222222222222222222222222222"
    inner = _keccak256(int(a1, 16).to_bytes(32, "big") + (1).to_bytes(32, "big"))
    expect = _ref(int(a2, 16).to_bytes(32, "big") + inner)
    out = eth_storage_slot(
        {"kind": "mapping", "slot": 1, "key_type": ["address", "address"]}, key=[a1, a2]
    )
    assert out["slot_hex"] == expect


def test_mapping_layout_as_json_string():
    out = eth_storage_slot(
        json.dumps({"kind": "mapping", "slot": 2, "key_type": "uint256"}), key=1
    )
    assert out["slot_hex"] == _ref((1).to_bytes(32, "big") + (2).to_bytes(32, "big"))


# --- dynamic arrays ------------------------------------------------------------
def test_dynamic_array_element():
    out = eth_storage_slot({"kind": "dynamic_array", "slot": 5}, index=7)
    start = int.from_bytes(_keccak256((5).to_bytes(32, "big")), "big")
    assert int(out["slot"]) == start + 7


def test_dynamic_array_element_size():
    out = eth_storage_slot(
        {"kind": "dynamic_array", "slot": 0, "element_size": 2}, index=3
    )
    start = int.from_bytes(_keccak256((0).to_bytes(32, "big")), "big")
    assert int(out["slot"]) == start + 6


def test_array_alias_matches_dynamic_array():
    a = eth_storage_slot({"kind": "array", "slot": 9}, index=1)
    b = eth_storage_slot({"kind": "dynamic_array", "slot": 9}, index=1)
    assert a == b


# --- other key types -----------------------------------------------------------
def test_mapping_bytes_key_is_unpadded():
    # `bytes` keys (like `string`) are used raw / unpadded.
    out = eth_storage_slot(
        {"kind": "mapping", "slot": 1, "key_type": "bytes"}, key="0xdeadbeef"
    )
    assert out["slot_hex"] == _ref(bytes.fromhex("deadbeef") + (1).to_bytes(32, "big"))


def test_mapping_bool_key_is_padded():
    out = eth_storage_slot(
        {"kind": "mapping", "slot": 1, "key_type": "bool"}, key=True
    )
    assert out["slot_hex"] == _ref((1).to_bytes(32, "big") + (1).to_bytes(32, "big"))


def test_mapping_bytes32_key_is_left_aligned():
    key = "0x" + "ab" * 32
    out = eth_storage_slot(
        {"kind": "mapping", "slot": 1, "key_type": "bytes32"}, key=key
    )
    assert out["slot_hex"] == _ref(bytes.fromhex("ab" * 32) + (1).to_bytes(32, "big"))


# --- error paths ---------------------------------------------------------------
def test_missing_kind_or_slot_raises():
    with pytest.raises(ValueError):
        eth_storage_slot({"slot": 0}, key=1)
    with pytest.raises(ValueError):
        eth_storage_slot({"kind": "mapping"}, key=1)


def test_mapping_without_key_raises():
    with pytest.raises(ValueError):
        eth_storage_slot({"kind": "mapping", "slot": 0})


def test_dynamic_array_without_index_raises():
    with pytest.raises(ValueError):
        eth_storage_slot({"kind": "dynamic_array", "slot": 0})


def test_key_type_list_length_mismatch_raises():
    with pytest.raises(ValueError):
        eth_storage_slot(
            {"kind": "mapping", "slot": 0, "key_type": ["address"]}, key=[1, 2]
        )


def test_unknown_kind_raises():
    with pytest.raises(ValueError):
        eth_storage_slot({"kind": "struct", "slot": 0})


def test_unsupported_key_type_raises():
    with pytest.raises(ValueError):
        eth_storage_slot({"kind": "mapping", "slot": 0, "key_type": "fixed"}, key=1)


# --- app registration ----------------------------------------------------------
def test_registered_and_callable_through_app():
    names = {t.name for t in asyncio.run(mcp.list_tools())}
    assert "eth_storage_slot" in names

    async def go():
        return await mcp.call_tool(
            "eth_storage_slot",
            {"layout": {"kind": "mapping", "slot": 2, "key_type": "uint256"}, "key": 1},
        )

    result = asyncio.run(go())
    contents = result[0] if isinstance(result, tuple) else result
    payload = json.loads(contents[0].text)
    assert payload["slot_hex"] == _ref(
        (1).to_bytes(32, "big") + (2).to_bytes(32, "big")
    )
