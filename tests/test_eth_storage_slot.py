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

"""TODO 13.5 / plan §2.4.5 / §1.15.4 — eth_storage_slot (+ TODO 20.5).

The mapping/array slot formulas are Solidity's storage layout rules; vectors
are cross-checked against the keccak preimage built by hand (the keccak itself
is already verified in test_eth_hash).

The well-known layouts (TODO 20.5) are pinned twice over: against the constants
published in EIP-1967 / EIP-1822 / ERC-7201 / EIP-2535 — including ERC-7201's
own "example.main" vector and the roots OpenZeppelin v5 documents in its
upgradeable contracts — and against the formula rebuilt here from keccak, so
neither the tool nor a pasted constant can drift alone."""

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
    out = eth_storage_slot({"kind": "mapping", "slot": 1, "key_type": "bool"}, key=True)
    assert out["slot_hex"] == _ref((1).to_bytes(32, "big") + (1).to_bytes(32, "big"))


def test_mapping_bytes32_key_is_left_aligned():
    key = "0x" + "ab" * 32
    out = eth_storage_slot(
        {"kind": "mapping", "slot": 1, "key_type": "bytes32"}, key=key
    )
    assert out["slot_hex"] == _ref(bytes.fromhex("ab" * 32) + (1).to_bytes(32, "big"))


# --- well-known layouts: EIP-1967 proxy slots (TODO 20.5) ----------------------
# The constants as published in EIP-1967.
EIP1967 = {
    "implementation": "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc",
    "admin": "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103",
    "beacon": "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50",
    "rollback": "0x4910fdfa16fed3260ed0e7147f7cc6da11a60208b5b9406d12a635614ffd9143",
}


@pytest.mark.parametrize("name, expect", sorted(EIP1967.items()))
def test_eip1967_slots_match_the_published_constants(name, expect):
    out = eth_storage_slot({"kind": "eip1967", "name": name})
    assert out["slot_hex"] == expect
    assert out["name"] == name
    assert out["formula"] == f'keccak256("eip1967.proxy.{name}") - 1'


def test_eip1967_slot_is_one_below_the_label_hash():
    # The -1 is the point of EIP-1967: it lands the slot outside keccak's image,
    # so no mapping or array entry can ever hash onto it.
    out = eth_storage_slot({"kind": "eip1967", "name": "admin"})
    assert int(out["slot"]) + 1 == int.from_bytes(
        _keccak256(b"eip1967.proxy.admin"), "big"
    )


def test_eip1967_defaults_to_the_implementation_slot():
    assert (
        eth_storage_slot({"kind": "eip1967"})["slot_hex"] == EIP1967["implementation"]
    )


def test_eip1967_needs_no_declared_slot():
    assert "slot" not in {"kind": "eip1967"}  # the layout carries no base slot
    assert (
        eth_storage_slot({"kind": "erc1967", "name": "beacon"})["slot_hex"]
        == (EIP1967["beacon"])
    )


def test_unknown_eip1967_name_raises():
    with pytest.raises(ValueError, match="unknown eip1967 slot name"):
        eth_storage_slot({"kind": "eip1967", "name": "logic"})


# --- well-known layouts: EIP-1822 (UUPS) ---------------------------------------
def test_eip1822_proxiable_uuid_has_no_off_by_one():
    out = eth_storage_slot({"kind": "eip1822"})
    assert out["slot_hex"] == (
        "0xc5f16f0fcc639fa48a6947836d9850f504798523bf8c9a3a87d5876cf622bcf7"
    )
    assert out["slot_hex"] == _ref(b"PROXIABLE")  # keccak itself, not keccak - 1
    assert out["formula"] == 'keccak256("PROXIABLE")'


def test_uups_spellings_are_the_same_layout():
    canonical = eth_storage_slot({"kind": "eip1822"})
    for alias in ("uups", "erc1822", "proxiable"):
        assert eth_storage_slot({"kind": alias}) == canonical


# --- well-known layouts: ERC-7201 namespaced storage ---------------------------
def test_erc7201_matches_the_specs_own_example():
    # The vector ERC-7201 itself publishes for id "example.main".
    out = eth_storage_slot({"kind": "erc7201", "namespace": "example.main"})
    assert out["slot_hex"] == (
        "0x183a6125c38840424c4a85fa12bab2ab606c4b6d0e7cc73c0c06ba5300eab500"
    )
    assert out["namespace"] == "example.main"


def test_erc7201_matches_openzeppelin_v5_roots():
    for namespace, expect in [
        (
            "openzeppelin.storage.ERC20",
            "0x52c63247e1f47db19d5ce0460030c497f067ca4cebf71ba98eeadabe20bace00",
        ),
        (
            "openzeppelin.storage.Ownable",
            "0x9016d09d72d40fdae2fd8ceac6b6234c7706214fd39c1cd1e609a0528c199300",
        ),
    ]:
        assert (
            eth_storage_slot({"kind": "erc7201", "namespace": namespace})["slot_hex"]
            == expect
        )


def test_erc7201_root_is_rebuilt_from_the_formula():
    inner = int.from_bytes(_keccak256(b"my.namespace"), "big") - 1
    expect = int.from_bytes(_keccak256(inner.to_bytes(32, "big")), "big") & ~0xFF
    out = eth_storage_slot({"kind": "erc7201", "namespace": "my.namespace"})
    assert int(out["slot"]) == expect
    assert out["slot_hex"].endswith("00")  # aligned to a 256-slot boundary


def test_erc7201_annotation_prefix_is_stripped():
    # `@custom:storage-location erc7201:openzeppelin.storage.ERC20` is what the
    # source says, so the id usually arrives with the prefix still on it.
    prefixed = eth_storage_slot(
        {"kind": "erc7201", "namespace": "erc7201:openzeppelin.storage.ERC20"}
    )
    bare = eth_storage_slot(
        {"kind": "erc7201", "namespace": "openzeppelin.storage.ERC20"}
    )
    assert prefixed == bare
    assert prefixed["namespace"] == "openzeppelin.storage.ERC20"


# --- well-known layouts: EIP-2535 diamond storage ------------------------------
def test_diamond_storage_is_a_plain_label_hash():
    out = eth_storage_slot(
        {"kind": "diamond", "namespace": "diamond.standard.diamond.storage"}
    )
    assert out["slot_hex"] == (
        "0xc8fcad8db84d3cc18b4c41d551ea0ee66dd599cde068d998e57d5e09332c131c"
    )
    assert out["slot_hex"] == _ref(b"diamond.standard.diamond.storage")
    assert eth_storage_slot({"kind": "erc2535", "namespace": "x"}) == eth_storage_slot(
        {"kind": "diamond", "namespace": "x"}
    )


# --- well-known layouts: members and composition -------------------------------
def test_index_steps_to_a_later_struct_member():
    root = eth_storage_slot(
        {"kind": "erc7201", "namespace": "openzeppelin.storage.ERC20"}
    )
    third = eth_storage_slot(
        {"kind": "erc7201", "namespace": "openzeppelin.storage.ERC20"}, index=2
    )
    assert int(third["slot"]) == int(root["slot"]) + 2
    assert third["index"] == 2
    assert "index" not in root  # only reported when it was asked for


def test_a_namespaced_root_composes_as_a_mapping_base():
    # ERC20Storage._balances is the first member of the namespaced struct, so its
    # root IS the mapping's declared slot.
    root = eth_storage_slot(
        {"kind": "erc7201", "namespace": "openzeppelin.storage.ERC20"}
    )["slot_hex"]
    holder = "0x1111111111111111111111111111111111111111"
    out = eth_storage_slot(
        {"kind": "mapping", "slot": root, "key_type": "address"}, key=holder
    )
    assert out["slot_hex"] == _ref(
        int(holder, 16).to_bytes(32, "big") + bytes.fromhex(root[2:])
    )


def test_namespace_is_required_for_namespaced_layouts():
    for kind in ("erc7201", "diamond"):
        with pytest.raises(ValueError, match="needs a 'namespace' string"):
            eth_storage_slot({"kind": kind})


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


def test_unknown_kind_raises_and_lists_the_kinds():
    with pytest.raises(ValueError, match="unknown layout kind") as exc:
        eth_storage_slot({"kind": "struct", "slot": 0})
    for kind in ("mapping", "dynamic_array", "eip1967", "erc7201", "diamond"):
        assert kind in str(exc.value)


def test_layout_that_is_not_an_object_raises():
    with pytest.raises(ValueError, match="must be an object with a 'kind'"):
        eth_storage_slot(["mapping", 0], key=1)


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
