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

"""TODO 20.4 — eth_bytecode (disassembly, dispatcher selectors, solc metadata).

TOKEN_RUNTIME below is real solc output, not a fixture invented here: it is
`solc 0.8.33 --bin-runtime --optimize` over the minimal ERC-20-shaped contract
quoted next to it. Its selectors are therefore checked against the public ERC-20
constants (transfer 0xa9059cbb, balanceOf 0x70a08231, totalSupply 0x18160ddd)
and against eth_selector, and its metadata trailer is a genuine one. The two
hand-rolled decoders — the CBOR subset and base58btc — are additionally
cross-checked against cbor2 and the base58 package where those are installed, so
neither is only ever compared with itself."""

import asyncio
import json

import pytest

pytest.importorskip("Crypto", reason="ethereum extra (pycryptodome) not installed")

from mcp_bytesmith.eth import (  # noqa: E402
    _base58btc,
    _cbor_read,
    eth_bytecode,
    eth_selector,
)
from mcp_bytesmith.server import mcp  # noqa: E402

# solc 0.8.33, --bin-runtime --optimize, of:
#     contract Token {
#         mapping(address => uint256) public balanceOf;
#         uint256 public totalSupply;
#         event Transfer(address indexed from, address indexed to, uint256 value);
#         function transfer(address to, uint256 amount) external returns (bool) {…}
#         function mint(uint256 amount) external {…}
#     }
TOKEN_RUNTIME = (
    "608060405234801561000f575f5ffd5b506004361061004a575f3560e01c806318"
    "160ddd1461004e57806370a082311461006a578063a0712d6814610089578063a9"
    "059cbb1461009e575b5f5ffd5b61005760015481565b6040519081526020015b60"
    "405180910390f35b6100576100783660046101b5565b5f60208190529081526040"
    "90205481565b61009c6100973660046101d5565b6100c1565b005b6100b16100ac"
    "3660046101ec565b6100ff565b6040519015158152602001610061565b335f9081"
    "5260208190526040812080548392906100df908490610228565b92505081905550"
    "8060015f8282546100f79190610228565b909155505050565b335f908152602081"
    "9052604081208054839190839061011f90849061023b565b909155505060016001"
    "60a01b0383165f908152602081905260408120805484929061014b908490610228"
    "565b90915550506040518281526001600160a01b0384169033907fddf252ad1be2"
    "c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef90602001604051"
    "80910390a35060015b92915050565b80356001600160a01b03811681146101b057"
    "5f5ffd5b919050565b5f602082840312156101c5575f5ffd5b6101ce8261019a56"
    "5b9392505050565b5f602082840312156101e5575f5ffd5b5035919050565b5f5f"
    "604083850312156101fd575f5ffd5b6102068361019a565b946020939093013593"
    "505050565b634e487b7160e01b5f52601160045260245ffd5b8082018082111561"
    "019457610194610214565b818103818111156101945761019461021456fea26469"
    "7066735822122058071a53283a2a863271e154efe2a25ffbfe3a761ce9de804f30"
    "e2f6eb0d882164736f6c63430008210033"
)
TOKEN_CODE_SIZE = 591  # bytes before the metadata trailer
TOKEN_SIZE = 644  # …and with it (51 CBOR bytes + the 2-byte length)


def names(out: dict) -> list[str | None]:
    return [ins["name"] for ins in out["instructions"]]


# --- disassemble ---------------------------------------------------------------
def test_push_immediates_are_swallowed_not_decoded():
    # 60 80 60 40 52 -> PUSH1 0x80, PUSH1 0x40, MSTORE: the standard free-memory
    # pointer prologue. The 0x80/0x40 bytes are data, never opcodes.
    out = eth_bytecode("disassemble", "0x6080604052")
    assert names(out) == ["PUSH1", "PUSH1", "MSTORE"]
    assert [ins["pc"] for ins in out["instructions"]] == [0, 2, 4]
    assert out["instructions"][0]["push_data"] == "0x80"
    assert out["instructions"][1]["push_data"] == "0x40"
    assert out["count"] == 3
    assert out["size"] == out["code_size"] == 5


def test_opcode_byte_is_reported_alongside_the_mnemonic():
    out = eth_bytecode("disassemble", "0x5b00")
    assert out["instructions"][0] == {"pc": 0, "opcode": "0x5b", "name": "JUMPDEST"}
    assert out["instructions"][1]["opcode"] == "0x00"


def test_post_london_opcodes_are_known():
    # PUSH0 (Shanghai), TLOAD/TSTORE/MCOPY (Cancun), BLOBHASH/BLOBBASEFEE.
    out = eth_bytecode("disassemble", "0x5f5c5d5e494a")
    assert names(out) == [
        "PUSH0",
        "TLOAD",
        "TSTORE",
        "MCOPY",
        "BLOBHASH",
        "BLOBBASEFEE",
    ]
    assert "push_data" not in out["instructions"][0]  # PUSH0 has no immediate


def test_unassigned_byte_is_flagged_not_guessed():
    out = eth_bytecode("disassemble", "0x0c5b00")
    assert out["instructions"][0]["name"] is None
    assert out["instructions"][0]["unknown"] is True
    assert names(out)[1:] == ["JUMPDEST", "STOP"]


def test_push_running_off_the_end_is_flagged_truncated():
    out = eth_bytecode("disassemble", "0x61ff")  # PUSH2 with only one byte left
    assert out["instructions"][0]["name"] == "PUSH2"
    assert out["instructions"][0]["push_data"] == "0xff"
    assert out["instructions"][0]["truncated"] is True


def test_real_runtime_code_disassembles_past_its_metadata():
    out = eth_bytecode("disassemble", TOKEN_RUNTIME, limit=0)
    assert out["size"] == TOKEN_SIZE
    assert out["code_size"] == TOKEN_CODE_SIZE
    assert out["metadata_offset"] == TOKEN_CODE_SIZE
    assert names(out)[:3] == ["PUSH1", "PUSH1", "MSTORE"]
    # Every instruction lies in the code region — the CBOR trailer is not code.
    assert max(ins["pc"] for ins in out["instructions"]) < TOKEN_CODE_SIZE
    assert "truncated" not in out


# --- disassemble: paging -------------------------------------------------------
def test_output_is_capped_and_pageable():
    first = eth_bytecode("disassemble", TOKEN_RUNTIME, limit=10)
    assert len(first["instructions"]) == 10
    assert first["truncated"] is True
    assert first["next_offset"] == 10
    assert first["count"] > 10  # the count is of the whole contract, not the page

    second = eth_bytecode("disassemble", TOKEN_RUNTIME, offset=10, limit=10)
    assert second["offset"] == 10
    assert second["instructions"][0]["pc"] > first["instructions"][-1]["pc"]

    every = eth_bytecode("disassemble", TOKEN_RUNTIME, limit=0)
    assert len(every["instructions"]) == every["count"]
    assert every["instructions"][10:20] == second["instructions"]


def test_last_page_is_not_marked_truncated():
    total = eth_bytecode("disassemble", TOKEN_RUNTIME, limit=0)["count"]
    out = eth_bytecode("disassemble", TOKEN_RUNTIME, offset=total - 3, limit=10)
    assert len(out["instructions"]) == 3
    assert "truncated" not in out and "next_offset" not in out


def test_offset_past_the_end_is_empty_not_an_error():
    out = eth_bytecode("disassemble", "0x6080604052", offset=99)
    assert out["instructions"] == []
    assert out["count"] == 3


def test_negative_offset_or_limit_raises():
    with pytest.raises(ValueError, match="`offset` must be >= 0"):
        eth_bytecode("disassemble", "0x00", offset=-1)
    with pytest.raises(ValueError, match="`limit` must be >= 0"):
        eth_bytecode("disassemble", "0x00", limit=-5)


# --- selectors -----------------------------------------------------------------
def test_dispatcher_selectors_match_the_public_erc20_constants():
    out = eth_bytecode("selectors", TOKEN_RUNTIME)
    assert out["count"] == 4
    assert out["selectors"] == [
        "0x18160ddd",  # totalSupply()
        "0x70a08231",  # balanceOf(address)
        "0xa0712d68",  # mint(uint256)
        "0xa9059cbb",  # transfer(address,uint256)
    ]
    for signature in ("transfer(address,uint256)", "balanceOf(address)"):
        assert eth_selector(signature)["selector"] in out["selectors"]
    assert all(site["op"] == "EQ" for site in out["sites"])
    assert all(site["pc"] < TOKEN_CODE_SIZE for site in out["sites"])


def test_a_push4_pattern_inside_another_immediate_is_not_a_selector():
    # PUSH32 whose data spells `PUSH4 a9059cbb EQ` — a regex over the hex would
    # report transfer(); a real decode sees one PUSH32 and no dispatcher at all.
    code = "0x7f" + "63a9059cbb14" + "00" * 26 + "00"
    assert "63a9059cbb" in code  # the trap is genuinely present in the hex
    assert names(eth_bytecode("disassemble", code)) == ["PUSH32", "STOP"]
    assert eth_bytecode("selectors", code)["selectors"] == []


def test_binary_search_pivot_is_reported_once_but_sited_twice():
    # DUP1 PUSH4 x GT PUSH2 dest JUMPI / DUP1 PUSH4 x EQ PUSH2 dest JUMPI —
    # solc's binary-search dispatcher pivots on a real selector, then compares it.
    code = "0x" + "8063b8c9d3651161012357" + "8063b8c9d3651461045657"
    out = eth_bytecode("selectors", code)
    assert out["selectors"] == ["0xb8c9d365"]
    assert [site["op"] for site in out["sites"]] == ["GT", "EQ"]
    assert [site["pc"] for site in out["sites"]] == [1, 12]


def test_a_dup_between_the_push_and_the_comparison_still_counts():
    out = eth_bytecode("selectors", "0x63a9059cbb8114")  # PUSH4 … DUP2 EQ
    assert out["selectors"] == ["0xa9059cbb"]


def test_a_push4_that_is_not_compared_is_not_a_selector():
    # PUSH4 0x4e487b71 PUSH1 0xe0 SHL — the Panic(uint256) selector being shifted
    # into place for a revert, which every 0.8.x contract contains.
    assert eth_bytecode("selectors", "0x634e487b7160e01b")["selectors"] == []


def test_sentinel_constants_are_not_selectors():
    assert eth_bytecode("selectors", "0x63ffffffff14630000000014")["selectors"] == []


def test_a_truncated_push4_is_not_a_selector():
    assert eth_bytecode("selectors", "0x63a9059c")["selectors"] == []


def test_empty_code_yields_nothing():
    assert eth_bytecode("selectors", "0x") == {
        "action": "selectors",
        "count": 0,
        "selectors": [],
        "sites": [],
    }
    assert eth_bytecode("disassemble", "0x")["instructions"] == []


# --- metadata ------------------------------------------------------------------
def test_solc_metadata_trailer_is_parsed():
    out = eth_bytecode("metadata", TOKEN_RUNTIME)
    assert out["present"] is True
    assert out["offset"] == TOKEN_CODE_SIZE
    assert out["length"] == 51
    assert out["cbor"].startswith("0xa26469706673")  # map(2), text(4) "ipfs"
    assert out["solc_version"] == "0.8.33"
    assert out["metadata"]["solc"] == "0x000821"  # 0.8.33 as three version bytes
    assert out["metadata"]["ipfs"].startswith("0x1220")  # sha2-256 multihash
    assert out["ipfs_cid"] == "QmUGGsLdX42ZML6u2LJYmspMFufDXPC5qXFzwpLkHDyJTS"


def test_metadata_cbor_span_is_exactly_the_reported_bytes():
    out = eth_bytecode("metadata", TOKEN_RUNTIME)
    raw = bytes.fromhex(TOKEN_RUNTIME)
    assert bytes.fromhex(out["cbor"][2:]) == raw[out["offset"] : -2]
    assert int.from_bytes(raw[-2:], "big") == out["length"]


def test_a_prerelease_version_string_and_experimental_flag():
    code = (
        "0x00"
        + "a264736f6c636e302e382e33312d646576656c6f706c6578706572696d656e74616cf50023"
    )
    out = eth_bytecode("metadata", code)
    assert out["solc_version"] == "0.8.31-develop"
    assert out["metadata"]["experimental"] is True
    assert "ipfs_cid" not in out  # nothing to render


def test_code_without_a_trailer_is_reported_not_raised():
    out = eth_bytecode("metadata", "0x6001600101")
    assert out["present"] is False
    assert "no CBOR metadata trailer" in out["reason"]


def test_a_plausible_length_over_garbage_is_not_metadata():
    # The last two bytes say "51 bytes of CBOR precede me", but they are not CBOR.
    assert eth_bytecode("metadata", "0x" + "ff" * 51 + "0033")["present"] is False


def test_a_trailer_that_is_not_a_map_is_not_metadata():
    # Valid CBOR of the right length, but a text string — solc always emits a map.
    assert eth_bytecode("metadata", "0x636162630004")["present"] is False


def test_metadata_is_excluded_from_the_code_region():
    # PUSH1 0x01, then a 4-byte CBOR map trailer {"a": 1} and its length word.
    out = eth_bytecode("disassemble", "0x6001" + "a1616101" + "0004", limit=0)
    assert names(out) == ["PUSH1"]  # the trailer is data, so it is not decoded
    assert out["code_size"] == 2
    assert out["size"] == 8
    assert out["metadata_offset"] == 2


# --- the hand-rolled decoders, against the reference libraries ------------------
def test_cbor_subset_agrees_with_cbor2():
    cbor2 = pytest.importorskip("cbor2", reason="cbor2 (serialize extra) missing")
    for value in [
        0,
        23,
        24,
        255,
        65535,
        2**32,
        -1,
        -1000,
        b"",
        b"\x12\x20\xff",
        "solc",
        True,
        False,
        None,
        [1, 2, [3]],
        {"solc": b"\x00\x08\x21", "experimental": True},
    ]:
        encoded = cbor2.dumps(value)
        assert _cbor_read(encoded, 0) == (value, len(encoded))


def test_base58btc_agrees_with_the_base58_package():
    base58 = pytest.importorskip("base58", reason="base58 (encoding extra) missing")
    for raw in [
        b"",
        b"\x00",
        b"\x00\x00\x01",
        b"hello world",
        bytes.fromhex("1220" + "58" * 32),
        bytes(range(32)),
    ]:
        assert _base58btc(raw) == base58.b58encode(raw).decode("ascii")


# --- errors --------------------------------------------------------------------
def test_unknown_action_raises():
    with pytest.raises(ValueError, match="unknown action"):
        eth_bytecode("decompile", "0x00")


def test_invalid_hex_raises():
    with pytest.raises(ValueError, match="invalid hex input"):
        eth_bytecode("disassemble", "0xzz")


# --- app registration ----------------------------------------------------------
def test_registered_and_callable_through_app():
    names_registered = {t.name for t in asyncio.run(mcp.list_tools())}
    assert "eth_bytecode" in names_registered

    async def go():
        return await mcp.call_tool(
            "eth_bytecode", {"action": "selectors", "code": TOKEN_RUNTIME}
        )

    result = asyncio.run(go())
    contents = result[0] if isinstance(result, tuple) else result
    payload = json.loads(contents[0].text)
    assert "0xa9059cbb" in payload["selectors"]


def test_registered_with_expected_schema():
    tool = next(t for t in asyncio.run(mcp.list_tools()) if t.name == "eth_bytecode")
    assert tool.inputSchema["required"] == ["action", "code"]
    assert tool.description
