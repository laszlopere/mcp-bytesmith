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

"""TODO 20.8 — abi_inspect (JSON ABI <-> human-readable, + the selector table).

The selectors and topic0s asserted here are the widely-known ERC-20 constants
(transfer 0xa9059cbb, balanceOf 0x70a08231, approve 0x095ea7b3, totalSupply
0x18160ddd, Transfer topic0 0xddf252ad…), so the tool is checked against public
values rather than against itself. Both directions are additionally pinned by
round-trip: human -> JSON ABI -> human must be a fixed point."""

import asyncio
import json

import pytest

pytest.importorskip("Crypto", reason="ethereum extra (pycryptodome) not installed")

from mcp_bytesmith.eth import abi_inspect, eth_selector  # noqa: E402
from mcp_bytesmith.server import mcp  # noqa: E402

TRANSFER_TOPIC0 = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"

ERC20_JSON = [
    {
        "type": "function",
        "name": "transfer",
        "stateMutability": "nonpayable",
        "inputs": [
            {"name": "to", "type": "address"},
            {"name": "amount", "type": "uint256"},
        ],
        "outputs": [{"name": "", "type": "bool"}],
    },
    {
        "type": "function",
        "name": "balanceOf",
        "stateMutability": "view",
        "inputs": [{"name": "owner", "type": "address"}],
        "outputs": [{"name": "", "type": "uint256"}],
    },
    {
        "type": "function",
        "name": "totalSupply",
        "stateMutability": "view",
        "inputs": [],
        "outputs": [{"name": "", "type": "uint256"}],
    },
    {
        "type": "event",
        "name": "Transfer",
        "anonymous": False,
        "inputs": [
            {"name": "from", "type": "address", "indexed": True},
            {"name": "to", "type": "address", "indexed": True},
            {"name": "value", "type": "uint256", "indexed": False},
        ],
    },
]


def _by_name(out, name):
    return next(e for e in out["entries"] if e["name"] == name)


# --- JSON ABI in: selectors and topics against public constants ----------------
def test_erc20_selectors_are_the_known_constants():
    out = abi_inspect(ERC20_JSON)
    assert out["count"] == 4
    assert out["selectors"] == {
        "0xa9059cbb": "transfer(address,uint256)",
        "0x70a08231": "balanceOf(address)",
        "0x18160ddd": "totalSupply()",
    }
    assert out["topics"] == {TRANSFER_TOPIC0: "Transfer(address,address,uint256)"}


def test_entry_carries_both_representations():
    entry = _by_name(abi_inspect(ERC20_JSON), "transfer")
    assert entry["type"] == "function"
    assert entry["signature"] == "transfer(address,uint256)"
    assert entry["selector"] == "0xa9059cbb"
    assert entry["human"] == (
        "function transfer(address to, uint256 amount) returns (bool)"
    )
    assert entry["stateMutability"] == "nonpayable"
    assert entry["inputs"] == [
        {"name": "to", "type": "address"},
        {"name": "amount", "type": "uint256"},
    ]


def test_event_entry_has_topic0_and_indexed_inputs():
    entry = _by_name(abi_inspect(ERC20_JSON), "Transfer")
    assert entry["topic0"] == TRANSFER_TOPIC0
    assert entry["anonymous"] is False
    assert "selector" not in entry
    assert [i.get("indexed", False) for i in entry["inputs"]] == [True, True, False]


def test_selector_parity_with_eth_selector():
    out = abi_inspect(ERC20_JSON)
    for entry in out["entries"]:
        kind = "event" if entry["type"] == "event" else "function"
        expected = eth_selector(entry["signature"], kind)
        got = entry.get("selector") or entry.get("topic0")
        assert got == (expected.get("selector") or expected.get("topic0"))


# --- human-readable in ---------------------------------------------------------
def test_human_input_produces_the_same_selectors():
    out = abi_inspect(
        [
            "function transfer(address to, uint256 amount) external returns (bool)",
            "function balanceOf(address owner) view returns (uint256)",
            "function totalSupply() view returns (uint256)",
            "event Transfer(address indexed from, address indexed to, uint256 value)",
        ]
    )
    assert out["selectors"] == abi_inspect(ERC20_JSON)["selectors"]
    assert out["topics"] == abi_inspect(ERC20_JSON)["topics"]


def test_human_input_without_a_kind_keyword_is_a_function():
    entry = abi_inspect("balanceOf(address)")["entries"][0]
    assert entry["type"] == "function"
    assert entry["selector"] == "0x70a08231"


def test_human_input_yields_json_abi_inputs():
    out = abi_inspect("function fill((address token, uint256 amt)[] orders, bytes d)")
    assert out["entries"][0]["inputs"] == [
        {
            "name": "orders",
            "type": "tuple[]",
            "components": [
                {"name": "token", "type": "address"},
                {"name": "amt", "type": "uint256"},
            ],
        },
        {"name": "d", "type": "bytes"},
    ]


def test_human_returns_clause_becomes_outputs():
    entry = abi_inspect("function f(uint256 a) returns (bool ok, uint256 n)")[
        "entries"
    ][0]
    assert entry["outputs"] == [
        {"name": "ok", "type": "bool"},
        {"name": "n", "type": "uint256"},
    ]
    assert entry["signature"] == "f(uint256)"  # outputs never affect the selector


def test_human_mutability_is_captured():
    for word in ("view", "pure", "payable"):
        entry = abi_inspect(f"function f() {word}")["entries"][0]
        assert entry["stateMutability"] == word


def test_human_anonymous_event():
    entry = abi_inspect("event Odd(uint256 indexed a) anonymous")["entries"][0]
    assert entry["anonymous"] is True
    assert entry["human"].endswith("anonymous")


def test_anonymous_event_is_absent_from_the_topics_map():
    # An anonymous event never emits topic0, so it is not a topic0 to look up.
    out = abi_inspect("event Odd(uint256 indexed a) anonymous")
    assert out["topics"] == {}
    assert out["entries"][0]["topic0"].startswith("0x")


def test_human_error_and_alias_normalization():
    out = abi_inspect("error InsufficientBalance(uint available, uint required)")
    entry = out["entries"][0]
    assert entry["type"] == "error"
    assert entry["signature"] == "InsufficientBalance(uint256,uint256)"
    assert entry["selector"] == "0xcf479181"


# --- constructor / fallback / receive ------------------------------------------
@pytest.mark.parametrize("text", ["constructor(uint256 supply)", "constructor()"])
def test_constructor_has_no_signature_or_selector(text):
    entry = abi_inspect(text)["entries"][0]
    assert entry["type"] == "constructor"
    assert entry["name"] is None
    assert "signature" not in entry and "selector" not in entry
    assert entry["human"] == text


@pytest.mark.parametrize("kind", ["fallback", "receive"])
def test_fallback_and_receive(kind):
    entry = abi_inspect({"type": kind, "stateMutability": "payable"})["entries"][0]
    assert entry["type"] == kind
    assert "selector" not in entry
    assert entry["human"] == f"{kind}()"


def test_constructor_from_json_abi():
    out = abi_inspect(
        [{"type": "constructor", "inputs": [{"n": 1, "type": "uint256"}]}]
    )
    assert out["entries"][0]["human"] == "constructor(uint256)"
    assert out["selectors"] == {}


# --- tuples both ways ----------------------------------------------------------
@pytest.mark.parametrize(
    "human,canonical",
    [
        ("function f((uint256 a, bool b) p)", "f((uint256,bool))"),
        ("function f((uint256,bool)[] p)", "f((uint256,bool)[])"),
        ("function f((uint256,bool)[2] p)", "f((uint256,bool)[2])"),
        ("function f(((uint8 x) inner, bytes b) p)", "f(((uint8),bytes))"),
        ("function f(uint256[2][] p)", "f(uint256[2][])"),
    ],
)
def test_tuple_shapes_round_trip(human, canonical):
    out = abi_inspect(human)
    entry = out["entries"][0]
    assert entry["signature"] == canonical
    # feed the derived JSON ABI back in and expect the identical signature
    back = abi_inspect(
        [{"type": "function", "name": entry["name"], "inputs": entry["inputs"]}]
    )
    assert back["entries"][0]["signature"] == canonical


def test_nested_tuple_components_are_nested_in_json():
    entry = abi_inspect("function f(((uint8 x) inner, bytes b) p)")["entries"][0]
    outer = entry["inputs"][0]
    assert outer["type"] == "tuple"
    assert outer["components"][0]["type"] == "tuple"
    assert outer["components"][0]["components"] == [{"name": "x", "type": "uint8"}]


# --- round-trip: human -> JSON ABI -> human is a fixed point -------------------
ROUND_TRIP = [
    "function transfer(address to, uint256 amount) returns (bool)",
    "function balanceOf(address owner) view returns (uint256)",
    "function fill((address token, uint256 amt)[] orders, bytes data) payable",
    "event Transfer(address indexed from, address indexed to, uint256 value)",
    "event Odd(uint256 indexed a) anonymous",
    "error InsufficientBalance(uint256 available, uint256 required)",
    "constructor(uint256 supply)",
]


@pytest.mark.parametrize("text", ROUND_TRIP)
def test_human_json_human_round_trip(text):
    first = abi_inspect(text)["entries"][0]
    fragment = {
        "type": first["type"],
        "name": first["name"],
        "inputs": first["inputs"],
        "outputs": first["outputs"],
    }
    if first["type"] == "event":
        fragment["anonymous"] = first["anonymous"]
    if "stateMutability" in first:
        fragment["stateMutability"] = first["stateMutability"]
    second = abi_inspect([fragment])["entries"][0]
    assert second["human"] == first["human"] == text
    assert second.get("signature") == first.get("signature")


# --- input forms ---------------------------------------------------------------
def test_single_json_object():
    out = abi_inspect({"type": "function", "name": "f", "inputs": []})
    assert out["count"] == 1 and out["selectors"] == {"0x26121ff0": "f()"}


def test_stringified_json_array():
    assert (
        abi_inspect(json.dumps(ERC20_JSON))["selectors"]
        == abi_inspect(ERC20_JSON)["selectors"]
    )


def test_stringified_json_object():
    out = abi_inspect(json.dumps({"type": "function", "name": "f", "inputs": []}))
    assert out["count"] == 1


def test_empty_abi():
    out = abi_inspect([])
    assert out == {"count": 0, "entries": [], "selectors": {}, "topics": {}}


def test_mixed_json_and_human_entries():
    out = abi_inspect([ERC20_JSON[0], "function balanceOf(address owner)"])
    assert set(out["selectors"]) == {"0xa9059cbb", "0x70a08231"}


def test_default_type_is_function_for_a_json_entry_without_one():
    out = abi_inspect([{"name": "totalSupply", "inputs": []}])
    assert out["selectors"] == {"0x18160ddd": "totalSupply()"}


# --- selector collisions -------------------------------------------------------
def test_selector_collision_is_reported():
    # Brute-forced pair: keccak("f8491()") and keccak("f130736()") share 4 bytes.
    out = abi_inspect(["function f8491()", "function f130736()"])
    assert (
        out["entries"][0]["selector"] == out["entries"][1]["selector"] == "0x62018627"
    )
    assert out["collisions"] == [
        {"selector": "0x62018627", "signatures": ["f8491()", "f130736()"]}
    ]


def test_no_collisions_key_when_clean():
    assert "collisions" not in abi_inspect(ERC20_JSON)


def test_overloads_are_not_collisions():
    out = abi_inspect(["function f(uint256)", "function f(address)"])
    assert "collisions" not in out
    assert len(out["selectors"]) == 2


def test_the_same_signature_twice_is_not_a_collision():
    out = abi_inspect(["function f(uint256)", "function f(uint256 x)"])
    assert "collisions" not in out


# --- errors --------------------------------------------------------------------
def test_unknown_entry_type_raises():
    with pytest.raises(ValueError, match="unknown ABI entry type"):
        abi_inspect([{"type": "modifier", "name": "onlyOwner"}])


def test_function_without_a_name_raises():
    with pytest.raises(ValueError, match="missing a `name`"):
        abi_inspect([{"type": "function", "inputs": []}])


def test_param_without_a_type_raises():
    with pytest.raises(ValueError, match="missing a `type`"):
        abi_inspect([{"type": "function", "name": "f", "inputs": [{"name": "a"}]}])


def test_param_that_is_not_an_object_raises():
    with pytest.raises(ValueError, match="must be an object"):
        abi_inspect([{"type": "function", "name": "f", "inputs": ["uint256"]}])


def test_entry_of_a_wrong_type_raises():
    with pytest.raises(ValueError, match="must be an ABI object or a signature"):
        abi_inspect([42])


def test_abi_that_is_not_a_list_raises():
    with pytest.raises(ValueError, match="must be a JSON ABI array/object"):
        abi_inspect(42)


def test_invalid_human_signature_raises():
    with pytest.raises(ValueError, match="invalid signature name"):
        abi_inspect("function 1bad(uint256)")


# --- app registration ----------------------------------------------------------
def test_registered_and_callable_through_app():
    names = {t.name for t in asyncio.run(mcp.list_tools())}
    assert "abi_inspect" in names

    async def go():
        return await mcp.call_tool("abi_inspect", {"abi": ERC20_JSON})

    result = asyncio.run(go())
    contents = result[0] if isinstance(result, tuple) else result
    payload = json.loads(contents[0].text)
    assert payload["selectors"]["0xa9059cbb"] == "transfer(address,uint256)"
    assert payload["topics"][TRANSFER_TOPIC0] == "Transfer(address,address,uint256)"


def test_registered_with_expected_schema():
    tool = next(t for t in asyncio.run(mcp.list_tools()) if t.name == "abi_inspect")
    assert tool.inputSchema["required"] == ["abi"]
    assert tool.description
