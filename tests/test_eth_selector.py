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

"""TODO 10.5 / plan §2.1.5 — eth_selector (4-byte selector / event topic0).

Selector vectors are the canonical ERC-20 values; the event topic0 is the
published ERC-20 Transfer signature hash."""

import asyncio
import json

import pytest

pytest.importorskip("Crypto", reason="ethereum extra (pycryptodome) not installed")

from mcp_bytesmith.eth import eth_selector  # noqa: E402
from mcp_bytesmith.server import mcp  # noqa: E402

# Canonical ERC-20 selectors.
SELECTORS = [
    ("transfer(address,uint256)", "0xa9059cbb"),
    ("transferFrom(address,address,uint256)", "0x23b872dd"),
    ("approve(address,uint256)", "0x095ea7b3"),
    ("balanceOf(address)", "0x70a08231"),
    ("totalSupply()", "0x18160ddd"),
]


@pytest.mark.parametrize("sig,selector", SELECTORS)
def test_function_selector(sig, selector):
    out = eth_selector(sig)  # kind defaults to "function"
    assert out == {"kind": "function", "signature": sig, "selector": selector}


def test_selector_strips_param_names_and_whitespace():
    assert (
        eth_selector("transfer(address to, uint256 amount)")["selector"] == "0xa9059cbb"
    )


def test_selector_normalizes_uint_int_aliases():
    # `uint` -> `uint256`, `int` -> `int256` must reach the canonical selector.
    assert eth_selector("transfer(address, uint)")["selector"] == "0xa9059cbb"
    out = eth_selector("foo(int x)")
    assert out["signature"] == "foo(int256)"


def test_selector_strips_data_location_keywords():
    out = eth_selector("batch(uint256[] calldata ids, bytes memory data)")
    assert out["signature"] == "batch(uint256[],bytes)"


def test_selector_canonicalizes_tuples():
    out = eth_selector("foo((uint256 a, address b) x, uint256[] y)")
    assert out["signature"] == "foo((uint256,address),uint256[])"


def test_selector_no_args():
    out = eth_selector("now()")
    assert out["signature"] == "now()"
    assert out["selector"].startswith("0x") and len(out["selector"]) == 10


# --- event topic0 --------------------------------------------------------------
ERC20_TRANSFER_TOPIC0 = (
    "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
)


def test_event_topic0():
    out = eth_selector(
        "Transfer(address indexed from, address indexed to, uint256 value)", "event"
    )
    assert out == {
        "kind": "event",
        "signature": "Transfer(address,address,uint256)",
        "topic0": ERC20_TRANSFER_TOPIC0,
    }


def test_event_topic0_is_full_32_bytes():
    out = eth_selector("Approval(address,address,uint256)", "event")
    assert len(out["topic0"]) == 66  # 0x + 64 hex chars


def test_selector_byte_alias_normalizes_to_bytes1():
    # Solidity's `byte` alias canonicalizes to `bytes1`.
    assert eth_selector("foo(byte x)")["signature"] == "foo(bytes1)"


def test_selector_tuple_array_suffix():
    # An array suffix on a tuple parameter is preserved after canonicalization.
    out = eth_selector("foo((uint256,address)[2] x)")
    assert out["signature"] == "foo((uint256,address)[2])"


# --- error paths ---------------------------------------------------------------
def test_empty_parameter_raises():
    # A trailing comma yields an empty parameter, which is rejected.
    with pytest.raises(ValueError):
        eth_selector("foo(uint256,)")


def test_unknown_kind_raises():
    with pytest.raises(ValueError):
        eth_selector("foo()", "modifier")


def test_no_parameter_list_raises():
    with pytest.raises(ValueError):
        eth_selector("transfer")


def test_invalid_name_raises():
    with pytest.raises(ValueError):
        eth_selector("1bad(uint256)")


def test_unbalanced_parens_raises():
    with pytest.raises(ValueError):
        eth_selector("foo(uint256")


# --- app registration / schema -------------------------------------------------
def test_registered_with_enum_schema():
    tool = next(t for t in asyncio.run(mcp.list_tools()) if t.name == "eth_selector")
    assert tool.inputSchema["properties"]["kind"]["enum"] == ["function", "event"]


def test_callable_through_app():
    async def go():
        return await mcp.call_tool(
            "eth_selector", {"signature": "transfer(address,uint256)"}
        )

    result = asyncio.run(go())
    contents = result[0] if isinstance(result, tuple) else result
    payload = json.loads(contents[0].text)
    assert payload["selector"] == "0xa9059cbb"
