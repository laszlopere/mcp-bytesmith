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

"""TODO 10.6 / plan §2.1.6 — eth_address_case (EIP-55 mixed-case checksum).

Vectors are the canonical examples from EIP-55 itself."""

import asyncio
import json

import pytest

pytest.importorskip("Crypto", reason="ethereum extra (pycryptodome) not installed")

from mcp_bytesmith.eth import eth_address_case  # noqa: E402
from mcp_bytesmith.server import mcp  # noqa: E402

# Canonical EIP-55 checksummed addresses (already correctly cased).
CHECKSUMMED = [
    "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
    "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
    "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
    "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
    "0x52908400098527886E0F7030069857D2E4169EE7",  # all-caps, still valid
    "0xde709f2102306220921060314715629080e2fb77",  # all-lower, still valid
]


@pytest.mark.parametrize("addr", CHECKSUMMED)
def test_encode_produces_canonical_checksum(addr):
    # Lowercasing then encoding must reproduce the canonical mixed case.
    out = eth_address_case("encode", addr.lower())
    assert out == {"action": "encode", "address": addr}


@pytest.mark.parametrize("addr", CHECKSUMMED)
def test_encode_is_prefix_insensitive(addr):
    # A bare (no 0x) lowercase body encodes the same as the 0x form.
    assert eth_address_case("encode", addr[2:].lower())["address"] == addr


@pytest.mark.parametrize("addr", CHECKSUMMED)
def test_verify_accepts_canonical(addr):
    out = eth_address_case("verify", addr)
    assert out["valid"] is True
    assert out["address"] == addr
    assert "reason" not in out


def test_verify_rejects_wrong_case():
    # A miscased address (lowercased one that has letters to flip) is invalid.
    addr = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
    out = eth_address_case("verify", addr.lower())
    assert out["valid"] is False
    assert out["reason"]
    assert out["address"] == addr  # still reports the correct form


def test_malformed_address_raises():
    for bad in ["0x123", "nothex_nothex_nothex_nothex_nothex_xxxxxx", "0x" + "g" * 40]:
        with pytest.raises(ValueError):
            eth_address_case("encode", bad)


def test_unknown_action_raises():
    with pytest.raises(ValueError):
        eth_address_case("frobnicate", CHECKSUMMED[0])


def test_action_param_exposes_enum_in_schema():
    # The Literal["encode", "verify"] annotation must surface as a JSON Schema
    # enum so clients see the valid actions without a round-trip ValueError.
    tool = next(
        t for t in asyncio.run(mcp.list_tools()) if t.name == "eth_address_case"
    )
    action = tool.inputSchema["properties"]["action"]
    assert action.get("enum") == ["encode", "verify"]


def test_registered_and_callable_through_app():
    names = {t.name for t in asyncio.run(mcp.list_tools())}
    assert "eth_address_case" in names

    async def go():
        return await mcp.call_tool(
            "eth_address_case",
            {"action": "encode", "address": CHECKSUMMED[0].lower()},
        )

    result = asyncio.run(go())
    contents = result[0] if isinstance(result, tuple) else result
    payload = json.loads(contents[0].text)
    assert payload["address"] == CHECKSUMMED[0]
