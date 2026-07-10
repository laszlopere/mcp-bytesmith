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

"""TODO 13.3 / plan §2.4.3 — eth_eoa_address (private key -> public key -> address).

Addresses are cross-checked against the well-known Hardhat/Anvil default accounts,
whose private keys are published fixtures (never use them for real funds)."""

import asyncio
import json

import pytest

pytest.importorskip("Crypto", reason="ethereum extra (pycryptodome) not installed")

from mcp_bytesmith.eth import eth_eoa_address  # noqa: E402
from mcp_bytesmith.server import mcp  # noqa: E402

# (private key, checksummed address) for the first Anvil default accounts.
ANVIL_ACCOUNTS = [
    (
        "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
        "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
    ),
    (
        "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
        "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
    ),
    (
        "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a",
        "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC",
    ),
]

# secp256k1 group order n — the first scalar that is NOT a valid private key.
SECP_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


# --- known-answer vectors ------------------------------------------------------
@pytest.mark.parametrize("private_key,address", ANVIL_ACCOUNTS)
def test_anvil_accounts(private_key, address):
    assert eth_eoa_address(private_key)["address"] == address  # EIP-55 checksummed


def test_private_key_one_is_the_generator():
    # k=1 -> the public key IS G, whose coordinates are the curve's fixed generator.
    out = eth_eoa_address("0x" + "00" * 31 + "01")
    assert out["public_key"] == (
        "0x0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
    )
    assert out["address"] == "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf"


# --- public key shape ----------------------------------------------------------
def test_public_key_is_uncompressed_and_matches_address():
    from mcp_bytesmith.eth import _pubkey_address

    out = eth_eoa_address(ANVIL_ACCOUNTS[0][0])
    pub = bytes.fromhex(out["public_key"][2:])
    assert len(pub) == 65 and pub[0] == 0x04  # 0x04 || X || Y
    assert out["address"] == _pubkey_address(pub[1:])


def test_result_keys_are_exactly_address_and_public_key():
    assert set(eth_eoa_address(ANVIL_ACCOUNTS[0][0])) == {"address", "public_key"}


# --- agreement with the HD-derivation path -------------------------------------
def test_matches_bip32_derive_for_the_same_key():
    from mcp_bytesmith.eth import bip32_derive

    hd = bip32_derive("00" * 32 + "ff" * 32, "m/44'/60'/0'/0/0")
    out = eth_eoa_address(hd["private_key"])
    assert out["address"] == hd["address"]
    assert out["public_key"] == hd["public_key"]


# --- input handling ------------------------------------------------------------
def test_0x_prefix_is_optional():
    bare = ANVIL_ACCOUNTS[0][0][2:]
    assert eth_eoa_address(bare) == eth_eoa_address(ANVIL_ACCOUNTS[0][0])


def test_uppercase_hex_accepted():
    upper = ANVIL_ACCOUNTS[0][0].upper().replace("0X", "0x")
    assert eth_eoa_address(upper)["address"] == ANVIL_ACCOUNTS[0][1]


# --- secrets policy (§2.0.6): the private key is never echoed back --------------
def test_private_key_not_echoed():
    private_key = ANVIL_ACCOUNTS[0][0]
    payload = json.dumps(eth_eoa_address(private_key))
    assert private_key not in payload and private_key[2:] not in payload


# --- error paths ---------------------------------------------------------------
@pytest.mark.parametrize("bad", ["0x00", "00" * 31, "00" * 33, ""])
def test_wrong_length_key_rejected(bad):
    with pytest.raises(ValueError, match="32 bytes"):
        eth_eoa_address(bad)


@pytest.mark.parametrize("odd", ["0xzz" + "00" * 31, "0x" + "0" * 63])
def test_malformed_hex_rejected(odd):
    with pytest.raises(ValueError):
        eth_eoa_address(odd)


@pytest.mark.parametrize(
    "out_of_range",
    [
        "00" * 32,  # k = 0
        f"{SECP_N:064x}",  # k = n
        f"{SECP_N + 1:064x}",  # k = n + 1
        "ff" * 32,  # k > n
    ],
)
def test_scalar_out_of_range_rejected(out_of_range):
    with pytest.raises(ValueError, match="secp256k1 range"):
        eth_eoa_address(out_of_range)


def test_largest_valid_scalar_accepted():
    assert eth_eoa_address(f"{SECP_N - 1:064x}")["address"].startswith("0x")


# --- app registration ----------------------------------------------------------
def test_registered():
    names = {t.name for t in asyncio.run(mcp.list_tools())}
    assert "eth_eoa_address" in names


def test_callable_through_app():
    async def go():
        return await mcp.call_tool(
            "eth_eoa_address", {"private_key": ANVIL_ACCOUNTS[0][0]}
        )

    result = asyncio.run(go())
    contents = result[0] if isinstance(result, tuple) else result
    payload = json.loads(contents[0].text)
    assert payload["address"] == ANVIL_ACCOUNTS[0][1]
