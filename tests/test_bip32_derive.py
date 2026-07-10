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

"""TODO 13.7 / plan §2.4.7 — bip32_derive (BIP-32/44 HD key + address derivation).

Private key / chain code are checked against the canonical BIP-32 Test Vector 1;
the Ethereum addresses are cross-checked against the well-known Hardhat/Anvil
default-mnemonic accounts (m/44'/60'/0'/0/i)."""

import asyncio
import base64
import hashlib
import json

import pytest

pytest.importorskip("Crypto", reason="ethereum extra (pycryptodome) not installed")

from mcp_bytesmith.eth import bip32_derive  # noqa: E402
from mcp_bytesmith.server import mcp  # noqa: E402

# Canonical BIP-32 Test Vector 1 seed (BIP-32 appendix / BIP-32.org).
BIP32_SEED = "000102030405060708090a0b0c0d0e0f"

# The Hardhat/Anvil default mnemonic; its BIP-39 seed drives the standard dev
# accounts. We derive the seed here (bip39 lives in a separate TODO) via stdlib.
ANVIL_MNEMONIC = "test test test test test test test test test test test junk"
ANVIL_SEED = hashlib.pbkdf2_hmac(
    "sha512", ANVIL_MNEMONIC.encode(), b"mnemonic", 2048, 64
).hex()
# (path suffix i, checksummed address, private key) for the first Anvil accounts.
ANVIL_ACCOUNTS = [
    (
        0,
        "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
        "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
    ),
    (
        1,
        "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
        "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
    ),
    (
        2,
        "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC",
        "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a",
    ),
]


# --- BIP-32 Test Vector 1 (chain-agnostic key material) ------------------------
def test_master_key_vector():
    out = bip32_derive(BIP32_SEED, "m")
    assert out["depth"] == 0
    assert out["path"] == "m"
    assert (
        out["private_key"]
        == "0xe8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35"
    )
    assert (
        out["chain_code"]
        == "0x873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508"
    )


def test_hardened_child_vector():
    # m/0' — the hardened path uses the parent private key in the HMAC data.
    out = bip32_derive(BIP32_SEED, "m/0'")
    assert out["depth"] == 1
    assert out["path"] == "m/0'"
    assert (
        out["private_key"]
        == "0xedb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea"
    )
    assert (
        out["chain_code"]
        == "0x47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141"
    )


def test_normal_child_vector():
    # m/0'/1 — a normal child derives from the parent's compressed public key.
    out = bip32_derive(BIP32_SEED, "m/0'/1")
    assert out["depth"] == 2
    assert (
        out["private_key"]
        == "0x3c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368"
    )


# --- Ethereum end-to-end (m/44'/60'/0'/0/i -> address) -------------------------
@pytest.mark.parametrize("index,address,private_key", ANVIL_ACCOUNTS)
def test_anvil_accounts(index, address, private_key):
    out = bip32_derive(ANVIL_SEED, f"m/44'/60'/0'/0/{index}")
    assert out["address"] == address  # EIP-55 checksummed
    assert out["private_key"] == private_key
    assert out["depth"] == 5
    assert out["path"] == f"m/44'/60'/0'/0/{index}"


def test_public_key_is_uncompressed_and_matches_address():
    from mcp_bytesmith.eth import _eip55, _keccak256

    out = bip32_derive(ANVIL_SEED, "m/44'/60'/0'/0/0")
    pub = bytes.fromhex(out["public_key"][2:])
    assert len(pub) == 65 and pub[0] == 0x04  # 0x04 || X || Y
    # address = last 20 bytes of keccak256 over the 64-byte X||Y body.
    assert out["address"] == _eip55(_keccak256(pub[1:])[-20:].hex())


# --- path parsing --------------------------------------------------------------
def test_h_and_apostrophe_are_equivalent():
    assert bip32_derive(BIP32_SEED, "m/0h") == bip32_derive(BIP32_SEED, "m/0'")


@pytest.mark.parametrize("empty", ["m", "M", ""])
def test_empty_path_is_master(empty):
    assert bip32_derive(BIP32_SEED, empty)["depth"] == 0


def test_path_is_normalized_in_output():
    # Leading 'M' and 'h' markers both normalize to canonical "m/…'" form.
    assert bip32_derive(BIP32_SEED, "M/44h/60h/0h/0/0")["path"] == "m/44'/60'/0'/0/0"


# --- input format --------------------------------------------------------------
def test_base64_seed_matches_hex():
    b64 = base64.b64encode(bytes.fromhex(BIP32_SEED)).decode()
    assert bip32_derive(b64, "m", input_format="base64") == bip32_derive(
        BIP32_SEED, "m"
    )


def test_0x_prefixed_seed_accepted():
    assert bip32_derive("0x" + BIP32_SEED, "m") == bip32_derive(BIP32_SEED, "m")


# --- secrets policy (§2.0.6): the seed is never echoed back ---------------------
def test_seed_not_echoed():
    out = bip32_derive(ANVIL_SEED, "m/44'/60'/0'/0/0")
    assert ANVIL_SEED not in json.dumps(out)


# --- error paths ---------------------------------------------------------------
@pytest.mark.parametrize("bad", ["m/", "m/44'/", "m/x", "m/-1", "m/ 1", "m/44''"])
def test_bad_path_segment_rejected(bad):
    with pytest.raises(ValueError):
        bip32_derive(BIP32_SEED, bad)


def test_index_out_of_range_rejected():
    with pytest.raises(ValueError):
        bip32_derive(BIP32_SEED, "m/2147483648")  # == 2^31, hardened space


def test_short_seed_rejected():
    with pytest.raises(ValueError):
        bip32_derive("00112233", "m")  # < 16 bytes


# --- app registration ----------------------------------------------------------
def test_registered():
    names = {t.name for t in asyncio.run(mcp.list_tools())}
    assert "bip32_derive" in names


def test_callable_through_app():
    async def go():
        return await mcp.call_tool(
            "bip32_derive", {"seed": ANVIL_SEED, "path": "m/44'/60'/0'/0/0"}
        )

    result = asyncio.run(go())
    contents = result[0] if isinstance(result, tuple) else result
    payload = json.loads(contents[0].text)
    assert payload["address"] == ANVIL_ACCOUNTS[0][1]
