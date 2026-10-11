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
    contents = result.content
    payload = json.loads(contents[0].text)
    assert payload["address"] == ANVIL_ACCOUNTS[0][1]


# --- private_key_file: the key is read server-side, never seen by the caller ----
@pytest.mark.parametrize(
    "content",
    [
        ANVIL_ACCOUNTS[1][0],  # 0x-prefixed hex
        ANVIL_ACCOUNTS[1][0][2:],  # bare hex
        ANVIL_ACCOUNTS[1][0] + "\n",  # trailing newline, as `echo > file` leaves
        "  " + ANVIL_ACCOUNTS[1][0].upper().replace("0X", "0x") + "\r\n",
    ],
)
def test_key_file_hex_forms(tmp_path, content):
    f = tmp_path / "key"
    f.write_text(content)
    assert eth_eoa_address(private_key_file=str(f))["address"] == ANVIL_ACCOUNTS[1][1]


def test_key_file_raw_bytes(tmp_path):
    f = tmp_path / "key.bin"
    f.write_bytes(bytes.fromhex(ANVIL_ACCOUNTS[2][0][2:]))
    assert eth_eoa_address(private_key_file=str(f))["address"] == ANVIL_ACCOUNTS[2][1]


def test_key_file_matches_inline_key(tmp_path):
    f = tmp_path / "key"
    f.write_text(ANVIL_ACCOUNTS[0][0])
    assert eth_eoa_address(private_key_file=str(f)) == eth_eoa_address(
        ANVIL_ACCOUNTS[0][0]
    )


def test_key_file_tilde_expanded(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    (tmp_path / "key").write_text(ANVIL_ACCOUNTS[0][0])
    assert eth_eoa_address(private_key_file="~/key")["address"] == ANVIL_ACCOUNTS[0][1]


def test_exactly_one_key_source_required(tmp_path):
    f = tmp_path / "key"
    f.write_text(ANVIL_ACCOUNTS[0][0])
    with pytest.raises(ValueError, match="exactly one"):
        eth_eoa_address()
    with pytest.raises(ValueError, match="exactly one"):
        eth_eoa_address(ANVIL_ACCOUNTS[0][0], private_key_file=str(f))


def test_key_file_missing(tmp_path):
    with pytest.raises(ValueError, match="not found"):
        eth_eoa_address(private_key_file=str(tmp_path / "nope"))


def test_key_file_is_a_directory(tmp_path):
    with pytest.raises(ValueError, match="not a regular file"):
        eth_eoa_address(private_key_file=str(tmp_path))


def test_key_file_too_large(tmp_path):
    f = tmp_path / "big"
    f.write_text("0" * 5000)
    with pytest.raises(ValueError, match="larger than"):
        eth_eoa_address(private_key_file=str(f))


@pytest.mark.parametrize(
    "content",
    [
        ANVIL_ACCOUNTS[0][0][:-1],  # one hex digit short
        ANVIL_ACCOUNTS[0][0][:-1] + "z",  # a typo'd digit
        ANVIL_ACCOUNTS[0][0] + "00",  # one byte too many
    ],
)
def test_key_file_malformed_error_does_not_quote_contents(tmp_path, content):
    # A near-miss key is still nearly the whole key, so the error must not quote it
    # (the inline path's hex parser does, which is fine there: the caller sent it).
    f = tmp_path / "key"
    f.write_text(content)
    with pytest.raises(ValueError) as exc:
        eth_eoa_address(private_key_file=str(f))
    message = str(exc.value)
    assert "32-byte key" in message
    assert ANVIL_ACCOUNTS[0][0][2:20] not in message.lower()


def test_key_file_out_of_range(tmp_path):
    f = tmp_path / "key"
    f.write_text("00" * 32)
    with pytest.raises(ValueError, match="secp256k1 range"):
        eth_eoa_address(private_key_file=str(f))


def test_key_file_through_app(tmp_path):
    f = tmp_path / "key"
    f.write_text(ANVIL_ACCOUNTS[0][0] + "\n")

    async def go():
        return await mcp.call_tool("eth_eoa_address", {"private_key_file": str(f)})

    text = asyncio.run(go()).content[0].text
    assert json.loads(text)["address"] == ANVIL_ACCOUNTS[0][1]
    assert ANVIL_ACCOUNTS[0][0][2:] not in text
