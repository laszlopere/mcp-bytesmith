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

"""TODO 10.4 / plan §2.1.4 — eth_hash (keccak-256 / EIP-191 / EIP-712).

keccak/eip191 vectors are the well-known canonical digests; the EIP-712 vector
is the Mail/Person example published in the EIP-712 specification itself."""

import asyncio
import json
import sys

import pytest

pytest.importorskip("Crypto", reason="ethereum extra (pycryptodome) not installed")

import mcp_bytesmith.eth as eth_mod  # noqa: E402
from mcp_bytesmith.eth import (  # noqa: E402
    _eip712_encode_value,
    _from_bytes,
    _keccak256,
    available,
    eth_hash,
)
from mcp_bytesmith.server import mcp  # noqa: E402

# --- keccak-256 ----------------------------------------------------------------
KECCAK_EMPTY = "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
KECCAK_HELLO = "0x1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8"


def test_keccak256_empty():
    assert eth_hash("keccak256", "") == {"kind": "keccak256", "hash": KECCAK_EMPTY}


def test_keccak256_text():
    assert eth_hash("keccak256", "hello")["hash"] == KECCAK_HELLO


def test_keccak256_hex_input_matches_text():
    # "hello" as hex bytes must hash identically to the text form.
    assert eth_hash("keccak256", "0x68656c6c6f", "hex")["hash"] == KECCAK_HELLO


def test_keccak256_base64_input_matches_text():
    assert eth_hash("keccak256", "aGVsbG8=", "base64")["hash"] == KECCAK_HELLO


def test_output_format_base64_round_trips():
    import base64

    out = eth_hash("keccak256", "hello", output_format="base64")
    assert base64.b64decode(out["hash"]).hex() == KECCAK_HELLO[2:]


# --- EIP-191 personal_sign -----------------------------------------------------
EIP191_HELLO = "0x50b2c43fd39106bafbba0da34fc430e1f91e3c96ea2acee2bc34119f92b37750"


def test_eip191_personal_sign():
    assert eth_hash("eip191", "hello")["hash"] == EIP191_HELLO


def test_eip191_differs_from_raw_keccak():
    # The \x19 prefix must actually change the digest.
    assert eth_hash("eip191", "hello")["hash"] != eth_hash("keccak256", "hello")["hash"]


# --- EIP-712 typed-data (canonical Mail example) -------------------------------
MAIL_TYPED_DATA = {
    "types": {
        "EIP712Domain": [
            {"name": "name", "type": "string"},
            {"name": "version", "type": "string"},
            {"name": "chainId", "type": "uint256"},
            {"name": "verifyingContract", "type": "address"},
        ],
        "Person": [
            {"name": "name", "type": "string"},
            {"name": "wallet", "type": "address"},
        ],
        "Mail": [
            {"name": "from", "type": "Person"},
            {"name": "to", "type": "Person"},
            {"name": "contents", "type": "string"},
        ],
    },
    "primaryType": "Mail",
    "domain": {
        "name": "Ether Mail",
        "version": "1",
        "chainId": 1,
        "verifyingContract": "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC",
    },
    "message": {
        "from": {"name": "Cow", "wallet": "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"},
        "to": {"name": "Bob", "wallet": "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"},
        "contents": "Hello, Bob!",
    },
}
EIP712_DOMAIN_SEP = "0xf2cee375fa42b42143804025fc449deafd50cc031ca257e0b194a650a912090f"
EIP712_STRUCT_HASH = (
    "0xc52c0ee5d84264471806290a3f2c4cecfc5490626bf912d01f240d7a274b371e"
)
EIP712_DIGEST = "0xbe609aee343fb3c4b28e1df9e632fca64fcfaede20f02e86244efddf30957bd2"


def test_eip712_canonical_mail():
    out = eth_hash("eip712", json.dumps(MAIL_TYPED_DATA))
    assert out == {
        "kind": "eip712",
        "hash": EIP712_DIGEST,
        "domain_separator": EIP712_DOMAIN_SEP,
        "struct_hash": EIP712_STRUCT_HASH,
    }


def test_eip712_accepts_already_parsed_dict():
    # `data` may arrive as a dict rather than a JSON string.
    assert eth_hash("eip712", MAIL_TYPED_DATA)["hash"] == EIP712_DIGEST


def test_eip712_missing_keys_raises():
    with pytest.raises(ValueError):
        eth_hash("eip712", json.dumps({"primaryType": "Mail"}))


# --- error paths ---------------------------------------------------------------
def test_unknown_kind_raises():
    with pytest.raises(ValueError):
        eth_hash("blake3", "hello")


def test_bad_hex_input_raises():
    with pytest.raises(ValueError):
        eth_hash("keccak256", "0xZZ", "hex")


def test_unknown_input_format_raises():
    with pytest.raises(ValueError):
        eth_hash("keccak256", "hello", "rot13")


# --- EIP-712 per-member value encoding (_eip712_encode_value) ------------------
# Exercising the value-type branches directly with exact 32-byte vectors.
def test_eip712_encode_value_bool():
    assert _eip712_encode_value("bool", True, {}) == (1).to_bytes(32, "big")
    assert _eip712_encode_value("bool", False, {}) == (0).to_bytes(32, "big")


def test_eip712_encode_value_bytes_is_keccak_of_payload():
    # dynamic `bytes` member hashes to keccak256 of the raw bytes.
    assert _eip712_encode_value("bytes", "0xdeadbeef", {}) == _keccak256(
        bytes.fromhex("deadbeef")
    )


def test_eip712_encode_value_bytesN_is_left_aligned():
    assert (
        _eip712_encode_value("bytes4", "0xdeadbeef", {})
        == bytes.fromhex("deadbeef") + b"\x00" * 28
    )


def test_eip712_encode_value_array_is_keccak_of_concatenation():
    # arrays encode to keccak256 of the concatenated element words.
    got = _eip712_encode_value("uint256[]", [1, 2], {})
    expect = _keccak256((1).to_bytes(32, "big") + (2).to_bytes(32, "big"))
    assert got == expect


def test_eip712_encode_value_unsupported_type_raises():
    with pytest.raises(ValueError):
        _eip712_encode_value("fixed128x18", 1, {})


# --- output codec / availability -----------------------------------------------
def test_from_bytes_unknown_output_format_raises():
    with pytest.raises(ValueError):
        _from_bytes(b"\x00", "octal")


def test_available_true_when_keccak_importable():
    assert available() is True


def test_available_false_when_crypto_missing(monkeypatch):
    # The import is guarded so the package loads without the `ethereum` extra;
    # simulate the missing dependency by breaking the keccak import.
    monkeypatch.setitem(sys.modules, "Crypto.Hash", None)
    assert eth_mod.available() is False


# --- app registration / schema -------------------------------------------------
def test_registered_with_enum_schema():
    tool = next(t for t in asyncio.run(mcp.list_tools()) if t.name == "eth_hash")
    props = tool.inputSchema["properties"]
    assert props["kind"]["enum"] == ["keccak256", "eip191", "eip712"]
    assert props["input_format"]["enum"] == ["text", "hex", "base64"]
    assert props["output_format"]["enum"] == ["hex", "base64"]


def test_callable_through_app():
    async def go():
        return await mcp.call_tool("eth_hash", {"kind": "keccak256", "data": "hello"})

    result = asyncio.run(go())
    contents = result[0] if isinstance(result, tuple) else result
    payload = json.loads(contents[0].text)
    assert payload["hash"] == KECCAK_HELLO
