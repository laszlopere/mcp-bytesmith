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

"""TODO 11.7 / plan §2.2.7 / §1.14.7 — eth_tx_codec.

The two from-recovery anchors are real vectors:

* the legacy tx is the canonical EIP-155 example (private key 0x4646..46, sender
  0x9d8A62f6..55A4F), and
* the EIP-1559 tx is a real mainnet transaction (block 25295372) — re-encoding
  its fields reproduces the on-chain transaction hash, and decoding recovers the
  on-chain sender.

The typed envelopes that lack a hand-checkable vector (2930 / 4844) are covered
by encode<->decode round trips and type detection."""

import asyncio
import json

import pytest

pytest.importorskip("Crypto", reason="ethereum extra (pycryptodome) not installed")

from mcp_bytesmith.eth import (  # noqa: E402
    _SECP_G,
    _SECP_N,
    _SECP_P,
    _ec_add,
    _ecrecover,
    eth_tx_codec,
)
from mcp_bytesmith.server import mcp  # noqa: E402

# --- canonical EIP-155 legacy vector (Ethereum yellow paper / EIP-155) ---------
LEGACY_RAW = (
    "0xf86c098504a817c800825208943535353535353535353535353535353535353535"
    "880de0b6b3a76400008025a028ef61340bd939bc2195fe537567866003e1a15d3c71"
    "ff63e1590620aa636276a067cbe9d8997f761aecb703304b3800ccf555c9f3dc6421"
    "4b297fb1966a3b6d83"
)
LEGACY_SENDER = "0x9d8A62f656a8d1615C1294fd71e9CFb3E4855A4F"

# --- real mainnet EIP-1559 tx, block 25295372 (empty access list) --------------
TX1559 = {
    "type": 2,
    "chainId": 1,
    "nonce": 0,
    "maxPriorityFeePerGas": "0x10c8e0",
    "maxFeePerGas": "0x22c31a42",
    "gasLimit": "0x10c0b",
    "to": "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
    "value": 0,
    "data": (
        "0xa9059cbb000000000000000000000000c8ca2c90bcb6c088d5e03535a5c9e178"
        "97eb53b600000000000000000000000000000000000000000000000000000000004cb53d"
    ),
    "accessList": [],
    "yParity": 0,
    "r": "0xf6252e0ba79a8a7a9bbb02aaba1ff10fe8a3a5733e7ca7e6ea07bb31c3a6b50c",
    "s": "0x4f2ea7f43440ee5f0655a8eddf1272b86f32ef336dc2c0cc6a0bf9af231bdab0",
}
TX1559_HASH = "0x768d1ae82e9cce636aab668f21f6784c65be7396a20040176f55891d92e7d38b"
TX1559_SENDER = "0xfc78e46a47b9da1598805466c5a4626fe8a1ce9c"


# --- legacy decode / encode ----------------------------------------------------
def test_legacy_decode_recovers_sender():
    out = eth_tx_codec("decode", data=LEGACY_RAW)
    assert out["type"] == 0
    assert out["from"] == LEGACY_SENDER


def test_legacy_decode_fields():
    f = eth_tx_codec("decode", data=LEGACY_RAW)["fields"]
    assert f["chainId"] == "1"  # derived from EIP-155 v
    assert f["v"] == "37"
    assert f["nonce"] == "9"
    assert f["gasPrice"] == "20000000000"
    assert f["gasLimit"] == "21000"
    assert f["value"] == "1000000000000000000"
    assert f["to"].lower() == "0x3535353535353535353535353535353535353535"
    assert f["data"] == "0x"


def test_legacy_hash():
    # tx hash = keccak256 of the raw signed serialization.
    assert eth_tx_codec("decode", data=LEGACY_RAW)["hash"] == (
        "0x33469b22e9f636356c4160a87eb19df52b7412e8eac32a4a55ffe88ea8350788"
    )


def test_legacy_reencode_round_trips_exactly():
    f = eth_tx_codec("decode", data=LEGACY_RAW)["fields"]
    assert eth_tx_codec("encode", fields={**f, "type": 0})["raw"] == LEGACY_RAW


# --- EIP-1559: serialize vs real chain, then recover sender --------------------
def test_1559_encode_matches_onchain_hash():
    out = eth_tx_codec("encode", fields=TX1559)
    assert out["type"] == 2
    assert out["hash"] == TX1559_HASH  # matches the real mainnet tx hash


def test_1559_decode_recovers_onchain_sender():
    raw = eth_tx_codec("encode", fields=TX1559)["raw"]
    out = eth_tx_codec("decode", data=raw)
    assert out["from"].lower() == TX1559_SENDER
    assert out["hash"] == TX1559_HASH


def test_1559_decode_fields():
    raw = eth_tx_codec("encode", fields=TX1559)["raw"]
    f = eth_tx_codec("decode", data=raw)["fields"]
    assert f["chainId"] == "1"
    assert f["nonce"] == "0"
    assert f["maxFeePerGas"] == str(0x22C31A42)
    assert f["maxPriorityFeePerGas"] == str(0x10C8E0)
    assert f["yParity"] == 0
    assert f["accessList"] == []
    assert f["r"] == TX1559["r"]


# --- EIP-2930: round trip with a populated access list -------------------------
def test_2930_round_trip_with_access_list():
    fields = {
        "type": 1,
        "chainId": 1,
        "nonce": 5,
        "gasPrice": "0x3b9aca00",
        "gasLimit": 21000,
        "to": "0x2222222222222222222222222222222222222222",
        "value": "0xde0b6b3a7640000",
        "data": "0x",
        "accessList": [
            {
                "address": "0x1111111111111111111111111111111111111111",
                "storageKeys": ["0x" + "00" * 31 + "01", "0x" + "ab" * 32],
            }
        ],
        "yParity": 1,
        "r": "0x" + "11" * 32,
        "s": "0x" + "22" * 32,
    }
    raw = eth_tx_codec("encode", fields=fields)["raw"]
    out = eth_tx_codec("decode", data=raw)
    assert out["type"] == 1
    al = out["fields"]["accessList"]
    assert al[0]["address"].lower() == "0x1111111111111111111111111111111111111111"
    assert al[0]["storageKeys"] == ["0x" + "00" * 31 + "01", "0x" + "ab" * 32]
    # re-encoding the decoded fields reproduces the same bytes
    assert eth_tx_codec("encode", fields={**out["fields"], "type": 1})["raw"] == raw


# --- EIP-4844: type inferred from blobVersionedHashes, round trip --------------
def test_4844_type_inferred_and_round_trips():
    fields = {
        "chainId": 1,
        "nonce": 7,
        "maxPriorityFeePerGas": 1,
        "maxFeePerGas": 100,
        "gasLimit": 21000,
        "to": "0x3333333333333333333333333333333333333333",
        "value": 0,
        "data": "0x",
        "accessList": [],
        "maxFeePerBlobGas": "0x3b9aca00",
        "blobVersionedHashes": ["0x01" + "cd" * 31],
        "yParity": 0,
        "r": "0x" + "33" * 32,
        "s": "0x" + "44" * 32,
    }
    enc = eth_tx_codec("encode", fields=fields)
    assert enc["type"] == 3  # inferred from blobVersionedHashes
    out = eth_tx_codec("decode", data=enc["raw"])
    assert out["type"] == 3
    assert out["fields"]["blobVersionedHashes"] == ["0x01" + "cd" * 31]
    assert out["fields"]["maxFeePerBlobGas"] == str(0x3B9ACA00)
    assert (
        eth_tx_codec("encode", fields={**out["fields"], "type": 3})["raw"] == enc["raw"]
    )


# --- contract creation: empty `to` becomes null --------------------------------
def test_contract_creation_empty_to_is_null():
    fields = {
        "type": 0,
        "nonce": 0,
        "gasPrice": 1,
        "gasLimit": 53000,
        "to": None,
        "value": 0,
        "data": "0x6000",
        "v": 27,
        "r": "0x" + "55" * 32,
        "s": "0x" + "66" * 32,
    }
    out = eth_tx_codec("decode", data=eth_tx_codec("encode", fields=fields)["raw"])
    assert out["fields"]["to"] is None
    assert "chainId" not in out["fields"]  # pre-EIP-155 (v=27) has no chain id


# --- type inference ------------------------------------------------------------
def test_type_inference():
    base = {
        "nonce": 1,
        "gasLimit": 21000,
        "to": "0x" + "00" * 20,
        "value": 1,
        "data": "0x",
        "r": "0x" + "01" * 32,
        "s": "0x" + "02" * 32,
    }
    assert eth_tx_codec("encode", fields={**base, "gasPrice": 1, "v": 27})["type"] == 0
    assert (
        eth_tx_codec(
            "encode", fields={**base, "gasPrice": 1, "accessList": [], "yParity": 0}
        )["type"]
        == 1
    )
    assert (
        eth_tx_codec(
            "encode",
            fields={
                **base,
                "maxFeePerGas": 1,
                "chainId": 1,
                "accessList": [],
                "yParity": 0,
            },
        )["type"]
        == 2
    )


def test_explicit_type_overrides_inference():
    # maxFeePerGas present but type forced to legacy serialization is honored.
    out = eth_tx_codec(
        "encode",
        fields={
            "type": 0,
            "nonce": 0,
            "gasPrice": 1,
            "gasLimit": 21000,
            "to": "0x" + "00" * 20,
            "value": 0,
            "data": "0x",
            "v": 27,
            "r": "0x" + "01" * 32,
            "s": "0x" + "02" * 32,
        },
    )
    assert out["type"] == 0


# --- unsigned signature -> no sender -------------------------------------------
def test_zero_signature_has_no_sender():
    fields = {
        "type": 2,
        "chainId": 1,
        "nonce": 0,
        "maxPriorityFeePerGas": 1,
        "maxFeePerGas": 100,
        "gasLimit": 21000,
        "to": "0x" + "00" * 20,
        "value": 0,
        "data": "0x",
        "accessList": [],
        "yParity": 0,
        "r": 0,
        "s": 0,
    }
    assert (
        eth_tx_codec("decode", data=eth_tx_codec("encode", fields=fields)["raw"])[
            "from"
        ]
        is None
    )


# --- access list in tuple ([address, [keys]]) form -----------------------------
def test_access_list_tuple_form():
    # The access list may be given as [[address, [storageKey,...]], ...] tuples
    # rather than {"address":..,"storageKeys":..} dicts.
    fields = {
        "type": 1,
        "chainId": 1,
        "nonce": 0,
        "gasPrice": 1,
        "gasLimit": 21000,
        "to": "0x" + "22" * 20,
        "value": 0,
        "data": "0x",
        "accessList": [["0x" + "11" * 20, ["0x" + "00" * 31 + "01"]]],
        "yParity": 0,
        "r": "0x" + "aa" * 32,
        "s": "0x" + "bb" * 32,
    }
    raw = eth_tx_codec("encode", fields=fields)["raw"]
    al = eth_tx_codec("decode", data=raw)["fields"]["accessList"]
    assert al[0]["address"].lower() == "0x" + "11" * 20
    assert al[0]["storageKeys"] == ["0x" + "00" * 31 + "01"]


# --- legacy tx with a non-standard / unsigned v (not 27/28, not EIP-155) -------
def test_legacy_unsigned_v_has_no_chain_id_or_sender():
    fields = {
        "type": 0,
        "nonce": 0,
        "gasPrice": 1,
        "gasLimit": 21000,
        "to": "0x" + "00" * 20,
        "value": 0,
        "data": "0x",
        "v": 0,  # neither EIP-155 (>=35) nor pre-EIP-155 (27/28)
        "r": "0x" + "11" * 32,
        "s": "0x" + "22" * 32,
    }
    raw = eth_tx_codec("encode", fields=fields)["raw"]
    out = eth_tx_codec("decode", data=raw)
    assert out["from"] is None
    assert "chainId" not in out["fields"]


# --- secp256k1 point arithmetic (used by from-recovery) ------------------------
def test_ec_add_identity_element():
    # The point at infinity (None) is the additive identity.
    assert _ec_add(_SECP_G, None) == _SECP_G
    assert _ec_add(None, _SECP_G) == _SECP_G


def test_ec_add_point_plus_negation_is_infinity():
    gx, gy = _SECP_G
    assert _ec_add(_SECP_G, (gx, _SECP_P - gy)) is None


def test_ec_add_doubling_matches_known_2g():
    # Well-known secp256k1 2*G x-coordinate.
    two_g = _ec_add(_SECP_G, _SECP_G)
    assert (
        two_g[0] == 0xC6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5
    )


# --- ecrecover argument validation ---------------------------------------------
def test_ecrecover_rejects_r_out_of_range():
    with pytest.raises(ValueError):
        _ecrecover(1, 0, 1, 0)
    with pytest.raises(ValueError):
        _ecrecover(1, _SECP_N, 1, 0)


def test_ecrecover_rejects_s_out_of_range():
    with pytest.raises(ValueError):
        _ecrecover(1, 1, 0, 0)


def test_ecrecover_rejects_bad_recovery_id():
    with pytest.raises(ValueError):
        _ecrecover(1, 1, 1, 4)


def test_ecrecover_rejects_x_out_of_field_range():
    # rec_id>=2 adds N to r; with r close to N this overflows the field prime.
    with pytest.raises(ValueError):
        _ecrecover(1, _SECP_N - 1, 1, 2)


# --- error paths ---------------------------------------------------------------
def test_encode_unsupported_tx_type_raises():
    with pytest.raises(ValueError):
        eth_tx_codec("encode", fields={"type": 5, "nonce": 0})


def test_decode_empty_raises():
    with pytest.raises(ValueError):
        eth_tx_codec("decode", data="0x")


def test_decode_bad_type_byte_raises():
    # 0x05 is not a known typed-envelope prefix and < 0xc0 (not an RLP list).
    with pytest.raises(ValueError):
        eth_tx_codec("decode", data="0x05c0")


def test_decode_trailing_bytes_raises():
    with pytest.raises(ValueError):
        eth_tx_codec("decode", data=LEGACY_RAW + "00")


def test_decode_wrong_field_count_raises():
    # a 3-item RLP list is not a valid legacy tx (needs 9 fields)
    with pytest.raises(ValueError):
        eth_tx_codec("decode", data="0xc3010203")


def test_encode_requires_fields_object():
    with pytest.raises(ValueError):
        eth_tx_codec("encode", fields=None)


def test_decode_requires_string_data():
    with pytest.raises(ValueError):
        eth_tx_codec("decode", data=None)


def test_unknown_action_raises():
    with pytest.raises(ValueError):
        eth_tx_codec("frobnicate", data=LEGACY_RAW)


# --- fields accepted as a JSON string ------------------------------------------
def test_encode_fields_as_json_string():
    out = eth_tx_codec("encode", fields=json.dumps(TX1559))
    assert out["hash"] == TX1559_HASH


# --- app registration ----------------------------------------------------------
def test_registered_and_callable_through_app():
    names = {t.name for t in asyncio.run(mcp.list_tools())}
    assert "eth_tx_codec" in names

    async def go():
        return await mcp.call_tool(
            "eth_tx_codec", {"action": "decode", "data": LEGACY_RAW}
        )

    result = asyncio.run(go())
    contents = result.content
    payload = json.loads(contents[0].text)
    assert payload["from"] == LEGACY_SENDER


# --- signing_hash: the digest the sender signs ------------------------------------
# References from eth_account (serializable_unsigned_transaction_from_dict /
# TypedTransaction .hash()); the EIP-155 one is also printed in the EIP itself.
# The key is EIP-155's published example key (never use it for real funds).
EIP155_KEY = "0x" + "46" * 32
LEGACY_UNSIGNED = {
    "nonce": 9,
    "gasPrice": 20 * 10**9,
    "gasLimit": 21000,
    "to": "0x3535353535353535353535353535353535353535",
    "value": 10**18,
    "data": "0x",
}
EIP155_SIGHASH = "0xdaf5a779ae972f972197303d7b574746c7ef83eadac0f2791ad23db92e4c8e53"
PRE155_SIGHASH = "0xf9e36c28c8cb35adba138005c02ab7aa7fbcd891f3139cb2eeed052a51cd2713"
PRE155_RAW = (
    "0xf86c098504a817c800825208943535353535353535353535353535353535353535"
    "880de0b6b3a7640000801ba08383adc8b8ae116f918fb44ca7ff9dfd8012596a5c13"
    "0c6246a2cc717ba41cdaa053ddfacf5bd4aa7e46d1575acf52636ea659b91f29e2fb"
    "91c75567a279738f38"
)
TX1559_SIGHASH = "0x8da87285bbe2cbb9babecd4cf8ff952d61221aac6ad8c023d351cd8273681b13"
TX1559_RAW_BY_EIP155_KEY = (
    "0x02f8af01808310c8e08422c31a4283010c0b94a0b86991c6218b36c1d19d4a2e9eb0ce"
    "3606eb4880b844a9059cbb000000000000000000000000c8ca2c90bcb6c088d5e03535a5"
    "c9e17897eb53b600000000000000000000000000000000000000000000000000000000004c"
    "b53dc001a0e949489aeb6cdf3a948e068a2643be194e422a48f3cdb8b20101990c6e0596"
    "f8a01f33f3643299b055d564b14ec95f4968a6f0df5d3c6ac215afe1545c32e6c285"
)


def _unsigned_1559():
    return {k: v for k, v in TX1559.items() if k not in ("yParity", "r", "s")}


def test_eip155_signing_hash_unsigned_and_signed():
    unsigned = eth_tx_codec("encode", fields={**LEGACY_UNSIGNED, "chainId": 1})
    assert unsigned["signing_hash"] == EIP155_SIGHASH
    # ...and the signed tx it becomes reports the same digest on both sides.
    assert eth_tx_codec("decode", data=LEGACY_RAW)["signing_hash"] == EIP155_SIGHASH
    signed = eth_tx_codec("decode", data=LEGACY_RAW)["fields"]
    assert eth_tx_codec("encode", fields=signed)["signing_hash"] == EIP155_SIGHASH


def test_unsigned_legacy_chain_id_goes_into_v():
    out = eth_tx_codec("encode", fields={**LEGACY_UNSIGNED, "chainId": 369})
    decoded = eth_tx_codec("decode", data=out["raw"])
    assert decoded["fields"]["v"] == "369" and decoded["fields"]["chainId"] == "369"
    assert decoded["signing_hash"] == out["signing_hash"]
    assert decoded["from"] is None


def test_pre_eip155_signing_hash():
    assert eth_tx_codec("encode", fields=LEGACY_UNSIGNED)["signing_hash"] == (
        PRE155_SIGHASH
    )
    decoded = eth_tx_codec("decode", data=PRE155_RAW)
    assert decoded["signing_hash"] == PRE155_SIGHASH
    assert "chainId" not in decoded["fields"]


def test_1559_signing_hash_unsigned_and_signed():
    assert eth_tx_codec("encode", fields=_unsigned_1559())["signing_hash"] == (
        TX1559_SIGHASH
    )
    # The signature does not change what was signed.
    assert eth_tx_codec("encode", fields=TX1559)["signing_hash"] == TX1559_SIGHASH
    raw = eth_tx_codec("encode", fields=TX1559)["raw"]
    assert eth_tx_codec("decode", data=raw)["signing_hash"] == TX1559_SIGHASH


def test_signed_legacy_v_must_match_chain_id():
    signed = eth_tx_codec("decode", data=LEGACY_RAW)["fields"]  # v=37 -> chain 1
    with pytest.raises(ValueError, match="does not encode chainId 5"):
        eth_tx_codec("encode", fields={**signed, "chainId": 5})
    with pytest.raises(ValueError, match="does not encode chainId"):
        eth_tx_codec("encode", fields={**signed, "v": 27})  # pre-155 v + chainId


def test_unsigned_legacy_v_must_equal_chain_id():
    with pytest.raises(ValueError, match="must be absent or equal chainId"):
        eth_tx_codec("encode", fields={**LEGACY_UNSIGNED, "chainId": 1, "v": 2})


# --- end to end: encode unsigned -> eth_sign -> encode signed --------------------
@pytest.fixture
def eip155_key_file(tmp_path):
    f = tmp_path / "key"
    f.write_text(EIP155_KEY)
    return str(f)


def test_sign_eip155_legacy_end_to_end(eip155_key_file):
    from mcp_bytesmith.eth import eth_sign

    fields = {**LEGACY_UNSIGNED, "chainId": 1}
    digest = eth_tx_codec("encode", fields=fields)["signing_hash"]
    sig = eth_sign("sign", message_hash=digest, private_key_file=eip155_key_file)
    signed = {**fields, "v": 1 * 2 + 35 + sig["yParity"], "r": sig["r"], "s": sig["s"]}
    out = eth_tx_codec("encode", fields=signed)
    assert out["raw"] == LEGACY_RAW  # byte for byte the EIP-155 example tx
    assert eth_tx_codec("decode", data=out["raw"])["from"] == LEGACY_SENDER


def test_sign_pre_eip155_legacy_end_to_end(eip155_key_file):
    from mcp_bytesmith.eth import eth_sign

    digest = eth_tx_codec("encode", fields=LEGACY_UNSIGNED)["signing_hash"]
    sig = eth_sign("sign", message_hash=digest, private_key_file=eip155_key_file)
    signed = {**LEGACY_UNSIGNED, "v": sig["v"], "r": sig["r"], "s": sig["s"]}
    assert eth_tx_codec("encode", fields=signed)["raw"] == PRE155_RAW


def test_sign_1559_end_to_end(eip155_key_file):
    from mcp_bytesmith.eth import eth_sign

    fields = _unsigned_1559()
    digest = eth_tx_codec("encode", fields=fields)["signing_hash"]
    sig = eth_sign("sign", message_hash=digest, private_key_file=eip155_key_file)
    signed = {**fields, "yParity": sig["yParity"], "r": sig["r"], "s": sig["s"]}
    out = eth_tx_codec("encode", fields=signed)
    assert out["raw"] == TX1559_RAW_BY_EIP155_KEY  # matches eth_account
    assert eth_tx_codec("decode", data=out["raw"])["from"] == LEGACY_SENDER
