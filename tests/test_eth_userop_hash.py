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

"""TODO 20.9 — eth_userop_hash (ERC-4337 userOpHash for EntryPoint 0.6/0.7/0.8).

Every expected hash here was read out of the DEPLOYED EntryPoint: each operation
below was ABI-encoded and passed to `getUserOpHash` on mainnet via eth_call, and
the value the contract returned is what the test asserts. So these are not the
tool checked against itself, nor against a formula transcribed from a spec — they
are the numbers the contract that will validate the operation actually computes:

    v0.6  0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789 -> 0x2a6821a5…027c
    v0.7  0x0000000071727De22E5E9d8BAf0edAc6f37da032 -> 0xbbc3e423…fd25
    v0.8  0x4337084D9E255Ff0702461CF8895CE9E3b5Ff108 -> 0x6e5f8579…c90a
    v0.7 with a factory and a paymaster                -> 0xff576254…f50e

v0.8's typed-data path is additionally rebuilt through eth_hash's generic EIP-712
engine, so the two independent implementations have to agree."""

import asyncio
import json

import pytest

pytest.importorskip("Crypto", reason="ethereum extra (pycryptodome) not installed")

from mcp_bytesmith.eth import eth_hash, eth_userop_hash  # noqa: E402
from mcp_bytesmith.server import mcp  # noqa: E402

EP06 = "0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789"
EP07 = "0x0000000071727De22E5E9d8BAf0edAc6f37da032"
EP08 = "0x4337084D9E255Ff0702461CF8895CE9E3b5Ff108"

# One operation, in the v0.6 (unpacked) spelling. v0.7/v0.8 read the same fields
# and pack them, so the three versions can be compared on identical input.
OP = {
    "sender": "0x1111111111111111111111111111111111111111",
    "nonce": 1,
    "initCode": "0x",
    "callData": "0xdeadbeef",
    "callGasLimit": 100000,
    "verificationGasLimit": 200000,
    "preVerificationGas": 21000,
    "maxFeePerGas": 1000000000,
    "maxPriorityFeePerGas": 500000000,
    "paymasterAndData": "0x",
    "signature": "0x",
}
HASH_06 = "0x2a6821a5acdd4bcc9b1cc4578e8486d0ac37446463f9cef6df2a7c9a8f89027c"
HASH_07 = "0xbbc3e423d27d9cbc7fb30512904539b7471a6c558e704ef34f7cf1de8eecfd25"
HASH_08 = "0x6e5f85792fa78373faad25463a7acc5c9ffb7a51e076bcf152d0a69ba673c90a"

# The same operation as a bundler's eth_sendUserOperation v0.7 request: a factory
# and a paymaster, none of it pre-packed.
OP_UNPACKED = {
    "sender": "0x2222222222222222222222222222222222222222",
    "nonce": "0x2a",
    "factory": "0x3333333333333333333333333333333333333333",
    "factoryData": "0xc0ffee",
    "callData": "0xdeadbeef",
    "callGasLimit": 100000,
    "verificationGasLimit": 200000,
    "preVerificationGas": 21000,
    "maxFeePerGas": 1000000000,
    "maxPriorityFeePerGas": 500000000,
    "paymaster": "0x4444444444444444444444444444444444444444",
    "paymasterVerificationGasLimit": 50000,
    "paymasterPostOpGasLimit": 30000,
    "paymasterData": "0xbeef",
    "signature": "0xaaaa",
}
HASH_07_UNPACKED = "0xff57625459d0fccfc9951cda9d08c18a1ae8f7d2651f083234765e0320c9f50e"


# --- the deployed EntryPoints' own answers -------------------------------------
@pytest.mark.parametrize(
    "entry_point, version, expect",
    [(EP06, "0.6", HASH_06), (EP07, "0.7", HASH_07), (EP08, "0.8", HASH_08)],
)
def test_matches_the_deployed_entry_point(entry_point, version, expect):
    out = eth_userop_hash(OP, entry_point, 1)
    assert out["user_op_hash"] == expect
    assert out["version"] == version  # read off the canonical address
    assert out["entry_point"] == entry_point  # echoed EIP-55 checksummed
    assert out["chain_id"] == "1"


def test_explicit_version_matches_the_detected_one():
    for entry_point, version in ((EP06, "0.6"), (EP07, "0.7"), (EP08, "0.8")):
        assert eth_userop_hash(OP, entry_point, 1, version=version) == eth_userop_hash(
            OP, entry_point, 1
        )


def test_the_three_versions_disagree_on_the_same_operation():
    # Same op, same chain — the hashing rule alone must change the answer.
    assert len({HASH_06, HASH_07, HASH_08}) == 3


# --- v0.7 packing --------------------------------------------------------------
def test_unpacked_bundler_json_packs_and_matches_the_entry_point():
    out = eth_userop_hash(OP_UNPACKED, EP07, 1)
    assert out["user_op_hash"] == HASH_07_UNPACKED
    assert out["packed"] == {
        # factory ++ factoryData
        "initCode": "0x3333333333333333333333333333333333333333c0ffee",
        # verificationGasLimit (high half) ++ callGasLimit (low half)
        "accountGasLimits": (
            "0x00000000000000000000000000030d40000000000000000000000000000186a0"
        ),
        "preVerificationGas": "21000",
        # maxPriorityFeePerGas (high half) ++ maxFeePerGas (low half)
        "gasFees": (
            "0x0000000000000000000000001dcd65000000000000000000000000003b9aca00"
        ),
        # paymaster ++ verificationGasLimit ++ postOpGasLimit ++ paymasterData
        "paymasterAndData": (
            "0x4444444444444444444444444444444444444444"
            "0000000000000000000000000000c350"
            "00000000000000000000000000007530"
            "beef"
        ),
    }


def test_pre_packed_fields_win_over_the_parts():
    packed_form = {
        "sender": OP_UNPACKED["sender"],
        "nonce": 42,
        "initCode": "0x3333333333333333333333333333333333333333c0ffee",
        "callData": "0xdeadbeef",
        "accountGasLimits": (
            "0x00000000000000000000000000030d40000000000000000000000000000186a0"
        ),
        "preVerificationGas": 21000,
        "gasFees": (
            "0x0000000000000000000000001dcd65000000000000000000000000003b9aca00"
        ),
        "paymasterAndData": (
            "0x44444444444444444444444444444444444444440000000000000000000000000000"
            "c35000000000000000000000000000007530beef"
        ),
    }
    assert eth_userop_hash(packed_form, EP07, 1)["user_op_hash"] == HASH_07_UNPACKED


def test_gas_halves_are_high_then_low():
    # Swapping verificationGasLimit and callGasLimit must change the hash — the
    # order of the two 16-byte halves is the easiest thing to get backwards.
    swapped = {**OP, "callGasLimit": 200000, "verificationGasLimit": 100000}
    assert eth_userop_hash(swapped, EP07, 1)["user_op_hash"] != HASH_07


def test_a_gas_value_too_large_for_its_half_raises():
    with pytest.raises(ValueError, match="`callGasLimit` does not fit in 16 bytes"):
        eth_userop_hash({**OP, "callGasLimit": 2**128}, EP07, 1)


def test_a_packed_word_of_the_wrong_width_raises():
    with pytest.raises(ValueError, match="`gasFees` must be a 32-byte word"):
        eth_userop_hash({**OP, "gasFees": "0xdeadbeef"}, EP07, 1)


# --- v0.8 typed data -----------------------------------------------------------
def test_v08_reports_its_eip712_components():
    out = eth_userop_hash(OP, EP08, 1)
    assert (
        out["domain_separator"].startswith("0x") and len(out["domain_separator"]) == 66
    )
    assert out["struct_hash"].startswith("0x") and len(out["struct_hash"]) == 66
    assert "op_hash" not in out  # v0.8 has no intermediate op hash, it has a struct


def test_v08_agrees_with_the_generic_eip712_engine():
    # Rebuild EntryPoint 0.8's digest through eth_hash's own EIP-712 code, which
    # knows nothing about ERC-4337 — two independent paths to the same number.
    packed = eth_userop_hash(OP, EP08, 1)["packed"]
    typed_data = {
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "version", "type": "string"},
                {"name": "chainId", "type": "uint256"},
                {"name": "verifyingContract", "type": "address"},
            ],
            "PackedUserOperation": [
                {"name": "sender", "type": "address"},
                {"name": "nonce", "type": "uint256"},
                {"name": "initCode", "type": "bytes"},
                {"name": "callData", "type": "bytes"},
                {"name": "accountGasLimits", "type": "bytes32"},
                {"name": "preVerificationGas", "type": "uint256"},
                {"name": "gasFees", "type": "bytes32"},
                {"name": "paymasterAndData", "type": "bytes"},
            ],
        },
        "primaryType": "PackedUserOperation",
        "domain": {
            "name": "ERC4337",
            "version": "1",
            "chainId": 1,
            "verifyingContract": EP08,
        },
        "message": {
            "sender": OP["sender"],
            "nonce": OP["nonce"],
            "initCode": packed["initCode"],
            "callData": OP["callData"],
            "accountGasLimits": packed["accountGasLimits"],
            "preVerificationGas": int(packed["preVerificationGas"]),
            "gasFees": packed["gasFees"],
            "paymasterAndData": packed["paymasterAndData"],
        },
    }
    reference = eth_hash("eip712", typed_data)
    assert reference["hash"] == HASH_08
    out = eth_userop_hash(OP, EP08, 1)
    assert out["domain_separator"] == reference["domain_separator"]
    assert out["struct_hash"] == reference["struct_hash"]


# --- what is and is not part of the hash ---------------------------------------
def test_signature_is_not_hashed():
    for entry_point in (EP06, EP07, EP08):
        signed = eth_userop_hash({**OP, "signature": "0x" + "ab" * 65}, entry_point, 1)
        assert signed == eth_userop_hash(OP, entry_point, 1)


def test_chain_id_and_entry_point_bind_the_hash():
    assert eth_userop_hash(OP, EP07, 8453)["user_op_hash"] != HASH_07
    assert eth_userop_hash(OP, EP07, "0x1")["user_op_hash"] == HASH_07  # hex chain id
    other = eth_userop_hash(OP, "0x" + "99" * 20, 1, version="0.7")
    assert other["user_op_hash"] != HASH_07


def test_every_hashed_field_changes_the_hash():
    for field, value in [
        ("sender", "0x" + "22" * 20),
        ("nonce", 2),
        ("initCode", "0xc0ffee"),
        ("callData", "0xfeed"),
        ("callGasLimit", 100001),
        ("verificationGasLimit", 200001),
        ("preVerificationGas", 21001),
        ("maxFeePerGas", 1000000001),
        ("maxPriorityFeePerGas", 500000001),
        ("paymasterAndData", "0x" + "44" * 20 + "00" * 32 + "beef"),
    ]:
        assert eth_userop_hash({**OP, field: value}, EP06, 1)["user_op_hash"] != (
            HASH_06
        ), field


# --- input shapes --------------------------------------------------------------
def test_snake_case_keys_and_hex_numbers_are_understood():
    snake = {
        "sender": OP["sender"],
        "nonce": "0x1",
        "init_code": "0x",
        "call_data": "0xdeadbeef",
        "call_gas_limit": "100000",
        "verification_gas_limit": "0x30d40",
        "pre_verification_gas": 21000,
        "max_fee_per_gas": "0x3b9aca00",
        "max_priority_fee_per_gas": 500000000,
        "paymaster_and_data": "0x",
    }
    assert eth_userop_hash(snake, EP06, 1)["user_op_hash"] == HASH_06


def test_user_op_as_a_json_string():
    assert eth_userop_hash(json.dumps(OP), EP07, 1)["user_op_hash"] == HASH_07


def test_empty_bytes_fields_may_be_omitted_entirely():
    lean = {k: v for k, v in OP.items() if k not in ("initCode", "paymasterAndData")}
    assert eth_userop_hash(lean, EP06, 1)["user_op_hash"] == HASH_06


# --- version resolution --------------------------------------------------------
def test_an_unknown_entry_point_needs_an_explicit_version():
    with pytest.raises(ValueError, match="is not a canonical EntryPoint") as exc:
        eth_userop_hash(OP, "0x" + "99" * 20, 1)
    assert EP07 in str(exc.value)  # the error names the canonical deployments
    assert eth_userop_hash(OP, "0x" + "99" * 20, 1, version="0.7")["version"] == "0.7"


def test_a_version_contradicting_a_canonical_entry_point_is_flagged():
    out = eth_userop_hash(OP, EP07, 1, version="0.6")
    assert out["version"] == "0.6"
    assert "canonical v0.7 EntryPoint" in out["reason"]
    assert out["user_op_hash"] != HASH_07  # it did what was asked, and says so
    assert "reason" not in eth_userop_hash(OP, EP07, 1)


# --- error paths ---------------------------------------------------------------
def test_missing_required_fields_are_named():
    with pytest.raises(ValueError, match="missing `sender`"):
        eth_userop_hash({k: v for k, v in OP.items() if k != "sender"}, EP06, 1)
    with pytest.raises(ValueError, match="missing `callGasLimit`"):
        eth_userop_hash({k: v for k, v in OP.items() if k != "callGasLimit"}, EP06, 1)
    with pytest.raises(ValueError, match="missing `preVerificationGas`"):
        eth_userop_hash(
            {k: v for k, v in OP.items() if k != "preVerificationGas"}, EP07, 1
        )


def test_negative_values_raise():
    with pytest.raises(ValueError, match="`nonce` must not be negative"):
        eth_userop_hash({**OP, "nonce": -1}, EP06, 1)
    with pytest.raises(ValueError, match="`chain_id` must not be negative"):
        eth_userop_hash(OP, EP06, -1)


def test_a_user_op_that_is_not_an_object_raises():
    with pytest.raises(ValueError, match="must be a user operation object"):
        eth_userop_hash("[1, 2]", EP06, 1)


def test_a_bad_sender_address_raises():
    with pytest.raises(ValueError, match="not a 20-byte hex address"):
        eth_userop_hash({**OP, "sender": "0xdeadbeef"}, EP06, 1)


# --- app registration ----------------------------------------------------------
def test_registered_and_callable_through_app():
    assert "eth_userop_hash" in {t.name for t in asyncio.run(mcp.list_tools())}

    async def go():
        return await mcp.call_tool(
            "eth_userop_hash", {"user_op": OP, "entry_point": EP07, "chain_id": 1}
        )

    result = asyncio.run(go())
    contents = result[0] if isinstance(result, tuple) else result
    payload = json.loads(contents[0].text)
    assert payload["user_op_hash"] == HASH_07


def test_registered_with_expected_schema():
    tool = next(t for t in asyncio.run(mcp.list_tools()) if t.name == "eth_userop_hash")
    assert tool.inputSchema["required"] == ["user_op", "entry_point", "chain_id"]
    assert tool.inputSchema["properties"]["version"]["enum"] == [
        "auto",
        "0.6",
        "0.7",
        "0.8",
    ]
    assert tool.description
