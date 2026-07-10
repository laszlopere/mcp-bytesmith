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

"""TODO 13.4 / plan §2.4.4 — eth_contract_address (CREATE / CREATE2 addresses).

CREATE2 is checked against all seven worked examples in EIP-1014 itself; CREATE
against the canonical keccak(rlp([sender, nonce])) sequence for one deployer."""

import asyncio
import json

import pytest

pytest.importorskip("Crypto", reason="ethereum extra (pycryptodome) not installed")

from mcp_bytesmith.eth import eth_contract_address  # noqa: E402
from mcp_bytesmith.server import mcp  # noqa: E402

ZERO_ADDR = "0x0000000000000000000000000000000000000000"
ZERO_SALT = "0x" + "00" * 32
FEED_SALT = "0x000000000000000000000000feed000000000000000000000000000000000000"
CAFE_SALT = "0x00000000000000000000000000000000000000000000000000000000cafebabe"

# The seven (deployer, salt, init_code, address) examples from EIP-1014.
EIP1014_EXAMPLES = [
    (ZERO_ADDR, ZERO_SALT, "0x00", "0x4D1A2e2bB4F88F0250f26Ffff098B0b30B26BF38"),
    (
        "0xdeadbeef00000000000000000000000000000000",
        ZERO_SALT,
        "0x00",
        "0xB928f69Bb1D91Cd65274e3c79d8986362984fDA3",
    ),
    (
        "0xdeadbeef00000000000000000000000000000000",
        FEED_SALT,
        "0x00",
        "0xD04116cDd17beBE565EB2422F2497E06cC1C9833",
    ),
    (ZERO_ADDR, ZERO_SALT, "0xdeadbeef", "0x70f2b2914A2a4b783FaEFb75f459A580616Fcb5e"),
    (
        "0x00000000000000000000000000000000deadbeef",
        CAFE_SALT,
        "0xdeadbeef",
        "0x60f3f640a8508fC6a86d45DF051962668E1e8AC7",
    ),
    (
        "0x00000000000000000000000000000000deadbeef",
        CAFE_SALT,
        "0x" + "deadbeef" * 11,
        "0x1d8bfDC5D46DC4f61D6b6115972536eBE6A8854C",
    ),
    (ZERO_ADDR, ZERO_SALT, "0x", "0xE33C0C7F7df4809055C3ebA6c09CFe4BaF1BD9e0"),
]

# keccak(rlp([deployer, nonce]))[12:] for nonce 0..3 — the addresses an account
# with this key deploys to, in order.
CREATE_DEPLOYER = "0x6ac7ea33f8831ea9dcc53393aaa88b25a785dbf0"
CREATE_ADDRESSES = [
    "0xcd234A471b72ba2F1Ccf0A70FCABA648a5eeCD8d",
    "0x343c43A37D37dfF08AE8C4A11544c718AbB4fCF8",
    "0xf778B86FA74E846c4f0a1fBd1335FE81c00a0C91",
    "0xffFd933A0bC612844eaF0C6Fe3E5b8E9B6C1d19c",
]


# --- CREATE2: the EIP-1014 examples ---------------------------------------------
@pytest.mark.parametrize("deployer,salt,init_code,address", EIP1014_EXAMPLES)
def test_eip1014_examples(deployer, salt, init_code, address):
    out = eth_contract_address("create2", deployer, salt=salt, init_code=init_code)
    assert out == {"address": address}  # EIP-55 checksummed, and nothing else


def test_create2_salt_changes_the_address():
    a = eth_contract_address("create2", ZERO_ADDR, salt=ZERO_SALT, init_code="0x00")
    b = eth_contract_address("create2", ZERO_ADDR, salt=CAFE_SALT, init_code="0x00")
    assert a != b


def test_create2_hashes_init_code_not_runtime_code():
    # Distinct init_code of the same length must give distinct addresses.
    a = eth_contract_address("create2", ZERO_ADDR, salt=ZERO_SALT, init_code="0xdead")
    b = eth_contract_address("create2", ZERO_ADDR, salt=ZERO_SALT, init_code="0xbeef")
    assert a != b


# --- CREATE: keccak(rlp([deployer, nonce])) -------------------------------------
@pytest.mark.parametrize("nonce,address", list(enumerate(CREATE_ADDRESSES)))
def test_create_nonce_sequence(nonce, address):
    assert eth_contract_address("create", CREATE_DEPLOYER, nonce=nonce) == {
        "address": address
    }


def test_create_nonce_accepts_decimal_and_hex_strings():
    expected = eth_contract_address("create", CREATE_DEPLOYER, nonce=128)
    assert eth_contract_address("create", CREATE_DEPLOYER, nonce="128") == expected
    assert eth_contract_address("create", CREATE_DEPLOYER, nonce="0x80") == expected


def test_create_nonce_zero_rlp_encodes_as_empty_string():
    # RLP encodes 0 as 0x80 (empty byte string), not as 0x00 — a classic footgun.
    from mcp_bytesmith.eth import _keccak256, _rlp_encode

    body = CREATE_DEPLOYER[2:]
    assert _rlp_encode([body, 0]).endswith(b"\x80")
    expected = "0x" + _keccak256(_rlp_encode([body, 0]))[-20:].hex()
    assert (
        eth_contract_address("create", CREATE_DEPLOYER, nonce=0)["address"].lower()
        == expected
    )


# --- deployer parsing -----------------------------------------------------------
def test_deployer_0x_prefix_optional_and_case_insensitive():
    expected = eth_contract_address("create", CREATE_DEPLOYER, nonce=0)
    assert eth_contract_address("create", CREATE_DEPLOYER[2:], nonce=0) == expected
    assert eth_contract_address("create", CREATE_DEPLOYER.upper()[2:], nonce=0) == (
        expected
    )


def test_checksummed_deployer_accepted():
    # A deployer that is itself EIP-55 cased must derive the same address.
    assert eth_contract_address("create", CREATE_ADDRESSES[0], nonce=0) == (
        eth_contract_address("create", CREATE_ADDRESSES[0].lower(), nonce=0)
    )


# --- unused arguments are ignored, not misread ----------------------------------
def test_create_ignores_salt_and_init_code():
    assert eth_contract_address(
        "create", CREATE_DEPLOYER, nonce=0, salt=CAFE_SALT, init_code="0xdeadbeef"
    ) == {"address": CREATE_ADDRESSES[0]}


def test_create2_ignores_nonce():
    with_nonce = eth_contract_address(
        "create2", ZERO_ADDR, nonce=7, salt=ZERO_SALT, init_code="0x00"
    )
    assert with_nonce == {"address": EIP1014_EXAMPLES[0][3]}


# --- error paths ----------------------------------------------------------------
def test_create_without_nonce_rejected():
    with pytest.raises(ValueError, match="requires `nonce`"):
        eth_contract_address("create", CREATE_DEPLOYER)


@pytest.mark.parametrize("kwargs", [{"salt": ZERO_SALT}, {"init_code": "0x00"}, {}])
def test_create2_without_salt_or_init_code_rejected(kwargs):
    with pytest.raises(ValueError, match="requires `salt` and `init_code`"):
        eth_contract_address("create2", ZERO_ADDR, **kwargs)


@pytest.mark.parametrize("bad_salt", ["0x", "0x00", "0x" + "00" * 31, "0x" + "00" * 33])
def test_salt_must_be_32_bytes(bad_salt):
    with pytest.raises(ValueError, match="salt must be 32 bytes"):
        eth_contract_address("create2", ZERO_ADDR, salt=bad_salt, init_code="0x00")


@pytest.mark.parametrize("bad", ["0x1234", "not-an-address", "0x" + "00" * 21, ""])
def test_bad_deployer_rejected(bad):
    with pytest.raises(ValueError, match="20-byte hex address"):
        eth_contract_address("create", bad, nonce=0)


@pytest.mark.parametrize("bad_nonce", [-1, 2**64, "0x" + "ff" * 9])
def test_nonce_out_of_range_rejected(bad_nonce):
    with pytest.raises(ValueError, match="nonce out of range"):
        eth_contract_address("create", CREATE_DEPLOYER, nonce=bad_nonce)


def test_max_nonce_accepted():
    out = eth_contract_address("create", CREATE_DEPLOYER, nonce=2**64 - 1)
    assert out["address"].startswith("0x")


def test_unknown_scheme_rejected():
    with pytest.raises(ValueError, match="unknown scheme"):
        eth_contract_address("create3", CREATE_DEPLOYER, nonce=0)


# --- app registration -----------------------------------------------------------
def test_registered():
    names = {t.name for t in asyncio.run(mcp.list_tools())}
    assert "eth_contract_address" in names


def test_callable_through_app():
    async def go():
        return await mcp.call_tool(
            "eth_contract_address",
            {"scheme": "create", "deployer": CREATE_DEPLOYER, "nonce": 0},
        )

    result = asyncio.run(go())
    contents = result[0] if isinstance(result, tuple) else result
    payload = json.loads(contents[0].text)
    assert payload["address"] == CREATE_ADDRESSES[0]
