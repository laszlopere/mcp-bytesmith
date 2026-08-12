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

"""TODO 20.2 — eth_log_decode (receipt log -> named event args).

The vector is the canonical ERC-20 Transfer log: topic0 0xddf252ad… (a
widely-known constant) over two address topics and a 1e18 data word. Its ERC-721
twin shares that exact topic0 while indexing tokenId instead, which is why the
topic COUNT — not topic0 — is the load-bearing identity check."""

import asyncio
import json

import pytest

pytest.importorskip("Crypto", reason="ethereum extra (pycryptodome) not installed")

from mcp_bytesmith.eth import (  # noqa: E402
    abi_codec,
    eth_hash,
    eth_log_decode,
    eth_selector,
)
from mcp_bytesmith.server import mcp  # noqa: E402

W = "0" * 64  # an all-zero 32-byte word in hex
VITALIK = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"  # EIP-55 checksummed
DEPOSIT = "0x00000000219ab540356cBB839Cbe05303d7705Fa"  # beacon deposit contract
TRANSFER_TOPIC0 = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
APPROVAL_TOPIC0 = "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925"
ERC20_SIG = "Transfer(address indexed from, address indexed to, uint256 value)"
ERC721_SIG = "Transfer(address indexed from, address indexed to, uint256 indexed id)"
AMOUNT_WORD = "0x" + format(10**18, "064x")


def _word(value):
    """Left-pad an address or int into a 32-byte topic word."""
    if isinstance(value, str):
        return "0x" + value.lower().removeprefix("0x").rjust(64, "0")
    return "0x" + format(value & (2**256 - 1), "064x")


ERC20_TOPICS = [TRANSFER_TOPIC0, _word(VITALIK), _word(DEPOSIT)]


def _dec(signature, topics, data=None, anonymous=False):
    return eth_log_decode(signature, topics, data=data, anonymous=anonymous)


def _one(type_str, topic, indexed=True):
    """Decode a single-argument event and return its one args entry."""
    mod = " indexed" if indexed else ""
    sig = f"E({type_str}{mod} x)"
    topics = [eth_selector(sig, "event")["topic0"]] + ([topic] if indexed else [])
    return _dec(sig, topics, data=None if indexed else topic)["args"][0]


# --- ERC-20 Transfer: the canonical vector -------------------------------------
def test_erc20_transfer_full_result():
    assert _dec(ERC20_SIG, ERC20_TOPICS, AMOUNT_WORD) == {
        "signature": "Transfer(address,address,uint256)",
        "anonymous": False,
        "topic0": TRANSFER_TOPIC0,
        "topic0_matches": True,
        "args": [
            {"name": "from", "type": "address", "value": VITALIK, "indexed": True},
            {"name": "to", "type": "address", "value": DEPOSIT, "indexed": True},
            {
                "name": "value",
                "type": "uint256",
                "value": "1000000000000000000",
                "indexed": False,
            },
        ],
    }


def test_topic0_matches_eth_selector():
    out = _dec(ERC20_SIG, ERC20_TOPICS, AMOUNT_WORD)
    assert out["topic0"] == eth_selector(ERC20_SIG, "event")["topic0"]
    assert out["topic0"] == TRANSFER_TOPIC0


def test_unnamed_indexed_params_have_null_names():
    sig = "Transfer(address indexed, address indexed, uint256)"
    out = _dec(sig, ERC20_TOPICS, AMOUNT_WORD)
    assert [a["name"] for a in out["args"]] == [None, None, None]
    assert [a["indexed"] for a in out["args"]] == [True, True, False]


def test_match_has_no_reason():
    out = _dec(ERC20_SIG, ERC20_TOPICS, AMOUNT_WORD)
    assert "reason" not in out
    assert "log_topic0" not in out


# --- ERC-721 Transfer: same topic0, different arity ----------------------------
def test_erc721_transfer_three_indexed_no_data():
    out = _dec(ERC721_SIG, ERC20_TOPICS + [_word(42)])
    assert [a["name"] for a in out["args"]] == ["from", "to", "id"]
    assert [a["indexed"] for a in out["args"]] == [True, True, True]
    assert out["args"][2]["value"] == "42"


def test_erc721_shares_topic0_with_erc20_so_arity_is_the_real_check():
    assert (
        eth_selector(ERC721_SIG, "event")["topic0"]
        == eth_selector(ERC20_SIG, "event")["topic0"]
        == TRANSFER_TOPIC0
    )
    # topic0 matches, so only the topic count catches the wrong signature.
    with pytest.raises(ValueError, match="implies 4 topic"):
        _dec(ERC721_SIG, ERC20_TOPICS, AMOUNT_WORD)


def test_explicit_0x_data_equals_omitted():
    assert _dec(ERC721_SIG, ERC20_TOPICS + [_word(1)], "0x") == _dec(
        ERC721_SIG, ERC20_TOPICS + [_word(1)]
    )


# --- indexed / non-indexed placement -------------------------------------------
def test_args_are_in_declaration_order():
    sig = "Mix(uint256 a, address indexed b, bool c)"
    topics = [eth_selector(sig, "event")["topic0"], _word(VITALIK)]
    data = "0x" + format(7, "064x") + format(1, "064x")
    out = _dec(sig, topics, data)
    assert [a["name"] for a in out["args"]] == ["a", "b", "c"]
    assert [a["indexed"] for a in out["args"]] == [False, True, False]
    assert [a["value"] for a in out["args"]] == ["7", VITALIK, True]


def test_zero_indexed_args_uses_only_topic0():
    sig = "Ping(uint256 n)"
    out = _dec(sig, [eth_selector(sig, "event")["topic0"]], _word(5))
    assert out["args"] == [
        {"name": "n", "type": "uint256", "value": "5", "indexed": False}
    ]


def test_all_indexed_empty_data():
    sig = "Pair(address indexed a, address indexed b)"
    topics = [eth_selector(sig, "event")["topic0"], _word(VITALIK), _word(DEPOSIT)]
    out = _dec(sig, topics)
    assert [a["value"] for a in out["args"]] == [VITALIK, DEPOSIT]


def test_tuple_component_names_are_reported():
    sig = "Filled((address token, uint256 amt) order)"
    data = "0x" + _word(VITALIK)[2:] + format(9, "064x")
    out = _dec(sig, [eth_selector(sig, "event")["topic0"]], data)
    arg = out["args"][0]
    assert arg["type"] == "(address,uint256)"
    assert arg["value"] == [VITALIK, "9"]
    assert [c["name"] for c in arg["components"]] == ["token", "amt"]


# --- the hash rule: only value types survive in a topic ------------------------
HASHED_TYPES = [
    "bytes",
    "string",
    "uint256[]",
    "uint256[3]",  # static, yet hashed — _abi_is_dynamic would say False
    "bytes32[2]",
    "address[]",
    "(uint256,bool)",  # static struct, yet hashed
    "(uint256,string)",
    "(uint256,bool)[2]",
]

VERBATIM_TYPES = ["uint256", "uint8", "int256", "bool", "address", "bytes32", "bytes1"]


@pytest.mark.parametrize("type_str", HASHED_TYPES)
def test_hashed_indexed_types_report_hash_only(type_str):
    arg = _one(type_str, "0x" + "ab" * 32)
    assert arg["value"] is None
    assert arg["hashed"] is True
    assert arg["hash"] == "0x" + "ab" * 32
    assert arg["indexed"] is True


@pytest.mark.parametrize("type_str", VERBATIM_TYPES)
def test_verbatim_indexed_types_decode_their_topic(type_str):
    arg = _one(type_str, W[:-1] + "1")
    assert "hashed" not in arg
    assert "hash" not in arg
    assert arg["value"] is not None


@pytest.mark.parametrize("type_str", ["uint", "int", "byte"])
def test_aliased_indexed_types_are_value_types(type_str):
    arg = _one(type_str, W[:-1] + "1")
    assert "hashed" not in arg
    assert arg["type"] in ("uint256", "int256", "bytes1")


def test_indexed_string_is_hash_only_with_keccak_parity():
    keccak_hello = eth_hash("keccak256", "hello")["hash"]
    arg = _one("string", keccak_hello)
    assert arg["value"] is None
    assert arg["hashed"] is True
    assert arg["hash"] == keccak_hello  # matchable against keccak(candidate)


def test_indexed_bytes32_vs_bytes():
    word = "0x" + "11" * 32
    fixed, dynamic = _one("bytes32", word), _one("bytes", word)
    assert fixed["value"] == word and "hashed" not in fixed
    assert dynamic["value"] is None and dynamic["hashed"] is True


def test_hashed_tuple_still_names_components():
    arg = _one("(uint256 a, bool b)", "0x" + "cd" * 32)
    assert arg["value"] is None and arg["hashed"] is True
    assert [c["name"] for c in arg["components"]] == ["a", "b"]


# --- values --------------------------------------------------------------------
def test_negative_int256_in_topic():
    assert _one("int256", "0x" + "ff" * 32)["value"] == "-1"
    assert _one("int256", _word(-42))["value"] == "-42"


def test_bool_topic():
    assert _one("bool", W[:-1] + "1")["value"] is True
    assert _one("bool", "0x" + W)["value"] is False


def test_indexed_address_is_checksummed():
    assert _one("address", _word(VITALIK.lower()))["value"] == VITALIK


def test_data_values_match_abi_codec():
    out = _dec(ERC20_SIG, ERC20_TOPICS, AMOUNT_WORD)
    expected = abi_codec("decode", ["uint256"], data=AMOUNT_WORD)["values"]
    assert [out["args"][2]["value"]] == expected


def test_tolerates_trailing_bytes_in_data():
    out = _dec(ERC20_SIG, ERC20_TOPICS, AMOUNT_WORD + "dead")
    assert out["args"][2]["value"] == "1000000000000000000"


def test_topics_without_0x_prefix_and_uppercase():
    out = _dec(ERC20_SIG, [t[2:].upper() for t in ERC20_TOPICS], AMOUNT_WORD)
    assert out["topic0_matches"] is True
    assert out["args"][0]["value"] == VITALIK


def test_accepts_stringified_json_topics():
    out = _dec(ERC20_SIG, json.dumps(ERC20_TOPICS), AMOUNT_WORD)
    assert out["topic0_matches"] is True


# --- anonymous events ----------------------------------------------------------
def test_anonymous_has_no_topic0_keys():
    sig = "Secret(address indexed who, uint256 n)"
    out = _dec(sig, [_word(VITALIK)], _word(3), anonymous=True)
    assert out["anonymous"] is True
    assert "topic0" not in out and "topic0_matches" not in out
    assert [a["value"] for a in out["args"]] == [VITALIK, "3"]


def test_anonymous_four_indexed():
    sig = "Quad(uint256 indexed a, uint256 indexed b, uint256 indexed c, "
    sig += "uint256 indexed d)"
    out = _dec(sig, [_word(i) for i in range(4)], anonymous=True)
    assert [a["value"] for a in out["args"]] == ["0", "1", "2", "3"]


def test_anonymous_zero_indexed_empty_topics():
    out = _dec("Quiet(uint256 n)", [], _word(8), anonymous=True)
    assert out["args"][0]["value"] == "8"


def test_anonymous_flag_omitted_raises_arity_mentioning_anonymous():
    sig = "Secret(address indexed who, uint256 n)"
    with pytest.raises(ValueError, match="anonymous=true"):
        _dec(sig, [_word(VITALIK)], _word(3))


def test_anonymous_undecodable_data_raises_raw_abi_error():
    # matched is None, so the mismatch wrapper must not fire.
    sig = "Bad(uint256[] xs)"
    with pytest.raises(ValueError, match="exceeds available data"):
        _dec(sig, [], "0x" + W[:-2] + "20" + "f" * 64, anonymous=True)


# --- topic0 mismatch is soft ---------------------------------------------------
def test_topic0_mismatch_is_soft():
    sig = "Approval(address indexed owner, address indexed spender, uint256 value)"
    out = _dec(sig, ERC20_TOPICS, AMOUNT_WORD)  # same arity, so arity passes
    assert out["topic0"] == APPROVAL_TOPIC0
    assert out["topic0_matches"] is False
    assert out["log_topic0"] == TRANSFER_TOPIC0
    assert "unreliable" in out["reason"]
    assert out["args"][2]["value"] == "1000000000000000000"  # still decoded


def test_mismatch_and_undecodable_raises():
    sig = "Bogus(address indexed a, address indexed b, uint256[] xs)"
    bad = "0x" + W[:-2] + "20" + "f" * 64
    with pytest.raises(ValueError, match="is not"):
        _dec(sig, ERC20_TOPICS, bad)


# --- errors --------------------------------------------------------------------
def test_too_few_topics_raises():
    with pytest.raises(ValueError, match="implies 3 topic"):
        _dec(ERC20_SIG, ERC20_TOPICS[:2], AMOUNT_WORD)


def test_too_many_topics_raises_without_the_anonymous_hint():
    # Too MANY topics is never a forgotten `anonymous`, so the hint stays out.
    with pytest.raises(ValueError, match="implies 3 topic") as exc:
        _dec(ERC20_SIG, ERC20_TOPICS + [_word(1)], AMOUNT_WORD)
    assert "anonymous=true" not in str(exc.value)


def test_four_indexed_non_anonymous_raises():
    sig = "Quad(uint256 indexed a, uint256 indexed b, uint256 indexed c, "
    sig += "uint256 indexed d)"
    with pytest.raises(ValueError, match="at most 3"):
        _dec(sig, [_word(i) for i in range(5)])


def test_five_indexed_anonymous_raises():
    sig = "Five(uint256 indexed a, uint256 indexed b, uint256 indexed c, "
    sig += "uint256 indexed d, uint256 indexed e)"
    with pytest.raises(ValueError, match="at most 4"):
        _dec(sig, [_word(i) for i in range(5)], anonymous=True)


def test_short_topic_raises_naming_the_index():
    with pytest.raises(ValueError, match=r"topics\[1\] must be 32 bytes, got 31"):
        _dec(
            ERC20_SIG, [TRANSFER_TOPIC0, "0x" + "11" * 31, _word(DEPOSIT)], AMOUNT_WORD
        )


def test_invalid_hex_topic_raises():
    with pytest.raises(ValueError):
        _dec(ERC20_SIG, [TRANSFER_TOPIC0, "0xzz", _word(DEPOSIT)], AMOUNT_WORD)


def test_non_string_topic_raises():
    with pytest.raises(ValueError, match=r"topics\[0\] must be a hex string"):
        _dec(ERC20_SIG, [1, _word(VITALIK), _word(DEPOSIT)], AMOUNT_WORD)


def test_topics_not_a_list_raises():
    with pytest.raises(ValueError, match="must be a list of 32-byte hex words"):
        _dec(ERC20_SIG, TRANSFER_TOPIC0, AMOUNT_WORD)


def test_data_too_short_raises():
    with pytest.raises(ValueError, match="log data is too short"):
        _dec(ERC20_SIG, ERC20_TOPICS, "0x" + "00" * 31)


def test_data_omitted_with_non_indexed_args_raises():
    with pytest.raises(ValueError, match="log data is too short"):
        _dec(ERC20_SIG, ERC20_TOPICS)


def test_invalid_signature_name_raises():
    with pytest.raises(ValueError, match="invalid signature name"):
        _dec("1bad(uint256)", [W])


def test_no_parameter_list_raises():
    with pytest.raises(ValueError, match="no parameter list"):
        _dec("Transfer", [W])


# --- app registration ----------------------------------------------------------
def test_registered_and_callable_through_app():
    names = {t.name for t in asyncio.run(mcp.list_tools())}
    assert "eth_log_decode" in names

    async def go():
        return await mcp.call_tool(
            "eth_log_decode",
            {"signature": ERC20_SIG, "topics": ERC20_TOPICS, "data": AMOUNT_WORD},
        )

    result = asyncio.run(go())
    contents = result[0] if isinstance(result, tuple) else result
    payload = json.loads(contents[0].text)
    assert payload["args"][0]["name"] == "from"
    assert payload["args"][0]["value"] == VITALIK
    assert payload["topic0_matches"] is True


def test_registered_with_expected_schema():
    tool = next(t for t in asyncio.run(mcp.list_tools()) if t.name == "eth_log_decode")
    schema = tool.inputSchema
    assert schema["properties"]["topics"]["type"] == "array"
    assert set(schema["required"]) == {"signature", "topics"}
    assert schema["properties"]["anonymous"]["default"] is False
    assert tool.description
