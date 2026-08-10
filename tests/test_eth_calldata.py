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

"""TODO 20.1 — eth_calldata (calldata <-> named arguments).

The vector is the canonical ERC-20 transfer call: selector 0xa9059cbb (a
widely-known constant) over a 20-byte address word and 1e18. Beyond it the
suite locks the new path to the existing implementations — the selector must
equal eth_selector's, and the argument encoding must equal abi_codec's."""

import asyncio
import json

import pytest

pytest.importorskip("Crypto", reason="ethereum extra (pycryptodome) not installed")

from mcp_bytesmith.eth import abi_codec, eth_calldata, eth_selector  # noqa: E402
from mcp_bytesmith.server import mcp  # noqa: E402

W = "0" * 64  # an all-zero 32-byte word in hex
VITALIK = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"  # EIP-55 checksummed
TRANSFER_SIG = "transfer(address to, uint256 amount)"
TRANSFER_CALLDATA = (
    "0xa9059cbb"
    "000000000000000000000000d8da6bf26964af9d7eed9e03e53415d37aa96045"
    "0000000000000000000000000000000000000000000000000de0b6b3a7640000"
)


def _dec(signature, data):
    return eth_calldata("decode", signature, data=data)


def _enc(signature, values=None):
    return eth_calldata("encode", signature, values=values)


# --- decode: names -------------------------------------------------------------
def test_decode_erc20_transfer_names_args():
    assert _dec(TRANSFER_SIG, TRANSFER_CALLDATA) == {
        "action": "decode",
        "signature": "transfer(address,uint256)",
        "selector": "0xa9059cbb",
        "selector_matches": True,
        "args": [
            {"name": "to", "type": "address", "value": VITALIK},
            {"name": "amount", "type": "uint256", "value": "1000000000000000000"},
        ],
    }


def test_decode_unnamed_params_have_null_names():
    out = _dec("transfer(address,uint256)", TRANSFER_CALLDATA)
    assert [a["name"] for a in out["args"]] == [None, None]
    assert out["args"][0]["value"] == VITALIK
    assert out["selector_matches"] is True


def test_decode_strips_data_location_from_name():
    data = _enc("batch(uint256[] calldata ids, bytes memory blob)", [[1, 2], "0xbeef"])
    out = _dec("batch(uint256[] calldata ids, bytes memory blob)", data["calldata"])
    assert [(a["name"], a["type"]) for a in out["args"]] == [
        ("ids", "uint256[]"),
        ("blob", "bytes"),
    ]
    assert [a["value"] for a in out["args"]] == [["1", "2"], "0xbeef"]


def test_decode_payable_and_unnamed_location():
    sig = "pay(address payable to, bytes calldata)"
    out = _dec(sig, _enc(sig, [VITALIK, "0x00"])["calldata"])
    assert [a["name"] for a in out["args"]] == ["to", None]


def test_decode_tuple_components_are_named():
    sig = "swap((address token, uint256 amt) order)"
    out = _dec(sig, _enc(sig, [[VITALIK, 7]])["calldata"])
    arg = out["args"][0]
    assert arg["name"] == "order"
    assert arg["type"] == "(address,uint256)"
    assert arg["value"] == [VITALIK, "7"]
    assert arg["components"] == [
        {"name": "token", "type": "address"},
        {"name": "amt", "type": "uint256"},
    ]


def test_decode_tuple_array():
    sig = "fill((address,uint256)[] orders)"
    out = _dec(sig, _enc(sig, [[[VITALIK, 1], [VITALIK, 2]]])["calldata"])
    arg = out["args"][0]
    assert arg["name"] == "orders"
    assert arg["type"] == "(address,uint256)[]"
    assert arg["value"] == [[VITALIK, "1"], [VITALIK, "2"]]
    assert [c["name"] for c in arg["components"]] == [None, None]


def test_decode_zero_arg_function():
    out = _dec("pause()", _enc("pause()")["calldata"])
    assert out["args"] == []
    assert out["selector_matches"] is True


def test_decode_ignores_returns_clause():
    out = _dec(
        "transfer(address to, uint256 amount) external returns (bool)",
        TRANSFER_CALLDATA,
    )
    assert out["selector_matches"] is True
    assert out["signature"] == "transfer(address,uint256)"


def test_decode_normalizes_uint_alias():
    out = _dec("transfer(address to, uint amount)", TRANSFER_CALLDATA)
    assert out["selector_matches"] is True
    assert out["args"][1]["type"] == "uint256"


# --- decode: values ------------------------------------------------------------
def test_decode_negative_int():
    sig = "adjust(int256 delta)"
    out = _dec(sig, _enc(sig, [-42])["calldata"])
    assert out["args"][0]["value"] == "-42"


def test_decode_checksums_lowercase_address():
    sig = "sweep(address to)"
    out = _dec(sig, _enc(sig, [VITALIK.lower()])["calldata"])
    assert out["args"][0]["value"] == VITALIK


def test_decode_tolerates_trailing_bytes():
    out = _dec(TRANSFER_SIG, TRANSFER_CALLDATA + "dead")
    assert out["args"][1]["value"] == "1000000000000000000"


def test_decode_accepts_bare_and_uppercase_hex():
    out = _dec(TRANSFER_SIG, TRANSFER_CALLDATA[2:].upper())
    assert out["selector_matches"] is True
    assert out["args"][0]["value"] == VITALIK


# --- decode: selector mismatch is soft -----------------------------------------
def test_decode_selector_mismatch_is_soft():
    out = _dec("approve(address spender, uint256 amount)", TRANSFER_CALLDATA)
    assert out["selector_matches"] is False
    assert out["data_selector"] == "0xa9059cbb"
    assert "unreliable" in out["reason"]
    assert out["args"][0]["value"] == VITALIK  # still decoded


def test_decode_selector_match_has_no_reason():
    out = _dec(TRANSFER_SIG, TRANSFER_CALLDATA)
    assert "reason" not in out
    assert "data_selector" not in out


def test_decode_mismatch_and_undecodable_raises():
    # Wrong selector, and an array whose length word is absurd: the head points
    # at word 1, which then claims 2**256-1 elements.
    bad = "0xdeadbeef" + W[:-2] + "20" + "f" * 64
    with pytest.raises(ValueError, match="is not"):
        _dec("burn(uint256[] ids)", bad)


# --- decode: errors ------------------------------------------------------------
def test_decode_too_short_for_selector_raises():
    with pytest.raises(ValueError, match="shorter than a 4-byte selector"):
        _dec(TRANSFER_SIG, "0x")


def test_decode_too_short_for_args_raises():
    with pytest.raises(ValueError, match="too short"):
        _dec(TRANSFER_SIG, "0xa9059cbb" + "00" * 31)


def test_decode_without_data_raises():
    with pytest.raises(ValueError, match="requires `data`"):
        eth_calldata("decode", TRANSFER_SIG)


def test_decode_invalid_hex_raises():
    with pytest.raises(ValueError):
        _dec(TRANSFER_SIG, "0xzz")


# --- encode --------------------------------------------------------------------
def test_encode_erc20_transfer():
    out = _enc(TRANSFER_SIG, [VITALIK, 10**18])
    assert out["calldata"] == TRANSFER_CALLDATA
    assert out["selector"] == "0xa9059cbb"
    assert out["signature"] == "transfer(address,uint256)"


def test_encode_echoes_named_args():
    out = _enc(TRANSFER_SIG, [VITALIK, 1])
    assert out["args"] == [
        {"name": "to", "type": "address", "value": VITALIK},
        {"name": "amount", "type": "uint256", "value": 1},
    ]


def test_encode_zero_arg_function_without_values():
    out = _enc("pause()")
    assert len(out["calldata"]) == 10  # "0x" + 4 selector bytes
    assert out["args"] == []


def test_encode_arity_mismatch_raises():
    with pytest.raises(ValueError, match=r"transfer\(address,uint256\) takes 2"):
        _enc(TRANSFER_SIG, [VITALIK])


def test_encode_accepts_stringified_json_values():
    out = eth_calldata("encode", TRANSFER_SIG, values=f'["{VITALIK}", 1000]')
    assert out["calldata"] == _enc(TRANSFER_SIG, [VITALIK, 1000])["calldata"]


def test_encode_tuple_and_dynamic_array():
    sig = "submit((uint8 kind, bytes payload) job, string[] tags)"
    out = _enc(sig, [[3, "0xabcd"], ["a", "b"]])
    assert out["signature"] == "submit((uint8,bytes),string[])"
    assert out["args"][0]["components"][1]["name"] == "payload"


# --- round-trip and parity locks -----------------------------------------------
@pytest.mark.parametrize(
    "types,values",
    [
        (["uint256"], [10**30]),
        (["int256"], [-1]),
        (["bool"], [True]),
        (["address"], [VITALIK]),
        (["bytes"], ["0xdeadbeef"]),
        (["string"], ["hello"]),
        (["bytes32"], ["0x" + "11" * 32]),
        (["uint256[]"], [[1, 2, 3]]),
        (["uint8[2]"], [[7, 8]]),
        (["(uint256,bool)"], [[5, True]]),
        (["(address,uint256)[2]"], [[[VITALIK, 1], [VITALIK, 2]]]),
        (["uint256", "bytes", "address"], [1, "0xbe", VITALIK]),
    ],
)
def test_round_trip_encode_then_decode(types, values):
    sig = f"f({','.join(types)})"
    out = _dec(sig, _enc(sig, values)["calldata"])
    assert out["selector_matches"] is True
    assert len(out["args"]) == len(types)
    assert [a["type"] for a in out["args"]] == types


@pytest.mark.parametrize(
    "signature,values",
    [
        (TRANSFER_SIG, [VITALIK, 0]),
        ("transfer(address,uint256)", [VITALIK, 0]),
        ("pause()", None),
        (
            "swap((address token, uint256 amt) order, uint256[] path)",
            [[VITALIK, 0], []],
        ),
        ("batch(uint256[] calldata ids, bytes memory blob)", [[], "0x"]),
    ],
)
def test_selector_matches_eth_selector(signature, values):
    assert _enc(signature, values)["selector"] == eth_selector(signature)["selector"]


def test_body_matches_abi_codec():
    values = [VITALIK, 10**18]
    calldata = _enc(TRANSFER_SIG, values)["calldata"]
    body = abi_codec("encode", ["address", "uint256"], values=values)["encoded"]
    assert calldata[10:] == body[2:]


# --- signature errors ----------------------------------------------------------
def test_unknown_action_raises():
    with pytest.raises(ValueError, match="unknown action"):
        eth_calldata("frobnicate", TRANSFER_SIG, data=TRANSFER_CALLDATA)


def test_invalid_signature_name_raises():
    with pytest.raises(ValueError, match="invalid signature name"):
        _enc("1bad(uint256)", [1])


def test_unbalanced_parens_raises():
    with pytest.raises(ValueError, match="unbalanced parentheses"):
        _enc("f(uint256", [1])


def test_no_parameter_list_raises():
    with pytest.raises(ValueError, match="no parameter list"):
        _enc("transfer", [1])


# --- app registration ----------------------------------------------------------
def test_registered_and_callable_through_app():
    names = {t.name for t in asyncio.run(mcp.list_tools())}
    assert "eth_calldata" in names

    async def go():
        return await mcp.call_tool(
            "eth_calldata",
            {
                "action": "decode",
                "signature": TRANSFER_SIG,
                "data": TRANSFER_CALLDATA,
            },
        )

    result = asyncio.run(go())
    contents = result[0] if isinstance(result, tuple) else result
    payload = json.loads(contents[0].text)
    assert payload["args"][0]["name"] == "to"
    assert payload["args"][0]["value"] == VITALIK


def test_registered_with_enum_schema():
    tool = next(t for t in asyncio.run(mcp.list_tools()) if t.name == "eth_calldata")
    assert tool.inputSchema["properties"]["action"]["enum"] == ["encode", "decode"]
    assert tool.description
