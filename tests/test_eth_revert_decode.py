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

"""TODO 20.3 — eth_revert_decode (revert data -> reason).

The two built-in selectors are widely-known constants — Error(string) is
0x08c379a0 and Panic(uint256) is 0x4e487b71 — and are asserted literally here
while the module derives them by keccak, so the two must agree. The panic codes
are Solidity's documented set; the Error vector carries OpenZeppelin's canonical
ERC-20 balance message."""

import asyncio
import json

import pytest

pytest.importorskip("Crypto", reason="ethereum extra (pycryptodome) not installed")

from mcp_bytesmith.eth import (  # noqa: E402
    abi_codec,
    eth_revert_decode,
    eth_selector,
)
from mcp_bytesmith.server import mcp  # noqa: E402

ERROR_SELECTOR = "0x08c379a0"
PANIC_SELECTOR = "0x4e487b71"
ERC20_MESSAGE = "ERC20: transfer amount exceeds balance"
CUSTOM_SIG = "InsufficientBalance(uint256 available, uint256 required)"
CUSTOM_SELECTOR = "0xcf479181"


def _error(message):
    return (
        ERROR_SELECTOR
        + abi_codec("encode", ["string"], values=[message])["encoded"][2:]
    )


def _panic(code):
    return (
        PANIC_SELECTOR + abi_codec("encode", ["uint256"], values=[code])["encoded"][2:]
    )


def _custom(values):
    body = abi_codec("encode", ["uint256", "uint256"], values=values)["encoded"][2:]
    return CUSTOM_SELECTOR + body


ERROR_DATA = _error(ERC20_MESSAGE)
CUSTOM_DATA = _custom([5, 10])


# --- the built-in selectors are the known constants ----------------------------
def test_builtin_selectors_are_the_canonical_constants():
    assert eth_selector("Error(string)")["selector"] == ERROR_SELECTOR
    assert eth_selector("Panic(uint256)")["selector"] == PANIC_SELECTOR
    assert eth_selector(CUSTOM_SIG)["selector"] == CUSTOM_SELECTOR


# --- Error(string) -------------------------------------------------------------
def test_error_string_full_result():
    assert eth_revert_decode(ERROR_DATA) == {
        "kind": "error",
        "selector": ERROR_SELECTOR,
        "signature": "Error(string)",
        "reason": ERC20_MESSAGE,
    }


def test_error_empty_message():
    assert eth_revert_decode(_error(""))["reason"] == ""


def test_error_unicode_message():
    assert eth_revert_decode(_error("nem elég fedezet ✗"))["reason"] == (
        "nem elég fedezet ✗"
    )


def test_error_accepts_bare_and_uppercase_hex():
    assert eth_revert_decode(ERROR_DATA[2:].upper())["reason"] == ERC20_MESSAGE


# --- Panic(uint256) ------------------------------------------------------------
@pytest.mark.parametrize(
    "code,fragment",
    [
        (0x00, "generic"),
        (0x01, "assert()"),
        (0x11, "overflow or underflow"),
        (0x12, "division or modulo by zero"),
        (0x21, "enum"),
        (0x22, "storage byte array"),
        (0x31, ".pop()"),
        (0x32, "out-of-bounds"),
        (0x41, "too much memory"),
        (0x51, "internal function type"),
    ],
)
def test_panic_codes(code, fragment):
    out = eth_revert_decode(_panic(code))
    assert out["kind"] == "panic"
    assert out["code"] == hex(code)
    assert fragment in out["meaning"]
    assert "reason" not in out


def test_panic_overflow_full_result():
    assert eth_revert_decode(_panic(0x11)) == {
        "kind": "panic",
        "selector": PANIC_SELECTOR,
        "signature": "Panic(uint256)",
        "code": "0x11",
        "meaning": "arithmetic overflow or underflow outside an unchecked block",
    }


def test_undocumented_panic_code_has_null_meaning():
    out = eth_revert_decode(_panic(0x99))
    assert out["kind"] == "panic"
    assert out["code"] == "0x99"
    assert out["meaning"] is None
    assert "not one of Solidity's documented panic codes" in out["reason"]


# --- empty revert data ---------------------------------------------------------
@pytest.mark.parametrize("empty", ["0x", ""])
def test_empty_revert_data(empty):
    out = eth_revert_decode(empty)
    assert out["kind"] == "empty"
    assert "without any data" in out["reason"]
    assert "selector" not in out


# --- custom errors -------------------------------------------------------------
def test_custom_error_named_args():
    assert eth_revert_decode(CUSTOM_DATA, CUSTOM_SIG) == {
        "kind": "custom",
        "selector": CUSTOM_SELECTOR,
        "signature": "InsufficientBalance(uint256,uint256)",
        "selector_matches": True,
        "args": [
            {"name": "available", "type": "uint256", "value": "5"},
            {"name": "required", "type": "uint256", "value": "10"},
        ],
    }


def test_custom_error_without_signature_is_unknown():
    out = eth_revert_decode(CUSTOM_DATA)
    assert out["kind"] == "unknown"
    assert out["selector"] == CUSTOM_SELECTOR
    assert "pass its `signature`" in out["reason"]
    assert "args" not in out


def test_custom_error_zero_args():
    sig = "Unauthorized()"
    data = eth_selector(sig)["selector"]
    out = eth_revert_decode(data, sig)
    assert out["kind"] == "custom"
    assert out["selector_matches"] is True
    assert out["args"] == []


def test_custom_error_with_tuple_and_dynamic_args():
    sig = "BadOrder((address token, uint256 amt) order, string note)"
    body = abi_codec(
        "encode",
        ["(address,uint256)", "string"],
        values=[["0x00000000219ab540356cBB839Cbe05303d7705Fa", 3], "nope"],
    )["encoded"][2:]
    out = eth_revert_decode(eth_selector(sig)["selector"] + body, sig)
    assert out["args"][0]["value"][1] == "3"
    assert [c["name"] for c in out["args"][0]["components"]] == ["token", "amt"]
    assert out["args"][1]["value"] == "nope"


def test_custom_unnamed_params_have_null_names():
    out = eth_revert_decode(CUSTOM_DATA, "InsufficientBalance(uint256,uint256)")
    assert [a["name"] for a in out["args"]] == [None, None]


def test_custom_signature_normalizes_aliases():
    out = eth_revert_decode(CUSTOM_DATA, "InsufficientBalance(uint available, uint b)")
    assert out["selector_matches"] is True
    assert [a["type"] for a in out["args"]] == ["uint256", "uint256"]


# --- signature vs built-in precedence ------------------------------------------
def test_builtin_wins_over_a_non_matching_signature():
    # "You guessed a custom error, but this is a standard Error(string)."
    out = eth_revert_decode(ERROR_DATA, CUSTOM_SIG)
    assert out["kind"] == "error"
    assert out["reason"] == ERC20_MESSAGE


def test_builtin_wins_over_a_non_matching_signature_for_panic():
    out = eth_revert_decode(_panic(0x12), CUSTOM_SIG)
    assert out["kind"] == "panic"
    assert out["code"] == "0x12"


def test_explicit_error_string_signature_is_honored():
    out = eth_revert_decode(ERROR_DATA, "Error(string reason)")
    assert out["kind"] == "custom"
    assert out["selector_matches"] is True
    assert out["args"][0]["value"] == ERC20_MESSAGE


def test_signature_mismatch_on_a_custom_selector_is_soft():
    other = "SomethingElse(uint256 a, uint256 b)"
    out = eth_revert_decode(CUSTOM_DATA, other)
    assert out["kind"] == "custom"
    assert out["selector_matches"] is False
    assert out["data_selector"] == CUSTOM_SELECTOR
    assert "unreliable" in out["reason"]
    assert [a["value"] for a in out["args"]] == ["5", "10"]  # still decoded


def test_match_has_no_reason_or_data_selector():
    out = eth_revert_decode(CUSTOM_DATA, CUSTOM_SIG)
    assert "reason" not in out
    assert "data_selector" not in out


def test_undecodable_mismatch_falls_back_to_unknown():
    # A mismatched signature whose types do not fit the tail must not raise —
    # the honest answer is that the selector is unrecognized.
    out = eth_revert_decode(CUSTOM_DATA, "Other(uint256 a, uint256 b, uint256 c)")
    assert out["kind"] == "unknown"
    assert out["selector"] == CUSTOM_SELECTOR


def test_undecodable_match_raises():
    truncated = CUSTOM_SELECTOR + "00" * 31
    with pytest.raises(ValueError, match="too short"):
        eth_revert_decode(truncated, CUSTOM_SIG)


# --- errors --------------------------------------------------------------------
def test_data_shorter_than_a_selector_raises():
    with pytest.raises(ValueError, match="shorter than a 4-byte selector"):
        eth_revert_decode("0x1234")


def test_error_string_too_short_raises():
    with pytest.raises(ValueError, match="too short for Error"):
        eth_revert_decode(ERROR_SELECTOR + "00" * 31)


def test_panic_too_short_raises():
    with pytest.raises(ValueError, match="too short for Panic"):
        eth_revert_decode(PANIC_SELECTOR + "00" * 31)


def test_invalid_hex_raises():
    with pytest.raises(ValueError):
        eth_revert_decode("0xzzzz")


def test_invalid_signature_raises():
    with pytest.raises(ValueError, match="invalid signature name"):
        eth_revert_decode(CUSTOM_DATA, "1bad(uint256)")


def test_tolerates_trailing_bytes():
    assert eth_revert_decode(ERROR_DATA + "dead")["reason"] == ERC20_MESSAGE


# --- app registration ----------------------------------------------------------
def test_registered_and_callable_through_app():
    names = {t.name for t in asyncio.run(mcp.list_tools())}
    assert "eth_revert_decode" in names

    async def go():
        return await mcp.call_tool("eth_revert_decode", {"data": ERROR_DATA})

    result = asyncio.run(go())
    contents = result[0] if isinstance(result, tuple) else result
    payload = json.loads(contents[0].text)
    assert payload["kind"] == "error"
    assert payload["reason"] == ERC20_MESSAGE


def test_registered_with_expected_schema():
    tool = next(
        t for t in asyncio.run(mcp.list_tools()) if t.name == "eth_revert_decode"
    )
    assert tool.inputSchema["required"] == ["data"]
    assert "signature" in tool.inputSchema["properties"]
    assert tool.description
