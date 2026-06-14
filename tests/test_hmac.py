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

"""TODO 10.3 / plan §2.1.3 (§1.3.1) — hmac: compute / verify a keyed-hash tag.

Tags are cross-checked against the stdlib `hmac` module and the published
RFC 4231 test vectors for HMAC-SHA224/256/384/512."""

import asyncio
import base64
import hmac as ref
import json

import pytest

from mcp_bytesmith.core import hmac as HM
from mcp_bytesmith.server import mcp


# --- RFC 4231 test case 2 (key "Jefe", data "what do ya want for nothing?") ----
RFC_KEY = "Jefe"
RFC_DATA = "what do ya want for nothing?"
RFC_VECTORS = {
    "sha224": "a30e01098bc6dbbf45690f3a7e9e6d0f8bbea2a39e6148008fd05e44",
    "sha256": "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
    "sha384": (
        "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec373"
        "6322445e8e2240ca5e69e2c78b3239ecfab21649"
    ),
    "sha512": (
        "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554"
        "9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737"
    ),
}


@pytest.mark.parametrize("algo,tag", RFC_VECTORS.items())
def test_rfc4231_vectors(algo, tag):
    assert HM(RFC_DATA, RFC_KEY, algo)["mac"] == tag


def test_default_sha256_matches_stdlib():
    out = HM("message", "secret")
    assert out["algorithm"] == "sha256"
    assert out["output_format"] == "hex"
    assert out["mac"] == ref.new(b"secret", b"message", "sha256").hexdigest()
    assert "valid" not in out  # absent without `expected`


@pytest.mark.parametrize("algo", ["md5", "sha1", "sha512", "sha3_256", "blake2b"])
def test_matches_stdlib(algo):
    assert (
        HM("hello world", "k", algo)["mac"]
        == ref.new(b"k", b"hello world", algo).hexdigest()
    )


# --- input / key / output formats ----------------------------------------------
def test_hex_and_base64_inputs_match_text():
    text = HM("hello", "secret")["mac"]
    assert HM("0x68656c6c6f", "secret", input_format="hex")["mac"] == text
    key_b64 = base64.b64encode(b"secret").decode()
    assert HM("hello", key_b64, key_format="base64")["mac"] == text


def test_base64_output():
    out = HM("message", "secret", output_format="base64")
    assert (
        base64.b64decode(out["mac"])
        == ref.new(b"secret", b"message", "sha256").digest()
    )


# --- soft-verify ---------------------------------------------------------------
def test_verify_match():
    tag = ref.new(b"secret", b"message", "sha256").hexdigest()
    assert HM("message", "secret", expected=tag)["valid"] is True


def test_verify_tolerates_case_and_0x_prefix():
    tag = ref.new(b"secret", b"message", "sha256").hexdigest().upper()
    assert HM("message", "secret", expected="0x" + tag)["valid"] is True


def test_verify_mismatch():
    assert HM("message", "secret", expected="00" * 32)["valid"] is False


def test_verify_wrong_key_is_invalid():
    tag = ref.new(b"secret", b"message", "sha256").hexdigest()
    assert HM("message", "WRONG", expected=tag)["valid"] is False


def test_verify_base64():
    tag = base64.b64encode(ref.new(b"secret", b"message", "sha256").digest()).decode()
    out = HM("message", "secret", expected=tag, output_format="base64")
    assert out["valid"] is True


def test_bad_expected_raises():
    with pytest.raises(ValueError):
        HM("message", "secret", expected="not-hex!")


# --- errors --------------------------------------------------------------------
def test_bad_hex_input_raises():
    with pytest.raises(ValueError):
        HM("0xZZ", "secret", input_format="hex")


# --- app registration / schema -------------------------------------------------
def test_registered_with_crypto_only_algorithms():
    tool = next(t for t in asyncio.run(mcp.list_tools()) if t.name == "hmac")
    algos = tool.inputSchema["properties"]["algorithm"]["enum"]
    assert "sha256" in algos and "blake2b" in algos
    assert "crc32" not in algos and "shake_128" not in algos and "xxh64" not in algos
    assert len(algos) == 10


def test_callable_through_app():
    async def go():
        return await mcp.call_tool("hmac", {"data": "message", "key": "secret"})

    result = asyncio.run(go())
    contents = result[0] if isinstance(result, tuple) else result
    payload = json.loads(contents[0].text)
    assert payload["mac"] == ref.new(b"secret", b"message", "sha256").hexdigest()
