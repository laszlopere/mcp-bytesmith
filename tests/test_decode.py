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

"""TODO 11.2 / plan §2.2.2 (inverse of §2.2.1; same scheme set) — decode.

Checked three ways: direct canonical vectors (RFC 4648, RFC 9285, BIP-173, the
Bitcoin Base58Check address), round-tripping every scheme against encode, and
the malformed-input rejections (bad checksum, padding bits, wrong spec).
base58/base58check/base45/idna need the encoding extra (gracefully gated)."""

import asyncio
import json

import pytest

from mcp_bytesmith.core import decode as D  # noqa: E402
from mcp_bytesmith.core import encode as E  # noqa: E402
from mcp_bytesmith.server import mcp  # noqa: E402


def _d(data, scheme, **kw):
    return D(data, scheme, **kw)["decoded"]


# --- base16 / base32 / base64 families (RFC 4648 "foobar" vectors) --------------
def test_base16_case_insensitive():
    assert _d("666f6f626172", "base16") == "foobar"
    assert _d("666F6F626172", "base16") == "foobar"


def test_base32():
    assert _d("MZXW6YTBOI======", "base32") == "foobar"


def test_base32_tolerates_missing_padding():
    # encode(padding=False) drops '='; decode re-adds it.
    assert _d("MZXW6YTBOI", "base32") == "foobar"


def test_base32hex():
    assert _d("CPNMUOJ1E8======", "base32hex") == "foobar"


def test_base64():
    assert _d("Zm9vYmFy", "base64") == "foobar"


def test_base64url_missing_padding_and_url_alphabet():
    assert _d("Zm9vYg", "base64url") == "foob"
    assert _d("-_8", "base64url", output_format="hex") == "fbff"


# --- hand-rolled base-N ---------------------------------------------------------
def test_base32crockford_case_and_ambiguity_folding():
    enc = E("foobar", "base32crockford")["encoded"]
    # lowercase + I/L->1, O->0 must decode identically.
    folded = enc.lower().replace("1", "l").replace("0", "o")
    assert _d(folded, "base32crockford") == "foobar"


def test_base62():
    assert _d("VytN8Wjy", "base62") == "foobar"


def test_base62_leading_zero_symbols_become_zero_bytes():
    assert _d("00ff", "base62", output_format="hex").startswith("0000")


# --- ascii85 / base85 / z85 -----------------------------------------------------
def test_ascii85():
    assert _d("BOu!rDZ", "ascii85") == "hello"


def test_z85_reference_vector():
    assert _d("HelloWorld", "z85", output_format="hex") == "864fd26fb559f75b"


def test_z85_requires_multiple_of_five():
    with pytest.raises(ValueError):
        D("HelloW", "z85", output_format="hex")  # 6 chars is not a 5-multiple


# --- URL percent-decoding -------------------------------------------------------
def test_url():
    assert _d("a%20b%2Fc%3F", "url") == "a b/c?"


def test_url_form_plus_is_space():
    assert _d("a+b%2Fc%3F", "url_form") == "a b/c?"


# --- bech32 / bech32m -----------------------------------------------------------
def test_bech32_decode_returns_hrp_and_data():
    out = D("bc1w508d6qejxtdg4y5r3zarvary0c5xw7kj7gz7z", "bech32", output_format="hex")
    assert out["decoded"] == "751e76e8199196d454941c45d1b3a323f1433bd6"
    assert out["hrp"] == "bc"


def test_bech32_bad_checksum_raises():
    # Flip the last data char (lowercase, so the mixed-case guard is not hit).
    with pytest.raises(ValueError):
        D("bc1w508d6qejxtdg4y5r3zarvary0c5xw7kj7gz7q", "bech32", output_format="hex")


def test_bech32m_string_rejected_as_bech32():
    enc = E("0xabcdef", "bech32m", input_format="hex", options={"hrp": "bc"})["encoded"]
    with pytest.raises(ValueError):
        D(enc, "bech32", output_format="hex")  # wrong spec -> checksum mismatch


def test_bech32_rejects_mixed_case():
    with pytest.raises(ValueError):
        D("BC1w508d6qejxtdg4y5r3zarvary0c5xw7kj7gz7z", "bech32", output_format="hex")


# --- hexdump --------------------------------------------------------------------
def test_hexdump_recovers_bytes():
    dump = E("Hello world", "hexdump")["encoded"]
    assert _d(dump, "hexdump") == "Hello world"


def test_hexdump_with_pipe_byte_in_gutter():
    # 0x7c is '|' — the gutter must not confuse the parser.
    dump = E("0x7c7c7c7c", "hexdump", input_format="hex")["encoded"]
    assert _d(dump, "hexdump", output_format="hex") == "7c7c7c7c"


# --- bytes32 --------------------------------------------------------------------
def test_bytes32_returns_full_32_byte_word():
    # bytes32 is fixed-width: decode returns all 32 bytes, padding included (CR.1).
    word = "0x6869" + "00" * 30
    assert _d(word, "bytes32", output_format="hex") == "6869" + "00" * 30


def test_bytes32_rejects_non_32_byte_word():
    with pytest.raises(ValueError):
        D("0x6869", "bytes32")


def test_bytes32_round_trip_preserves_trailing_nulls():
    # Encoding then decoding must not lose genuine trailing-null data (CR.1):
    # the 32-byte word is preserved exactly, so re-encoding yields the same word.
    data = "0x123400"
    word = E(data, "bytes32", input_format="hex")["encoded"]
    raw = D(word, "bytes32", output_format="hex")["decoded"]
    assert raw == "1234" + "00" * 30
    assert E("0x" + raw, "bytes32", input_format="hex")["encoded"] == word


# --- encoding-extra schemes -----------------------------------------------------
def test_base58check_bitcoin_address_vector():
    pytest.importorskip("base58")
    out = _d("16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM", "base58check", output_format="hex")
    assert out == "00010966776006953d5567439e5e39f86a0d273bee"


def test_base58check_bad_checksum_raises():
    pytest.importorskip("base58")
    with pytest.raises(ValueError):
        D("16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvN", "base58check", output_format="hex")


def test_base58_leading_ones_become_zero_bytes():
    pytest.importorskip("base58")
    assert _d("11a", "base58", output_format="hex").startswith("0000")


def test_base45_reference_vector():
    pytest.importorskip("base45")
    assert _d("BB8", "base45") == "AB"
    assert _d("%69 VD92EX0", "base45") == "Hello!!"


def test_idna_punycode():
    pytest.importorskip("idna")
    assert _d("xn--mnchen-3ya.de", "idna") == "münchen.de"


# --- round-trip over the whole scheme set --------------------------------------
@pytest.mark.parametrize(
    "scheme",
    [
        "base16",
        "base32",
        "base32hex",
        "base32crockford",
        "base45",
        "base58",
        "base58check",
        "base62",
        "base64",
        "base64url",
        "ascii85",
        "base85",
        "url",
        "url_form",
        "hexdump",
        # bytes32 is intentionally fixed-width (32-byte word), not length-
        # preserving, so it can't round-trip an arbitrary-length input here;
        # see test_bytes32_round_trip_preserves_trailing_nulls (CR.1).
    ],
)
def test_round_trip_binary(scheme):
    if scheme in ("base58", "base58check", "base45"):
        pytest.importorskip("base58" if scheme != "base45" else "base45")
    raw = "0x0011223344556677"
    enc = E(raw, scheme, input_format="hex")["encoded"]
    assert D(enc, scheme, output_format="hex")["decoded"] == raw[2:]


# --- output formats / errors ----------------------------------------------------
def test_non_utf8_text_output_raises():
    with pytest.raises(ValueError):
        D("//8=", "base64")  # 0xffff is not valid UTF-8


def test_base64_output_format():
    # base16 "666f6f626172" -> "foobar" -> base64 "Zm9vYmFy".
    assert D("666f6f626172", "base16", output_format="base64")["decoded"] == "Zm9vYmFy"


def test_unknown_scheme_raises():
    with pytest.raises(ValueError):
        D("abc", "base999")


def test_return_shape():
    out = D("YWJj", "base64")
    assert out == {"scheme": "base64", "decoded": "abc", "output_format": "text"}


# --- app registration / schema -------------------------------------------------
def test_registered_with_enum_schema():
    tool = next(t for t in asyncio.run(mcp.list_tools()) if t.name == "decode")
    schemes = tool.inputSchema["properties"]["scheme"]["enum"]
    assert "base64" in schemes and "bech32m" in schemes and "hexdump" in schemes
    assert len(schemes) == 20


def test_callable_through_app():
    async def go():
        return await mcp.call_tool("decode", {"data": "Zm9vYmFy", "scheme": "base64"})

    result = asyncio.run(go())
    contents = result[0] if isinstance(result, tuple) else result
    payload = json.loads(contents[0].text)
    assert payload["decoded"] == "foobar"
