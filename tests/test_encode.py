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

"""TODO 11.1 / plan §2.2.1 (merges §1.4.1-9,14, 1.5.5, 1.12.2, 1.15.6) — encode.

Base16/32/64 families are checked against the RFC 4648 "foobar" vectors;
base45 against RFC 9285; z85 against the ZeroMQ reference vector; bech32 against
the BIP-173 algorithm; base58check against the canonical Bitcoin-address example.
base58/base58check/base45/idna need the encoding extra (gracefully gated)."""

import asyncio
import base64 as b64
import json

import pytest

from mcp_bytesmith.core import encode as E  # noqa: E402
from mcp_bytesmith.server import mcp  # noqa: E402


def _e(data, scheme, **kw):
    return E(data, scheme, **kw)["encoded"]


# --- base16 / base32 / base64 families (RFC 4648 "foobar" vectors) --------------
def test_base16():
    assert _e("foobar", "base16") == "666F6F626172"


def test_base32():
    assert _e("foobar", "base32") == "MZXW6YTBOI======"


def test_base32_no_padding():
    assert _e("foobar", "base32", options={"padding": False}) == "MZXW6YTBOI"


def test_base32hex():
    assert _e("foobar", "base32hex") == "CPNMUOJ1E8======"


def test_base64():
    assert _e("foobar", "base64") == "Zm9vYmFy"


def test_base64url_is_url_safe():
    # 0xfbff -> '-_' in url-safe alphabet ('+/' would be '+/' in std base64).
    assert _e("0xfbff", "base64url", input_format="hex") == "-_8="


def test_base64url_no_padding():
    assert _e("foob", "base64url", options={"padding": False}) == "Zm9vYg"


# --- hand-rolled base-N ---------------------------------------------------------
def test_base32crockford_excludes_ambiguous_letters():
    out = _e("foobar", "base32crockford")
    assert set(out) <= set("0123456789ABCDEFGHJKMNPQRSTVWXYZ")
    assert "I" not in out and "L" not in out and "O" not in out and "U" not in out


def test_base62_round_trippable_alphabet():
    assert _e("foobar", "base62") == "VytN8Wjy"


def test_base62_leading_zero_bytes_become_leading_symbols():
    assert _e("0x0000ff", "base62", input_format="hex").startswith("00")


def test_base62_rejects_bad_alphabet():
    with pytest.raises(ValueError):
        E("foobar", "base62", options={"alphabet": "0123"})


# --- ascii85 / base85 / z85 -----------------------------------------------------
def test_ascii85():
    assert _e("hello", "ascii85") == b64.a85encode(b"hello").decode()


def test_base85():
    assert _e("hello", "base85") == b64.b85encode(b"hello").decode()


def test_z85_reference_vector():
    # ZeroMQ Z85 spec: 0x864FD26FB559F75B -> "HelloWorld".
    assert _e("0x864FD26FB559F75B", "z85", input_format="hex") == "HelloWorld"


def test_z85_requires_multiple_of_four():
    with pytest.raises(ValueError):
        E("0x010203", "z85", input_format="hex")


# --- URL percent-encoding -------------------------------------------------------
def test_url_encodes_reserved():
    assert _e("a b/c?", "url") == "a%20b%2Fc%3F"


def test_url_form_uses_plus_for_space():
    assert _e("a b/c?", "url_form") == "a+b%2Fc%3F"


# --- bech32 / bech32m -----------------------------------------------------------
def test_bech32_matches_reference():
    # BIP-173: convertbits(8->5) of the 20-byte program under hrp 'bc'.
    out = _e(
        "751e76e8199196d454941c45d1b3a323f1433bd6",
        "bech32",
        input_format="hex",
        options={"hrp": "bc"},
    )
    assert out == "bc1w508d6qejxtdg4y5r3zarvary0c5xw7kj7gz7z"


def test_bech32m_differs_from_bech32():
    args = dict(input_format="hex", options={"hrp": "bc"})
    assert _e("0xabcdef", "bech32", **args) != _e("0xabcdef", "bech32m", **args)


def test_bech32_requires_hrp():
    with pytest.raises(ValueError):
        E("0xabcd", "bech32", input_format="hex")


def test_bech32_rejects_uppercase_hrp():
    with pytest.raises(ValueError):
        E("0xabcd", "bech32", input_format="hex", options={"hrp": "BC"})


# --- hexdump --------------------------------------------------------------------
def test_hexdump_layout():
    out = _e("Hello world", "hexdump")
    lines = out.splitlines()
    assert lines[0].startswith("00000000  ")
    assert "48 65 6c 6c 6f" in lines[0]  # "Hello"
    assert lines[0].endswith("|Hello world|")
    assert lines[-1] == "0000000b"  # trailing end-offset (11 bytes)


def test_hexdump_custom_width():
    out = _e("abcd", "hexdump", options={"width": 2})
    # 4 bytes / 2-per-line -> two data lines + the end-offset line.
    assert len([ln for ln in out.splitlines() if ln.endswith("|")]) == 2


def test_hexdump_width_capped():
    # A huge width pads every line to gigabytes of spaces (CR.4).
    with pytest.raises(ValueError):
        _e("abcd", "hexdump", options={"width": 2_000_000})


# --- bytes32 --------------------------------------------------------------------
def test_bytes32_right_pads_to_32():
    out = _e("hi", "bytes32")
    assert out == "0x6869" + "00" * 30
    assert len(out) == 2 + 64


def test_bytes32_rejects_oversize():
    with pytest.raises(ValueError):
        E("0x" + "ab" * 33, "bytes32", input_format="hex")


# --- encoding-extra schemes (base58 / base58check / base45 / idna) --------------
def test_base58check_bitcoin_address_vector():
    pytest.importorskip("base58")
    # Canonical Bitcoin wiki example: version+hash160 -> Base58Check address.
    out = _e(
        "00010966776006953D5567439E5E39F86A0D273BEE",
        "base58check",
        input_format="hex",
    )
    assert out == "16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM"


def test_base58_leading_zero_bytes_become_ones():
    pytest.importorskip("base58")
    out = _e("0x000061", "base58", input_format="hex")
    assert out.startswith("11")  # two leading 0x00 -> two '1's


def test_base45_reference_vector():
    pytest.importorskip("base45")
    # RFC 9285 examples.
    assert _e("AB", "base45") == "BB8"
    assert _e("Hello!!", "base45") == "%69 VD92EX0"


def test_idna_punycode():
    pytest.importorskip("idna")
    assert _e("münchen.de", "idna") == "xn--mnchen-3ya.de"


# --- errors / options -----------------------------------------------------------
def test_base32crockford_empty_input():
    # Empty input yields an empty Crockford string (no symbols, no padding).
    assert _e("", "base32crockford") == ""


def test_bech32_rejects_non_printable_hrp():
    # A truthy but out-of-range hrp char (ord > 126) fails the hrp validation.
    with pytest.raises(ValueError, match="invalid bech32 hrp"):
        E("0xabcd", "bech32", input_format="hex", options={"hrp": "b€"})


def test_hexdump_zero_width_raises():
    with pytest.raises(ValueError, match="width must be positive"):
        E("abcd", "hexdump", options={"width": 0})


def test_options_string_must_decode_to_object():
    # A JSON scalar (not an object) is rejected.
    with pytest.raises(ValueError, match="`options` must be an object"):
        E("foobar", "base32", options="123")


def test_unknown_scheme_raises():
    with pytest.raises(ValueError):
        E("abc", "base999")


def test_bad_base64_input_raises():
    # The base64 input-format branch of the shared _to_bytes decoder.
    with pytest.raises(ValueError, match="invalid base64 input"):
        E("@@@@", "base64", input_format="base64")


def test_bad_hex_input_raises():
    with pytest.raises(ValueError):
        E("0xZZ", "base64", input_format="hex")


def test_options_accepts_json_string():
    # Clients may stringify the options object.
    assert (
        E("foobar", "base32", options='{"padding": false}')["encoded"] == "MZXW6YTBOI"
    )


def test_return_shape():
    out = E("abc", "base64")
    assert out == {"scheme": "base64", "encoded": "YWJj"}


# --- app registration / schema -------------------------------------------------
def test_registered_with_enum_schema():
    tool = next(t for t in asyncio.run(mcp.list_tools()) if t.name == "encode")
    schemes = tool.inputSchema["properties"]["scheme"]["enum"]
    assert "base64" in schemes and "bech32m" in schemes and "hexdump" in schemes
    assert len(schemes) == 20


def test_callable_through_app():
    async def go():
        return await mcp.call_tool("encode", {"data": "foobar", "scheme": "base64"})

    result = asyncio.run(go())
    contents = result[0] if isinstance(result, tuple) else result
    payload = json.loads(contents[0].text)
    assert payload["encoded"] == "Zm9vYmFy"
