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

"""TODO 14.1 / plan §2.5.1 / §1.11.4 — random.

Covers each kind (bytes/hex/urlsafe/token/passphrase), the sizing args and their
defaults, entropy_bits accounting, output_format for raw bytes, custom and
bundled wordlists, randomness (successive calls differ), and validation. The
generated value is a secret, so tests assert on shape/length/entropy, not on a
fixed value."""

import asyncio
import base64
import json as _json
import math

import pytest

from mcp_bytesmith.core import random as RND  # noqa: E402
from mcp_bytesmith.core import _eff_wordlist
from mcp_bytesmith.server import mcp  # noqa: E402

ALNUM = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")


# --- defaults ------------------------------------------------------------------
def test_default_kind_is_urlsafe_256_bits():
    out = RND()
    assert out["kind"] == "urlsafe"
    assert out["entropy_bits"] == 256
    # token_urlsafe(32) is base64url of 32 bytes: no padding, url-safe alphabet.
    assert set(out["value"]) <= set(
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
    )


# --- byte-derived kinds (nbytes) -----------------------------------------------
def test_bytes_hex_default_length_and_entropy():
    out = RND(kind="bytes")
    assert out["entropy_bits"] == 256
    assert len(out["value"]) == 64  # 32 bytes as hex
    assert bytes.fromhex(out["value"])  # valid hex


def test_bytes_base64_output_format():
    out = RND(kind="bytes", nbytes=4, output_format="base64")
    raw = base64.b64decode(out["value"])
    assert len(raw) == 4
    assert out["entropy_bits"] == 32


def test_hex_kind_is_hex_of_nbytes():
    out = RND(kind="hex", nbytes=8)
    assert out["entropy_bits"] == 64
    assert len(out["value"]) == 16
    bytes.fromhex(out["value"])


def test_urlsafe_kind_respects_nbytes():
    out = RND(kind="urlsafe", nbytes=16)
    assert out["entropy_bits"] == 128


def test_nbytes_must_be_positive():
    for kind in ("bytes", "hex", "urlsafe"):
        with pytest.raises(ValueError, match="nbytes must be positive"):
            RND(kind=kind, nbytes=0)


# --- token (length, alphanumeric) ----------------------------------------------
def test_token_default_length_alphabet_and_entropy():
    out = RND(kind="token")
    assert out["kind"] == "token"
    assert len(out["value"]) == 32
    assert set(out["value"]) <= ALNUM
    assert out["entropy_bits"] == math.floor(32 * math.log2(62))  # 190


def test_token_custom_length():
    out = RND(kind="token", length=8)
    assert len(out["value"]) == 8
    assert out["entropy_bits"] == math.floor(8 * math.log2(62))  # 47


def test_token_length_must_be_positive():
    with pytest.raises(ValueError, match="length must be positive"):
        RND(kind="token", length=0)


# --- passphrase (words/separator/wordlist) -------------------------------------
def test_passphrase_default_six_words_from_eff_list():
    out = RND(kind="passphrase")
    parts = out["value"].split("-")
    assert len(parts) == 6
    eff = set(_eff_wordlist())
    assert all(p in eff for p in parts)
    assert out["entropy_bits"] == math.floor(6 * math.log2(7776))  # 77


def test_passphrase_word_count_and_separator():
    out = RND(kind="passphrase", words=3, separator=".")
    assert len(out["value"].split(".")) == 3


def test_passphrase_custom_wordlist_entropy():
    wl = ["alpha", "bravo", "charlie", "delta"]
    out = RND(kind="passphrase", words=4, wordlist=wl)
    parts = out["value"].split("-")
    assert len(parts) == 4
    assert all(p in wl for p in parts)
    assert out["entropy_bits"] == math.floor(4 * math.log2(4))  # 8


def test_passphrase_words_must_be_positive():
    with pytest.raises(ValueError, match="words must be positive"):
        RND(kind="passphrase", words=0)


def test_passphrase_wordlist_needs_two_words():
    with pytest.raises(ValueError, match="at least 2 words"):
        RND(kind="passphrase", wordlist=["only"])


# --- bundled wordlist sanity ---------------------------------------------------
def test_eff_wordlist_is_7776_unique_words():
    wl = _eff_wordlist()
    assert len(wl) == 7776
    assert len(set(wl)) == 7776


# --- randomness ----------------------------------------------------------------
def test_successive_calls_differ():
    for kind in ("bytes", "hex", "urlsafe", "token", "passphrase"):
        assert RND(kind=kind)["value"] != RND(kind=kind)["value"]


# --- validation ----------------------------------------------------------------
def test_unknown_kind_rejected():
    with pytest.raises(ValueError, match="unknown kind"):
        RND(kind="uuid")

    with pytest.raises(ValueError, match="unknown output_format"):
        RND(kind="bytes", output_format="base32")


# --- app wiring ----------------------------------------------------------------
def test_registered_with_kind_enum():
    tool = next(t for t in asyncio.run(mcp.list_tools()) if t.name == "random")
    kinds = tool.inputSchema["properties"]["kind"]["enum"]
    assert set(kinds) == {"bytes", "hex", "urlsafe", "token", "passphrase"}


def test_callable_through_app():
    async def go():
        return await mcp.call_tool("random", {"kind": "hex", "nbytes": 4})

    result = asyncio.run(go())
    contents = result[0] if isinstance(result, tuple) else result
    payload = _json.loads(contents[0].text)
    assert payload["kind"] == "hex"
    assert payload["entropy_bits"] == 32
    assert len(payload["value"]) == 8
