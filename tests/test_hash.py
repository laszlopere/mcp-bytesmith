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

"""TODO 10.1 / plan §2.1.1 (merges §1.1.1-7) — hash / crc / fast_hash.

Crypto digests are cross-checked against hashlib; CRC/fast-hash values are the
canonical "check" results (CRC of "123456789" from the reveng catalogue, and
the published FNV-1a / xxHash vectors). xxh* needs the encoding extra (xxhash)."""

import asyncio
import base64
import hashlib
import json

import pytest

from mcp_bytesmith.core import hash as H  # noqa: E402
from mcp_bytesmith.server import mcp  # noqa: E402

CHECK = "123456789"  # standard CRC check string


# --- cryptographic (stdlib hashlib) --------------------------------------------
@pytest.mark.parametrize("algo", ["md5", "sha1", "sha256", "sha512", "sha3_256"])
def test_crypto_matches_hashlib(algo):
    out = H("hello world", algo)
    assert out["digest"] == hashlib.new(algo, b"hello world").hexdigest()
    assert out["output_format"] == "hex"
    assert out["bits"] == len(hashlib.new(algo, b"").digest()) * 8
    assert "int" not in out  # crypto hashes are digest-only


def test_empty_md5():
    assert H("", "md5")["digest"] == "d41d8cd98f00b204e9800998ecf8427e"


def test_hex_input_matches_text():
    assert (
        H("0x68656c6c6f", "sha256", "hex")["digest"] == H("hello", "sha256")["digest"]
    )


def test_base64_output():
    out = H("abc", "sha256", output_format="base64")
    assert base64.b64decode(out["digest"]) == hashlib.sha256(b"abc").digest()


# --- shake (variable length) ---------------------------------------------------
def test_shake_requires_length():
    with pytest.raises(ValueError):
        H("abc", "shake_128")


def test_shake_length():
    out = H("abc", "shake_128", length=16)
    assert out["digest"] == hashlib.shake_128(b"abc").hexdigest(16)
    assert out["bits"] == 128


def test_length_rejected_for_non_shake():
    with pytest.raises(ValueError):
        H("abc", "sha256", length=8)


def test_shake_length_capped():
    # Unbounded length would let a caller allocate gigabytes (CR.3).
    with pytest.raises(ValueError):
        H("abc", "shake_128", length=2**31)


def test_shake_length_zero_is_empty_digest():
    # Boundary: a zero-length SHAKE digest is valid and empty.
    assert H("abc", "shake_256", length=0)["digest"] == ""


def test_shake_negative_length_raises():
    with pytest.raises(ValueError, match="non-negative"):
        H("abc", "shake_128", length=-1)


# --- keyed blake2 --------------------------------------------------------------
def test_blake2b_keyed():
    out = H("message", "blake2b", key="secret")
    assert out["digest"] == hashlib.blake2b(b"message", key=b"secret").hexdigest()


def test_blake2s_keyed():
    out = H("message", "blake2s", key="secret")
    assert out["digest"] == hashlib.blake2s(b"message", key=b"secret").hexdigest()
    assert out["bits"] == 256


def test_blake2s_keyless():
    out = H("message", "blake2s")
    assert out["digest"] == hashlib.blake2s(b"message").hexdigest()


def test_key_rejected_for_non_blake2():
    with pytest.raises(ValueError):
        H("abc", "sha256", key="secret")


# --- CRC (canonical check values) ----------------------------------------------
CRC_CHECK = {
    "crc8": ("f4", 0xF4, 8),
    "crc16": ("bb3d", 0xBB3D, 16),
    "crc32": ("cbf43926", 0xCBF43926, 32),
    "crc32c": ("e3069283", 0xE3069283, 32),
    "crc64": ("995dc9bbdf1939fa", 0x995DC9BBDF1939FA, 64),
}


@pytest.mark.parametrize("algo,hexd,intv,bits", [(k, *v) for k, v in CRC_CHECK.items()])
def test_crc_check_value(algo, hexd, intv, bits):
    out = H(CHECK, algo)
    assert out["digest"] == hexd
    assert out["int"] == intv
    assert out["bits"] == bits


def test_crc32_matches_zlib():
    import zlib

    assert H("hello", "crc32")["int"] == zlib.crc32(b"hello")


# --- FNV-1a (published vectors) ------------------------------------------------
def test_fnv1a_vectors():
    assert H("", "fnv1a_32")["int"] == 0x811C9DC5  # offset basis
    assert H("a", "fnv1a_32")["int"] == 0xE40C292C
    assert H("a", "fnv1a_64")["int"] == 0xAF63DC4C8601EC8C


def test_fnv1a_seed_overrides_offset_basis():
    # Seeding fnv with the default basis reproduces the unseeded result.
    assert H("a", "fnv1a_32", seed=0x811C9DC5)["int"] == H("a", "fnv1a_32")["int"]


# --- xxHash (encoding extra) ---------------------------------------------------
def test_xxh_vectors():
    assert H("", "xxh32")["int"] == 0x02CC5D05
    assert H("", "xxh64")["int"] == 0xEF46DB3751D8E999
    assert H("", "xxh3_128")["bits"] == 128


def test_xxh_matches_library():
    import xxhash

    assert (
        H("hello", "xxh64", seed=99)["int"]
        == xxhash.xxh64(b"hello", seed=99).intdigest()
    )


def test_seed_rejected_for_non_fast_hash():
    with pytest.raises(ValueError):
        H("abc", "sha256", seed=1)


# --- errors --------------------------------------------------------------------
def test_unknown_algorithm_raises():
    with pytest.raises(ValueError):
        H("abc", "sha999")


def test_bad_hex_input_raises():
    with pytest.raises(ValueError):
        H("0xZZ", "sha256", "hex")


# --- app registration / schema -------------------------------------------------
def test_registered_with_enum_schema():
    tool = next(t for t in asyncio.run(mcp.list_tools()) if t.name == "hash")
    algos = tool.inputSchema["properties"]["algorithm"]["enum"]
    assert "sha256" in algos and "crc32" in algos and "xxh64" in algos
    assert len(algos) == 23


def test_callable_through_app():
    async def go():
        return await mcp.call_tool("hash", {"data": "abc", "algorithm": "sha256"})

    result = asyncio.run(go())
    contents = result[0] if isinstance(result, tuple) else result
    payload = json.loads(contents[0].text)
    assert payload["digest"] == hashlib.sha256(b"abc").hexdigest()
