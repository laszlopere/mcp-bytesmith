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

"""TODO 10.2 / plan §2.1.2 (§1.1.8) — hash_file: checksum a file + soft-verify.

Digests are cross-checked against hashlib / the canonical CRC check value; the
streaming crypto path is exercised with a file larger than one chunk."""

import asyncio
import base64
import hashlib
import json

import pytest

from mcp_bytesmith.core import _FILE_CHUNK
from mcp_bytesmith.core import hash_file as HF
from mcp_bytesmith.server import mcp

CONTENT = b"hello world\n"


@pytest.fixture
def sample(tmp_path):
    p = tmp_path / "data.bin"
    p.write_bytes(CONTENT)
    return p


# --- digest correctness --------------------------------------------------------
def test_default_sha256(sample):
    out = HF(str(sample))
    assert out["algorithm"] == "sha256"
    assert out["digest"] == hashlib.sha256(CONTENT).hexdigest()
    assert out["path"] == str(sample)
    assert out["size"] == len(CONTENT)
    assert "verified" not in out  # absent without `expected`


@pytest.mark.parametrize("algo", ["md5", "sha1", "sha512", "sha3_256", "blake2b"])
def test_crypto_matches_hashlib(sample, algo):
    assert HF(str(sample), algo)["digest"] == hashlib.new(algo, CONTENT).hexdigest()


def test_base64_output(sample):
    out = HF(str(sample), "sha256", output_format="base64")
    assert base64.b64decode(out["digest"]) == hashlib.sha256(CONTENT).digest()


def test_crc32_check_value(tmp_path):
    p = tmp_path / "check.txt"
    p.write_bytes(b"123456789")  # canonical CRC check string
    assert HF(str(p), "crc32")["digest"] == "cbf43926"


def test_xxh64_matches_library(sample):
    xxhash = pytest.importorskip("xxhash")
    out = HF(str(sample), "xxh64")
    assert out["digest"] == xxhash.xxh64(CONTENT).hexdigest()


def test_fnv1a_32_matches_in_memory_hash(sample):
    from mcp_bytesmith.core import hash as H

    out = HF(str(sample), "fnv1a_32")
    assert out["digest"] == H(CONTENT.decode(), "fnv1a_32")["digest"]


def test_fnv1a_64_matches_in_memory_hash(sample):
    from mcp_bytesmith.core import hash as H

    out = HF(str(sample), "fnv1a_64")
    assert out["digest"] == H(CONTENT.decode(), "fnv1a_64")["digest"]


def test_empty_file(tmp_path):
    p = tmp_path / "empty"
    p.write_bytes(b"")
    out = HF(str(p), "sha256")
    assert out["size"] == 0
    assert out["digest"] == hashlib.sha256(b"").hexdigest()


def test_streams_large_file(tmp_path):
    # Larger than one read chunk to exercise the incremental update loop.
    blob = b"A" * (_FILE_CHUNK * 2 + 17)
    p = tmp_path / "big.bin"
    p.write_bytes(blob)
    out = HF(str(p), "sha256")
    assert out["digest"] == hashlib.sha256(blob).hexdigest()
    assert out["size"] == len(blob)


# --- soft-verify ---------------------------------------------------------------
def test_verify_match(sample):
    digest = hashlib.sha256(CONTENT).hexdigest()
    assert HF(str(sample), expected=digest)["verified"] is True


def test_verify_tolerates_case_and_0x_prefix(sample):
    digest = hashlib.sha256(CONTENT).hexdigest().upper()
    assert HF(str(sample), expected="0x" + digest)["verified"] is True


def test_verify_mismatch(sample):
    assert HF(str(sample), expected="00" * 32)["verified"] is False


def test_verify_base64(sample):
    digest = base64.b64encode(hashlib.sha256(CONTENT).digest()).decode()
    assert HF(str(sample), expected=digest, output_format="base64")["verified"] is True


def test_bad_expected_hex_raises(sample):
    with pytest.raises(ValueError):
        HF(str(sample), expected="not-hex!")


def test_bad_expected_base64_raises(sample):
    # In base64 output mode an `expected` that is not valid base64 is rejected.
    with pytest.raises(ValueError, match="not valid base64"):
        HF(str(sample), expected="@@@@not-base64", output_format="base64")


# --- filesystem errors ---------------------------------------------------------
def test_missing_file_raises(tmp_path):
    with pytest.raises(ValueError):
        HF(str(tmp_path / "nope"))


def test_directory_raises(tmp_path):
    with pytest.raises(ValueError):
        HF(str(tmp_path))


# --- app registration / schema -------------------------------------------------
def test_registered_without_shake():
    tool = next(t for t in asyncio.run(mcp.list_tools()) if t.name == "hash_file")
    algos = tool.inputSchema["properties"]["algorithm"]["enum"]
    assert "sha256" in algos and "crc32" in algos
    assert "shake_128" not in algos and "shake_256" not in algos
    assert len(algos) == 21


def test_callable_through_app(sample):
    async def go():
        return await mcp.call_tool("hash_file", {"path": str(sample)})

    result = asyncio.run(go())
    contents = result[0] if isinstance(result, tuple) else result
    payload = json.loads(contents[0].text)
    assert payload["digest"] == hashlib.sha256(CONTENT).hexdigest()
