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

"""TODO 10.7 / plan §2.1.7 — ens_namehash (EIP-137 namehash + labelhash).

namehash values are the canonical EIP-137 vectors; labelhash is cross-checked
against keccak-256 of the leftmost label."""

import asyncio
import json

import pytest

pytest.importorskip("Crypto", reason="ethereum extra (pycryptodome) not installed")

from mcp_bytesmith.eth import _keccak256, ens_namehash  # noqa: E402
from mcp_bytesmith.server import mcp  # noqa: E402

ZERO = "0x" + "00" * 32

# Canonical EIP-137 namehash vectors.
VECTORS = {
    "": ZERO,
    "eth": "0x93cdeb708b7545dc668eb9280176169d1c33cfd8ed6f04690a0bcc88a93fc4ae",
    "foo.eth": "0xde9b09fd7c5f901e23a3f19fecc54828e9c848539801e86591bd9801b019f84f",
}


@pytest.mark.parametrize("name,node", VECTORS.items())
def test_namehash_vectors(name, node):
    assert ens_namehash(name)["namehash"] == node


def test_root_labelhash_is_zero():
    # The root name has no label; both fields collapse to 32 zero bytes.
    out = ens_namehash("")
    assert out["namehash"] == ZERO
    assert out["labelhash"] == ZERO


def test_labelhash_is_keccak_of_leftmost_label():
    out = ens_namehash("foo.eth")
    assert out["labelhash"] == "0x" + _keccak256(b"foo").hex()
    # single-label name: labelhash is keccak of that label
    assert ens_namehash("eth")["labelhash"] == "0x" + _keccak256(b"eth").hex()


def test_echoes_name():
    assert ens_namehash("alice.eth")["name"] == "alice.eth"


def test_subdomain_chains_correctly():
    # namehash('alice.eth') = keccak(namehash('eth') ++ keccak('alice'))
    parent = bytes.fromhex(ens_namehash("eth")["namehash"][2:])
    expected = _keccak256(parent + _keccak256(b"alice"))
    assert ens_namehash("alice.eth")["namehash"] == "0x" + expected.hex()


def test_unicode_label_hashed_as_utf8():
    # Name is hashed as given (UTF-8); label "münchen" uses its raw bytes.
    out = ens_namehash("münchen.eth")
    assert out["labelhash"] == "0x" + _keccak256("münchen".encode("utf-8")).hex()


# --- error paths ---------------------------------------------------------------
@pytest.mark.parametrize("bad", ["foo..eth", ".eth", "eth.", "a.b.."])
def test_empty_label_rejected(bad):
    with pytest.raises(ValueError):
        ens_namehash(bad)


# --- app registration ----------------------------------------------------------
def test_registered():
    names = {t.name for t in asyncio.run(mcp.list_tools())}
    assert "ens_namehash" in names


def test_callable_through_app():
    async def go():
        return await mcp.call_tool("ens_namehash", {"name": "foo.eth"})

    result = asyncio.run(go())
    contents = result[0] if isinstance(result, tuple) else result
    payload = json.loads(contents[0].text)
    assert payload["namehash"] == VECTORS["foo.eth"]
