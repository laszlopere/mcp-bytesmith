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

"""TODO 14.2 / plan §2.5.2 / §1.8.1-3 — id_generate.

Covers each kind (uuid v1/4/5/7, ulid, nanoid), batching via `count`, the
version/variant bits every UUID must carry, v5's determinism against the RFC
9562 namespace vectors, the time-sortability of v7 and ULID, nanoid's alphabet
and size, and validation. Random IDs are asserted on shape and structure, never
on a fixed value; only v5 has a fixed expectation."""

import asyncio
import json as _json
import time
import uuid

import pytest

from mcp_bytesmith.core import _MAX_IDS, _MAX_NANOID_SIZE, id_generate
from mcp_bytesmith.server import mcp

CROCKFORD = set("0123456789ABCDEFGHJKMNPQRSTVWXYZ")
NANOID_DEFAULT = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_")


def _ulid_timestamp_ms(value: str) -> int:
    """Decode a ULID's leading 48-bit millisecond timestamp."""
    alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
    num = 0
    for char in value:
        num = num * 32 + alphabet.index(char)
    return num >> 80


# --- uuid ----------------------------------------------------------------------
def test_uuid_defaults_to_v4():
    out = id_generate("uuid")
    assert out["kind"] == "uuid"
    assert out["version"] == 4
    assert len(out["ids"]) == 1
    parsed = uuid.UUID(out["ids"][0])
    assert parsed.version == 4
    assert parsed.variant == uuid.RFC_4122


@pytest.mark.parametrize("version", [1, 4, 7])
def test_uuid_versions_carry_their_version_and_variant_bits(version):
    ids = id_generate("uuid", version=version, count=5)["ids"]
    for value in ids:
        parsed = uuid.UUID(value)
        assert parsed.version == version
        assert parsed.variant == uuid.RFC_4122


def test_uuid_v4_and_v7_are_unique_across_a_batch():
    for version in (4, 7):
        ids = id_generate("uuid", version=version, count=50)["ids"]
        assert len(set(ids)) == 50


def test_uuid_v1_uses_a_random_node_not_the_host_mac():
    # The node's multicast bit (LSB of the first octet) marks it as not-a-MAC,
    # per RFC 9562 §6.10 — and the node must differ between calls.
    nodes = {uuid.UUID(v).node for v in id_generate("uuid", version=1, count=5)["ids"]}
    assert len(nodes) == 5
    for node in nodes:
        assert node & (1 << 40)
    assert uuid.getnode() not in nodes


def test_uuid_v5_matches_the_rfc_namespace_vector():
    out = id_generate("uuid", version=5, namespace="dns", name="example.com")
    assert out["ids"] == ["cfbff0d1-9375-5685-968c-48ce8b15ae17"]
    assert uuid.UUID(out["ids"][0]).version == 5


def test_uuid_v5_is_deterministic_so_a_batch_repeats():
    out = id_generate(
        "uuid", version=5, namespace="url", name="https://example.com", count=3
    )
    assert len(out["ids"]) == 3
    assert len(set(out["ids"])) == 1
    assert out["ids"][0] == str(uuid.uuid5(uuid.NAMESPACE_URL, "https://example.com"))


@pytest.mark.parametrize(
    "namespace, expected_ns",
    [
        ("dns", uuid.NAMESPACE_DNS),
        ("URL", uuid.NAMESPACE_URL),
        ("oid", uuid.NAMESPACE_OID),
        ("x500", uuid.NAMESPACE_X500),
        ("6ba7b810-9dad-11d1-80b4-00c04fd430c8", uuid.NAMESPACE_DNS),
    ],
)
def test_uuid_v5_namespace_names_and_literals(namespace, expected_ns):
    out = id_generate("uuid", version=5, namespace=namespace, name="a")
    assert out["ids"][0] == str(uuid.uuid5(expected_ns, "a"))


def test_uuid_v5_requires_namespace_and_name():
    with pytest.raises(ValueError, match="requires both"):
        id_generate("uuid", version=5, name="a")
    with pytest.raises(ValueError, match="requires both"):
        id_generate("uuid", version=5, namespace="dns")


def test_uuid_v5_rejects_an_unknown_namespace():
    with pytest.raises(ValueError, match="invalid namespace"):
        id_generate("uuid", version=5, namespace="not-a-namespace", name="a")


def test_uuid_v7_embeds_the_current_millisecond_and_sorts_by_time():
    before = time.time_ns() // 1_000_000
    ids = id_generate("uuid", version=7, count=3)["ids"]
    after = time.time_ns() // 1_000_000
    for value in ids:
        ts_ms = uuid.UUID(value).int >> 80
        assert before <= ts_ms <= after
    # v7 is designed so a later ID never carries an earlier timestamp.
    later = id_generate("uuid", version=7)["ids"][0]
    assert (uuid.UUID(later).int >> 80) >= max(uuid.UUID(v).int >> 80 for v in ids)


# --- ulid ----------------------------------------------------------------------
def test_ulid_shape_and_alphabet():
    out = id_generate("ulid", count=4)
    assert out["kind"] == "ulid"
    assert len(out["ids"]) == 4
    assert len(set(out["ids"])) == 4
    for value in out["ids"]:
        assert len(value) == 26
        assert set(value) <= CROCKFORD


def test_ulid_embeds_the_current_millisecond():
    before = time.time_ns() // 1_000_000
    value = id_generate("ulid")["ids"][0]
    after = time.time_ns() // 1_000_000
    assert before <= _ulid_timestamp_ms(value) <= after


def test_ulid_first_character_stays_within_the_128_bit_range():
    # 26 Crockford symbols hold 130 bits; a 128-bit ULID leaves the leading
    # symbol at most '7'. A right-padding encoder would break this.
    for value in id_generate("ulid", count=5)["ids"]:
        assert value[0] in "01234567"


# --- nanoid --------------------------------------------------------------------
def test_nanoid_defaults_to_21_url_safe_characters():
    out = id_generate("nanoid")
    assert out["kind"] == "nanoid"
    assert out["size"] == 21
    value = out["ids"][0]
    assert len(value) == 21
    assert set(value) <= NANOID_DEFAULT


def test_nanoid_honours_size_and_custom_alphabet():
    out = id_generate("nanoid", size=8, alphabet="abc", count=3)
    assert out["size"] == 8
    assert len(out["ids"]) == 3
    for value in out["ids"]:
        assert len(value) == 8
        assert set(value) <= set("abc")


def test_nanoid_rejects_a_degenerate_alphabet():
    with pytest.raises(ValueError, match="at least 2 distinct"):
        id_generate("nanoid", alphabet="aaaa")


@pytest.mark.parametrize("size", [0, -1, _MAX_NANOID_SIZE + 1])
def test_nanoid_rejects_an_out_of_range_size(size):
    with pytest.raises(ValueError, match="size must be between"):
        id_generate("nanoid", size=size)


# --- count / validation --------------------------------------------------------
@pytest.mark.parametrize("kind", ["uuid", "ulid", "nanoid"])
def test_count_controls_the_batch_size(kind):
    assert len(id_generate(kind, count=7)["ids"]) == 7


@pytest.mark.parametrize("count", [0, -1, _MAX_IDS + 1])
def test_count_out_of_range_is_rejected(count):
    with pytest.raises(ValueError, match="count must be between"):
        id_generate("uuid", count=count)


def test_unknown_kind_is_rejected():
    with pytest.raises(ValueError, match="unknown kind"):
        id_generate("guid")


# --- registration / end-to-end through the MCP layer ---------------------------
def test_tool_is_registered_with_a_schema():
    tool = next(t for t in asyncio.run(mcp.list_tools()) if t.name == "id_generate")
    assert tool.description and tool.description.strip()
    assert "kind" in tool.inputSchema["properties"]
    assert tool.inputSchema["required"] == ["kind"]


def test_invoke_through_the_app():
    async def go():
        return await mcp.call_tool(
            "id_generate",
            {"kind": "uuid", "version": 5, "namespace": "dns", "name": "example.com"},
        )

    result = asyncio.run(go())
    contents = result[0] if isinstance(result, tuple) else result
    payload = _json.loads(contents[0].text)
    assert payload == {
        "kind": "uuid",
        "version": 5,
        "ids": ["cfbff0d1-9375-5685-968c-48ce8b15ae17"],
    }
