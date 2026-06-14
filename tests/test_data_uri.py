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

"""TODO 11.3 / plan §2.2.3 / §1.4.13 — data_uri (RFC 2397).

build/parse are checked against the RFC 2397 examples (the base64 and the
percent-encoded "brief note" forms), round-tripped for binary payloads, and
exercised on the malformed-input rejections."""

import asyncio
import json

import pytest

from mcp_bytesmith.core import data_uri as DU  # noqa: E402
from mcp_bytesmith.server import mcp  # noqa: E402


def _build(**kw):
    return DU("build", **kw)["uri"]


def _parse(uri, **kw):
    return DU("parse", uri=uri, **kw)


# --- build ---------------------------------------------------------------------
def test_build_base64_default():
    assert _build(data="Hello, World!") == "data:;base64,SGVsbG8sIFdvcmxkIQ=="


def test_build_with_media_type():
    uri = _build(media_type="text/plain", data="hi")
    assert uri == "data:text/plain;base64,aGk="


def test_build_percent_encoded():
    assert _build(data="A brief note", base64=False) == "data:,A%20brief%20note"


def test_build_percent_encodes_utf8():
    uri = _build(media_type="text/plain;charset=utf-8", data="héllo", base64=False)
    assert uri == "data:text/plain;charset=utf-8,h%C3%A9llo"


def test_build_binary_from_hex():
    # GIF magic bytes via hex input.
    assert _build(media_type="image/gif", data="47494638", input_format="hex") == (
        "data:image/gif;base64,R0lGOA=="
    )


def test_build_requires_data():
    with pytest.raises(ValueError):
        DU("build")


# --- parse ---------------------------------------------------------------------
def test_parse_base64():
    out = _parse("data:text/plain;base64,SGVsbG8sIFdvcmxkIQ==")
    assert out["media_type"] == "text/plain"
    assert out["is_base64"] is True
    assert out["data"] == "Hello, World!"
    assert out["parameters"] == {}


def test_parse_percent_encoded():
    out = _parse("data:,A%20brief%20note")
    assert out["media_type"] == "text/plain"  # RFC default when absent
    assert out["is_base64"] is False
    assert out["data"] == "A brief note"


def test_parse_extracts_parameters():
    out = _parse("data:text/plain;charset=iso-8859-7;foo=bar,hi")
    assert out["media_type"] == "text/plain"
    assert out["parameters"] == {"charset": "iso-8859-7", "foo": "bar"}


def test_parse_valueless_parameter_segment():
    # A bare ';flag' segment (no '=') is recorded with an empty-string value.
    out = _parse("data:text/plain;flag,hi")
    assert out["media_type"] == "text/plain"
    assert out["parameters"] == {"flag": ""}
    assert out["data"] == "hi"


def test_parse_binary_payload_as_hex():
    out = _parse("data:image/png;base64,iVBORw0KGgo=", output_format="hex")
    assert out["media_type"] == "image/png"
    assert out["data"] == "89504e470d0a1a0a"  # PNG magic


def test_parse_base64_no_media_type():
    out = _parse("data:;base64,Zm9v")
    assert out["is_base64"] is True
    assert out["data"] == "foo"


def test_parse_tolerates_whitespace_in_base64():
    # HTML often wraps long base64 payloads across lines.
    out = _parse("data:text/plain;base64,SGVs bG8s\nIFdvcmxkIQ==")
    assert out["data"] == "Hello, World!"


def test_parse_rejects_non_data_uri():
    with pytest.raises(ValueError):
        DU("parse", uri="http://example.com")


def test_parse_rejects_missing_comma():
    with pytest.raises(ValueError):
        DU("parse", uri="data:text/plain;base64")


def test_parse_requires_uri():
    with pytest.raises(ValueError):
        DU("parse")


# --- round-trips ---------------------------------------------------------------
@pytest.mark.parametrize("b64", [True, False])
def test_round_trip_text(b64):
    uri = _build(media_type="text/plain", data="round trip!", base64=b64)
    assert _parse(uri)["data"] == "round trip!"


def test_round_trip_binary():
    payload = "0x0011223344ffee"
    uri = _build(
        media_type="application/octet-stream", data=payload, input_format="hex"
    )
    assert _parse(uri, output_format="hex")["data"] == payload[2:]


# --- errors / app --------------------------------------------------------------
def test_unknown_action_raises():
    with pytest.raises(ValueError):
        DU("frobnicate", data="x")


def test_registered_with_action_enum():
    tool = next(t for t in asyncio.run(mcp.list_tools()) if t.name == "data_uri")
    actions = tool.inputSchema["properties"]["action"]["enum"]
    assert set(actions) == {"build", "parse"}


def test_callable_through_app():
    async def go():
        return await mcp.call_tool(
            "data_uri", {"action": "parse", "uri": "data:;base64,Zm9v"}
        )

    result = asyncio.run(go())
    contents = result[0] if isinstance(result, tuple) else result
    payload = json.loads(contents[0].text)
    assert payload["data"] == "foo"
