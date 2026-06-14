"""TODO 11.9 / plan §1.17.1-6 — serialize_codec (four-format core).

cbor/msgpack/bencode round-trip encode <-> decode; protobuf is verified against
hand-built wire vectors (à la `protoc --decode_raw`). Bencode vectors are the
canonical BEP-3 examples."""

import asyncio
import json

import pytest

pytest.importorskip("cbor2", reason="serialize extra (cbor2) not installed")
pytest.importorskip("msgpack", reason="serialize extra (msgpack) not installed")

from mcp_bytesmith.serialize import serialize_codec  # noqa: E402
from mcp_bytesmith.server import mcp  # noqa: E402


def _enc(fmt, data):
    return serialize_codec(fmt, "encode", data)["encoded"]


def _dec(fmt, data):
    return serialize_codec(fmt, "decode", data)["decoded"]


def _roundtrip(fmt, value):
    return _dec(fmt, _enc(fmt, value))


# --- cbor / msgpack round trips ------------------------------------------------
@pytest.mark.parametrize("fmt", ["cbor", "msgpack"])
@pytest.mark.parametrize(
    "value",
    [
        0,
        42,
        -7,
        "hello",
        "",
        [1, 2, 3],
        [],
        {"a": 1, "b": [2, 3]},
        {"nested": {"x": [True, False, None]}},
    ],
)
def test_cbor_msgpack_roundtrip(fmt, value):
    assert _roundtrip(fmt, value) == value


def test_cbor_known_vector():
    # RFC 8949: the integer 1 encodes to 0x01; "a" -> 0x6161; [] -> 0x80.
    assert _enc("cbor", 1) == "01"
    assert _enc("cbor", "a") == "6161"
    assert _enc("cbor", []) == "80"


def test_msgpack_known_vector():
    # MessagePack: positive fixint 1 -> 0x01; fixstr "a" -> 0xa161; fixarray [] -> 0x90.
    assert _enc("msgpack", 1) == "01"
    assert _enc("msgpack", "a") == "a161"
    assert _enc("msgpack", []) == "90"


def test_decode_accepts_0x_prefix():
    assert _dec("cbor", "0x01") == 1


# --- bencode -------------------------------------------------------------------
def test_bencode_known_vectors():
    # i42e, 4:spam, l4:spami42ee, d3:bar4:spam3:fooi42ee (keys sorted).
    assert _enc("bencode", 42) == b"i42e".hex()
    assert _enc("bencode", "spam") == b"4:spam".hex()
    assert _enc("bencode", ["spam", 42]) == b"l4:spami42ee".hex()
    assert _enc("bencode", {"foo": 42, "bar": "spam"}) == b"d3:bar4:spam3:fooi42ee".hex()


def test_bencode_keys_are_sorted_by_bytes():
    # Insertion order is foo-then-bar; output must still sort keys (bar < foo).
    assert _enc("bencode", {"foo": 1, "bar": 2}) == b"d3:bari2e3:fooi1ee".hex()


@pytest.mark.parametrize(
    "value",
    [0, -7, 42, "spam", "", ["spam", 42], [], {"a": 1, "b": ["c", 2]}],
)
def test_bencode_roundtrip(value):
    assert _roundtrip("bencode", value) == value


def test_bencode_non_utf8_string_decodes_to_hex():
    # 2:<0xff 0xfe> — not valid UTF-8, so decode falls back to bare hex.
    encoded = b"2:\xff\xfe".hex()
    assert _dec("bencode", encoded) == "fffe"


def test_bencode_bool_rejected():
    with pytest.raises(ValueError):
        serialize_codec("bencode", "encode", True)


# --- protobuf (decode only) ----------------------------------------------------
def test_protobuf_varint_field():
    # field 1, wire 0 (varint), value 150 -> 08 96 01.
    assert _dec("protobuf", "089601") == [
        {"field": 1, "wire_type": "varint", "value": 150}
    ]


def test_protobuf_length_delimited_string():
    # field 2, wire 2, "testing" -> 12 07 74 65 73 74 69 6e 67.
    assert _dec("protobuf", "120774657374696e67") == [
        {"field": 2, "wire_type": "bytes", "value": {"string": "testing"}}
    ]


def test_protobuf_nested_message():
    # field 3, wire 2 wrapping {field 1 varint 150}: 1a 03 08 96 01.
    assert _dec("protobuf", "1a03089601") == [
        {
            "field": 3,
            "wire_type": "bytes",
            "value": {"message": [{"field": 1, "wire_type": "varint", "value": 150}]},
        }
    ]


def test_protobuf_repeated_field():
    # field 1 varint 1, then field 1 varint 2 -> two entries, same field number.
    assert _dec("protobuf", "08010802") == [
        {"field": 1, "wire_type": "varint", "value": 1},
        {"field": 1, "wire_type": "varint", "value": 2},
    ]


def test_protobuf_encode_rejected():
    with pytest.raises(ValueError):
        serialize_codec("protobuf", "encode", {"field": 1})


def test_protobuf_truncated_varint_raises():
    with pytest.raises(ValueError):
        serialize_codec("protobuf", "decode", "0x08")


# --- error paths ---------------------------------------------------------------
def test_unknown_format_raises():
    with pytest.raises(ValueError):
        serialize_codec("yaml", "encode", {})


def test_unknown_action_raises():
    with pytest.raises(ValueError):
        serialize_codec("cbor", "frobnicate", 1)


def test_decode_non_string_raises():
    with pytest.raises(ValueError):
        serialize_codec("cbor", "decode", [1, 2, 3])


def test_decode_bad_hex_raises():
    with pytest.raises(ValueError):
        serialize_codec("cbor", "decode", "0xzz")


def test_options_must_be_object():
    with pytest.raises(ValueError):
        serialize_codec("cbor", "encode", 1, options="[1, 2]")


def test_encode_stringified_structure_is_parsed():
    # A client that stringifies the object still works (JSON-parsed when it
    # starts with '{' or '[').
    assert _enc("cbor", '{"a": 1}') == _enc("cbor", {"a": 1})
    assert _enc("cbor", "plain") != _enc("cbor", '{"a": 1}')  # bare string stays a string


# --- app registration ----------------------------------------------------------
def test_registered_and_callable_through_app():
    names = {t.name for t in asyncio.run(mcp.list_tools())}
    assert "serialize_codec" in names

    async def go():
        return await mcp.call_tool(
            "serialize_codec",
            {"format": "cbor", "action": "encode", "data": {"a": 1}},
        )

    result = asyncio.run(go())
    contents = result[0] if isinstance(result, tuple) else result
    payload = json.loads(contents[0].text)
    # {"a": 1} in CBOR is 0xa1 0x61 0x61 0x01.
    assert payload["encoded"] == "a1616101"
