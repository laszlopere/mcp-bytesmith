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
    assert (
        _enc("bencode", {"foo": 42, "bar": "spam"}) == b"d3:bar4:spam3:fooi42ee".hex()
    )


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
    assert _enc("cbor", "plain") != _enc(
        "cbor", '{"a": 1}'
    )  # bare string stays a string


# --- available() guard ---------------------------------------------------------
def test_available_true_when_deps_present():
    from mcp_bytesmith.serialize import available

    assert available() is True


def test_available_false_when_dep_missing(monkeypatch):
    # Force the cbor2/msgpack imports to fail so available() takes its except path.
    import builtins

    from mcp_bytesmith import serialize as serialize_mod

    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name in ("cbor2", "msgpack"):
            raise ImportError(name)
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    assert serialize_mod.available() is False


# --- cbor / msgpack extra reference vectors ------------------------------------
def test_cbor_more_known_vectors():
    # RFC 8949 appendix A: -1 -> 0x20, "" -> 0x60, [1,2,3] -> 0x83010203,
    # {"a":1} -> 0xa1616101, false/true/null -> f4/f5/f6.
    assert _enc("cbor", -1) == "20"
    assert _enc("cbor", "") == "60"
    assert _enc("cbor", [1, 2, 3]) == "83010203"
    assert _enc("cbor", {"a": 1}) == "a1616101"
    assert _enc("cbor", False) == "f4"
    assert _enc("cbor", True) == "f5"
    assert _enc("cbor", None) == "f6"


def test_msgpack_more_known_vectors():
    # MessagePack spec: -1 -> 0xff (negative fixint), "" -> 0xa0 (fixstr len 0),
    # [1,2,3] -> 0x93010203, {"a":1} -> 0x81a16101, false/true/nil -> c2/c3/c0.
    assert _enc("msgpack", -1) == "ff"
    assert _enc("msgpack", "") == "a0"
    assert _enc("msgpack", [1, 2, 3]) == "93010203"
    assert _enc("msgpack", {"a": 1}) == "81a16101"
    assert _enc("msgpack", False) == "c2"
    assert _enc("msgpack", True) == "c3"
    assert _enc("msgpack", None) == "c0"


# --- bencode encode-side type handling -----------------------------------------
def test_bencode_encode_bytes_value():
    # Raw bytes encode as <len>:<bytes> just like strings (0xff 0xfe -> 2:..).
    assert _enc("bencode", b"\xff\xfe") == b"2:\xff\xfe".hex()


def test_bencode_encode_negative_and_zero_int():
    assert _enc("bencode", 0) == b"i0e".hex()
    assert _enc("bencode", -7) == b"i-7e".hex()


def test_bencode_encode_non_string_dict_key_rejected():
    with pytest.raises(ValueError, match="dict keys must be strings"):
        serialize_codec("bencode", "encode", {1: "a"})


def test_bencode_encode_unsupported_type_rejected():
    with pytest.raises(ValueError, match="cannot encode value of type float"):
        serialize_codec("bencode", "encode", 1.5)


# --- bencode decode-side error paths -------------------------------------------
def _bdec_hex(text_bytes):
    return serialize_codec("bencode", "decode", text_bytes.hex())["decoded"]


def test_bencode_decode_empty_truncated():
    with pytest.raises(ValueError, match="truncated"):
        serialize_codec("bencode", "decode", "")


def test_bencode_decode_integer_missing_terminator():
    with pytest.raises(ValueError, match="missing its 'e' terminator"):
        _bdec_hex(b"i42")


@pytest.mark.parametrize("token", [b"ie", b"i-e", b"i03e", b"i-0e"])
def test_bencode_decode_malformed_integer(token):
    with pytest.raises(ValueError, match="malformed bencode integer"):
        _bdec_hex(token)


def test_bencode_decode_list_missing_terminator():
    with pytest.raises(ValueError, match="list is missing its 'e' terminator"):
        _bdec_hex(b"l")


def test_bencode_decode_dict_non_string_key():
    # d i1e 1:a e — an integer key is not a byte-string.
    with pytest.raises(ValueError, match="dict keys must be byte-strings"):
        _bdec_hex(b"di1e1:ae")


def test_bencode_decode_dict_missing_terminator():
    with pytest.raises(ValueError, match="dict is missing its 'e' terminator"):
        _bdec_hex(b"d")


def test_bencode_decode_string_missing_colon():
    with pytest.raises(ValueError, match="missing its ':' separator"):
        _bdec_hex(b"4")


def test_bencode_decode_string_longer_than_input():
    with pytest.raises(ValueError, match="string longer than input"):
        _bdec_hex(b"5:ab")


def test_bencode_decode_unexpected_marker():
    with pytest.raises(ValueError, match="unexpected bencode marker"):
        _bdec_hex(b"x")


def test_bencode_decode_trailing_bytes():
    with pytest.raises(ValueError, match="trailing bytes after the top-level"):
        _bdec_hex(b"i1ei2e")


# --- protobuf decode-side error paths and wire types ---------------------------
def test_protobuf_varint_exceeds_64_bits():
    # field 1 varint, then ten continuation bytes -> shift overflows 64 bits.
    with pytest.raises(ValueError, match="exceeds 64 bits"):
        serialize_codec("protobuf", "decode", "08" + "ff" * 10)


def test_protobuf_field_number_zero_invalid():
    with pytest.raises(ValueError, match="field number 0 is invalid"):
        serialize_codec("protobuf", "decode", "00")


def test_protobuf_i64_field():
    # field 1, wire 1 (i64): tag 0x09 + 8 bytes -> rendered as 0x-prefixed hex.
    assert _dec("protobuf", "090011223344556677") == [
        {"field": 1, "wire_type": "i64", "value": "0x0011223344556677"}
    ]


def test_protobuf_i64_truncated():
    with pytest.raises(ValueError, match="i64 field truncated"):
        serialize_codec("protobuf", "decode", "0900")


def test_protobuf_i32_field():
    # field 1, wire 5 (i32): tag 0x0d + 4 bytes.
    assert _dec("protobuf", "0d11223344") == [
        {"field": 1, "wire_type": "i32", "value": "0x11223344"}
    ]


def test_protobuf_i32_truncated():
    with pytest.raises(ValueError, match="i32 field truncated"):
        serialize_codec("protobuf", "decode", "0d11")


def test_protobuf_length_delimited_truncated():
    # field 2, wire 2, declared length 5 but only 1 byte follows.
    with pytest.raises(ValueError, match="length-delimited field truncated"):
        serialize_codec("protobuf", "decode", "0a05ab")


def test_protobuf_chunk_non_utf8_falls_back_to_hex():
    # field 2, wire 2, content 0xff 0xff: not a sub-message, not UTF-8 -> hex.
    assert _dec("protobuf", "1202ffff") == [
        {"field": 2, "wire_type": "bytes", "value": {"hex": "0xffff"}}
    ]


def test_protobuf_group_wire_type_unsupported():
    # field 1, wire 3 (start-group): tag 0x0b -> rejected.
    with pytest.raises(ValueError, match="unsupported protobuf wire type"):
        serialize_codec("protobuf", "decode", "0b")


# --- decode unknown format -----------------------------------------------------
def test_decode_unknown_format_raises():
    with pytest.raises(ValueError, match="unknown format"):
        serialize_codec("yaml", "decode", "00")


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
