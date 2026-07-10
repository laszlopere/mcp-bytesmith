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

"""TODO 11.9.5 / 11.9.6 / plan §1.17.5, §1.17.2 — serialize_codec asn1 + ssz.

asn1 (DER/BER TLV) is round-tripped against hand-built vectors and a small
X.509-style AlgorithmIdentifier; ssz encode/decode and its hash_tree_root are
checked against vectors independently confirmed with the `remerkleable`
reference implementation."""

import pytest

pytest.importorskip("cbor2", reason="serialize extra (cbor2) not installed")
pytest.importorskip("msgpack", reason="serialize extra (msgpack) not installed")

from mcp_bytesmith.serialize import serialize_codec as SC  # noqa: E402


def _enc(fmt, data, **opt):
    kw = {"options": opt["options"]} if "options" in opt else {}
    return SC(fmt, "encode", data, **kw)


def _dec(fmt, data, **opt):
    kw = {"options": opt["options"]} if "options" in opt else {}
    return SC(fmt, "decode", data, **kw)


# =============================================================================
# ASN.1 (needs asn1crypto; gate the whole module's asn1 tests on it)
# =============================================================================
asn1crypto = pytest.importorskip("asn1crypto", reason="crypto extra not installed")


def _asn1_rt(hexstr):
    """decode(hex) then encode(node) must reproduce the original hex."""
    node = SC("asn1", "decode", hexstr)["decoded"]
    return node, SC("asn1", "encode", node)["encoded"]


def test_asn1_sequence_of_integers():
    node, reenc = _asn1_rt("3006020101020102")  # SEQUENCE { INTEGER 1, INTEGER 2 }
    assert node["type"] == "sequence" and node["constructed"] is True
    assert [c["value"] for c in node["children"]] == [1, 2]
    assert reenc == "3006020101020102"


def test_asn1_integer_negative_and_large():
    # INTEGER -128 -> 02 01 80 ; INTEGER 128 -> 02 02 00 80 (leading zero for sign).
    assert SC("asn1", "decode", "020180")["decoded"]["value"] == -128
    assert SC("asn1", "decode", "02020080")["decoded"]["value"] == 128
    assert (
        SC("asn1", "encode", {"type": "integer", "value": 128})["encoded"] == "02020080"
    )
    assert (
        SC("asn1", "encode", {"type": "integer", "value": -128})["encoded"] == "020180"
    )


def test_asn1_boolean():
    assert SC("asn1", "decode", "0101ff")["decoded"]["value"] is True
    assert SC("asn1", "decode", "010100")["decoded"]["value"] is False
    assert (
        SC("asn1", "encode", {"type": "boolean", "value": True})["encoded"] == "0101ff"
    )


def test_asn1_null():
    node, reenc = _asn1_rt("0500")
    assert node["type"] == "null" and node["value"] is None
    assert reenc == "0500"


def test_asn1_object_identifier():
    # 1.2.840.113549 (RSA) -> 06 06 2a 86 48 86 f7 0d
    node, reenc = _asn1_rt("06062a864886f70d")
    assert node["value"] == "1.2.840.113549"
    assert reenc == "06062a864886f70d"


def test_asn1_oid_first_arc_forms():
    # 2.100.3 exercises a second arc > 39 (only legal when the first arc is 2).
    enc = SC("asn1", "encode", {"type": "object_identifier", "value": "2.100.3"})[
        "encoded"
    ]
    assert SC("asn1", "decode", enc)["decoded"]["value"] == "2.100.3"


def test_asn1_utf8_string():
    node, reenc = _asn1_rt("0c026869")  # UTF8String "hi"
    assert node["type"] == "utf8_string" and node["value"] == "hi"
    assert reenc == "0c026869"


def test_asn1_octet_string_is_value_hex():
    node, reenc = _asn1_rt("0403010203")  # OCTET STRING 0x010203
    assert node["type"] == "octet_string" and node["value_hex"] == "010203"
    assert reenc == "0403010203"


def test_asn1_context_tagged_primitive():
    node, reenc = _asn1_rt("800105")  # [0] primitive, content 0x05
    assert node["class"] == "context" and node["tag"] == 0
    assert node["value_hex"] == "05"
    assert reenc == "800105"


def test_asn1_ber_indefinite_reencodes_to_der():
    # BER indefinite-length SEQUENCE { INTEGER 1 } (00 00 end-of-contents) -> DER.
    node = SC("asn1", "decode", "30800201010000")["decoded"]
    assert [c["value"] for c in node["children"]] == [1]
    assert SC("asn1", "encode", node)["encoded"] == "3003020101"  # definite length


def test_asn1_algorithm_identifier_roundtrip():
    # SEQUENCE { OID 1.2.840.113549.1.1.11 (sha256WithRSA), NULL } — a real X.509 field.
    der = "300d06092a864886f70d01010b0500"
    node, reenc = _asn1_rt(der)
    assert node["children"][0]["value"] == "1.2.840.113549.1.1.11"
    assert node["children"][1]["type"] == "null"
    assert reenc == der


def test_asn1_encode_list_of_values():
    # A JSON array encodes as several concatenated top-level TLVs.
    out = SC(
        "asn1",
        "encode",
        [
            {"type": "integer", "value": 1},
            {"type": "integer", "value": 2},
        ],
    )["encoded"]
    assert out == "020101020102"


def test_asn1_decode_trailing_bytes_rejected():
    with pytest.raises(ValueError, match="trailing bytes"):
        SC("asn1", "decode", "020101020102")  # two top-level INTEGERs


def test_asn1_encode_rejects_unknown_class():
    with pytest.raises(ValueError, match="unknown ASN.1 class"):
        SC("asn1", "encode", {"class": "bogus", "tag": 2, "value_hex": "01"})


def test_asn1_encode_requires_tag_or_type():
    with pytest.raises(ValueError, match="needs a `tag` or a universal `type`"):
        SC("asn1", "encode", {"class": "context", "value_hex": "01"})


def test_asn1_encode_uninterpretable_value_needs_value_hex():
    # octet_string carries value_hex, not value — encoding a bare `value` must fail.
    with pytest.raises(ValueError, match="supply `value_hex`"):
        SC("asn1", "encode", {"type": "octet_string", "value": "abc"})


def test_asn1_missing_extra_raises_actionable(monkeypatch):
    import builtins

    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "asn1crypto" or name.startswith("asn1crypto."):
            raise ImportError(name)
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    with pytest.raises(ValueError, match=r"crypto.*extra.*asn1crypto"):
        SC("asn1", "decode", "0500")


# =============================================================================
# SSZ — encode / decode / hash_tree_root
# =============================================================================
def _ssz(action, data, schema):
    return SC("ssz", action, data, options={"schema": schema})


def test_ssz_uint_widths_roundtrip():
    for t, size in [("uint8", 1), ("uint16", 2), ("uint32", 4), ("uint64", 8)]:
        r = _ssz("encode", 5, t)
        assert r["encoded"] == "05" + "00" * (size - 1)  # little-endian
        assert _ssz("decode", r["encoded"], t)["decoded"] == 5


def test_ssz_uint256_accepts_string():
    big = 2**200 + 7
    r = _ssz("encode", str(big), "uint256")
    assert _ssz("decode", r["encoded"], "uint256")["decoded"] == big


def test_ssz_uint_known_root():
    # uint64(1) root is the little-endian value right-padded to 32 bytes.
    r = _ssz("encode", 1, "uint64")
    assert r["encoded"] == "0100000000000000"
    assert r["root"] == "0x" + "0100000000000000" + "00" * 24


def test_ssz_boolean():
    assert _ssz("encode", True, "boolean")["encoded"] == "01"
    assert _ssz("encode", False, "boolean")["encoded"] == "00"
    assert _ssz("decode", "01", "boolean")["decoded"] is True
    assert _ssz("decode", "00", "bool")["decoded"] is False  # "bool" alias


def test_ssz_container_fixed_known_vector():
    schema = {"type": "container", "fields": [["a", "uint64"], ["b", "boolean"]]}
    r = _ssz("encode", {"a": 1, "b": True}, schema)
    assert r["encoded"] == "010000000000000001"
    # root independently confirmed against remerkleable.
    assert (
        r["root"]
        == "0x56d8a66fbae0300efba7ec2c531973aaae22e7a2ed6ded081b5b32d07a32780a"
    )
    assert _ssz("decode", r["encoded"], schema)["decoded"] == {"a": 1, "b": True}


def test_ssz_container_with_variable_list_field_offsets():
    # a fixed uint64 followed by a variable List[uint8, 32] → a 4-byte offset.
    schema = {
        "type": "container",
        "fields": [
            ["a", "uint64"],
            ["b", {"type": "list", "element": "uint8", "limit": 32}],
        ],
    }
    value = {"a": 1, "b": [1, 2, 3, 4]}
    r = _ssz("encode", value, schema)
    # 8 bytes uint64 + 4-byte offset (=12) + the four list bytes.
    assert r["encoded"] == "0100000000000000" + "0c000000" + "01020304"
    assert _ssz("decode", r["encoded"], schema)["decoded"] == value


def test_ssz_vector_uint16_known_vector():
    schema = {"type": "vector", "element": "uint16", "length": 4}
    r = _ssz("encode", [10, 20, 30, 40], schema)
    assert r["encoded"] == "0a0014001e002800"
    assert r["root"] == "0x0a0014001e002800" + "00" * 24
    assert _ssz("decode", r["encoded"], schema)["decoded"] == [10, 20, 30, 40]


def test_ssz_list_uint8_known_vector():
    schema = {"type": "list", "element": "uint8", "limit": 32}
    r = _ssz("encode", [1, 2, 3, 4], schema)
    assert r["encoded"] == "01020304"
    assert (
        r["root"]
        == "0x95c1f630b7a8428b56d51da4dfaece951967a7035968222ffb560e7c78cd4235"
    )
    assert _ssz("decode", r["encoded"], schema)["decoded"] == [1, 2, 3, 4]


def test_ssz_list_of_containers_roundtrip():
    schema = {
        "type": "list",
        "element": {"type": "container", "fields": [["x", "uint16"], ["y", "uint16"]]},
        "limit": 4,
    }
    value = [{"x": 1, "y": 2}, {"x": 3, "y": 4}]
    r = _ssz("encode", value, schema)
    assert _ssz("decode", r["encoded"], schema)["decoded"] == value


def test_ssz_empty_list():
    schema = {"type": "list", "element": "uint8", "limit": 8}
    r = _ssz("encode", [], schema)
    assert r["encoded"] == ""
    assert _ssz("decode", "", schema)["decoded"] == []


def test_ssz_bitvector_known_vector():
    schema = {"type": "bitvector", "length": 8}
    bits = [True, False, True, True, False, True, False, False]
    r = _ssz("encode", bits, schema)
    assert r["encoded"] == "2d"  # 0b00101101
    assert _ssz("decode", r["encoded"], schema)["decoded"] == bits


def test_ssz_bitlist_known_vector():
    schema = {"type": "bitlist", "limit": 100}
    bits = [True, False, True, True, False, True]
    r = _ssz("encode", bits, schema)
    assert r["encoded"] == "6d"  # bits 0b101101 + delimiter bit at index 6
    # root independently confirmed against remerkleable.
    assert (
        r["root"]
        == "0xe1c705529bd78c7569d410ec93e657dc2bf2915a638d2c37e7729d7f9ad305c7"
    )
    assert _ssz("decode", r["encoded"], schema)["decoded"] == bits


def test_ssz_bytevector_and_bytelist():
    r = _ssz("encode", "0xdeadbeef", {"type": "bytevector", "length": 4})
    assert r["encoded"] == "deadbeef"
    assert (
        _ssz("decode", "deadbeef", {"type": "bytevector", "length": 4})["decoded"]
        == "0xdeadbeef"
    )
    r2 = _ssz("encode", "0xcafe", {"type": "bytelist", "limit": 8})
    assert (
        _ssz("decode", r2["encoded"], {"type": "bytelist", "limit": 8})["decoded"]
        == "0xcafe"
    )


# --- ssz error paths -----------------------------------------------------------
def test_ssz_requires_schema():
    with pytest.raises(ValueError, match="requires `options.schema`"):
        SC("ssz", "encode", 1)
    with pytest.raises(ValueError, match="requires `options.schema`"):
        SC("ssz", "decode", "01")


def test_ssz_uint_out_of_range():
    with pytest.raises(ValueError, match="out of range"):
        _ssz("encode", 256, "uint8")


def test_ssz_uint_rejects_boolean():
    with pytest.raises(ValueError, match="not a boolean"):
        _ssz("encode", True, "uint8")


def test_ssz_vector_length_mismatch():
    with pytest.raises(ValueError, match="vector expects 4 elements"):
        _ssz("encode", [1, 2, 3], {"type": "vector", "element": "uint16", "length": 4})


def test_ssz_list_exceeds_limit():
    with pytest.raises(ValueError, match="exceeds limit"):
        _ssz("encode", [1, 2, 3], {"type": "list", "element": "uint8", "limit": 2})


def test_ssz_bytevector_wrong_size():
    with pytest.raises(ValueError, match="bytevector expects 4 bytes"):
        _ssz("encode", "0xdead", {"type": "bytevector", "length": 4})


def test_ssz_bitlist_exceeds_limit():
    with pytest.raises(ValueError, match="exceeds limit"):
        _ssz("encode", [1, 1, 1], {"type": "bitlist", "limit": 2})


def test_ssz_unknown_type():
    with pytest.raises(ValueError, match="unknown ssz type"):
        _ssz("encode", 1, "uint7")


def test_ssz_stringified_schema_is_parsed():
    # A client that JSON-stringifies the schema object still works.
    schema_str = '{"type": "vector", "element": "uint16", "length": 4}'
    r = SC("ssz", "encode", [10, 20, 30, 40], options={"schema": schema_str})
    assert r["encoded"] == "0a0014001e002800"


def test_ssz_decode_wrong_length():
    with pytest.raises(ValueError, match="uint32 expects 4 bytes"):
        _ssz("decode", "0100", "uint32")
