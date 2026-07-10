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

"""Structured-serialization toolset — gated on the `serialize` extra (TODO 11.9 / plan §1.17).

One multiplexed `serialize_codec(format, action, data, options)` tool dispatches
across the schemaless binary serializers by `format`, mirroring how
`core.encode`/`decode` dispatch on `scheme` — so we avoid six near-identical
encode/decode tools. RLP and ABI keep their own ethereum codecs (11.5-11.6).

All six formats ship: cbor, msgpack (from the `serialize` extra), bencode +
protobuf + ssz (pure-Python, no deps), and asn1 (needs the `crypto` extra's
asn1crypto, checked per-call). `cbor2`/`msgpack` imports are guarded so the
package loads even when the extra is absent — `available()` reports whether this
toolset can register, and server.py only calls `register()` when it can. asn1
and ssz ride along under the same `serialize` gate; asn1 additionally raises an
actionable error at call time when asn1crypto is missing.

Toolset module contract (the pattern every gated toolset follows):
    available() -> bool      can this toolset's deps be imported?
    register(mcp) -> None    attach its @mcp.tool() functions to the app
"""

import hashlib
import json
from typing import Annotated, Any, Literal

from pydantic import Field

from mcp_bytesmith.core import _to_bytes


def available() -> bool:
    """True when the `serialize` extra is installed (cbor2 + msgpack importable)."""
    try:
        import cbor2  # noqa: F401
        import msgpack  # noqa: F401
    except ImportError:
        return False
    return True


# --- bencode (BitTorrent; ints / byte-strings / lists / dicts) -----------------
# A tiny, RLP-simple grammar: i<int>e, <len>:<bytes>, l<items>e, d<pairs>e.
# Dict keys are byte-strings, emitted sorted by their raw bytes (BEP-3).
def _bencode_encode(value: Any) -> bytes:
    if isinstance(value, bool):
        # bool is an int subclass; bencode has no boolean — reject explicitly.
        raise ValueError("bencode has no boolean type; use 0/1 instead")
    if isinstance(value, int):
        return b"i" + str(value).encode("ascii") + b"e"
    if isinstance(value, str):
        body = value.encode("utf-8")
        return str(len(body)).encode("ascii") + b":" + body
    if isinstance(value, (bytes, bytearray)):
        body = bytes(value)
        return str(len(body)).encode("ascii") + b":" + body
    if isinstance(value, list):
        return b"l" + b"".join(_bencode_encode(item) for item in value) + b"e"
    if isinstance(value, dict):
        items = []
        for key in value:
            if not isinstance(key, str):
                raise ValueError("bencode dict keys must be strings")
            items.append((key.encode("utf-8"), value[key]))
        items.sort(key=lambda kv: kv[0])  # keys sorted as raw byte strings
        out = b"d"
        for raw_key, val in items:
            out += str(len(raw_key)).encode("ascii") + b":" + raw_key
            out += _bencode_encode(val)
        return out + b"e"
    raise ValueError(f"bencode cannot encode value of type {type(value).__name__}")


def _bencode_string(value: bytes) -> str:
    """Render a bencode byte-string as UTF-8 text, else a bare-hex string."""
    try:
        return value.decode("utf-8")
    except UnicodeDecodeError:
        return value.hex()


def _bencode_decode_item(data: bytes, pos: int) -> tuple[Any, int]:
    if pos >= len(data):
        raise ValueError("bencode input truncated")
    marker = data[pos : pos + 1]
    if marker == b"i":  # integer: i<digits>e
        end = data.find(b"e", pos)
        if end < 0:
            raise ValueError("bencode integer is missing its 'e' terminator")
        token = data[pos + 1 : end]
        if (
            token in (b"", b"-")
            or (token[:1] == b"0" and token != b"0")
            or token[:2] == b"-0"
        ):
            raise ValueError(f"malformed bencode integer {token!r}")
        return int(token), end + 1
    if marker == b"l":  # list: l<items>e
        items, cur = [], pos + 1
        while cur < len(data) and data[cur : cur + 1] != b"e":
            value, cur = _bencode_decode_item(data, cur)
            items.append(value)
        if cur >= len(data):
            raise ValueError("bencode list is missing its 'e' terminator")
        return items, cur + 1
    if marker == b"d":  # dict: d<key><value>...e (keys are byte-strings)
        result, cur = {}, pos + 1
        while cur < len(data) and data[cur : cur + 1] != b"e":
            key, cur = _bencode_decode_item(data, cur)
            if not isinstance(key, str):
                raise ValueError("bencode dict keys must be byte-strings")
            value, cur = _bencode_decode_item(data, cur)
            result[key] = value
        if cur >= len(data):
            raise ValueError("bencode dict is missing its 'e' terminator")
        return result, cur + 1
    if marker.isdigit():  # byte-string: <len>:<bytes>
        colon = data.find(b":", pos)
        if colon < 0:
            raise ValueError("bencode string is missing its ':' separator")
        length = int(data[pos:colon])
        start = colon + 1
        end = start + length
        if end > len(data):
            raise ValueError("bencode string longer than input")
        return _bencode_string(data[start:end]), end
    raise ValueError(f"unexpected bencode marker {marker!r} at offset {pos}")


# --- protobuf raw wire decode (schemaless; like `protoc --decode_raw`) ----------
# No .proto schema, so we surface (field number, wire type, value) only — never
# field names. Length-delimited fields are recursively decoded as a sub-message
# when they parse cleanly, else shown as UTF-8 text, else as hex.
def _read_varint(data: bytes, pos: int) -> tuple[int, int]:
    result = shift = 0
    while True:
        if pos >= len(data):
            raise ValueError("protobuf varint truncated")
        byte = data[pos]
        result |= (byte & 0x7F) << shift
        pos += 1
        if not byte & 0x80:
            return result, pos
        shift += 7
        if shift > 63:
            raise ValueError("protobuf varint exceeds 64 bits")


def _protobuf_decode_message(data: bytes) -> list[dict]:
    fields, pos = [], 0
    while pos < len(data):
        tag, pos = _read_varint(data, pos)
        field_number, wire_type = tag >> 3, tag & 0x07
        if field_number == 0:
            raise ValueError("protobuf field number 0 is invalid")
        if wire_type == 0:  # varint
            value, pos = _read_varint(data, pos)
            fields.append(
                {"field": field_number, "wire_type": "varint", "value": value}
            )
        elif wire_type == 1:  # 64-bit fixed
            if pos + 8 > len(data):
                raise ValueError("protobuf i64 field truncated")
            fields.append(
                {
                    "field": field_number,
                    "wire_type": "i64",
                    "value": "0x" + data[pos : pos + 8].hex(),
                }
            )
            pos += 8
        elif wire_type == 2:  # length-delimited
            length, pos = _read_varint(data, pos)
            end = pos + length
            if end > len(data):
                raise ValueError("protobuf length-delimited field truncated")
            chunk = data[pos:end]
            pos = end
            fields.append(
                {
                    "field": field_number,
                    "wire_type": "bytes",
                    "value": _protobuf_chunk(chunk),
                }
            )
        elif wire_type == 5:  # 32-bit fixed
            if pos + 4 > len(data):
                raise ValueError("protobuf i32 field truncated")
            fields.append(
                {
                    "field": field_number,
                    "wire_type": "i32",
                    "value": "0x" + data[pos : pos + 4].hex(),
                }
            )
            pos += 4
        else:  # 3/4 are deprecated start/end-group markers
            raise ValueError(
                f"unsupported protobuf wire type {wire_type} (groups are not supported)"
            )
    return fields


def _protobuf_chunk(chunk: bytes) -> Any:
    """Interpret a length-delimited chunk: sub-message, then UTF-8 text, then hex."""
    if chunk:
        try:
            return {"message": _protobuf_decode_message(chunk)}
        except ValueError:
            pass
    try:
        return {"string": chunk.decode("utf-8")}
    except UnicodeDecodeError:
        return {"hex": "0x" + chunk.hex()}


# --- ASN.1 DER/BER (schemaless TLV; §1.17.5) -----------------------------------
# A tag-length-value tree, decoded/encoded through asn1crypto's low-level
# parser.parse / parser.emit (which do the length framing) — we own the recursion
# and the interpretation of the common UNIVERSAL primitives. Every node carries
# {class, tag, [type], constructed} plus either `children` (constructed) or a
# `value` (interpreted primitive) / `value_hex` (raw primitive) — enough to
# round-trip. BER indefinite-length input re-encodes to definite-length DER.
_ASN1_CLASSES = {0: "universal", 1: "application", 2: "context", 3: "private"}
_ASN1_CLASS_NUMS = {v: k for k, v in _ASN1_CLASSES.items()}
_ASN1_UNIVERSAL = {
    1: "boolean", 2: "integer", 3: "bit_string", 4: "octet_string",
    5: "null", 6: "object_identifier", 10: "enumerated", 12: "utf8_string",
    16: "sequence", 17: "set", 18: "numeric_string", 19: "printable_string",
    20: "t61_string", 22: "ia5_string", 23: "utc_time", 24: "generalized_time",
    26: "visible_string", 27: "general_string", 30: "bmp_string",
}  # fmt: skip
_ASN1_UNIVERSAL_NUM = {v: k for k, v in _ASN1_UNIVERSAL.items()}
# Interpretable string types and the codec each decodes/encodes with.
_ASN1_TEXT_CODECS = {
    "utf8_string": "utf-8", "printable_string": "ascii", "ia5_string": "ascii",
    "numeric_string": "ascii", "visible_string": "ascii", "general_string": "utf-8",
    "bmp_string": "utf-16-be", "utc_time": "ascii", "generalized_time": "ascii",
    "t61_string": "latin-1",
}  # fmt: skip


def _asn1_parser():
    """Lazily import asn1crypto's low-level parser (the `crypto` extra)."""
    try:
        from asn1crypto import parser
    except ImportError as exc:  # per-format extra, gated at call time
        raise ValueError(
            "format='asn1' needs the `crypto` extra (asn1crypto); "
            "install mcp-bytesmith[crypto]"
        ) from exc
    return parser


def _oid_decode(data: bytes) -> str:
    """Decode an OBJECT IDENTIFIER's content bytes to a dotted-decimal string."""
    if not data:
        raise ValueError("empty OBJECT IDENTIFIER")
    values, val = [], 0
    for byte in data:  # each arc is a base-128 group; the first combines two arcs
        val = (val << 7) | (byte & 0x7F)
        if not byte & 0x80:
            values.append(val)
            val = 0
    head = values[0]
    arcs = [0, head] if head < 40 else ([1, head - 40] if head < 80 else [2, head - 80])
    return ".".join(str(a) for a in [*arcs, *values[1:]])


def _oid_encode(oid: str) -> bytes:
    """Encode a dotted-decimal OID string to its content bytes."""
    try:
        arcs = [int(p) for p in oid.split(".")]
    except ValueError as exc:
        raise ValueError(f"malformed OID {oid!r}") from exc
    if len(arcs) < 2 or arcs[0] > 2 or (arcs[0] < 2 and arcs[1] > 39):
        raise ValueError(f"invalid OID arcs in {oid!r}")

    def base128(n: int) -> bytes:
        groups = [n & 0x7F]
        n >>= 7
        while n:
            groups.append((n & 0x7F) | 0x80)
            n >>= 7
        return bytes(reversed(groups))

    out = base128(40 * arcs[0] + arcs[1])
    for arc in arcs[2:]:
        out += base128(arc)
    return out


def _asn1_int_encode(n: int) -> bytes:
    """Two's-complement minimal-length INTEGER content (DER)."""
    magnitude = n if n >= 0 else ~n  # ~n handles negative powers of two
    length = magnitude.bit_length() // 8 + 1
    return n.to_bytes(length, "big", signed=True)


def _asn1_node(class_: int, method: int, tag: int, content: bytes, parser) -> dict:
    node: dict[str, Any] = {"class": _ASN1_CLASSES[class_], "tag": tag}
    if class_ == 0 and tag in _ASN1_UNIVERSAL:
        node["type"] = _ASN1_UNIVERSAL[tag]
    node["constructed"] = bool(method)
    if method:  # constructed → recurse over the content
        node["children"] = _asn1_children(content, parser)
        return node
    _asn1_set_primitive(node, tag if class_ == 0 else None, content)
    return node


def _asn1_set_primitive(node: dict, universal_tag: int | None, content: bytes) -> None:
    typ = _ASN1_UNIVERSAL.get(universal_tag) if universal_tag is not None else None
    if typ == "boolean":
        node["value"] = any(content)
    elif typ in ("integer", "enumerated"):
        node["value"] = int.from_bytes(content, "big", signed=True) if content else 0
    elif typ == "null":
        node["value"] = None
    elif typ == "object_identifier":
        node["value"] = _oid_decode(content)
    elif typ in _ASN1_TEXT_CODECS:
        try:
            node["value"] = content.decode(_ASN1_TEXT_CODECS[typ])
        except UnicodeDecodeError:
            node["value_hex"] = content.hex()
    else:  # octet/bit string, unknown universal tag, or non-universal primitive
        node["value_hex"] = content.hex()


def _asn1_children(data: bytes, parser) -> list[dict]:
    nodes, rest = [], data
    while rest:
        class_, method, tag, header, content, trailer = parser.parse(rest)
        nodes.append(_asn1_node(class_, method, tag, content, parser))
        rest = rest[len(header) + len(content) + len(trailer) :]
    return nodes


def _asn1_decode(raw: bytes, parser) -> dict:
    class_, method, tag, header, content, trailer = parser.parse(raw)
    if len(header) + len(content) + len(trailer) != len(raw):
        raise ValueError("trailing bytes after the top-level ASN.1 value")
    return _asn1_node(class_, method, tag, content, parser)


def _asn1_encode(value: Any, parser) -> bytes:
    if isinstance(value, list):  # several concatenated top-level values
        return b"".join(_asn1_encode_node(n, parser) for n in value)
    return _asn1_encode_node(value, parser)


def _asn1_encode_node(node: Any, parser) -> bytes:
    if not isinstance(node, dict):
        raise ValueError("an ASN.1 node must be an object")
    cls = node.get("class", "universal")
    if cls not in _ASN1_CLASS_NUMS:
        raise ValueError(f"unknown ASN.1 class {cls!r}")
    class_ = _ASN1_CLASS_NUMS[cls]
    if "tag" in node:
        tag = node["tag"]
    elif node.get("type") in _ASN1_UNIVERSAL_NUM:
        tag = _ASN1_UNIVERSAL_NUM[node["type"]]
    else:
        raise ValueError("an ASN.1 node needs a `tag` or a universal `type`")
    if node.get("constructed", "children" in node):
        content = b"".join(
            _asn1_encode_node(c, parser) for c in node.get("children", [])
        )
        return parser.emit(class_, 1, tag, content)
    return parser.emit(class_, 0, tag, _asn1_encode_primitive(node, class_, tag))


def _asn1_encode_primitive(node: dict, class_: int, tag: int) -> bytes:
    if "value_hex" in node:
        return _to_bytes(node["value_hex"], "hex")
    if "value" not in node:
        return b""
    typ = node.get("type")
    if typ is None and class_ == 0:
        typ = _ASN1_UNIVERSAL.get(tag)
    value = node["value"]
    if typ == "boolean":
        return b"\xff" if value else b"\x00"
    if typ in ("integer", "enumerated"):
        return _asn1_int_encode(int(value))
    if typ == "null":
        return b""
    if typ == "object_identifier":
        return _oid_encode(str(value))
    if typ in _ASN1_TEXT_CODECS:
        return str(value).encode(_ASN1_TEXT_CODECS[typ])
    raise ValueError(
        f"cannot ASN.1-encode a primitive value for type {typ!r}; supply `value_hex`"
    )


# --- SSZ (Simple Serialize; ETH consensus layer; §1.17.2) ----------------------
# Schema-driven (unlike the self-describing formats): options.schema names the
# type, and we serialize/deserialize AND compute the hash_tree_root. Pure-Python
# (SHA-256 merkleization is stdlib, so no `ethereum` dep is actually needed).
# Schema grammar (JSON): a basic-type string ("uint8".."uint256", "boolean"), or
#   {"type":"vector","element":<schema>,"length":N}
#   {"type":"list","element":<schema>,"limit":N}
#   {"type":"container","fields":[[name,<schema>],...]}
#   {"type":"bitvector","length":N} | {"type":"bitlist","limit":N}
#   {"type":"bytevector","length":N} | {"type":"bytelist","limit":N}
_SSZ_UINT_BITS = {
    "uint8": 8, "uint16": 16, "uint32": 32,
    "uint64": 64, "uint128": 128, "uint256": 256,
}  # fmt: skip
_SSZ_OFFSET = 4  # BYTES_PER_LENGTH_OFFSET
_SSZ_ZERO = b"\x00" * 32


def _ssz_norm(schema: Any) -> dict:
    """Canonicalize a schema to a {'type': ...} dict (basic names → dict form)."""
    if isinstance(schema, str):
        name = "boolean" if schema == "bool" else schema
        if name in _SSZ_UINT_BITS or name == "boolean":
            return {"type": name}
        raise ValueError(f"unknown ssz type {schema!r}")
    if isinstance(schema, dict) and "type" in schema:
        return {**schema, "type": "boolean"} if schema["type"] == "bool" else schema
    raise ValueError("ssz schema must be a type name or an object with a 'type' field")


def _ssz_is_basic(s: dict) -> bool:
    return s["type"] in _SSZ_UINT_BITS or s["type"] == "boolean"


def _ssz_basic_size(s: dict) -> int:
    return _SSZ_UINT_BITS[s["type"]] // 8 if s["type"] in _SSZ_UINT_BITS else 1


def _ssz_is_fixed(schema: Any) -> bool:
    s = _ssz_norm(schema)
    t = s["type"]
    if _ssz_is_basic(s) or t in ("bytevector", "bitvector"):
        return True
    if t == "vector":
        return _ssz_is_fixed(s["element"])
    if t == "container":
        return all(_ssz_is_fixed(f[1]) for f in s["fields"])
    return False  # list, bytelist, bitlist, or a variable-element vector


def _ssz_fixed_size(schema: Any) -> int:
    s = _ssz_norm(schema)
    t = s["type"]
    if _ssz_is_basic(s):
        return _ssz_basic_size(s)
    if t == "bytevector":
        return int(s["length"])
    if t == "bitvector":
        return (int(s["length"]) + 7) // 8
    if t == "vector":
        return int(s["length"]) * _ssz_fixed_size(s["element"])
    if t == "container":
        return sum(_ssz_fixed_size(f[1]) for f in s["fields"])
    raise ValueError(f"ssz type {t!r} is not fixed-size")


def _ssz_uint(value: Any, t: str) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{t} value must be an integer, not a boolean")
    n = int(value) if isinstance(value, str) else value
    if not isinstance(n, int):
        raise ValueError(f"{t} value must be an integer")
    if not 0 <= n < (1 << _SSZ_UINT_BITS[t]):
        raise ValueError(f"{n} out of range for {t}")
    return n


def _ssz_bit(b: Any) -> int:
    if b is True or b == 1:
        return 1
    if b is False or b == 0:
        return 0
    raise ValueError("ssz bit must be 0/1 or a boolean")


def _ssz_pack_bits(bits: list[int], nbytes: int) -> bytes:
    out = bytearray(nbytes)
    for i, bit in enumerate(bits):
        if bit:
            out[i // 8] |= 1 << (i % 8)
    return bytes(out)


def _ssz_serialize(schema: Any, value: Any) -> bytes:
    s = _ssz_norm(schema)
    t = s["type"]
    if t in _SSZ_UINT_BITS:
        return _ssz_uint(value, t).to_bytes(_SSZ_UINT_BITS[t] // 8, "little")
    if t == "boolean":
        if not isinstance(value, bool):
            raise ValueError("boolean value must be true or false")
        return b"\x01" if value else b"\x00"
    if t == "bytevector":
        raw = _to_bytes(value, "hex")
        if len(raw) != int(s["length"]):
            raise ValueError(f"bytevector expects {s['length']} bytes, got {len(raw)}")
        return raw
    if t == "bytelist":
        raw = _to_bytes(value, "hex")
        if len(raw) > int(s["limit"]):
            raise ValueError(f"bytelist exceeds limit {s['limit']} ({len(raw)} bytes)")
        return raw
    if t == "bitvector":
        bits = [_ssz_bit(b) for b in value]
        if len(bits) != int(s["length"]):
            raise ValueError(f"bitvector expects {s['length']} bits, got {len(bits)}")
        return _ssz_pack_bits(bits, (int(s["length"]) + 7) // 8)
    if t == "bitlist":
        bits = [_ssz_bit(b) for b in value]
        if len(bits) > int(s["limit"]):
            raise ValueError(f"bitlist exceeds limit {s['limit']} ({len(bits)} bits)")
        return _ssz_pack_bits([*bits, 1], (len(bits) + 8) // 8)  # + delimiter bit
    if t == "vector":
        if len(value) != int(s["length"]):
            raise ValueError(f"vector expects {s['length']} elements, got {len(value)}")
        return _ssz_serialize_series([s["element"]] * len(value), value)
    if t == "list":
        if len(value) > int(s["limit"]):
            raise ValueError(f"list exceeds limit {s['limit']} ({len(value)} elements)")
        return _ssz_serialize_series([s["element"]] * len(value), value)
    if t == "container":
        return _ssz_serialize_series(
            [f[1] for f in s["fields"]], [value[f[0]] for f in s["fields"]]
        )
    raise ValueError(f"unknown ssz type {t!r}")


def _ssz_serialize_series(schemas: list, values: list) -> bytes:
    fixed: list[bytes | None] = []
    variable: list[bytes] = []
    for sc, val in zip(schemas, values):
        if _ssz_is_fixed(sc):
            fixed.append(_ssz_serialize(sc, val))
            variable.append(b"")
        else:
            fixed.append(None)
            variable.append(_ssz_serialize(sc, val))
    fixed_len = sum(len(p) if p is not None else _SSZ_OFFSET for p in fixed)
    out, offset = bytearray(), fixed_len
    for fp, vp in zip(fixed, variable):
        if fp is not None:
            out += fp
        else:  # a 4-byte offset into the variable region
            out += offset.to_bytes(_SSZ_OFFSET, "little")
            offset += len(vp)
    return bytes(out) + b"".join(variable)


def _ssz_deserialize(schema: Any, data: bytes) -> Any:
    s = _ssz_norm(schema)
    t = s["type"]
    if t in _SSZ_UINT_BITS:
        size = _SSZ_UINT_BITS[t] // 8
        if len(data) != size:
            raise ValueError(f"{t} expects {size} bytes, got {len(data)}")
        return int.from_bytes(data, "little")
    if t == "boolean":
        if len(data) != 1 or data[0] > 1:
            raise ValueError("boolean expects a single 0x00/0x01 byte")
        return data[0] == 1
    if t == "bytevector":
        if len(data) != int(s["length"]):
            raise ValueError(f"bytevector expects {s['length']} bytes, got {len(data)}")
        return "0x" + data.hex()
    if t == "bytelist":
        if len(data) > int(s["limit"]):
            raise ValueError(f"bytelist exceeds limit {s['limit']} ({len(data)} bytes)")
        return "0x" + data.hex()
    if t == "bitvector":
        return _ssz_unpack_bits(data, int(s["length"]), delimit=False)
    if t == "bitlist":
        return _ssz_unpack_bits(data, int(s["limit"]), delimit=True)
    if t == "vector":
        return _ssz_deserialize_series([s["element"]] * int(s["length"]), data)
    if t == "list":
        return _ssz_deserialize_series(_ssz_list_schemas(s, data), data)
    if t == "container":
        vals = _ssz_deserialize_series([f[1] for f in s["fields"]], data)
        return {f[0]: v for f, v in zip(s["fields"], vals)}
    raise ValueError(f"unknown ssz type {t!r}")


def _ssz_list_schemas(s: dict, data: bytes) -> list:
    """Derive a variable-length list's element count from the serialized data."""
    el, limit = s["element"], int(s["limit"])
    if _ssz_is_fixed(el):
        size = _ssz_fixed_size(el)
        if size == 0:
            count = 0
        elif len(data) % size:
            raise ValueError("list data is not a whole number of fixed elements")
        else:
            count = len(data) // size
    elif not data:
        count = 0
    else:  # the first 4-byte offset points past all the offsets → element count
        count = int.from_bytes(data[:_SSZ_OFFSET], "little") // _SSZ_OFFSET
    if count > limit:
        raise ValueError(f"list of {count} elements exceeds limit {limit}")
    return [el] * count


def _ssz_deserialize_series(schemas: list, data: bytes) -> list:
    n = len(schemas)
    sizes = [_ssz_fixed_size(s) if _ssz_is_fixed(s) else None for s in schemas]
    spans: list = [None] * n
    pos = 0
    for i, size in enumerate(sizes):
        if size is not None:
            spans[i] = data[pos : pos + size]
            pos += size
        else:
            spans[i] = int.from_bytes(data[pos : pos + _SSZ_OFFSET], "little")
            pos += _SSZ_OFFSET
    var = [i for i, size in enumerate(sizes) if size is None]
    for j, i in enumerate(var):  # variable field spans its offset → next offset
        start = spans[i]
        end = spans[var[j + 1]] if j + 1 < len(var) else len(data)
        spans[i] = data[start:end]
    return [_ssz_deserialize(schemas[i], spans[i]) for i in range(n)]


def _ssz_unpack_bits(data: bytes, capacity: int, delimit: bool) -> list[bool]:
    total = len(data) * 8
    bits = [bool((data[i // 8] >> (i % 8)) & 1) for i in range(total)]
    if not delimit:
        return bits[:capacity]
    hi = next((i for i in range(total - 1, -1, -1) if bits[i]), -1)
    if hi < 0:
        raise ValueError("bitlist is missing its length-delimiter bit")
    if hi > capacity:
        raise ValueError(f"bitlist of {hi} bits exceeds limit {capacity}")
    return bits[:hi]


# --- SSZ merkleization (hash_tree_root) ----------------------------------------
def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _ssz_pack(raw: bytes) -> list[bytes]:
    """Right-pad to a multiple of 32 and split into 32-byte chunks."""
    if len(raw) % 32:
        raw += b"\x00" * (32 - len(raw) % 32)
    return [raw[i : i + 32] for i in range(0, len(raw), 32)]


def _merkleize(chunks: list[bytes], limit: int | None = None) -> bytes:
    count = len(chunks)
    if limit is not None and count > limit:
        raise ValueError(f"ssz: {count} chunks exceed merkleization limit {limit}")
    target = count if limit is None else limit
    width = 1
    while width < target:
        width *= 2
    nodes = [*chunks, *([_SSZ_ZERO] * (width - count))] or [_SSZ_ZERO]
    while len(nodes) > 1:
        nodes = [_sha256(nodes[i] + nodes[i + 1]) for i in range(0, len(nodes), 2)]
    return nodes[0]


def _mix_in_length(root: bytes, length: int) -> bytes:
    return _sha256(root + length.to_bytes(32, "little"))


def _ssz_htr(schema: Any, value: Any) -> bytes:
    s = _ssz_norm(schema)
    t = s["type"]
    if _ssz_is_basic(s):
        return _ssz_serialize(s, value).ljust(32, b"\x00")
    if t == "bytevector":
        raw = _to_bytes(value, "hex")
        return _merkleize(_ssz_pack(raw), (int(s["length"]) + 31) // 32)
    if t == "bytelist":
        raw = _to_bytes(value, "hex")
        root = _merkleize(_ssz_pack(raw), (int(s["limit"]) + 31) // 32)
        return _mix_in_length(root, len(raw))
    if t == "bitvector":
        return _merkleize(
            _ssz_pack(_ssz_serialize(s, value)), (int(s["length"]) + 255) // 256
        )
    if t == "bitlist":
        packed = _ssz_pack_bits([_ssz_bit(b) for b in value], (len(value) + 7) // 8)
        root = _merkleize(_ssz_pack(packed), (int(s["limit"]) + 255) // 256)
        return _mix_in_length(root, len(value))
    if t == "vector":
        return _ssz_htr_series(s["element"], value, int(s["length"]), is_list=False)
    if t == "list":
        return _ssz_htr_series(s["element"], value, int(s["limit"]), is_list=True)
    if t == "container":
        roots = [_ssz_htr(f[1], value[f[0]]) for f in s["fields"]]
        return _merkleize(roots)
    raise ValueError(f"unknown ssz type {t!r}")


def _ssz_htr_series(element: Any, value: list, bound: int, is_list: bool) -> bytes:
    el = _ssz_norm(element)
    if _ssz_is_basic(el):
        packed = _ssz_pack(b"".join(_ssz_serialize(el, v) for v in value))
        limit = (bound * _ssz_basic_size(el) + 31) // 32
        root = _merkleize(packed, limit)
    else:
        root = _merkleize([_ssz_htr(el, v) for v in value], bound)
    return _mix_in_length(root, len(value)) if is_list else root


# --- the multiplexed tool ------------------------------------------------------
def serialize_codec(
    format: Annotated[
        Literal["cbor", "msgpack", "bencode", "protobuf", "asn1", "ssz"],
        Field(
            description="Serializer: cbor/msgpack/bencode (encode+decode), asn1 (DER/BER TLV, encode+decode), ssz (schema-driven, encode+decode+root), or protobuf (decode-only raw wire)."
        ),
    ],
    action: Annotated[
        Literal["encode", "decode"],
        Field(
            description="encode a JSON value to hex, or decode a hex string back to a value."
        ),
    ],
    data: Annotated[
        Any,
        Field(
            description="When encoding, the JSON value (string starting with { or [ is parsed as JSON); when decoding, a hex string (0x prefix optional)."
        ),
    ] = None,
    options: Annotated[
        dict[str, Any] | None,
        Field(
            description="Per-format typing. `options.schema` is REQUIRED for ssz (the SSZ type) and unused by the other formats."
        ),
    ] = None,
) -> dict:
    """Encode / decode schemaless structured data across these binary serializers.

    ONE codec multiplexed by `format` (cf. encode/decode's scheme dispatch):
      cbor (RFC 8949) | msgpack | bencode | asn1 (DER/BER)  — encode + decode
      ssz (Simple Serialize)  — encode + decode, schema-driven, also returns `root`
      protobuf  — decode only (raw wire format; no field names without a .proto)

    Encode `data` is a JSON value (object/array/string/number/bool/null); a string
    that begins with `{` or `[` is parsed as JSON (clients sometimes stringify
    structures). Decode `data` is a hex string (an optional 0x prefix is accepted).

    asn1 is a schemaless TLV tree: each node is {class, tag, [type], constructed}
    plus `children` (constructed) or `value`/`value_hex` (primitive); BER
    indefinite-length input re-encodes to definite-length DER. asn1 needs the
    `crypto` extra (asn1crypto). ssz is schema-DRIVEN — pass the SSZ type in
    `options.schema` (a basic name like "uint64"/"boolean", or an object such as
    {"type":"container","fields":[["a","uint64"],["b",{"type":"list","element":"uint8","limit":32}]]});
    both actions also return the 32-byte hash_tree_root as `root`.

    Returns include the echoed `format` and `action`, plus the payload key:
      action=encode -> {format, action, encoded} (+ `root` for ssz); `encoded` is bare hex.
      action=decode -> {format, action, decoded} (+ `root` for ssz). For protobuf, `decoded`
        is a list of {field, wire_type, value} entries (repeated fields appear more than
        once); bencode/protobuf byte-strings render as UTF-8 text when valid, else hex.
    Example: serialize_codec("cbor","encode",[1,2,3])
      -> {"format":"cbor","action":"encode","encoded":"83010203"}

    Errors: protobuf rejects encode (decode-only); bencode rejects booleans (use
    0/1) and requires string dict keys; ssz requires `options.schema`; action=decode
    requires a hex string `data`.
    """
    opts = json.loads(options) if isinstance(options, str) else (options or {})
    if not isinstance(opts, dict):
        raise ValueError("`options` must be an object")
    schema = opts.get("schema")
    if isinstance(schema, str) and schema.lstrip()[:1] in ("{", "["):
        schema = json.loads(schema)  # client stringified the schema object

    if action == "encode":
        value = data
        if isinstance(data, str) and data.lstrip()[:1] in ("{", "["):
            value = json.loads(data)  # client stringified the structure
        if format == "protobuf":
            raise ValueError(
                "protobuf is decode-only — no field names without a .proto schema"
            )
        if format == "cbor":
            import cbor2

            encoded = cbor2.dumps(value)
        elif format == "msgpack":
            import msgpack

            encoded = msgpack.packb(value, use_bin_type=True)
        elif format == "bencode":
            encoded = _bencode_encode(value)
        elif format == "asn1":
            encoded = _asn1_encode(value, _asn1_parser())
        elif format == "ssz":
            if schema is None:
                raise ValueError("format='ssz' requires `options.schema`")
            return {
                "format": "ssz",
                "action": "encode",
                "encoded": _ssz_serialize(schema, value).hex(),
                "root": "0x" + _ssz_htr(schema, value).hex(),
            }
        else:
            raise ValueError(
                f"unknown format {format!r}; expected 'cbor', 'msgpack', "
                f"'bencode', 'protobuf', 'asn1', or 'ssz'"
            )
        return {"format": format, "action": "encode", "encoded": encoded.hex()}

    if action == "decode":
        if not isinstance(data, str):
            raise ValueError("action=decode requires a hex string `data`")
        raw = _to_bytes(data, "hex")
        if format == "cbor":
            import cbor2

            decoded = cbor2.loads(raw)
        elif format == "msgpack":
            import msgpack

            decoded = msgpack.unpackb(raw, raw=False, strict_map_key=False)
        elif format == "bencode":
            decoded, pos = _bencode_decode_item(raw, 0)
            if pos != len(raw):
                raise ValueError("trailing bytes after the top-level bencode value")
        elif format == "protobuf":
            decoded = _protobuf_decode_message(raw)
        elif format == "asn1":
            decoded = _asn1_decode(raw, _asn1_parser())
        elif format == "ssz":
            if schema is None:
                raise ValueError("format='ssz' requires `options.schema`")
            decoded = _ssz_deserialize(schema, raw)
            return {
                "format": "ssz",
                "action": "decode",
                "decoded": decoded,
                "root": "0x" + _ssz_htr(schema, decoded).hex(),
            }
        else:
            raise ValueError(
                f"unknown format {format!r}; expected 'cbor', 'msgpack', "
                f"'bencode', 'protobuf', 'asn1', or 'ssz'"
            )
        return {"format": format, "action": "decode", "decoded": decoded}

    raise ValueError(f"unknown action {action!r}; expected 'encode' or 'decode'")


def register(mcp) -> None:
    """Register the serialize toolset's tools against the FastMCP app."""
    mcp.tool()(serialize_codec)
