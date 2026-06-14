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

This first cut ships the four-format core: cbor, msgpack (both from the
`serialize` extra), and bencode + protobuf (pure-Python, no deps). ASN.1 and SSZ
are deferred. `cbor2`/`msgpack` imports are guarded so the package loads even
when the extra is absent — `available()` reports whether this toolset can
register, and server.py only calls `register()` when it can.

Toolset module contract (the pattern every gated toolset follows):
    available() -> bool      can this toolset's deps be imported?
    register(mcp) -> None    attach its @mcp.tool() functions to the app
"""

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


# --- the multiplexed tool ------------------------------------------------------
def serialize_codec(
    format: Annotated[
        Literal["cbor", "msgpack", "bencode", "protobuf"],
        Field(
            description="Serializer: cbor, msgpack, bencode (encode+decode), or protobuf (decode-only raw wire)."
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
            description="Reserved for future per-format typing (e.g. an ssz schema); currently unused."
        ),
    ] = None,
) -> dict:
    """Encode / decode schemaless structured data across these binary serializers.

    ONE codec multiplexed by `format` (cf. encode/decode's scheme dispatch):
      cbor (RFC 8949) | msgpack | bencode  — encode + decode
      protobuf  — decode only (raw wire format; no field names without a .proto)

    Encode `data` is a JSON value (object/array/string/number/bool/null); a string
    that begins with `{` or `[` is parsed as JSON (clients sometimes stringify
    structures). Decode `data` is a hex string (an optional 0x prefix is accepted).

    Returns include the echoed `format` and `action`, plus the payload key:
      action=encode -> {format, action, encoded} where `encoded` is bare lowercase hex.
      action=decode -> {format, action, decoded}. For protobuf, `decoded` is a list of
        {field, wire_type, value} entries (repeated fields appear more than once);
        bencode/protobuf byte-strings render as UTF-8 text when valid, else hex.
    Example: serialize_codec("cbor","encode",[1,2,3])
      -> {"format":"cbor","action":"encode","encoded":"83010203"}

    Errors: protobuf rejects encode (decode-only); bencode rejects booleans (use
    0/1) and requires string dict keys; action=decode requires a hex string `data`.
    `options` is reserved (per-format typing, e.g. a future ssz schema) and unused.
    """
    opts = json.loads(options) if isinstance(options, str) else (options or {})
    if not isinstance(opts, dict):
        raise ValueError("`options` must be an object")

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
        else:
            raise ValueError(
                f"unknown format {format!r}; expected 'cbor', 'msgpack', "
                f"'bencode', or 'protobuf'"
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
        else:
            raise ValueError(
                f"unknown format {format!r}; expected 'cbor', 'msgpack', "
                f"'bencode', or 'protobuf'"
            )
        return {"format": format, "action": "decode", "decoded": decoded}

    raise ValueError(f"unknown action {action!r}; expected 'encode' or 'decode'")


def register(mcp) -> None:
    """Register the serialize toolset's tools against the FastMCP app."""
    mcp.tool()(serialize_codec)
