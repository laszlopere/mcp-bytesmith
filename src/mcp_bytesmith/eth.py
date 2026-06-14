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

"""Ethereum/EVM toolset — gated on the `ethereum` extra (plan.txt §2, gate: ethereum).

keccak-256 is the pre-NIST Ethereum variant; it is NOT hashlib's SHA-3 (different
padding), so it comes from pycryptodome. The import is guarded so the package
loads even when the extra is absent — `available()` reports whether this toolset
can register, and server.py only calls `register()` when it can.

Toolset module contract (the pattern every gated toolset follows):
    available() -> bool      can this toolset's deps be imported?
    register(mcp) -> None    attach its @mcp.tool() functions to the app
"""

import base64
import json
from typing import Any, Literal

from mcp_bytesmith.core import _to_bytes

_HEX = frozenset("0123456789abcdefABCDEF")

# EIP-712 `types`: struct name -> ordered list of {"type", "name"} members (CR.14).
_EIP712Types = dict[str, list[dict[str, str]]]


def available() -> bool:
    """True when the `ethereum` extra is installed (keccak is importable)."""
    try:
        from Crypto.Hash import keccak  # noqa: F401
    except ImportError:
        return False
    return True


def _keccak256(data: bytes) -> bytes:
    from Crypto.Hash import keccak

    return keccak.new(digest_bits=256, data=data).digest()


def _eip55(addr_lower: str) -> str:
    """Apply the EIP-55 mixed-case checksum to 40 lowercase hex chars (no 0x)."""
    digest = _keccak256(addr_lower.encode("ascii")).hex()
    out = [
        ch.upper() if ch.isalpha() and int(digest[i], 16) >= 8 else ch
        for i, ch in enumerate(addr_lower)
    ]
    return "0x" + "".join(out)


# --- output codec (input side: core._to_bytes, plan §2.0.6) --------------------
def _from_bytes(raw: bytes, output_format: str) -> str:
    """Render bytes back out per output_format (hex is 0x-prefixed | base64)."""
    if output_format == "hex":
        return "0x" + raw.hex()
    if output_format == "base64":
        return base64.b64encode(raw).decode("ascii")
    raise ValueError(
        f"unknown output_format {output_format!r}; expected 'hex' or 'base64'"
    )


# --- EIP-712 typed-data hashing (§1.14.2) --------------------------------------
def _eip712_type_deps(type_name: str, types: _EIP712Types, found: set[str]) -> None:
    """Collect the struct types `type_name` references, transitively."""
    base = type_name.split("[", 1)[0]  # strip any array suffix
    if base in found or base not in types:
        return
    found.add(base)
    for member in types[base]:
        _eip712_type_deps(member["type"], types, found)


def _eip712_encode_type(primary_type: str, types: _EIP712Types) -> str:
    """The EIP-712 encodeType string: primary first, referenced types A-Z."""
    found: set[str] = set()
    _eip712_type_deps(primary_type, types, found)
    found.discard(primary_type)
    ordered = [primary_type] + sorted(found)
    return "".join(
        f"{t}(" + ",".join(f"{m['type']} {m['name']}" for m in types[t]) + ")"
        for t in ordered
    )


def _eip712_parse_int(value: Any) -> int:
    if isinstance(value, str):
        return int(value, 16) if value[:2].lower() == "0x" else int(value)
    return int(value)


# Shared 32-byte word encoders — one source of truth for the value-type encodings
# repeated across EIP-712, ABI, and storage-slot code (CR.9/CR.10/CR.18).
def _encode_bool_32(value: Any) -> bytes:
    return (1 if value else 0).to_bytes(32, "big")


def _encode_address_32(value: Any) -> bytes:
    return (_eip712_parse_int(value) & (2**160 - 1)).to_bytes(32, "big")


def _encode_int_32(value: Any) -> bytes:
    # two's-complement big-endian, 32 bytes (mask sign-extends negatives)
    return (_eip712_parse_int(value) & (2**256 - 1)).to_bytes(32, "big")


def _eip712_encode_value(type_name: str, value: Any, types: _EIP712Types) -> bytes:
    """Encode a single typed-data member to its 32-byte EIP-712 word."""
    if type_name.endswith("]"):  # array: keccak of concatenated element encodings
        base = type_name[: type_name.rindex("[")]
        return _keccak256(
            b"".join(_eip712_encode_value(base, item, types) for item in value)
        )
    if type_name in types:  # nested struct -> its hashStruct (already 32 bytes)
        return _eip712_hash_struct(type_name, value, types)
    if type_name == "string":
        return _keccak256(value.encode("utf-8"))
    if type_name == "bytes":
        return _keccak256(_to_bytes(value, "hex"))
    if type_name == "bool":
        return _encode_bool_32(value)
    if type_name == "address":
        return _encode_address_32(value)
    if type_name.startswith(("uint", "int")):
        return _encode_int_32(value)
    if type_name.startswith("bytes"):  # bytesN: left-aligned, zero-padded right
        return _to_bytes(value, "hex").ljust(32, b"\x00")
    raise ValueError(f"unsupported EIP-712 type: {type_name!r}")


def _eip712_hash_struct(
    primary_type: str, data: dict[str, Any], types: _EIP712Types
) -> bytes:
    type_hash = _keccak256(_eip712_encode_type(primary_type, types).encode("ascii"))
    enc = type_hash
    for member in types[primary_type]:
        enc += _eip712_encode_value(member["type"], data[member["name"]], types)
    return _keccak256(enc)


def _eip712_digest(typed_data: dict) -> tuple[bytes, bytes, bytes]:
    """Return (digest, domain_separator, struct_hash) for a typed-data object."""
    try:
        types = typed_data["types"]
        primary_type = typed_data["primaryType"]
        domain = typed_data["domain"]
        message = typed_data["message"]
    except (KeyError, TypeError) as exc:
        raise ValueError(
            "eip712 data needs 'types', 'primaryType', 'domain', and 'message'"
        ) from exc
    domain_separator = _eip712_hash_struct("EIP712Domain", domain, types)
    struct_hash = _eip712_hash_struct(primary_type, message, types)
    digest = _keccak256(b"\x19\x01" + domain_separator + struct_hash)
    return digest, domain_separator, struct_hash


def eth_hash(
    kind: Literal["keccak256", "eip191", "eip712"],
    data: str,
    input_format: Literal["text", "hex", "base64"] = "text",
    output_format: Literal["hex", "base64"] = "hex",
) -> dict:
    """Compute an Ethereum hash: raw keccak-256, EIP-191, or EIP-712 typed-data."""
    if kind == "keccak256":
        digest = _keccak256(_to_bytes(data, input_format))
        return {"kind": kind, "hash": _from_bytes(digest, output_format)}
    if kind == "eip191":
        # personal_sign: keccak256("\x19Ethereum Signed Message:\n" + len + msg)
        msg = _to_bytes(data, input_format)
        prefix = b"\x19Ethereum Signed Message:\n" + str(len(msg)).encode("ascii")
        digest = _keccak256(prefix + msg)
        return {"kind": kind, "hash": _from_bytes(digest, output_format)}
    if kind == "eip712":
        # `data` is the typed-data JSON object (string or already-parsed dict).
        typed_data = json.loads(data) if isinstance(data, str) else data
        digest, domain_separator, struct_hash = _eip712_digest(typed_data)
        return {
            "kind": kind,
            "hash": _from_bytes(digest, output_format),
            "domain_separator": _from_bytes(domain_separator, output_format),
            "struct_hash": _from_bytes(struct_hash, output_format),
        }
    raise ValueError(
        f"unknown kind {kind!r}; expected 'keccak256', 'eip191', or 'eip712'"
    )


# --- canonical ABI signature -> selector / topic0 (§1.13.2) --------------------
def _split_top_level(s: str) -> list[str]:
    """Split a parameter list on top-level commas (ignoring nested ()/[])."""
    parts, depth, cur = [], 0, ""
    for ch in s:
        if ch in "([":
            depth += 1
        elif ch in ")]":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append(cur)
            cur = ""
        else:
            cur += ch
    parts.append(cur)
    return parts


def _canon_alias(base: str) -> str:
    """Normalize Solidity type aliases to their canonical ABI form."""
    if base in ("uint", "int"):
        return base + "256"
    if base == "byte":
        return "bytes1"
    return base


def _leading_arrays(rest: str) -> str:
    """Pull leading [..] array suffixes off `rest`, dropping any trailing name."""
    rest, suffix = rest.strip(), ""
    while rest.startswith("["):
        close = rest.index("]")
        suffix += rest[: close + 1].replace(" ", "")
        rest = rest[close + 1 :].strip()
    return suffix


def _canon_param(param: str) -> str:
    """Canonicalize one parameter: drop name/location, normalize the type."""
    param = param.strip()
    if not param:
        raise ValueError("empty parameter in signature")
    if param.startswith("("):  # tuple — recurse into its members
        depth = 0
        for i, ch in enumerate(param):
            depth += ch == "("
            depth -= ch == ")"
            if depth == 0:
                break
        inner = _split_top_level(param[1:i])
        members = ",".join(_canon_param(p) for p in inner)
        return f"({members})" + _leading_arrays(param[i + 1 :])
    token = param.split()[0]  # type sits before any data-location / name
    bracket = token.find("[")
    if bracket == -1:
        return _canon_alias(token)
    return _canon_alias(token[:bracket]) + token[bracket:]


def _canonical_signature(signature: str) -> str:
    """Reduce a function/event signature to its canonical `name(types)` form."""
    sig = signature.strip()
    open_i = sig.find("(")
    if open_i == -1:
        raise ValueError(f"signature has no parameter list: {signature!r}")
    name = sig[:open_i].strip()
    if not name.isidentifier():
        raise ValueError(f"invalid signature name: {name!r}")
    depth = 0
    close_i = -1
    for i in range(open_i, len(sig)):
        depth += sig[i] == "("
        depth -= sig[i] == ")"
        if depth == 0:
            close_i = i
            break
    if close_i == -1:
        raise ValueError(f"unbalanced parentheses in signature: {signature!r}")
    body = sig[open_i + 1 : close_i].strip()
    params = (
        "" if not body else ",".join(_canon_param(p) for p in _split_top_level(body))
    )
    return f"{name}({params})"


def eth_selector(
    signature: str, kind: Literal["function", "event"] = "function"
) -> dict:
    """Derive the 4-byte function selector or 32-byte event topic from a signature."""
    canonical = _canonical_signature(signature)
    digest = _keccak256(canonical.encode("ascii"))
    if kind == "function":
        return {
            "kind": kind,
            "signature": canonical,
            "selector": "0x" + digest[:4].hex(),
        }
    if kind == "event":
        return {"kind": kind, "signature": canonical, "topic0": "0x" + digest.hex()}
    raise ValueError(f"unknown kind {kind!r}; expected 'function' or 'event'")


# --- RLP encode / decode (§1.13.5) ---------------------------------------------
# RLP encodes two things: byte strings and (recursively) lists of items. Leaves
# cross the JSON boundary as hex strings; integers are accepted on encode and
# stored minimal big-endian (RLP's canonical integer form, 0 -> empty string).
# Decode is the inverse — leaves come back as 0x-hex, lists as arrays — but the
# byte/int distinction is not on the wire, so decoded leaves are always hex.
def _rlp_length(length: int, offset: int) -> bytes:
    """RLP length prefix: short form < 56, else a length-of-length header."""
    if length < 56:
        return bytes([offset + length])
    len_bytes = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([offset + 55 + len(len_bytes)]) + len_bytes


def _rlp_leaf_bytes(item: Any) -> bytes:
    """Coerce an encode leaf to bytes: hex string, or minimal-big-endian integer."""
    if isinstance(item, bool):  # bool is an int subclass — reject the footgun
        raise ValueError("RLP leaves must be hex strings or integers, not booleans")
    if isinstance(item, int):
        if item < 0:
            raise ValueError("cannot RLP-encode a negative integer")
        return item.to_bytes((item.bit_length() + 7) // 8, "big")  # 0 -> b""
    if isinstance(item, str):
        return _to_bytes(item, "hex")
    raise ValueError(f"cannot RLP-encode value of type {type(item).__name__}")


def _rlp_encode(item: Any) -> bytes:
    if isinstance(item, (list, tuple)):
        payload = b"".join(_rlp_encode(x) for x in item)
        return _rlp_length(len(payload), 0xC0) + payload
    raw = _rlp_leaf_bytes(item)
    if len(raw) == 1 and raw[0] < 0x80:  # a lone low byte is its own encoding
        return raw
    return _rlp_length(len(raw), 0x80) + raw


def _rlp_payload_span(data: bytes, pos: int, short_base: int) -> tuple[int, int]:
    """Resolve the [start, end) payload span of a length-prefixed RLP item (CR.11).

    Strings and lists share the same short/long-form rule; only the base differs:
    `short_base` is 0x80 for strings / 0xC0 for lists, and the long-form threshold
    sits 0x37 above it (0xB7 / 0xF7). Returns (start, end) offsets into `data`.
    """
    prefix = data[pos]
    short_max = short_base + 0x37  # 0xB7 (string) or 0xF7 (list)
    if prefix <= short_max:
        start, length = pos + 1, prefix - short_base
    else:
        ll = prefix - short_max  # number of length bytes
        length = int.from_bytes(data[pos + 1 : pos + 1 + ll], "big")
        start = pos + 1 + ll
    return start, start + length


def _rlp_decode_item(data: bytes, pos: int) -> tuple[Any, int]:
    """Decode one RLP item at `pos`, returning (value, next position)."""
    if pos >= len(data):
        raise ValueError("RLP input truncated")
    prefix = data[pos]
    if prefix <= 0x7F:  # single byte, itself
        return "0x" + data[pos : pos + 1].hex(), pos + 1
    if prefix <= 0xBF:  # string: short (<=0xb7) or length-prefixed (<=0xbf)
        start, end = _rlp_payload_span(data, pos, 0x80)
        if end > len(data):
            raise ValueError("RLP string longer than input")
        return "0x" + data[start:end].hex(), end
    # list: short (<=0xf7) or length-prefixed (<=0xff)
    start, end = _rlp_payload_span(data, pos, 0xC0)
    if end > len(data):
        raise ValueError("RLP list longer than input")
    items, cur = [], start
    while cur < end:
        value, cur = _rlp_decode_item(data, cur)
        items.append(value)
    if cur != end:
        raise ValueError("RLP list payload overran its declared length")
    return items, end


def rlp_codec(action: Literal["encode", "decode"], data: Any) -> dict:
    """RLP-encode structured data, or RLP-decode a hex string.

    Encode `data` is a recursive structure: a leaf (hex string, or a non-negative
    integer stored minimal big-endian) or a JSON array of items (nested allowed);
    a JSON-array string is parsed too. action=encode -> {encoded:'0x...'}.
    Decode `data` is a 0x-hex string; action=decode -> {decoded} with leaves as
    0x-hex and lists as arrays.
    """
    if action == "encode":
        item = data
        if isinstance(data, str) and data.lstrip().startswith("["):
            item = json.loads(data)  # client stringified the array
        return {"action": "encode", "encoded": "0x" + _rlp_encode(item).hex()}
    if action == "decode":
        if not isinstance(data, str):
            raise ValueError("action=decode requires a hex string `data`")
        raw = _to_bytes(data, "hex")
        value, pos = _rlp_decode_item(raw, 0)
        if pos != len(raw):
            raise ValueError("trailing bytes after the top-level RLP item")
        return {"action": "decode", "decoded": value}
    raise ValueError(f"unknown action {action!r}; expected 'encode' or 'decode'")


# --- ABI encode / decode (§1.13.3, §1.13.6) ------------------------------------
# Solidity ABI: scalars occupy one 32-byte word; `bytes`/`string`/`T[]` and any
# tuple/fixed-array containing them are "dynamic" and use head/tail offset
# pointers. encodePacked ("packed") drops all padding and length prefixes — tight
# and non-standard, so it is encode-only (not uniquely decodable).
def _ceil32(n: int) -> int:
    return (n + 31) // 32 * 32


def _array_split(t: str) -> tuple[str, str] | None:
    """Split a trailing array suffix: 'uint[2][]' -> ('uint[2]', ''); None if scalar/tuple."""
    t = t.strip()
    if not t.endswith("]"):
        return None
    i = t.rindex("[")  # outermost dimension is the LAST bracket group
    return t[:i].strip(), t[i + 1 : -1].strip()


def _is_tuple(t: str) -> bool:
    """A bare tuple type — '(...)'. (Tuple arrays are peeled off by _array_split first.)"""
    return t.strip().startswith("(")


def _split_tuple(t: str) -> list[str]:
    """Component types of a tuple string; '()' -> []."""
    inner = t.strip()[1:-1].strip()
    return [p.strip() for p in _split_top_level(inner)] if inner else []


def _abi_is_dynamic(t: str) -> bool:
    arr = _array_split(t)
    if arr is not None:
        base, inner = arr
        return True if inner == "" else _abi_is_dynamic(base)
    if _is_tuple(t):
        return any(_abi_is_dynamic(c) for c in _split_tuple(t))
    return _canon_alias(t.strip()) in ("bytes", "string")


def _abi_static_size(t: str) -> int:
    """Head-region byte width of a static type (offset pointers handled by caller)."""
    arr = _array_split(t)
    if arr is not None:
        base, inner = arr
        return int(inner) * _abi_static_size(base)
    if _is_tuple(t):
        return sum(_abi_static_size(c) for c in _split_tuple(t))
    return 32


def _abi_enc_scalar(t: str, v: Any) -> bytes:
    """Standard (padded) encoding of one non-container value; t is alias-normalized."""
    if t == "bool":
        return _encode_bool_32(v)
    if t == "address":
        return _encode_address_32(v)
    if t in ("bytes", "string"):
        raw = v.encode("utf-8") if t == "string" else _to_bytes(v, "hex")
        return len(raw).to_bytes(32, "big") + raw.ljust(_ceil32(len(raw)), b"\x00")
    if t.startswith("bytes"):  # bytesN: left-aligned, right-padded
        n = int(t[5:])
        raw = _to_bytes(v, "hex")
        if len(raw) > n:
            raise ValueError(f"value too long for {t}: {len(raw)} bytes")
        return raw.ljust(32, b"\x00")
    if t.startswith(("uint", "int")):  # two's-complement, 32 bytes (mask = sign-extend)
        return _encode_int_32(v)
    raise ValueError(f"unsupported ABI type: {t!r}")


def _abi_enc(t: str, v: Any) -> bytes:
    """Standard encoding of one value (arrays/tuples recurse through _abi_enc_tuple)."""
    arr = _array_split(t)
    if arr is not None:
        base, inner = arr
        if inner == "":  # dynamic array: length prefix + tuple of elements
            return len(v).to_bytes(32, "big") + _abi_enc_tuple([base] * len(v), v)
        k = int(inner)
        if len(v) != k:
            raise ValueError(f"{t} expects {k} elements, got {len(v)}")
        return _abi_enc_tuple([base] * k, v)
    if _is_tuple(t):
        return _abi_enc_tuple(_split_tuple(t), v)
    return _abi_enc_scalar(_canon_alias(t.strip()), v)


def _abi_enc_tuple(types: list, values: list) -> bytes:
    """Head/tail encode a tuple of (types, values) — the core ABI algorithm."""
    if len(types) != len(values):
        raise ValueError(f"types/values length mismatch: {len(types)} vs {len(values)}")
    encs = [_abi_enc(t, v) for t, v in zip(types, values)]
    dyn = [_abi_is_dynamic(t) for t in types]
    offset = sum(32 if d else len(e) for d, e in zip(dyn, encs))  # total head size
    head, tail = [], []
    for d, e in zip(dyn, encs):
        if d:
            head.append(offset.to_bytes(32, "big"))
            tail.append(e)
            offset += len(e)
        else:
            head.append(e)
    return b"".join(head) + b"".join(tail)


def _abi_enc_packed_scalar(t: str, v: Any) -> bytes:
    """encodePacked of one scalar/bytes — no padding; t is alias-normalized."""
    if t == "bool":
        return b"\x01" if v else b"\x00"
    if t == "address":
        return (_eip712_parse_int(v) & (2**160 - 1)).to_bytes(20, "big")
    if t == "string":
        return v.encode("utf-8")
    if t == "bytes":
        return _to_bytes(v, "hex")
    if t.startswith("bytes"):  # bytesN: exactly N bytes
        n = int(t[5:])
        raw = _to_bytes(v, "hex")
        if len(raw) > n:
            raise ValueError(f"value too long for {t}: {len(raw)} bytes")
        return raw.ljust(n, b"\x00")
    if t.startswith("uint"):
        bits = int(t[4:] or 256)
        return (_eip712_parse_int(v) & (2**bits - 1)).to_bytes(bits // 8, "big")
    if t.startswith("int"):
        bits = int(t[3:] or 256)
        return (_eip712_parse_int(v) & (2**bits - 1)).to_bytes(bits // 8, "big")
    raise ValueError(f"unsupported ABI type: {t!r}")


def _abi_enc_packed(t: str, v: Any) -> bytes:
    """encodePacked of one value. Array elements ARE padded to 32 bytes (Solidity rule)."""
    arr = _array_split(t)
    if arr is not None:
        base, inner = arr
        if _abi_is_dynamic(base):
            raise ValueError("encodePacked does not support arrays of dynamic types")
        if inner != "" and len(v) != int(inner):
            raise ValueError(f"{t} expects {int(inner)} elements, got {len(v)}")
        return b"".join(_abi_enc(base, el) for el in v)  # padded element encoding
    if _is_tuple(t):
        raise ValueError("encodePacked does not support tuples")
    return _abi_enc_packed_scalar(_canon_alias(t.strip()), v)


def _abi_dec_scalar(t: str, data: bytes, pos: int) -> Any:
    """Decode one non-container value at byte offset pos; t is alias-normalized."""
    word = data[pos : pos + 32]
    if t == "bool":
        return bool(int.from_bytes(word, "big"))
    if t == "address":
        body = format(int.from_bytes(word, "big") & (2**160 - 1), "040x")
        return _eip55(body)
    if t in ("bytes", "string"):
        length = int.from_bytes(word, "big")
        payload = data[pos + 32 : pos + 32 + length]
        return payload.decode("utf-8") if t == "string" else "0x" + payload.hex()
    if t.startswith("bytes"):  # bytesN
        return "0x" + word[: int(t[5:])].hex()
    if t.startswith("uint"):
        return str(int.from_bytes(word, "big"))
    if t.startswith("int"):
        n = int.from_bytes(word, "big")
        return str(n - 2**256 if n >= 2**255 else n)  # two's-complement
    raise ValueError(f"unsupported ABI type: {t!r}")


def _abi_dec(t: str, data: bytes, pos: int) -> Any:
    """Decode one value located at byte offset pos (a tail/inline position)."""
    arr = _array_split(t)
    if arr is not None:
        base, inner = arr
        if inner == "":  # dynamic array: length word, then element tuple after it
            length = int.from_bytes(data[pos : pos + 32], "big")
            # Every element occupies >= 32 bytes (a head word) in the remaining
            # data, so a length exceeding that word count is malformed — reject it
            # before allocating, rather than OOMing on an untrusted length word.
            if length > max(0, len(data) - pos - 32) // 32:
                raise ValueError(f"ABI array length {length} exceeds available data")
            return _abi_dec_tuple([base] * length, data, pos + 32)
        return _abi_dec_tuple([base] * int(inner), data, pos)
    if _is_tuple(t):
        return _abi_dec_tuple(_split_tuple(t), data, pos)
    return _abi_dec_scalar(_canon_alias(t.strip()), data, pos)


def _abi_dec_tuple(types: list, data: bytes, base: int) -> list:
    """Decode a tuple whose head region starts at byte offset `base`."""
    values, head = [], 0
    for t in types:
        if _abi_is_dynamic(t):  # head holds an offset relative to `base`
            ptr = int.from_bytes(data[base + head : base + head + 32], "big")
            values.append(_abi_dec(t, data, base + ptr))
            head += 32
        else:  # static value sits inline in the head
            values.append(_abi_dec(t, data, base + head))
            head += _abi_static_size(t)
    return values


def abi_codec(
    action: Literal["encode", "decode"],
    types: list[str],
    values: list | None = None,
    data: str | None = None,
    mode: Literal["standard", "packed"] = "standard",
) -> dict:
    """ABI-encode values or ABI-decode call/return/log data.

    `types` is a list of ABI type strings (e.g. ["uint256", "address",
    "(uint8,bytes)[]"]); aliases like uint/int/byte are normalized.
    action=encode (needs `values`) -> {encoded, mode}. mode=packed is
    abi.encodePacked (tight, no padding) and is encode-only. action=decode
    (needs `data`, standard only) -> {values}; ints are returned as decimal
    strings and addresses EIP-55 checksummed.
    """
    type_list = json.loads(types) if isinstance(types, str) else types
    if not isinstance(type_list, list):
        raise ValueError("`types` must be a list of ABI type strings")

    if action == "encode":
        vals = json.loads(values) if isinstance(values, str) else values
        if vals is None:
            raise ValueError("action=encode requires `values`")
        if len(vals) != len(type_list):
            raise ValueError(
                f"types/values length mismatch: {len(type_list)} vs {len(vals)}"
            )
        if mode == "packed":
            encoded = b"".join(_abi_enc_packed(t, v) for t, v in zip(type_list, vals))
        elif mode == "standard":
            encoded = _abi_enc_tuple(type_list, vals)
        else:
            raise ValueError(f"unknown mode {mode!r}; expected 'standard' or 'packed'")
        return {"action": "encode", "mode": mode, "encoded": "0x" + encoded.hex()}

    if action == "decode":
        if mode != "standard":
            raise ValueError("decode is standard-only (encodePacked is not decodable)")
        if data is None:
            raise ValueError("action=decode requires `data`")
        return {
            "action": "decode",
            "values": _abi_dec_tuple(type_list, _to_bytes(data, "hex"), 0),
        }

    raise ValueError(f"unknown action {action!r}; expected 'encode' or 'decode'")


# --- storage-slot layout (§1.15.4) ---------------------------------------------
def _storage_encode_key(value: Any, key_type: str) -> bytes:
    """Encode a mapping key for slot derivation.

    Value-type keys are left/right-padded to 32 bytes; `bytes`/`string` keys are
    used raw (unpadded), per Solidity's mapping storage layout.
    """
    if key_type == "string":
        return value.encode("utf-8")
    if key_type == "bytes":
        return _to_bytes(value, "hex")  # raw, unpadded
    if key_type == "bool":
        return _encode_bool_32(value)
    if key_type == "address":
        return _encode_address_32(value)
    if key_type.startswith(("uint", "int")):
        return _encode_int_32(value)
    if key_type.startswith("bytes"):  # bytesN: left-aligned, zero-padded right
        return _to_bytes(value, "hex").ljust(32, b"\x00")
    raise ValueError(f"unsupported mapping key type: {key_type!r}")


def _storage_result(slot_int: int) -> dict:
    slot_int &= 2**256 - 1  # storage space is 2^256 slots
    return {
        "slot": str(slot_int),
        "slot_hex": "0x" + slot_int.to_bytes(32, "big").hex(),
    }


def eth_storage_slot(
    layout: dict[str, Any], key: Any = None, index: int | None = None
) -> dict:
    """Compute the storage slot for a mapping/array entry given a layout.

    layout: {"kind": "mapping"|"dynamic_array", "slot": <declared slot>, ...}
      mapping       -> needs `key`; "key_type" (default uint256). For nested
                       mappings pass `key` (and optionally "key_type") as lists.
      dynamic_array -> needs `index`; optional "element_size" in slots (default 1).
    Returns the slot both as a decimal string and a 0x 32-byte hex word.
    """
    spec = json.loads(layout) if isinstance(layout, str) else layout
    try:
        kind = spec["kind"]
        base = _eip712_parse_int(spec["slot"])
    except (KeyError, TypeError) as exc:
        raise ValueError("layout needs 'kind' and 'slot'") from exc

    if kind == "mapping":
        if key is None:
            raise ValueError("mapping layout requires `key`")
        keys = key if isinstance(key, list) else [key]
        kt = spec.get("key_type", "uint256")
        key_types = kt if isinstance(kt, list) else [kt] * len(keys)
        if len(key_types) != len(keys):
            raise ValueError("`key_type` list length must match `key` list length")
        cur = base.to_bytes(32, "big")
        for k, ktype in zip(keys, key_types):  # outer-to-inner mapping nesting
            cur = _keccak256(_storage_encode_key(k, ktype) + cur)
        return _storage_result(int.from_bytes(cur, "big"))

    if kind in ("dynamic_array", "array"):
        if index is None:
            raise ValueError("dynamic_array layout requires `index`")
        element_size = _eip712_parse_int(spec.get("element_size", 1))
        start = int.from_bytes(_keccak256(base.to_bytes(32, "big")), "big")
        return _storage_result(start + _eip712_parse_int(index) * element_size)

    raise ValueError(
        f"unknown layout kind {kind!r}; expected 'mapping' or 'dynamic_array'"
    )


# --- secp256k1 ecrecover (§1.14.4, used by tx `from` recovery) -----------------
# Pure-Python curve math — enough to recover a public key from a signature. The
# curve is y^2 = x^3 + 7 over F_p; recovery rebuilds point R from (r, recovery_id)
# then Q = r^-1 (s*R - z*G), whose keccak tail is the signer address.
_SECP_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_SECP_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_SECP_G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)


def _ec_add(p: tuple | None, q: tuple | None) -> tuple | None:
    """Add two secp256k1 points (None is the point at infinity)."""
    if p is None:
        return q
    if q is None:
        return p
    x1, y1 = p
    x2, y2 = q
    if x1 == x2 and (y1 + y2) % _SECP_P == 0:
        return None  # P + (-P) = O
    if p == q:
        m = (3 * x1 * x1) * pow(2 * y1, -1, _SECP_P) % _SECP_P
    else:
        m = (y2 - y1) * pow(x2 - x1, -1, _SECP_P) % _SECP_P
    x3 = (m * m - x1 - x2) % _SECP_P
    y3 = (m * (x1 - x3) - y1) % _SECP_P
    return (x3, y3)


def _ec_mul(k: int, p: tuple | None) -> tuple | None:
    """Scalar-multiply point `p` by `k` (double-and-add)."""
    result: tuple | None = None
    addend = p
    while k:
        if k & 1:
            result = _ec_add(result, addend)
        addend = _ec_add(addend, addend)
        k >>= 1
    return result


def _ecrecover(z: int, r: int, s: int, rec_id: int) -> bytes:
    """Recover the 20-byte signer address from a message hash and signature."""
    if not 0 < r < _SECP_N:
        raise ValueError("signature r out of range")
    if not 0 < s < _SECP_N:
        raise ValueError("signature s out of range")
    if rec_id not in (0, 1, 2, 3):
        raise ValueError(f"invalid recovery id: {rec_id}")
    x = r + (_SECP_N if rec_id >= 2 else 0)
    if x >= _SECP_P:
        raise ValueError("recovered x is out of the field range")
    alpha = (pow(x, 3, _SECP_P) + 7) % _SECP_P
    beta = pow(alpha, (_SECP_P + 1) // 4, _SECP_P)  # sqrt mod p (p % 4 == 3)
    y = beta if beta % 2 == rec_id & 1 else _SECP_P - beta
    if (y * y - alpha) % _SECP_P != 0:
        raise ValueError("recovered point is not on the curve")
    point_r = (x, y)
    rinv = pow(r, -1, _SECP_N)
    # Q = r^-1 (s*R - z*G) = r^-1 (s*R + (-z)*G)
    q = _ec_mul(rinv, _ec_add(_ec_mul(s, point_r), _ec_mul((-z) % _SECP_N, _SECP_G)))
    if q is None:
        raise ValueError("recovered public key is the point at infinity")
    pubkey = q[0].to_bytes(32, "big") + q[1].to_bytes(32, "big")
    return _keccak256(pubkey)[-20:]


# --- transaction encode / decode (§1.14.7) -------------------------------------
# A signed Ethereum tx is RLP. Legacy is a bare 9-item list [nonce, gasPrice,
# gasLimit, to, value, data, v, r, s]; the typed envelopes (EIP-2930/1559/4844)
# are `type_byte || rlp([...])`. encode serializes the (already-signed) fields a
# caller supplies — it does NOT sign. decode parses the wire form back to fields
# and recovers `from` via the signing hash + ecrecover.
_TX_SIGNED_FIELDS: dict[int, list[str]] = {
    0: ["nonce", "gasPrice", "gasLimit", "to", "value", "data", "v", "r", "s"],
    1: [
        "chainId",
        "nonce",
        "gasPrice",
        "gasLimit",
        "to",
        "value",
        "data",
        "accessList",
        "yParity",
        "r",
        "s",
    ],
    2: [
        "chainId",
        "nonce",
        "maxPriorityFeePerGas",
        "maxFeePerGas",
        "gasLimit",
        "to",
        "value",
        "data",
        "accessList",
        "yParity",
        "r",
        "s",
    ],
    3: [
        "chainId",
        "nonce",
        "maxPriorityFeePerGas",
        "maxFeePerGas",
        "gasLimit",
        "to",
        "value",
        "data",
        "accessList",
        "maxFeePerBlobGas",
        "blobVersionedHashes",
        "yParity",
        "r",
        "s",
    ],
}


def _tx_to_leaf(value: Any) -> str:
    """`to`/address leaf: a 0x-hex string, or '0x' for contract creation / empty."""
    if value in (None, "", "0x"):
        return "0x"
    return value


def _access_list_to_rlp(access_list: Any) -> list:
    """Turn an access list into its RLP shape: [[address, [storageKey, ...]], ...]."""
    out = []
    for entry in access_list or []:
        if isinstance(entry, dict):
            addr = entry.get("address")
            keys = entry.get("storageKeys") or entry.get("storage_keys") or []
        else:  # [address, [keys]] tuple form
            addr, keys = entry[0], entry[1]
        out.append([_tx_to_leaf(addr), [_tx_to_leaf(k) for k in keys]])
    return out


def _tx_rlp_item(name: str, value: Any) -> Any:
    """Coerce one named tx field to its RLP item (int leaf, hex leaf, or list)."""
    if name == "accessList":
        return _access_list_to_rlp(value)
    if name == "blobVersionedHashes":
        return [_tx_to_leaf(h) for h in (value or [])]
    if name in ("to", "data"):
        return _tx_to_leaf(value if name == "to" else (value or "0x"))
    return _eip712_parse_int(value) if value is not None else 0  # numeric leaf


def _tx_infer_type(fields: dict) -> int:
    """Pick the tx type from an explicit `type`, else from which fields are present."""
    if fields.get("type") is not None:
        return _eip712_parse_int(fields["type"])
    if "blobVersionedHashes" in fields or "maxFeePerBlobGas" in fields:
        return 3
    if "maxFeePerGas" in fields or "maxPriorityFeePerGas" in fields:
        return 2
    if "accessList" in fields:
        return 1
    return 0


def _tx_encode(fields: dict) -> tuple[int, bytes]:
    tx_type = _tx_infer_type(fields)
    if tx_type not in _TX_SIGNED_FIELDS:
        raise ValueError(f"unsupported transaction type: {tx_type}")
    items = [_tx_rlp_item(n, fields.get(n)) for n in _TX_SIGNED_FIELDS[tx_type]]
    body = _rlp_encode(items)
    return tx_type, body if tx_type == 0 else bytes([tx_type]) + body


def _tx_leaf_int(leaf: str) -> int:
    return int(leaf, 16) if leaf not in ("0x", "") else 0  # RLP empty = integer 0


def _tx_addr(leaf: str) -> str | None:
    """Render an address leaf as an EIP-55 string, or None for the empty `to`."""
    body = leaf[2:] if leaf[:2].lower() == "0x" else leaf
    return None if body == "" else _eip55(body.lower().zfill(40))


def _tx_word_hex(leaf: str) -> str:
    """Render an r/s leaf as a 0x-prefixed 32-byte word (decode strips zeros)."""
    return "0x" + _tx_leaf_int(leaf).to_bytes(32, "big").hex()


def _tx_render_access_list(leaf: Any) -> list:
    return [
        {"address": _tx_addr(addr), "storageKeys": list(keys)} for addr, keys in leaf
    ]


def _tx_render_field(name: str, leaf: Any) -> Any:
    if name == "to":
        return _tx_addr(leaf)
    if name == "data":
        return leaf  # already a 0x-hex string from the RLP decoder
    if name == "accessList":
        return _tx_render_access_list(leaf)
    if name == "blobVersionedHashes":
        return list(leaf)
    if name in ("r", "s"):
        return _tx_word_hex(leaf)
    if name == "yParity":
        return _tx_leaf_int(leaf)
    return str(_tx_leaf_int(leaf))  # numeric fields (incl. legacy v) -> decimal


def _tx_signing_hash(tx_type: int, items: list) -> tuple[bytes, int | None, int | None]:
    """Return (signing_hash, chain_id, recovery_id) for a decoded tx item list."""
    if tx_type == 0:
        v = _tx_leaf_int(items[6])
        if v >= 35:  # EIP-155: v = chainId*2 + 35 + recovery_id
            chain_id, rec_id = (v - 35) // 2, (v - 35) % 2
            unsigned = items[:6] + [chain_id, 0, 0]
        elif v in (27, 28):  # pre-EIP-155
            chain_id, rec_id = None, v - 27
            unsigned = items[:6]
        else:
            chain_id, rec_id = None, None  # unsigned / non-standard v
            unsigned = items[:6]
        return _keccak256(_rlp_encode(unsigned)), chain_id, rec_id
    # typed envelope: sign over type_byte || rlp(fields without yParity, r, s)
    rec_id = _tx_leaf_int(items[-3])
    chain_id = _tx_leaf_int(items[0])
    digest = _keccak256(bytes([tx_type]) + _rlp_encode(items[:-3]))
    return digest, chain_id, rec_id


def _tx_decode(data: str) -> dict:
    raw = _to_bytes(data, "hex")
    if not raw:
        raise ValueError("empty transaction data")
    first = raw[0]
    if first >= 0xC0:  # RLP list header -> legacy tx
        tx_type, offset = 0, 0
    elif first in (1, 2, 3):  # EIP-2718 typed envelope
        tx_type, offset = first, 1
    else:
        raise ValueError(f"unrecognized transaction type byte: 0x{first:02x}")
    items, pos = _rlp_decode_item(raw, offset)
    if pos != len(raw):
        raise ValueError("trailing bytes after the transaction payload")
    names = _TX_SIGNED_FIELDS[tx_type]
    if not isinstance(items, list) or len(items) != len(names):
        raise ValueError(
            f"type-{tx_type} tx expects {len(names)} fields, got "
            f"{len(items) if isinstance(items, list) else 'a non-list'}"
        )

    sighash, chain_id, rec_id = _tx_signing_hash(tx_type, items)
    fields: dict[str, Any] = {}
    if tx_type == 0 and chain_id is not None:
        fields["chainId"] = str(chain_id)  # EIP-155 chain id is implied by v
    for name, leaf in zip(names, items):
        fields[name] = _tx_render_field(name, leaf)

    from_addr = None
    if rec_id is not None:
        r_int, s_int = _tx_leaf_int(items[-2]), _tx_leaf_int(items[-1])
        if r_int and s_int:  # a zeroed signature means the tx is unsigned
            try:
                from_addr = _eip55(
                    _ecrecover(
                        int.from_bytes(sighash, "big"), r_int, s_int, rec_id
                    ).hex()
                )
            except ValueError:
                from_addr = None

    return {
        "action": "decode",
        "type": tx_type,
        "fields": fields,
        "hash": "0x" + _keccak256(raw).hex(),
        "from": from_addr,
    }


def eth_tx_codec(
    action: Literal["encode", "decode"],
    data: str | None = None,
    fields: dict | None = None,
) -> dict:
    """Serialize signed tx fields into a raw transaction, or decode a raw tx.

    action=encode (needs `fields`) serializes the supplied, already-signed fields
    (it does not sign) -> {type, raw:'0x...', hash}. `fields` is an object; the
    type is taken from a `type` key or inferred from which fields are present
    (maxFeePerGas -> 1559, blobVersionedHashes -> 4844, accessList -> 2930, else
    legacy). Numbers accept int / decimal / 0x-hex; `to`/`data` are 0x-hex.
    action=decode (needs `data`, a 0x-hex raw tx) -> {type, fields, hash, from},
    recovering `from` from the signature; numeric fields come back as decimal
    strings, addresses EIP-55 checksummed.
    """
    if action == "encode":
        spec = json.loads(fields) if isinstance(fields, str) else fields
        if not isinstance(spec, dict):
            raise ValueError("action=encode requires a `fields` object")
        tx_type, raw = _tx_encode(spec)
        return {
            "action": "encode",
            "type": tx_type,
            "raw": "0x" + raw.hex(),
            "hash": "0x" + _keccak256(raw).hex(),
        }
    if action == "decode":
        if not isinstance(data, str):
            raise ValueError("action=decode requires a hex string `data`")
        return _tx_decode(data)
    raise ValueError(f"unknown action {action!r}; expected 'encode' or 'decode'")


def eth_address_case(action: Literal["encode", "verify"], address: str) -> dict:
    """Apply or verify an EIP-55 mixed-case address checksum."""
    body = address[2:] if address[:2].lower() == "0x" else address
    if len(body) != 40 or any(ch not in _HEX for ch in body):
        raise ValueError(f"not a 20-byte hex address (need 40 hex chars): {address!r}")
    checksummed = _eip55(body.lower())
    if action == "encode":
        return {"action": "encode", "address": checksummed}
    if action == "verify":
        valid = "0x" + body == checksummed
        result = {"action": "verify", "address": checksummed, "valid": valid}
        if not valid:
            result["reason"] = "casing does not match the EIP-55 checksum"
        return result
    raise ValueError(f"unknown action {action!r}; expected 'encode' or 'verify'")


# --- ENS namehash (§1.15.5, EIP-137) -------------------------------------------
# Recursive keccak: namehash('') = 32 zero bytes; namehash(label.rest) =
# keccak256(namehash(rest) ++ keccak256(label)). `labelhash` is the keccak of the
# leftmost label (the .eth registrar token id for that name). The name is hashed
# as given — EIP-137 expects it already UTS-46 normalized (use unicode_normalize
# first if needed); empty labels (leading/trailing/double dots) are rejected.
def ens_namehash(name: str) -> dict:
    """Compute the EIP-137 namehash (and labelhash) of an ENS name."""
    node = b"\x00" * 32
    labels = name.split(".") if name else []
    if any(label == "" for label in labels):
        raise ValueError(f"name has an empty label (stray dot): {name!r}")
    for label in reversed(labels):
        node = _keccak256(node + _keccak256(label.encode("utf-8")))
    labelhash = _keccak256(labels[0].encode("utf-8")) if labels else node
    return {
        "name": name,
        "namehash": "0x" + node.hex(),
        "labelhash": "0x" + labelhash.hex(),
    }


def register(mcp) -> None:
    """Register the ethereum toolset's tools against the FastMCP app."""
    mcp.tool()(eth_hash)
    mcp.tool()(eth_selector)
    mcp.tool()(rlp_codec)
    mcp.tool()(abi_codec)
    mcp.tool()(eth_storage_slot)
    mcp.tool()(eth_tx_codec)
    mcp.tool()(eth_address_case)
    mcp.tool()(ens_namehash)
