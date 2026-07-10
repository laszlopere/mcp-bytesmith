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
import hashlib
import hmac
import json
import secrets
import unicodedata
from importlib.resources import files
from typing import Annotated, Any, Literal

from pydantic import Field

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


def _address_body(address: str) -> str:
    """Validate a 20-byte hex address (0x prefix optional) -> its 40 hex chars.

    Casing is preserved, so callers that check an EIP-55 checksum can compare it.
    """
    body = address[2:] if address[:2].lower() == "0x" else address
    if len(body) != 40 or any(ch not in _HEX for ch in body):
        raise ValueError(f"not a 20-byte hex address (need 40 hex chars): {address!r}")
    return body


def _pubkey_address(pubkey_body: bytes) -> str:
    """EIP-55 address for a 64-byte uncompressed public key body (X || Y, no 0x04)."""
    return _eip55(_keccak256(pubkey_body)[-20:].hex())


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
    kind: Annotated[
        Literal["keccak256", "eip191", "eip712"],
        Field(
            description="Hash flavor: 'keccak256' (raw Ethereum keccak-256), "
            "'eip191' (personal_sign prefixed message), or 'eip712' (typed-data "
            "digest)."
        ),
    ],
    data: Annotated[
        str,
        Field(
            description="Polymorphic: for keccak256/eip191 it is the message bytes "
            "decoded per input_format; for eip712 it is the typed-data JSON object "
            "(a JSON string or already-parsed dict with types/primaryType/domain/"
            "message) and input_format is ignored."
        ),
    ],
    input_format: Annotated[
        Literal["text", "hex", "base64"],
        Field(
            description="How to decode `data` to bytes for keccak256/eip191 "
            "(ignored for eip712); hex is 0x-prefixed or bare."
        ),
    ] = "text",
    output_format: Annotated[
        Literal["hex", "base64"],
        Field(description="Digest encoding: 'hex' is 0x-prefixed, or 'base64'."),
    ] = "hex",
) -> dict:
    """Compute an Ethereum hash: raw keccak-256, EIP-191, or EIP-712 typed-data.

    Returns {kind, hash}. For kind=eip712 the result also carries
    {domain_separator, struct_hash}, the two EIP-712 component hashes. Note
    keccak-256 is the pre-NIST Ethereum variant, not hashlib's SHA3-256.

    Example: eth_hash("keccak256", "hello", "text") ->
    hash="0x1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8".
    """
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
    signature: Annotated[
        str,
        Field(
            description="A Solidity function/event signature, e.g. "
            "'transfer(address,uint256)'; parameter names, data locations, and "
            "type aliases (uint->uint256) are normalized to canonical ABI form."
        ),
    ],
    kind: Annotated[
        Literal["function", "event"],
        Field(
            description="'function' returns the 4-byte selector; 'event' returns "
            "the 32-byte topic0 (keccak of the canonical signature)."
        ),
    ] = "function",
) -> dict:
    """Derive the 4-byte function selector or 32-byte event topic from a signature.

    Returns {kind, signature (canonicalized), selector} for functions, or
    {kind, signature, topic0} for events.

    Example: eth_selector("transfer(address,uint256)") -> selector="0xa9059cbb".
    """
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


def rlp_codec(
    action: Annotated[
        Literal["encode", "decode"],
        Field(description="'encode' structured data to RLP, or 'decode' a hex RLP."),
    ],
    data: Annotated[
        Any,
        Field(
            description="On encode: a leaf (0x-hex string or non-negative integer) "
            "or a (possibly nested) JSON array of items; a stringified JSON array "
            "is parsed. On decode: a 0x-prefixed hex string of the RLP payload."
        ),
    ],
) -> dict:
    """RLP-encode structured data, or RLP-decode a hex string.

    Encode `data` is a recursive structure: a leaf (hex string, or a non-negative
    integer stored minimal big-endian) or a JSON array of items (nested allowed);
    a JSON-array string is parsed too. action=encode -> {encoded:'0x...'}.
    Decode `data` is a 0x-hex string; action=decode -> {decoded} with leaves as
    0x-hex and lists as arrays.

    Example: rlp_codec("encode", ["0x636174"]) -> encoded="0xc483636174".
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
    action: Annotated[
        Literal["encode", "decode"],
        Field(description="'encode' values to ABI bytes, or 'decode' ABI bytes."),
    ],
    types: Annotated[
        list[str],
        Field(
            description="List of ABI type strings, e.g. "
            '["uint256","address","(uint8,bytes)[]"]; aliases uint/int/byte are '
            "normalized. A stringified JSON array is accepted."
        ),
    ],
    values: Annotated[
        list | None,
        Field(
            description="Values to encode (required for action=encode), positionally "
            "matching `types`; ints accept int/decimal/0x-hex, bytes are 0x-hex, "
            "addresses are 0x-hex. A stringified JSON array is accepted."
        ),
    ] = None,
    data: Annotated[
        str | None,
        Field(
            description="0x-prefixed ABI-encoded bytes to decode (required for "
            "action=decode)."
        ),
    ] = None,
    mode: Annotated[
        Literal["standard", "packed"],
        Field(
            description="'standard' head/tail ABI encoding, or 'packed' "
            "(abi.encodePacked: tight, no padding/length prefixes) — packed is "
            "encode-only as it is not uniquely decodable."
        ),
    ] = "standard",
) -> dict:
    """ABI-encode values or ABI-decode call/return/log data.

    `types` is a list of ABI type strings (e.g. ["uint256", "address",
    "(uint8,bytes)[]"]); aliases like uint/int/byte are normalized.
    action=encode (needs `values`) -> {encoded, mode}. mode=packed is
    abi.encodePacked (tight, no padding) and is encode-only. action=decode
    (needs `data`, standard only) -> {values}; ints are returned as decimal
    strings and addresses EIP-55 checksummed.

    Example: abi_codec("encode", ["uint256"], [69]) -> encoded="0x00..0045"
    (the 32-byte word 0x...0045).
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
    layout: Annotated[
        dict[str, Any],
        Field(
            description='Layout object: {"kind":"mapping"|"dynamic_array", "slot":'
            " <declared base slot, int/decimal/0x-hex>, ...}. mapping takes optional"
            ' "key_type" (default "uint256"; lists for nested mappings); '
            'dynamic_array takes optional "element_size" in slots (default 1). A '
            "stringified JSON object is accepted."
        ),
    ],
    key: Annotated[
        Any,
        Field(
            description="Mapping key (required for kind=mapping); pass a list of "
            "keys outer-to-inner for nested mappings. Ignored for arrays."
        ),
    ] = None,
    index: Annotated[
        int | None,
        Field(
            description="Element index (required for kind=dynamic_array); "
            "int/decimal/0x-hex. Ignored for mappings."
        ),
    ] = None,
) -> dict:
    """Compute the storage slot for a mapping/array entry given a layout.

    layout: {"kind": "mapping"|"dynamic_array", "slot": <declared slot>, ...}
      mapping       -> needs `key`; "key_type" (default uint256). For nested
                       mappings pass `key` (and optionally "key_type") as lists.
      dynamic_array -> needs `index`; optional "element_size" in slots (default 1).
    Returns {slot, slot_hex}: the slot as a decimal string and a 0x 32-byte word.

    Example: eth_storage_slot({"kind":"mapping","slot":1},
    "0x0000000000000000000000000000000000000000") ->
    slot_hex="0xa6eef7e35abe7026729641147f7915573c7e97b47efa546f5f6e3230263bcb49".
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


def _secp_pubkey_point(k: int) -> tuple[int, int]:
    """The secp256k1 public point k*G; k is a valid non-zero scalar < n, so never O."""
    point = _ec_mul(k, _SECP_G)
    assert point is not None  # 0 < k < n by construction (checked by callers)
    return point


def _secp_pubkey_compressed(k: int) -> bytes:
    """33-byte compressed public key (0x02/0x03 || X) for private scalar k."""
    x, y = _secp_pubkey_point(k)
    return (b"\x03" if y & 1 else b"\x02") + x.to_bytes(32, "big")


def _secp_pubkey_uncompressed(k: int) -> bytes:
    """65-byte uncompressed public key (0x04 || X || Y) for private scalar k."""
    x, y = _secp_pubkey_point(k)
    return b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")


def _private_key_scalar(private_key: str) -> int:
    """Parse a 32-byte hex private key into a valid secp256k1 scalar."""
    raw = _to_bytes(private_key, "hex")
    if len(raw) != 32:
        raise ValueError(f"private key must be 32 bytes, got {len(raw)}")
    k = int.from_bytes(raw, "big")
    if not 0 < k < _SECP_N:  # 0 and >= n have no valid public point
        raise ValueError("private key is out of the secp256k1 range (0 < k < n)")
    return k


# --- address derivation: EOA (§1.14.6) and contract (§1.14.1) ------------------
# Both addresses are keccak tails, differing only in what gets hashed. An EOA's
# is the last 20 bytes of keccak256 over the 64-byte public key body (X || Y),
# i.e. the key determines the address. A contract's is chosen by the DEPLOYER:
# CREATE hashes rlp([deployer, nonce]) — so it depends on how many times that
# account has deployed — while CREATE2 (EIP-1014) hashes
# 0xff || deployer || salt || keccak256(init_code), which is counterfactual: it
# can be computed before the contract exists. Neither tool deploys anything.
def eth_eoa_address(
    private_key: Annotated[
        str,
        Field(
            description="A 32-byte secp256k1 private key as hex (0x prefix optional). "
            "Never echoed back in the result."
        ),
    ],
) -> dict:
    """Derive an EOA's Ethereum address and public key from its private key.

    The public key is the curve point k*G, serialized uncompressed (0x04 || X || Y);
    the address is the last 20 bytes of keccak256(X || Y), EIP-55 checksummed. This
    is the externally-owned-account counterpart to `eth_contract_address` — it
    derives, it does not create an account. Returns {address, public_key}; the
    private key is never echoed back.

    Example: eth_eoa_address(
    "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80") ->
    address="0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266".
    """
    pubkey = _secp_pubkey_uncompressed(_private_key_scalar(private_key))
    return {
        "address": _pubkey_address(pubkey[1:]),
        "public_key": "0x" + pubkey.hex(),
    }


def eth_contract_address(
    scheme: Annotated[
        Literal["create", "create2"],
        Field(
            description="'create' derives from the deployer and its `nonce`; "
            "'create2' (EIP-1014) derives from the deployer, a `salt`, and the "
            "`init_code`, so the address is known before deployment."
        ),
    ],
    deployer: Annotated[
        str,
        Field(
            description="The deploying account's 20-byte hex address (0x optional, "
            "any casing) — an EOA for a top-level deploy, or the factory contract."
        ),
    ],
    nonce: Annotated[
        int | str | None,
        Field(
            description="The deployer's transaction nonce for this deploy (required "
            "for scheme=create; int, decimal string, or 0x-hex). A contract "
            "deployer's nonce starts at 1, an EOA's at 0."
        ),
    ] = None,
    salt: Annotated[
        str | None,
        Field(
            description="A 32-byte hex salt chosen by the deployer (required for "
            "scheme=create2)."
        ),
    ] = None,
    init_code: Annotated[
        str | None,
        Field(
            description="The full contract creation bytecode as hex — constructor "
            "code plus its ABI-encoded arguments, NOT the deployed runtime code "
            "(required for scheme=create2)."
        ),
    ] = None,
) -> dict:
    """Compute a contract's CREATE or CREATE2 deployment address.

    scheme=create  -> needs `nonce`;  address = keccak256(rlp([deployer, nonce]))[12:]
    scheme=create2 -> needs `salt` and `init_code`;
                      address = keccak256(0xff ++ deployer ++ salt ++
                                          keccak256(init_code))[12:]
    Returns {address}, EIP-55 checksummed. Computes only — nothing is deployed.

    Example: eth_contract_address("create",
    "0x6ac7ea33f8831ea9dcc53393aaa88b25a785dbf0", nonce=0) ->
    address="0xcd234A471b72ba2F1Ccf0A70FCABA648a5eeCD8d".
    """
    deployer_bytes = bytes.fromhex(_address_body(deployer))

    if scheme == "create":
        if nonce is None:
            raise ValueError("scheme=create requires `nonce`")
        nonce_int = _eip712_parse_int(nonce)
        if not 0 <= nonce_int < 2**64:  # EIP-2681 caps account nonces at 2^64-1
            raise ValueError(f"nonce out of range (0..2^64-1): {nonce}")
        digest = _keccak256(_rlp_encode([deployer_bytes.hex(), nonce_int]))
    elif scheme == "create2":
        if salt is None or init_code is None:
            raise ValueError("scheme=create2 requires `salt` and `init_code`")
        salt_bytes = _to_bytes(salt, "hex")
        if len(salt_bytes) != 32:
            raise ValueError(f"salt must be 32 bytes, got {len(salt_bytes)}")
        code_hash = _keccak256(_to_bytes(init_code, "hex"))
        digest = _keccak256(b"\xff" + deployer_bytes + salt_bytes + code_hash)
    else:
        raise ValueError(f"unknown scheme {scheme!r}; expected 'create' or 'create2'")

    return {"address": _eip55(digest[-20:].hex())}


# --- BIP-39 mnemonic <-> seed (§1.15.1) ----------------------------------------
# A mnemonic encodes ENT bits of entropy (128..256, a multiple of 32) plus an
# ENT/32-bit checksum — the leading bits of sha256(entropy) — as 11-bit indices
# into a 2048-word list, giving 12..24 words. The seed that BIP-32 consumes is a
# separate step: PBKDF2-HMAC-SHA512 over the NFKD mnemonic with salt
# "mnemonic" + passphrase, 2048 rounds, 64 bytes out. The passphrase is the
# "25th word": any passphrase yields a valid-looking wallet, so a wrong one
# silently opens a different (empty) wallet rather than failing.
#
# The bundled wordlist is the canonical BIP-39 English list (see README).
_BIP39_WORDLIST: tuple[str, ...] | None = None
_BIP39_INDEX: dict[str, int] | None = None

# Legal mnemonic lengths: word count -> entropy bytes. 11 bits/word, and the
# checksum is ENT/32 bits, so 33 bits of mnemonic carry 32 bits of entropy.
_BIP39_SIZES = {12: 16, 15: 20, 18: 24, 21: 28, 24: 32}


def _bip39_wordlist() -> tuple[str, ...]:
    """Load (and cache) the bundled BIP-39 English wordlist, one word per line."""
    global _BIP39_WORDLIST
    if _BIP39_WORDLIST is None:
        text = (files("mcp_bytesmith") / "wordlists" / "bip39_english.txt").read_text(
            "utf-8"
        )
        words = tuple(w for w in text.split() if w)
        if len(words) != 2048:  # 11 bits per word requires exactly 2^11 words
            raise ValueError(
                f"BIP-39 wordlist is corrupt: {len(words)} words, want 2048"
            )
        _BIP39_WORDLIST = words
    return _BIP39_WORDLIST


def _bip39_index() -> dict[str, int]:
    """Word -> index lookup over the bundled wordlist."""
    global _BIP39_INDEX
    if _BIP39_INDEX is None:
        _BIP39_INDEX = {w: i for i, w in enumerate(_bip39_wordlist())}
    return _BIP39_INDEX


def _bip39_checksum_bits(entropy: bytes) -> tuple[int, int]:
    """(checksum value, checksum bit-length) for `entropy` — the sha256 prefix."""
    bit_len = len(entropy) * 8 // 32  # 4..8 bits, so always inside the first byte
    return hashlib.sha256(entropy).digest()[0] >> (8 - bit_len), bit_len


def _bip39_encode(entropy: bytes) -> str:
    """Entropy -> a canonical (lowercase, single-spaced) BIP-39 mnemonic."""
    if len(entropy) not in _BIP39_SIZES.values():
        raise ValueError(
            f"entropy must be 16, 20, 24, 28, or 32 bytes, got {len(entropy)}"
        )
    checksum, cs_bits = _bip39_checksum_bits(entropy)
    bits = (int.from_bytes(entropy, "big") << cs_bits) | checksum
    total = len(entropy) * 8 + cs_bits
    words = _bip39_wordlist()
    return " ".join(
        words[(bits >> (total - 11 * (i + 1))) & 0x7FF] for i in range(total // 11)
    )


def _bip39_split(mnemonic: str) -> list[str]:
    """NFKD-normalize and split a mnemonic; casing and extra whitespace forgiven."""
    return unicodedata.normalize("NFKD", mnemonic).lower().split()


def _bip39_check(words: list[str]) -> str | None:
    """None when `words` is a valid mnemonic, else the reason it is not.

    Positions (not the words) are reported for unknown entries: a mnemonic is a
    secret, so it must not be echoed back even inside an error (§2.0.6).
    """
    if len(words) not in _BIP39_SIZES:
        return f"mnemonic has {len(words)} words; expected 12, 15, 18, 21, or 24"
    index = _bip39_index()
    unknown = [i + 1 for i, w in enumerate(words) if w not in index]
    if unknown:
        return f"words at position(s) {unknown} are not in the BIP-39 English wordlist"
    if _bip39_to_entropy(words) is None:
        return "checksum does not match the mnemonic's entropy (likely a typo)"
    return None


def _bip39_to_entropy(words: list[str]) -> bytes | None:
    """Recover the entropy behind a wordlist-valid mnemonic; None if the checksum fails."""
    index = _bip39_index()
    bits = 0
    for word in words:
        bits = (bits << 11) | index[word]
    total = len(words) * 11
    cs_bits = total // 33
    entropy = (bits >> cs_bits).to_bytes((total - cs_bits) // 8, "big")
    if (bits & ((1 << cs_bits) - 1)) != _bip39_checksum_bits(entropy)[0]:
        return None
    return entropy


def bip39(
    action: Annotated[
        Literal["generate", "validate", "to_seed"],
        Field(
            description="'generate' builds a mnemonic (from `entropy`, or fresh "
            "CSPRNG entropy of `strength` bits); 'validate' checks a mnemonic's "
            "wordlist membership and checksum; 'to_seed' derives the 64-byte BIP-32 "
            "seed from a mnemonic and optional `passphrase`."
        ),
    ],
    mnemonic: Annotated[
        str | None,
        Field(
            description="The mnemonic sentence (required for validate/to_seed). "
            "Casing and extra whitespace are forgiven; it is never echoed back."
        ),
    ] = None,
    entropy: Annotated[
        str | None,
        Field(
            description="Entropy as hex (0x optional) for action=generate: 16, 20, "
            "24, 28, or 32 bytes, giving 12..24 words. Omit to draw fresh CSPRNG "
            "entropy of `strength` bits. Never echoed back."
        ),
    ] = None,
    passphrase: Annotated[
        str,
        Field(
            description='The optional BIP-39 passphrase (the "25th word") for '
            "action=to_seed. Any passphrase is valid and yields a DIFFERENT seed, so "
            "a wrong one silently opens a different wallet. Never echoed back."
        ),
    ] = "",
    strength: Annotated[
        Literal[128, 160, 192, 224, 256],
        Field(
            description="Entropy bits for action=generate when `entropy` is omitted "
            "(128 -> 12 words, 256 -> 24 words). Ignored when `entropy` is given."
        ),
    ] = 128,
) -> dict:
    """Generate, validate, or convert a BIP-39 mnemonic to a seed.

    action=generate -> {action, mnemonic, word_count, strength}. With `entropy` the
      mnemonic is deterministic; without it, fresh CSPRNG entropy of `strength` bits.
    action=validate -> {action, valid, word_count} plus a `reason` when invalid — a
      bad mnemonic is a soft result, not an error (§2.0.5).
    action=to_seed  -> {action, seed, word_count}: the 64-byte seed as 0x-hex, ready
      for `bip32_derive`. PBKDF2-HMAC-SHA512(mnemonic, "mnemonic"+passphrase, 2048).
      An invalid mnemonic raises here; use action=validate to inspect it first.

    Neither the mnemonic, the entropy, nor the passphrase is ever echoed back.

    Example: bip39("to_seed", mnemonic="abandon abandon abandon abandon abandon
    abandon abandon abandon abandon abandon abandon about") -> seed="0x5eb00bbd..."
    """
    if action == "generate":
        raw = (
            secrets.token_bytes(strength // 8)
            if entropy is None
            else _to_bytes(entropy, "hex")
        )
        sentence = _bip39_encode(raw)
        return {
            "action": "generate",
            "mnemonic": sentence,
            "word_count": len(sentence.split()),
            "strength": len(raw) * 8,
        }

    if mnemonic is None:
        raise ValueError(f"action={action} requires `mnemonic`")
    words = _bip39_split(mnemonic)

    if action == "validate":
        reason = _bip39_check(words)
        result = {
            "action": "validate",
            "valid": reason is None,
            "word_count": len(words),
        }
        if reason is not None:
            result["reason"] = reason
        return result

    if action == "to_seed":
        reason = _bip39_check(words)
        if reason is not None:
            raise ValueError(f"invalid mnemonic: {reason}")
        # The seed is defined over the NFKD mnemonic and the NFKD salt; we feed the
        # canonical lowercase, single-spaced form so forgiven input still derives
        # the standard seed.
        salt = unicodedata.normalize("NFKD", "mnemonic" + passphrase)
        seed = hashlib.pbkdf2_hmac(
            "sha512", " ".join(words).encode("utf-8"), salt.encode("utf-8"), 2048, 64
        )
        return {
            "action": "to_seed",
            "seed": "0x" + seed.hex(),
            "word_count": len(words),
        }

    raise ValueError(
        f"unknown action {action!r}; expected 'generate', 'validate', or 'to_seed'"
    )


# --- BIP-32 / BIP-44 HD derivation (§1.15.2) -----------------------------------
# An HD wallet grows a tree of keys from one seed. The master key is
# HMAC-SHA512("Bitcoin seed", seed): left half = master private key (a secp256k1
# scalar), right half = master chain code. Each path step i derives a child from
# HMAC-SHA512(chain_code, data || ser32(i)), where data is 0x00||ser256(k_parent)
# for a HARDENED step (i >= 2^31) or the 33-byte compressed parent pubkey for a
# normal one; the child key is (IL + k_parent) mod n and the child chain code is
# IR. The curve math reuses _ec_mul/_SECP_* above. Ethereum uses coin type 60, so
# the conventional account-0 path is m/44'/60'/0'/0/0.
_BIP32_HARDENED = 0x80000000


def _bip32_master(seed: bytes) -> tuple[int, bytes]:
    """Master (private-key scalar, chain code) from a seed per BIP-32."""
    i = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    k = int.from_bytes(i[:32], "big")
    if k == 0 or k >= _SECP_N:  # astronomically unlikely; BIP-32 mandates the check
        raise ValueError("seed produced an invalid master key (try another seed)")
    return k, i[32:]


def _bip32_ckd_priv(k_par: int, c_par: bytes, index: int) -> tuple[int, bytes]:
    """Derive child (private-key scalar, chain code) at `index` from a parent."""
    if index & _BIP32_HARDENED:
        data = b"\x00" + k_par.to_bytes(32, "big") + index.to_bytes(4, "big")
    else:
        data = _secp_pubkey_compressed(k_par) + index.to_bytes(4, "big")
    i = hmac.new(c_par, data, hashlib.sha512).digest()
    il = int.from_bytes(i[:32], "big")
    k_child = (il + k_par) % _SECP_N
    if il >= _SECP_N or k_child == 0:  # BIP-32: skip to the next index in practice
        raise ValueError(f"derived key at index {index} is invalid; try another path")
    return k_child, i[32:]


def _parse_bip32_path(path: str) -> list[int]:
    """Parse an "m/44'/60'/0'/0/0"-style path into a list of 32-bit child indices."""
    text = path.strip()
    if text in ("", "m", "M"):
        return []
    parts = text.split("/")
    if parts[0] in ("m", "M"):
        parts = parts[1:]
    indices: list[int] = []
    for part in parts:
        hardened = part[-1:] in ("'", "h", "H")
        num_str = part[:-1] if hardened else part
        if not num_str.isdigit():  # rejects '', signs, whitespace, non-decimal
            raise ValueError(f"invalid path segment {part!r} in {path!r}")
        num = int(num_str)
        if num >= _BIP32_HARDENED:
            raise ValueError(f"path index {num} out of range (0..2^31-1) in {path!r}")
        indices.append(num + _BIP32_HARDENED if hardened else num)
    return indices


def _format_bip32_path(indices: list[int]) -> str:
    """Render a list of child indices back to canonical "m/44'/…" form."""
    out = ["m"]
    for idx in indices:
        if idx & _BIP32_HARDENED:
            out.append(f"{idx - _BIP32_HARDENED}'")
        else:
            out.append(str(idx))
    return "/".join(out)


def bip32_derive(
    seed: Annotated[
        str,
        Field(
            description="BIP-32 seed bytes (typically the 64-byte BIP-39 "
            "mnemonic-to-seed output), as hex or base64 per `input_format`. This is a "
            "SEED, not a mnemonic — derive the seed from words first. Never echoed back."
        ),
    ],
    path: Annotated[
        str,
        Field(
            description="BIP-32/44 derivation path, e.g. \"m/44'/60'/0'/0/0\" (the "
            "conventional Ethereum account-0 key). Use ' or h to mark a hardened step; "
            '"m" (or empty) yields the master key itself.'
        ),
    ],
    input_format: Annotated[
        Literal["hex", "base64"],
        Field(
            description="How to decode `seed` to bytes: 'hex' (0x optional) or 'base64'."
        ),
    ] = "hex",
) -> dict:
    """Derive an HD child key and its Ethereum address from a seed along a BIP-32/44 path.

    The master key comes from HMAC-SHA512("Bitcoin seed", seed); each path step
    derives a child via BIP-32 CKDpriv (hardened steps use the parent private key,
    normal steps its compressed public key). The Ethereum address is the last 20
    bytes of keccak256(uncompressed pubkey), EIP-55 checksummed. Returns {path,
    depth, private_key, public_key, chain_code, address}; the derived child
    private_key IS returned (it is new output, not the seed), but the input seed is
    never echoed.

    Example: bip32_derive(<64-byte seed hex>, "m/44'/60'/0'/0/0") ->
    {"address": "0x...", "private_key": "0x...", ...}.
    """
    seed_bytes = _to_bytes(seed, input_format)
    if len(seed_bytes) < 16:  # BIP-32 mandates 128..512 bits of seed entropy
        raise ValueError("seed must be at least 16 bytes")
    indices = _parse_bip32_path(path)
    k, chain_code = _bip32_master(seed_bytes)
    for index in indices:
        k, chain_code = _bip32_ckd_priv(k, chain_code, index)
    pubkey = _secp_pubkey_uncompressed(k)
    address = _pubkey_address(pubkey[1:])
    return {
        "path": _format_bip32_path(indices),
        "depth": len(indices),
        "private_key": "0x" + k.to_bytes(32, "big").hex(),
        "public_key": "0x" + pubkey.hex(),
        "chain_code": "0x" + chain_code.hex(),
        "address": address,
    }


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
    action: Annotated[
        Literal["encode", "decode"],
        Field(
            description="'encode' signed fields into a raw tx, or 'decode' a raw tx."
        ),
    ],
    data: Annotated[
        str | None,
        Field(
            description="0x-prefixed raw transaction bytes to decode (required for "
            "action=decode): a legacy RLP list or an EIP-2718 typed envelope."
        ),
    ] = None,
    fields: Annotated[
        dict | None,
        Field(
            description="Already-signed tx fields object (required for "
            "action=encode); does NOT sign. The type comes from a `type` key or is "
            "inferred (maxFeePerGas->1559, blobVersionedHashes->4844, "
            "accessList->2930, else legacy). Numbers accept int/decimal/0x-hex; "
            "`to`/`data` are 0x-hex. A stringified JSON object is accepted."
        ),
    ] = None,
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

    Example: eth_tx_codec("encode", fields={"nonce":0,"gasPrice":"0x09184e72a000",
    "gasLimit":"0x2710","to":"0x00..00","value":0,"data":"0x"}) -> type=0,
    raw="0xe5808609184e72a00082271094...808080".
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


def eth_address_case(
    action: Annotated[
        Literal["encode", "verify"],
        Field(
            description="'encode' applies the EIP-55 checksum casing; 'verify' "
            "checks whether the input's casing already matches it."
        ),
    ],
    address: Annotated[
        str,
        Field(
            description="A 20-byte hex address, 40 hex chars with or without a 0x "
            "prefix; any casing is accepted (verify compares the given casing "
            "against the EIP-55 checksum)."
        ),
    ],
) -> dict:
    """Apply or verify an EIP-55 mixed-case address checksum.

    action=encode -> {action, address} with the checksummed (mixed-case) address.
    action=verify -> {action, address (checksummed), valid}, plus a `reason` when
    the supplied casing does not match the EIP-55 checksum.

    Example: eth_address_case("encode",
    "0x52908400098527886e0f7030069857d2e4169ee7") ->
    address="0x52908400098527886E0F7030069857D2E4169EE7".
    """
    body = _address_body(address)
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
def ens_namehash(
    name: Annotated[
        str,
        Field(
            description="A dot-separated ENS name, e.g. 'vitalik.eth' (''=the root). "
            "EIP-137 expects it ALREADY UTS-46 normalized — run unicode_normalize "
            "first if it may contain uppercase/unicode. Empty labels (leading/"
            "trailing/double dots) are rejected."
        ),
    ],
) -> dict:
    """Compute the EIP-137 namehash (and labelhash) of an ENS name.

    The name is hashed exactly as given; EIP-137 expects it already UTS-46
    normalized (use unicode_normalize first if needed), and empty labels from a
    stray dot are rejected. Returns {name, namehash, labelhash}, where labelhash
    is the keccak of the leftmost label — for a single label that is the .eth
    registrar token id for that name.

    Example: ens_namehash("vitalik.eth") ->
    namehash="0xee6c4522aab0003e8d14cd40a6af439055fd2577951148c14b6cea9a53475835".
    """
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
    mcp.tool()(eth_eoa_address)
    mcp.tool()(eth_contract_address)
    mcp.tool()(bip39)
    mcp.tool()(eth_tx_codec)
    mcp.tool()(eth_address_case)
    mcp.tool()(ens_namehash)
    mcp.tool()(bip32_derive)
