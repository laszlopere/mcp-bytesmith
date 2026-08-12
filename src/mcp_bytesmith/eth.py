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


def _peel_arrays(rest: str) -> tuple[str, str]:
    """Pull leading [..] array suffixes off `rest` -> (suffix, remaining text).

    The remainder is whatever follows the dimensions — the data location and/or
    the declared parameter name. The canonical type drops those, but the
    calldata decoder (TODO 20.1) wants the name, so they are returned rather
    than discarded.
    """
    rest, suffix = rest.strip(), ""
    while rest.startswith("["):
        close = rest.index("]")
        suffix += rest[: close + 1].replace(" ", "")
        rest = rest[close + 1 :].strip()
    return suffix, rest


# Keywords that may sit between a parameter's type and its name. `indexed` is an
# event modifier — captured rather than merely skipped so a later log decoder can
# split indexed from non-indexed args off this same parse.
_PARAM_MODIFIERS = frozenset({"calldata", "memory", "storage", "payable", "indexed"})


def _param_tail(rest: str) -> tuple[str | None, bool]:
    """Declared name (None when unnamed) and the `indexed` flag from a param tail."""
    tokens = rest.split()
    indexed = "indexed" in tokens
    name = None
    if tokens and tokens[-1] not in _PARAM_MODIFIERS and tokens[-1].isidentifier():
        name = tokens[-1]
    return name, indexed


def _parse_param(param: str) -> dict:
    """Parse one parameter -> {type, name, indexed} (+ components for tuples).

    `type` is the canonical ABI type, `name` the declared parameter name or None.
    Tuples also carry `components`, so the dict matches a JSON ABI input entry.
    """
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
        components = [_parse_param(p) for p in _split_top_level(param[1:i])]
        suffix, rest = _peel_arrays(param[i + 1 :])
        name, indexed = _param_tail(rest)
        members = ",".join(c["type"] for c in components)
        return {
            "type": f"({members}){suffix}",
            "name": name,
            "indexed": indexed,
            "components": components,
        }
    tokens = param.split()  # type sits before any data-location / name
    bracket = tokens[0].find("[")
    if bracket == -1:
        canon = _canon_alias(tokens[0])
    else:
        canon = _canon_alias(tokens[0][:bracket]) + tokens[0][bracket:]
    name, indexed = _param_tail(" ".join(tokens[1:]))
    return {"type": canon, "name": name, "indexed": indexed}


def _canon_param(param: str) -> str:
    """Canonicalize one parameter: drop name/location, normalize the type."""
    return _parse_param(param)["type"]


def _split_signature(signature: str) -> tuple[str, list[str]]:
    """Split 'name(a, b)' -> (name, raw unparsed parameter strings).

    Anything after the matching close paren (a Solidity `external returns (bool)`
    clause) is ignored, so a line pasted straight out of source works.
    """
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
    return name, (_split_top_level(body) if body else [])


def _parse_signature(signature: str) -> tuple[str, list[dict]]:
    """Signature -> (function/event name, parsed params carrying types AND names)."""
    name, raw = _split_signature(signature)
    return name, [_parse_param(p) for p in raw]


def _canonical_signature(signature: str) -> str:
    """Reduce a function/event signature to its canonical `name(types)` form."""
    name, params = _parse_signature(signature)
    return f"{name}({','.join(p['type'] for p in params)})"


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


# --- calldata <-> named arguments (TODO 20.1) ----------------------------------
# Calldata is a 4-byte selector followed by the standard ABI encoding of the
# argument tuple, so abi_codec already does half the job. What this adds is the
# selector split and the argument NAMES: the canonical signature discards names
# (they do not affect the selector), but they are the whole point when reading a
# transaction, so they are parsed and carried through to the result.
_NO_VALUE = object()  # sentinel: an args entry with no value (tuple components)


def _calldata_arg(param: dict, value: Any = _NO_VALUE) -> dict:
    """Project a parsed param (+ optional value) into an output `args` entry."""
    arg: dict[str, Any] = {"name": param["name"], "type": param["type"]}
    if value is not _NO_VALUE:
        arg["value"] = value
    if "components" in param:  # struct: name the members; values stay nested
        arg["components"] = [_calldata_arg(c) for c in param["components"]]
    return arg


def eth_calldata(
    action: Annotated[
        Literal["encode", "decode"],
        Field(
            description="'encode' a call's arguments into calldata, or 'decode' "
            "calldata into named arguments."
        ),
    ],
    signature: Annotated[
        str,
        Field(
            description="A human-readable Solidity function signature, e.g. "
            "'transfer(address to, uint256 amount)'. Parameter names are optional "
            "and are reported back; data locations, aliases (uint->uint256) and a "
            "trailing 'external returns (...)' clause are normalized away."
        ),
    ],
    data: Annotated[
        str | None,
        Field(
            description="0x-prefixed calldata to decode: the 4-byte selector "
            "followed by the encoded arguments (required for action=decode)."
        ),
    ] = None,
    values: Annotated[
        list | None,
        Field(
            description="Argument values to encode, positionally matching the "
            "signature's parameters; ints accept int/decimal/0x-hex, bytes are "
            "0x-hex, tuples and arrays are nested lists. A stringified JSON array "
            "is accepted. Omit for a zero-argument signature."
        ),
    ] = None,
) -> dict:
    """Split calldata into named, typed arguments — or build calldata from them.

    `signature` is human-readable, e.g. "transfer(address to, uint256 amount)";
    parameter names are optional and come back as `args[].name` (null when the
    signature declares none), with `args[].components` naming a struct's members.
    action=encode (needs `values`) -> {action, signature (canonical), selector,
    calldata, args}; `values` may be omitted for a zero-argument signature.
    action=decode (needs `data`) -> {action, signature, selector,
    selector_matches, args}; ints are decimal strings and addresses EIP-55
    checksummed. When the calldata's leading 4 bytes are not this signature's
    selector the arguments are still decoded, but `selector_matches` is false and
    `data_selector` + `reason` report the mismatch — the values are then almost
    certainly meaningless.

    Example: eth_calldata("decode", "transfer(address to, uint256 amount)",
    "0xa9059cbb...") -> args=[{name="to", ...}, {name="amount", ...}].
    """
    name, params = _parse_signature(signature)
    types = [p["type"] for p in params]
    canonical = f"{name}({','.join(types)})"
    selector = _keccak256(canonical.encode("ascii"))[:4]

    if action == "encode":
        vals = json.loads(values) if isinstance(values, str) else values
        if vals is None:
            vals = []  # a zero-argument call needs no `values`
        if len(vals) != len(types):
            raise ValueError(
                f"{canonical} takes {len(types)} argument(s), got {len(vals)}"
            )
        body = _abi_enc_tuple(types, vals)
        return {
            "action": "encode",
            "signature": canonical,
            "selector": "0x" + selector.hex(),
            "calldata": "0x" + (selector + body).hex(),
            "args": [_calldata_arg(p, v) for p, v in zip(params, vals)],
        }

    if action == "decode":
        if data is None:
            raise ValueError("action=decode requires `data`")
        raw = _to_bytes(data, "hex")
        if len(raw) < 4:
            raise ValueError(
                f"calldata is shorter than a 4-byte selector: {len(raw)} bytes"
            )
        body, matched = raw[4:], raw[:4] == selector
        # Minimum head size: one word per dynamic argument (its offset pointer)
        # plus the inline width of every static one. Short data would otherwise
        # decode to silent zeros off the end of the buffer. Trailing bytes PAST
        # the arguments are tolerated (as in abi_codec) — some protocols append
        # non-ABI suffixes to a call.
        head = sum(32 if _abi_is_dynamic(t) else _abi_static_size(t) for t in types)
        if len(body) < head:
            raise ValueError(
                f"calldata is too short for {canonical}: {len(body)} bytes after "
                f"the selector, need at least {head}"
            )
        try:
            decoded = _abi_dec_tuple(types, body, 0)
        except ValueError as exc:
            if matched:
                raise
            raise ValueError(
                f"calldata selector 0x{raw[:4].hex()} is not {canonical}'s "
                f"(0x{selector.hex()}), and the remaining data does not decode "
                f"as its arguments"
            ) from exc
        result = {
            "action": "decode",
            "signature": canonical,
            "selector": "0x" + selector.hex(),
            "selector_matches": matched,
            "args": [_calldata_arg(p, v) for p, v in zip(params, decoded)],
        }
        if not matched:
            result["data_selector"] = "0x" + raw[:4].hex()
            result["reason"] = (
                f"calldata starts with 0x{raw[:4].hex()}, not {canonical}'s "
                f"selector 0x{selector.hex()}; the decoded arguments are unreliable"
            )
        return result

    raise ValueError(f"unknown action {action!r}; expected 'encode' or 'decode'")


# --- receipt log -> named event args (TODO 20.2) -------------------------------
# A log is `topics` (at most 4 words) plus `data`. For a non-anonymous event
# topics[0] is keccak(canonical signature) and topics[1:] hold the indexed
# arguments; an anonymous event has no topic0 and starts them at topics[0]. The
# subtlety is what a topic actually HOLDS: only a value type (uintN/intN/bool/
# address/bytesN) sits there verbatim. Every array, every struct, and
# bytes/string are keccak-hashed into their topic, so the value is gone and only
# equality matching survives. That is NOT _abi_is_dynamic's test — uint256[3]
# and (uint256,bool) are static yet hashed — hence the predicate below.
def _abi_indexed_is_hashed(t: str) -> bool:
    """True when an indexed argument of type `t` reaches its topic as a keccak hash."""
    return (
        _array_split(t) is not None
        or _is_tuple(t)
        or _canon_alias(t.strip()) in ("bytes", "string")
    )


def _log_arg(param: dict, value: Any = _NO_VALUE, topic: bytes | None = None) -> dict:
    """Project a parsed event param into an output `args` entry (log flavour).

    Adds `indexed` to the shared calldata projection, plus — for an indexed
    argument whose type is hashed into its topic — the `hashed`/`hash` pair
    reporting the topic word that stands in for the unrecoverable value.
    """
    arg = _calldata_arg(param, value)
    arg["indexed"] = param["indexed"]
    if topic is not None:
        arg["hashed"] = True
        arg["hash"] = "0x" + topic.hex()
    return arg


def eth_log_decode(
    signature: Annotated[
        str,
        Field(
            description="A human-readable Solidity event signature, e.g. "
            "'Transfer(address indexed from, address indexed to, uint256 value)'. "
            "The `indexed` modifier is what splits the arguments between `topics` "
            "and `data`; parameter names are optional and are reported back, and "
            "aliases (uint->uint256) are normalized away."
        ),
    ],
    topics: Annotated[
        list[str],
        Field(
            description="The log's topics as 32-byte hex words (0x prefix "
            "optional): topic0 (the event's keccak signature hash) first, then one "
            "word per indexed argument. An anonymous event has no topic0. A "
            "stringified JSON array is accepted."
        ),
    ],
    data: Annotated[
        str | None,
        Field(
            description="0x-prefixed log data: the standard ABI encoding of the "
            "NON-indexed arguments. Omit (or pass '0x') when every argument is "
            "indexed."
        ),
    ] = None,
    anonymous: Annotated[
        bool,
        Field(
            description="True when the event is declared `anonymous` in Solidity — "
            "its log carries no topic0, so indexed arguments start at topics[0] "
            "and up to 4 are allowed."
        ),
    ] = False,
) -> dict:
    """Turn a receipt log's topics and data into named event arguments.

    `signature` is human-readable, e.g. "Transfer(address indexed from, address
    indexed to, uint256 value)"; `indexed` is what splits the arguments between
    `topics` and `data`. Returns {signature (canonical), anonymous, topic0,
    topic0_matches, args}; `topic0` and `topic0_matches` are omitted for an
    anonymous event, which carries no topic0 to check. `args` lists EVERY
    argument in declaration order — indexed and not, interleaved — as
    {name (null when undeclared), type, value, indexed}, plus `components` on
    tuple args. Only a value type (uintN/intN/bool/address/bytesN) survives in a
    topic: every array, every struct, and bytes/string are keccak-hashed into it,
    so those come back with value null plus {hashed: true, hash} — enough to
    match against keccak of a candidate, never the value itself. A topics[0] that
    is not this signature's topic0 is soft (topic0_matches false, plus
    `log_topic0` and `reason`), but a topic COUNT that contradicts the signature
    raises: ERC-20 and ERC-721 Transfer share a topic0 and differ only there.

    Example: eth_log_decode("Transfer(address indexed from, address indexed to,
    uint256 value)", [topic0, from_word, to_word], "0x..0de0b6b3a7640000") ->
    args=[{name="from", ...}, {name="to", ...}, {name="value", ...}].
    """
    name, params = _parse_signature(signature)
    types = [p["type"] for p in params]
    canonical = f"{name}({','.join(types)})"
    topic0 = _keccak256(canonical.encode("ascii"))

    topic_list = topics
    if isinstance(topic_list, str) and topic_list.lstrip().startswith("["):
        topic_list = json.loads(topic_list)  # client stringified the array
    if not isinstance(topic_list, list):
        raise ValueError("`topics` must be a list of 32-byte hex words")
    words = []
    for i, t in enumerate(topic_list):
        if not isinstance(t, str):
            raise ValueError(
                f"topics[{i}] must be a hex string, got {type(t).__name__}"
            )
        word = _to_bytes(t, "hex")
        if len(word) != 32:
            raise ValueError(f"topics[{i}] must be 32 bytes, got {len(word)}")
        words.append(word)

    indexed_params = [p for p in params if p["indexed"]]
    plain_params = [p for p in params if not p["indexed"]]

    # No LOGn opcode can emit more than 4 topics, so a signature needing more
    # indexed arguments than that could never have produced any log at all.
    limit = 4 if anonymous else 3
    if len(indexed_params) > limit:
        raise ValueError(
            f"{canonical} has {len(indexed_params)} indexed arguments; a"
            f"{' anonymous' if anonymous else ''} event allows at most {limit}"
        )

    # Arity is checked BEFORE topic0: a wrong count means the indexed arguments
    # cannot be paired with topic words at all, so any output would be invented.
    # It also catches what topic0 cannot — ERC-20 and ERC-721 Transfer hash to
    # the same topic0 and differ only in how many arguments are indexed.
    expected = len(indexed_params) if anonymous else len(indexed_params) + 1
    if len(words) != expected:
        # Exactly one topic short of a non-anonymous event is the shape a
        # forgotten `anonymous` produces — the only place that flag surfaces.
        hint = (
            "; an anonymous event carries no topic0 — pass anonymous=true if it "
            "is declared anonymous"
            if not anonymous and len(words) == expected - 1
            else ""
        )
        raise ValueError(
            f"{canonical} implies {expected} topic(s) ({len(indexed_params)} "
            f"indexed{'' if anonymous else ' plus topic0'}), got {len(words)}{hint}"
        )

    result: dict[str, Any] = {"signature": canonical, "anonymous": anonymous}
    if anonymous:
        indexed_words, matched = words, None
    else:
        matched = words[0] == topic0
        indexed_words = words[1:]
        result["topic0"] = "0x" + topic0.hex()
        result["topic0_matches"] = matched

    plain_types = [p["type"] for p in plain_params]
    body = _to_bytes(data, "hex") if data is not None else b""
    # Same guard as eth_calldata: one word per dynamic argument plus the inline
    # width of every static one. Trailing bytes past the arguments are tolerated.
    head = sum(32 if _abi_is_dynamic(t) else _abi_static_size(t) for t in plain_types)
    if len(body) < head:
        raise ValueError(
            f"log data is too short for {canonical}: {len(body)} bytes, "
            f"need at least {head} for its {len(plain_types)} non-indexed argument(s)"
        )
    try:
        decoded = _abi_dec_tuple(plain_types, body, 0)
    except ValueError as exc:
        if matched is not False:  # anonymous, or the identity checked out
            raise
        raise ValueError(
            f"topics[0] 0x{words[0].hex()} is not {canonical}'s topic0 "
            f"(0x{topic0.hex()}), and the data does not decode as its "
            f"non-indexed arguments"
        ) from exc

    args, ti, pi = [], 0, 0
    for p in params:
        if p["indexed"]:
            word = indexed_words[ti]
            ti += 1
            if _abi_indexed_is_hashed(p["type"]):
                args.append(_log_arg(p, value=None, topic=word))
            else:
                args.append(
                    _log_arg(p, value=_abi_dec_scalar(_canon_alias(p["type"]), word, 0))
                )
        else:
            args.append(_log_arg(p, value=decoded[pi]))
            pi += 1
    result["args"] = args

    if matched is False:
        result["log_topic0"] = "0x" + words[0].hex()
        result["reason"] = (
            f"topics[0] 0x{words[0].hex()} is not {canonical}'s topic0 "
            f"(0x{topic0.hex()}); the decoded arguments are unreliable"
        )
    return result


# --- revert data -> reason (TODO 20.3) -----------------------------------------
# A failed call returns its revert data in the same shape as calldata: a 4-byte
# selector plus ABI-encoded arguments. Two are built into Solidity — Error(string)
# from `require`/`revert("...")` and Panic(uint256) from the compiler's own checks
# — and everything else is a user-declared custom error, undecodable without its
# signature. An empty payload is its own answer: `revert()` with no reason, or a
# require that never carried one.
_ERROR_SIG = "Error(string)"
_PANIC_SIG = "Panic(uint256)"
_ERROR_SELECTOR = _keccak256(_ERROR_SIG.encode("ascii"))[:4]  # 0x08c379a0
_PANIC_SELECTOR = _keccak256(_PANIC_SIG.encode("ascii"))[:4]  # 0x4e487b71

# Solidity's documented panic codes (docs.soliditylang.org, "Panic via assert").
_PANIC_CODES = {
    0x00: "generic compiler-inserted panic",
    0x01: "assert() with an argument that evaluated to false",
    0x11: "arithmetic overflow or underflow outside an unchecked block",
    0x12: "division or modulo by zero",
    0x21: "a value too large or negative was converted to an enum type",
    0x22: "an incorrectly encoded storage byte array was accessed",
    0x31: ".pop() was called on an empty array",
    0x32: "an array was accessed at an out-of-bounds or negative index",
    0x41: "too much memory was allocated, or an array was created too large",
    0x51: "a zero-initialized variable of internal function type was called",
}


def eth_revert_decode(
    data: Annotated[
        str,
        Field(
            description="The 0x-prefixed revert data returned by a failed call: a "
            "4-byte error selector followed by its ABI-encoded arguments. An empty "
            "'0x' is a revert that carried no reason."
        ),
    ],
    signature: Annotated[
        str | None,
        Field(
            description="A custom error's human-readable signature, e.g. "
            "'InsufficientBalance(uint256 available, uint256 required)'. Only "
            "needed for user-declared errors — Error(string) and Panic(uint256) "
            "are recognized without it."
        ),
    ] = None,
) -> dict:
    """Decode a failed call's revert data into a human-readable reason.

    Returns {kind, ...} where `kind` selects the rest of the payload:
    'empty' (no revert data at all) -> {reason}; 'error' (Error(string), the
    require/revert message) -> {selector, signature, reason}; 'panic'
    (Panic(uint256), a compiler check) -> {selector, signature, code, meaning};
    'custom' (a user-declared error, needs `signature`) -> {selector, signature,
    selector_matches, args} with args as {name, type, value} exactly as
    eth_calldata reports them; 'unknown' (an unrecognized selector and no
    `signature` given) -> {selector, reason}. A `signature` whose selector is not
    the one in `data` still decodes, but selector_matches is false and `reason`
    says so.

    Example: eth_revert_decode("0x08c379a0...") -> kind="error",
    reason="ERC20: transfer amount exceeds balance".
    """
    raw = _to_bytes(data, "hex")
    if not raw:
        return {
            "kind": "empty",
            "reason": "reverted without any data — revert()/require() with no "
            "reason string, or a failure that returned none (e.g. out of gas)",
        }
    if len(raw) < 4:
        raise ValueError(
            f"revert data is shorter than a 4-byte selector: {len(raw)} bytes"
        )
    selector, body = raw[:4], raw[4:]

    def _decode(types: list[str], label: str) -> list:
        """ABI-decode the argument tail, refusing to read past its end."""
        head = sum(32 if _abi_is_dynamic(t) else _abi_static_size(t) for t in types)
        if len(body) < head:
            raise ValueError(
                f"revert data is too short for {label}: {len(body)} bytes after "
                f"the selector, need at least {head}"
            )
        return _abi_dec_tuple(types, body, 0)

    if signature is not None:
        name, params = _parse_signature(signature)
        types = [p["type"] for p in params]
        canonical = f"{name}({','.join(types)})"
        custom_selector = _keccak256(canonical.encode("ascii"))[:4]
        matched = selector == custom_selector
        # A built-in takes precedence over a signature that does not match the
        # data — "you guessed X, but this is a standard Error(string)" is the
        # more useful answer than forcing the guess onto it.
        if matched or selector not in (_ERROR_SELECTOR, _PANIC_SELECTOR):
            try:
                values = _decode(types, canonical)
            except ValueError:
                if matched:
                    raise
                values = None
            if values is not None:
                result = {
                    "kind": "custom",
                    "selector": "0x" + custom_selector.hex(),
                    "signature": canonical,
                    "selector_matches": matched,
                    "args": [_calldata_arg(p, v) for p, v in zip(params, values)],
                }
                if not matched:
                    result["data_selector"] = "0x" + selector.hex()
                    result["reason"] = (
                        f"revert data starts with 0x{selector.hex()}, not "
                        f"{canonical}'s selector 0x{custom_selector.hex()}; the "
                        f"decoded arguments are unreliable"
                    )
                return result

    if selector == _ERROR_SELECTOR:
        return {
            "kind": "error",
            "selector": "0x" + selector.hex(),
            "signature": _ERROR_SIG,
            "reason": _decode(["string"], _ERROR_SIG)[0],
        }

    if selector == _PANIC_SELECTOR:
        code = int(_decode(["uint256"], _PANIC_SIG)[0])
        result = {
            "kind": "panic",
            "selector": "0x" + selector.hex(),
            "signature": _PANIC_SIG,
            "code": hex(code),
            "meaning": _PANIC_CODES.get(code),
        }
        if result["meaning"] is None:
            result["reason"] = (
                f"{hex(code)} is not one of Solidity's documented panic codes"
            )
        return result

    return {
        "kind": "unknown",
        "selector": "0x" + selector.hex(),
        "reason": (
            f"0x{selector.hex()} is neither Error(string) nor Panic(uint256); it "
            f"is a custom error — pass its `signature` to decode the arguments"
        ),
    }


# --- JSON ABI <-> human-readable, and the selector table (TODO 20.8) -----------
# The sibling tools (eth_calldata, eth_log_decode, eth_revert_decode) all speak
# human-readable signatures, because that is what a person pastes. A compiled
# artifact speaks JSON ABI instead, where a tuple is spelled {"type": "tuple",
# "components": [...]}. This translates in both directions off ONE parsed form —
# the same {type, name, indexed, components} dicts _parse_param produces — and
# derives every selector and topic0 along the way, which is the lookup table you
# need before you can call any of the others.
_ABI_KINDS = ("function", "event", "error", "constructor", "fallback", "receive")
_ABI_MUTABILITY = ("pure", "view", "payable", "nonpayable")


def _abi_json_type(entry: dict) -> str:
    """Canonical ABI type for one JSON ABI input/output entry (tuples expanded)."""
    t = entry.get("type")
    if not isinstance(t, str) or not t:
        raise ValueError(f"ABI parameter is missing a `type`: {entry!r}")
    if t.startswith("tuple"):
        inner = ",".join(_abi_json_type(c) for c in entry.get("components") or [])
        return f"({inner}){t[len('tuple') :]}"
    return _canon_alias(t)


def _params_from_abi(entries: Any) -> list[dict]:
    """JSON ABI inputs -> the parsed-param dicts _parse_param produces."""
    params = []
    for entry in entries or []:
        if not isinstance(entry, dict):
            raise ValueError(f"ABI parameter must be an object, got {entry!r}")
        param = {
            "type": _abi_json_type(entry),
            "name": entry.get("name") or None,
            "indexed": bool(entry.get("indexed", False)),
        }
        if str(entry.get("type", "")).startswith("tuple"):
            param["components"] = _params_from_abi(entry.get("components"))
        params.append(param)
    return params


def _tuple_head_end(t: str) -> int:
    """Index of the ')' closing a tuple type's leading '(...)' group."""
    depth = 0
    for i, ch in enumerate(t):
        depth += ch == "("
        depth -= ch == ")"
        if depth == 0:
            return i
    raise ValueError(f"unbalanced parentheses in type: {t!r}")


def _abi_json_params(params: list[dict]) -> list[dict]:
    """Parsed params -> JSON ABI entries (the inverse of _params_from_abi)."""
    entries = []
    for p in params:
        if "components" in p:
            close = _tuple_head_end(p["type"])
            entry: dict[str, Any] = {
                "name": p["name"] or "",
                "type": "tuple" + p["type"][close + 1 :],
                "components": _abi_json_params(p["components"]),
            }
        else:
            entry = {"name": p["name"] or "", "type": p["type"]}
        if p.get("indexed"):
            entry["indexed"] = True
        entries.append(entry)
    return entries


def _human_param(p: dict) -> str:
    """Render one parsed param back to Solidity source form, names included."""
    t = p["type"]
    if "components" in p:
        close = _tuple_head_end(t)
        members = ", ".join(_human_param(c) for c in p["components"])
        t = f"({members}){t[close + 1 :]}"
    bits = [t]
    if p.get("indexed"):
        bits.append("indexed")
    if p["name"]:
        bits.append(p["name"])
    return " ".join(bits)


def _abi_entry_from_human(text: str) -> dict:
    """Parse one human-readable declaration into a normalized ABI record."""
    text = text.strip()
    kind, rest = "function", text
    head = text.split("(", 1)[0].split()
    if head and head[0] in _ABI_KINDS:
        kind, rest = head[0], text[len(head[0]) :].lstrip()
    if kind in ("constructor", "fallback", "receive") and "(" not in rest:
        rest += "()"
    if kind == "constructor" and not rest.split("(", 1)[0].strip():
        rest = "constructor" + rest  # _split_signature needs an identifier
    name, raw = _split_signature(rest)
    tail = rest[rest.index(")", rest.index("(")) :]
    # Solidity puts modifiers and an optional `returns (...)` after the params.
    outputs: list[dict] = []
    if "returns" in tail:
        after = tail.split("returns", 1)[1].lstrip()
        if after.startswith("("):
            outputs = [
                _parse_param(p)
                for p in _split_top_level(after[1 : _tuple_head_end(after)])
                if p.strip()
            ]
    record: dict[str, Any] = {
        "type": kind,
        "name": None if kind in ("constructor", "fallback", "receive") else name,
        "inputs": [_parse_param(p) for p in raw],
        "outputs": outputs,
    }
    words = tail.split("returns", 1)[0].split()
    for word in words:
        if word in _ABI_MUTABILITY:
            record["stateMutability"] = word
    if kind == "event":
        record["anonymous"] = "anonymous" in words
    return record


def _abi_entry_from_json(fragment: dict) -> dict:
    """Normalize one JSON ABI fragment into the same record shape."""
    kind = fragment.get("type", "function")
    if kind not in _ABI_KINDS:
        raise ValueError(f"unknown ABI entry type {kind!r}")
    record: dict[str, Any] = {
        "type": kind,
        "name": fragment.get("name") or None,
        "inputs": _params_from_abi(fragment.get("inputs")),
        "outputs": _params_from_abi(fragment.get("outputs")),
    }
    if fragment.get("stateMutability"):
        record["stateMutability"] = fragment["stateMutability"]
    if kind == "event":
        record["anonymous"] = bool(fragment.get("anonymous", False))
    if kind not in ("constructor", "fallback", "receive") and not record["name"]:
        raise ValueError(f"ABI {kind} entry is missing a `name`")
    return record


def abi_inspect(
    abi: Annotated[
        list | dict | str,
        Field(
            description="A contract ABI in either representation: a JSON ABI "
            "(array of entries, or one entry object), or human-readable Solidity "
            "declarations (one string, or an array of them) such as 'function "
            "transfer(address to, uint256 amount)'. A stringified JSON array or "
            "object is accepted."
        ),
    ],
) -> dict:
    """List an ABI's entries with their canonical signatures and selectors.

    Accepts a JSON ABI or human-readable declarations and returns BOTH forms for
    every entry, so it converts in either direction. Returns {count, entries,
    selectors, topics}: `entries` carries {type, name, signature (canonical),
    human, inputs, outputs} per entry plus `selector` for functions and errors,
    `topic0` and `anonymous` for events, and `stateMutability` when known;
    `inputs`/`outputs` are JSON ABI shape, so feeding human-readable text in and
    reading them out is the human -> JSON ABI direction, and `human` is the
    reverse. `selectors` maps every 4-byte selector to its canonical signature
    and `topics` every topic0 — the lookup table eth_calldata, eth_log_decode and
    eth_revert_decode take as input. `collisions` is added only if two distinct
    signatures share a selector. constructor/fallback/receive entries carry no
    signature or selector, having none.

    Example: abi_inspect("function transfer(address to, uint256 amount)") ->
    selectors={"0xa9059cbb": "transfer(address,uint256)"}.
    """
    spec = abi
    if isinstance(spec, str):
        text = spec.strip()
        spec = json.loads(text) if text.startswith(("[", "{")) else [text]
    if isinstance(spec, dict):
        spec = [spec]
    if not isinstance(spec, list):
        raise ValueError("`abi` must be a JSON ABI array/object or signature text")

    records = []
    for i, item in enumerate(spec):
        if isinstance(item, dict):
            records.append(_abi_entry_from_json(item))
        elif isinstance(item, str):
            records.append(_abi_entry_from_human(item))
        else:
            raise ValueError(
                f"abi[{i}] must be an ABI object or a signature string, got "
                f"{type(item).__name__}"
            )

    entries: list[dict] = []
    selectors: dict[str, str] = {}
    topics: dict[str, str] = {}
    collisions: list[dict] = []
    for record in records:
        kind, name = record["type"], record["name"]
        params = record["inputs"]
        entry: dict[str, Any] = {"type": kind, "name": name}
        human_params = ", ".join(_human_param(p) for p in params)
        if kind in ("constructor", "fallback", "receive"):
            entry["human"] = f"{kind}({human_params})" if params else f"{kind}()"
        else:
            canonical = f"{name}({','.join(p['type'] for p in params)})"
            entry["signature"] = canonical
            digest = _keccak256(canonical.encode("ascii"))
            if kind == "event":
                entry["topic0"] = "0x" + digest.hex()
                if not record["anonymous"]:
                    topics[entry["topic0"]] = canonical
            else:
                entry["selector"] = "0x" + digest[:4].hex()
                previous = selectors.setdefault(entry["selector"], canonical)
                if previous != canonical:
                    collisions.append(
                        {
                            "selector": entry["selector"],
                            "signatures": [previous, canonical],
                        }
                    )
            entry["human"] = f"{kind} {name}({human_params})"
        if kind == "event" and record["anonymous"]:
            entry["anonymous"] = True
            entry["human"] += " anonymous"
        elif kind == "event":
            entry["anonymous"] = False
        if record.get("stateMutability"):
            entry["stateMutability"] = record["stateMutability"]
            if kind == "function" and record["stateMutability"] != "nonpayable":
                entry["human"] += f" {record['stateMutability']}"
        if record["outputs"]:
            entry["human"] += (
                f" returns ({', '.join(_human_param(p) for p in record['outputs'])})"
            )
        entry["inputs"] = _abi_json_params(params)
        entry["outputs"] = _abi_json_params(record["outputs"])
        entries.append(entry)

    result = {
        "count": len(entries),
        "entries": entries,
        "selectors": selectors,
        "topics": topics,
    }
    if collisions:
        result["collisions"] = collisions
    return result


# --- runtime bytecode: disassembly, dispatcher, metadata (TODO 20.4) -----------
# EVM bytecode is a flat byte string with ONE irregularity: PUSH1..PUSH32 carry
# their immediate inline, so the bytes 0x60..0x7f swallow the 1..32 bytes that
# follow them. Everything here depends on walking that correctly — grepping the
# raw hex for 0x63 (PUSH4) also hits the middle of some other push's immediate,
# which is exactly how a naive selector scraper invents functions that do not
# exist. So the dispatcher scrape below runs over a real decode, never a regex.
_EVM_OPCODES: dict[int, str] = {
    0x00: "STOP",
    0x01: "ADD",
    0x02: "MUL",
    0x03: "SUB",
    0x04: "DIV",
    0x05: "SDIV",
    0x06: "MOD",
    0x07: "SMOD",
    0x08: "ADDMOD",
    0x09: "MULMOD",
    0x0A: "EXP",
    0x0B: "SIGNEXTEND",
    0x10: "LT",
    0x11: "GT",
    0x12: "SLT",
    0x13: "SGT",
    0x14: "EQ",
    0x15: "ISZERO",
    0x16: "AND",
    0x17: "OR",
    0x18: "XOR",
    0x19: "NOT",
    0x1A: "BYTE",
    0x1B: "SHL",
    0x1C: "SHR",
    0x1D: "SAR",
    0x20: "KECCAK256",
    0x30: "ADDRESS",
    0x31: "BALANCE",
    0x32: "ORIGIN",
    0x33: "CALLER",
    0x34: "CALLVALUE",
    0x35: "CALLDATALOAD",
    0x36: "CALLDATASIZE",
    0x37: "CALLDATACOPY",
    0x38: "CODESIZE",
    0x39: "CODECOPY",
    0x3A: "GASPRICE",
    0x3B: "EXTCODESIZE",
    0x3C: "EXTCODECOPY",
    0x3D: "RETURNDATASIZE",
    0x3E: "RETURNDATACOPY",
    0x3F: "EXTCODEHASH",
    0x40: "BLOCKHASH",
    0x41: "COINBASE",
    0x42: "TIMESTAMP",
    0x43: "NUMBER",
    0x44: "PREVRANDAO",  # DIFFICULTY before the merge (EIP-4399)
    0x45: "GASLIMIT",
    0x46: "CHAINID",
    0x47: "SELFBALANCE",
    0x48: "BASEFEE",
    0x49: "BLOBHASH",
    0x4A: "BLOBBASEFEE",
    0x50: "POP",
    0x51: "MLOAD",
    0x52: "MSTORE",
    0x53: "MSTORE8",
    0x54: "SLOAD",
    0x55: "SSTORE",
    0x56: "JUMP",
    0x57: "JUMPI",
    0x58: "PC",
    0x59: "MSIZE",
    0x5A: "GAS",
    0x5B: "JUMPDEST",
    0x5C: "TLOAD",
    0x5D: "TSTORE",
    0x5E: "MCOPY",
    0x5F: "PUSH0",
    0xF0: "CREATE",
    0xF1: "CALL",
    0xF2: "CALLCODE",
    0xF3: "RETURN",
    0xF4: "DELEGATECALL",
    0xF5: "CREATE2",
    0xFA: "STATICCALL",
    0xFD: "REVERT",
    0xFE: "INVALID",
    0xFF: "SELFDESTRUCT",
}
_EVM_OPCODES.update({0x60 + i: f"PUSH{i + 1}" for i in range(32)})
_EVM_OPCODES.update({0x80 + i: f"DUP{i + 1}" for i in range(16)})
_EVM_OPCODES.update({0x90 + i: f"SWAP{i + 1}" for i in range(16)})
_EVM_OPCODES.update({0xA0 + i: f"LOG{i}" for i in range(5)})

# What a dispatcher does with a selector it just pushed. solc's linear dispatcher
# compares with EQ; its binary-search dispatcher (emitted once a contract has
# enough external functions) pivots on GT/LT against real selector values; other
# compilers reach for XOR or SUB followed by ISZERO.
_DISPATCH_COMPARISONS = frozenset({"EQ", "GT", "LT", "XOR", "SUB"})


def _disassemble(code: bytes) -> list[dict]:
    """Decode bytecode into instructions: [{pc, opcode, name}] (+ push_data)."""
    out, pc = [], 0
    while pc < len(code):
        op = code[pc]
        name = _EVM_OPCODES.get(op)
        ins: dict[str, Any] = {"pc": pc, "opcode": f"0x{op:02x}", "name": name}
        pc += 1
        if name is None:
            ins["unknown"] = True  # unassigned byte — the EVM aborts on it
        elif 0x60 <= op <= 0x7F:  # PUSHn swallows the n bytes after it
            n = op - 0x5F
            immediate = code[pc : pc + n]
            ins["push_data"] = "0x" + immediate.hex()
            if len(immediate) < n:  # code ends inside the immediate
                ins["truncated"] = True
            pc += n
        out.append(ins)
    return out


# --- solc's trailing CBOR metadata ---------------------------------------------
# solc appends CBOR to the deployed code — the source metadata's IPFS/Swarm hash,
# the compiler version — followed by a 2-byte big-endian length of that CBOR. It
# is data, not code, so it is peeled off before disassembly. The reader below is
# a deliberately small CBOR subset (the definite-length types solc emits) rather
# than cbor2: that library sits behind the `serialize` extra, and this tool is
# gated on `ethereum` alone. Anything outside the subset raises, which the caller
# reads as "no metadata here" rather than a bad decode.
def _cbor_read(data: bytes, pos: int) -> tuple[Any, int]:
    """Decode one definite-length CBOR item at `pos` -> (value, next position)."""
    if pos >= len(data):
        raise ValueError("CBOR input truncated")
    major, info = data[pos] >> 5, data[pos] & 0x1F
    pos += 1
    if info < 24:
        value = info
    elif info < 28:  # 24/25/26/27 -> a 1/2/4/8-byte argument follows
        width = 1 << (info - 24)
        if pos + width > len(data):
            raise ValueError("CBOR argument truncated")
        value = int.from_bytes(data[pos : pos + width], "big")
        pos += width
    else:
        raise ValueError(f"unsupported CBOR additional info {info} (indefinite?)")

    if major == 0:  # unsigned integer
        return value, pos
    if major == 1:  # negative integer
        return -1 - value, pos
    if major in (2, 3):  # byte string / text string
        if pos + value > len(data):
            raise ValueError("CBOR string longer than input")
        payload = data[pos : pos + value]
        return (payload if major == 2 else payload.decode("utf-8")), pos + value
    if major == 4:  # array
        items = []
        for _ in range(value):
            item, pos = _cbor_read(data, pos)
            items.append(item)
        return items, pos
    if major == 5:  # map
        mapping = {}
        for _ in range(value):
            key, pos = _cbor_read(data, pos)
            if not isinstance(key, str):
                raise ValueError("CBOR map key is not a text string")
            mapping[key], pos = _cbor_read(data, pos)
        return mapping, pos
    if major == 7 and value in (20, 21, 22):
        return {20: False, 21: True, 22: None}[value], pos
    raise ValueError(f"unsupported CBOR major type {major}")


def _cbor_json(value: Any) -> Any:
    """Render a decoded CBOR value JSON-safely (byte strings become 0x-hex)."""
    if isinstance(value, bytes):
        return "0x" + value.hex()
    if isinstance(value, dict):
        return {k: _cbor_json(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_cbor_json(v) for v in value]
    return value


def _solc_metadata(code: bytes) -> tuple[int, int, dict] | None:
    """(offset, CBOR length, decoded map) of the trailing metadata, else None.

    None means "this code has no readable metadata trailer" — the 2-byte length
    suffix has to land exactly on a CBOR map that ends where it says it does, so
    a coincidental pair of trailing bytes cannot fake one.
    """
    if len(code) < 3:
        return None
    length = int.from_bytes(code[-2:], "big")
    start = len(code) - 2 - length
    if length == 0 or start < 0:
        return None
    try:
        value, end = _cbor_read(code, start)
    except (ValueError, UnicodeDecodeError):
        return None
    if end != len(code) - 2 or not isinstance(value, dict):
        return None
    return start, length, value


# base58btc, for rendering the metadata's IPFS multihash as the CIDv0 you can
# paste into a gateway. Hand-rolled for the same reason as the CBOR reader: the
# `base58` package lives behind the `encoding` extra (core.encode uses it), and
# this toolset is gated on `ethereum`.
_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _base58btc(raw: bytes) -> str:
    """Bitcoin/IPFS base58 of `raw` (each leading zero byte becomes a '1')."""
    number, out = int.from_bytes(raw, "big"), ""
    while number:
        number, rem = divmod(number, 58)
        out = _B58_ALPHABET[rem] + out
    return "1" * (len(raw) - len(raw.lstrip(b"\x00"))) + out


def eth_bytecode(
    action: Annotated[
        Literal["disassemble", "selectors", "metadata"],
        Field(
            description="'disassemble' decodes the code into instructions; "
            "'selectors' scrapes the function selectors out of its dispatcher; "
            "'metadata' parses the trailing solc CBOR metadata."
        ),
    ],
    code: Annotated[
        str,
        Field(
            description="Contract bytecode as hex (0x prefix optional) — the "
            "DEPLOYED runtime code, as returned by eth_getCode. Creation "
            "bytecode also decodes, but its constructor carries the runtime code "
            "as an inline blob, so the tail disassembles as data."
        ),
    ],
    offset: Annotated[
        int,
        Field(
            description="action=disassemble only: index of the first instruction "
            "to return (not a byte offset), for paging through a large contract."
        ),
    ] = 0,
    limit: Annotated[
        int,
        Field(
            description="action=disassemble only: how many instructions to "
            "return; 0 removes the cap and returns all of them."
        ),
    ] = 1024,
) -> dict:
    """Disassemble EVM bytecode, scrape its selectors, or read its solc metadata.

    `code` is hex runtime bytecode. The trailing solc CBOR metadata is data, not
    code, so it is excluded from both the disassembly and the selector scrape and
    reported as `metadata_offset` instead.
    action=disassemble -> {size, code_size, count, offset, instructions} with each
      instruction {pc, opcode, name} plus `push_data` for PUSH1..PUSH32; an
      unassigned byte has name null and `unknown`, and code ending mid-immediate
      is flagged `truncated`. Output is capped at `limit` instructions, which adds
      {truncated, next_offset} — page with `offset`, or pass limit=0 for all.
    action=selectors -> {count, selectors, sites}: every PUSH4 the dispatcher then
      compares (EQ, or GT/LT in solc's binary-search dispatcher), decoded rather
      than grepped, so a PUSH4 pattern inside another push's immediate cannot
      masquerade as one. `sites` gives the {selector, pc, op} of each comparison.
      This is a heuristic on unstructured code: an ERC-165 interface id is a
      PUSH4 compared with EQ and is indistinguishable from a selector here, and
      an unconventional dispatcher may hide one. Feed the results to
      `abi_inspect`'s `selectors` map (or a 4-byte database) to name them.
    action=metadata -> {present, offset, length, cbor, metadata} plus
      `solc_version` and, when the hash is an IPFS CIDv0 multihash, `ipfs_cid`.
      Code compiled with metadata stripped returns present=false, not an error.

    Example: eth_bytecode("selectors", "0x6080...") ->
    selectors=["0xa9059cbb", "0x70a08231"].
    """
    raw = _to_bytes(code, "hex")
    meta = _solc_metadata(raw)
    body = raw[: meta[0]] if meta else raw  # the code region, metadata peeled off

    if action == "disassemble":
        if offset < 0:
            raise ValueError(f"`offset` must be >= 0, got {offset}")
        if limit < 0:
            raise ValueError(f"`limit` must be >= 0 (0 removes the cap), got {limit}")
        instructions = _disassemble(body)
        window = instructions[offset:] if limit == 0 else instructions[offset:][:limit]
        result: dict[str, Any] = {
            "action": "disassemble",
            "size": len(raw),
            "code_size": len(body),
            "count": len(instructions),
            "offset": offset,
            "instructions": window,
        }
        if offset + len(window) < len(instructions):
            result["truncated"] = True
            result["next_offset"] = offset + len(window)
        if meta is not None:
            result["metadata_offset"] = meta[0]
        return result

    if action == "selectors":
        instructions = _disassemble(body)
        selectors: list[str] = []
        sites: list[dict] = []
        for i, ins in enumerate(instructions):
            if ins["name"] != "PUSH4" or ins.get("truncated"):
                continue
            value = ins["push_data"]
            # 0x00000000 and 0xffffffff are the sentinel/mask constants solc emits
            # around a dispatcher, not functions anyone declared.
            if value in ("0x00000000", "0xffffffff"):
                continue
            # The comparison is usually the very next instruction, but a DUP can
            # sit between the push and it, so look one further.
            for following in instructions[i + 1 : i + 3]:
                if following["name"] in _DISPATCH_COMPARISONS:
                    sites.append(
                        {"selector": value, "pc": ins["pc"], "op": following["name"]}
                    )
                    if value not in selectors:
                        selectors.append(value)
                    break
        return {
            "action": "selectors",
            "count": len(selectors),
            "selectors": selectors,
            "sites": sites,
        }

    if action == "metadata":
        if meta is None:
            return {
                "action": "metadata",
                "present": False,
                "reason": "no CBOR metadata trailer — the last two bytes are not "
                "the length of a CBOR map ending just before them (code compiled "
                "with --no-cbor-metadata, or not solc output at all)",
            }
        start, length, value = meta
        result = {
            "action": "metadata",
            "present": True,
            "offset": start,
            "length": length,
            "cbor": "0x" + raw[start : start + length].hex(),
            "metadata": _cbor_json(value),
        }
        solc = value.get("solc")
        if isinstance(solc, bytes) and len(solc) == 3:  # release: 3 version bytes
            result["solc_version"] = ".".join(str(b) for b in solc)
        elif isinstance(solc, str):  # prerelease/nightly: the version string
            result["solc_version"] = solc
        ipfs = value.get("ipfs")
        # CIDv0 is the bare base58btc multihash, and only sha2-256/32 qualifies.
        if isinstance(ipfs, bytes) and len(ipfs) == 34 and ipfs[:2] == b"\x12\x20":
            result["ipfs_cid"] = _base58btc(ipfs)
        return result

    raise ValueError(
        f"unknown action {action!r}; expected 'disassemble', 'selectors', or 'metadata'"
    )


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
    mcp.tool()(abi_inspect)
    mcp.tool()(eth_calldata)
    mcp.tool()(eth_log_decode)
    mcp.tool()(eth_revert_decode)
    mcp.tool()(eth_bytecode)
    mcp.tool()(eth_storage_slot)
    mcp.tool()(eth_eoa_address)
    mcp.tool()(eth_contract_address)
    mcp.tool()(bip39)
    mcp.tool()(eth_tx_codec)
    mcp.tool()(eth_address_case)
    mcp.tool()(ens_namehash)
    mcp.tool()(bip32_derive)
