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

"""Always-on stdlib toolset — tools whose `gate:` is `stdlib` (plan §2.0.7).

Unlike the optional toolsets (eth.py and friends), these need no extra, so they
register unconditionally. Same `register(mcp)` contract as a gated toolset, just
without `available()` — stdlib is, by definition, always importable.

`_to_bytes` lives here as the canonical input-format decoder; gated toolsets
(eth.py) import it rather than duplicating the logic.
"""

import base64
import binascii
import codecs
import hashlib
import html
import json
import math
import quopri
import secrets
import shlex
import string
import sys
import unicodedata
import zlib
from email.header import decode_header, make_header
from importlib.resources import files
from typing import Any, Literal
from urllib.parse import quote, quote_plus, unquote_to_bytes


# Upper bound on caller-controlled output sizes (SHAKE digest length, hexdump
# width, pad target). Guards against memory exhaustion from an untrusted length;
# 1 MiB is far beyond any legitimate use of these tools.
_MAX_ALLOC = 1_048_576


# --- shared string<->bytes codec (plan §2.0.6: input/output_format) ------------
def _to_bytes(data: str, input_format: str) -> bytes:
    """Map a string arg to raw bytes per input_format (text|hex|base64)."""
    if input_format == "text":
        return data.encode("utf-8")
    if input_format == "hex":
        body = data[2:] if data[:2].lower() == "0x" else data
        try:
            return bytes.fromhex(body)
        except ValueError as exc:
            raise ValueError(f"invalid hex input: {data!r}") from exc
    if input_format == "base64":
        try:
            return base64.b64decode(data, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise ValueError(f"invalid base64 input: {data!r}") from exc
    raise ValueError(
        f"unknown input_format {input_format!r}; expected 'text', 'hex', or 'base64'"
    )


def _render(raw: bytes, output_format: str) -> str:
    """Render a digest as bare hex (no 0x; general-hash convention) or base64."""
    if output_format == "hex":
        return raw.hex()
    if output_format == "base64":
        return base64.b64encode(raw).decode("ascii")
    raise ValueError(
        f"unknown output_format {output_format!r}; expected 'hex' or 'base64'"
    )


# --- num_convert (§2.9.4) ------------------------------------------------------
# base name -> (int() radix, output prefix, format() spec, bits per digit)
_RADIX = {"hex": 16, "dec": 10, "bin": 2, "oct": 8}
_PREFIX = {"hex": "0x", "dec": "", "bin": "0b", "oct": "0o"}
_FMT = {"hex": "x", "dec": "d", "bin": "b", "oct": "o"}
_BITS_PER_DIGIT = {"hex": 4, "bin": 1, "oct": 3}


def num_convert(
    value: str,
    from_base: Literal["hex", "dec", "bin", "oct"],
    to_base: Literal["hex", "dec", "bin", "oct"],
    pad_bytes: int | None = None,
) -> dict:
    """Convert a big-integer between bases (hex/dec/bin/oct).

    Parses `value` as a `from_base` integer (a leading 0x/0b/0o and a `-` sign
    are accepted) and renders it in `to_base`, prefixed for non-decimal output.
    `pad_bytes` zero-fills the output to that byte width (a minimum, never
    truncating); it is bit-aligned, so it is rejected for decimal output.
    Arbitrary precision — a 32-byte RPC value converts losslessly.
    """
    if from_base not in _RADIX:
        raise ValueError(f"unknown from_base {from_base!r}; expected hex|dec|bin|oct")
    if to_base not in _RADIX:
        raise ValueError(f"unknown to_base {to_base!r}; expected hex|dec|bin|oct")
    try:
        n = int(value.strip(), _RADIX[from_base])
    except (ValueError, AttributeError) as exc:
        raise ValueError(f"invalid {from_base} integer: {value!r}") from exc

    if to_base == "dec":
        if pad_bytes is not None:
            raise ValueError("pad_bytes is not meaningful for decimal output")
        result = str(n)
    else:
        digits = format(abs(n), _FMT[to_base])
        if pad_bytes is not None:
            if pad_bytes <= 0:
                raise ValueError(f"pad_bytes must be positive, got {pad_bytes}")
            width = -(-pad_bytes * 8 // _BITS_PER_DIGIT[to_base])  # ceil(bits/digit)
            digits = digits.zfill(width)
        result = ("-" if n < 0 else "") + _PREFIX[to_base] + digits

    return {
        "value": value,
        "from_base": from_base,
        "to_base": to_base,
        "result": result,
    }


# --- byte_order (§2.9.5 / TODO 18.5 — host<->network endianness) ---------------
# The htons/htonl/ntohs/ntohl family generalized to arbitrary widths: swap a
# value's byte order between little- and big-endian (network == big). With no
# `width` the whole buffer is one field reversed end-to-end; with `width` the
# buffer is a sequence of fixed-size fields — a short value is left zero-padded up
# to `width` first, a longer one is split into `width`-byte groups each swapped
# independently (array semantics, like htonl over a uint32[]). `host` resolves to
# the running platform's sys.byteorder, so on a little-endian box host->network
# reproduces the C macros. A no-op swap (from==to) still applies the width
# normalization, so `result` is always width-aligned.
ByteOrder = Literal["host", "little", "big", "network"]


def _resolve_byte_order(order: str) -> str:
    """Map an order name to 'little'/'big' (network->big, host->sys.byteorder)."""
    if order == "network":
        return "big"
    if order == "host":
        return sys.byteorder
    if order in ("little", "big"):
        return order
    raise ValueError(f"unknown byte order {order!r}; expected host|little|big|network")


def byte_order(
    data: str,
    from_order: ByteOrder,
    to_order: ByteOrder,
    width: int | None = None,
    input_format: Literal["text", "hex", "base64"] = "hex",
    output_format: Literal["hex", "base64"] = "hex",
) -> dict:
    """Convert a value between host and network byte order (htons/htonl/ntohs/ntohl).

    `data` is decoded via `input_format` (hex default). `from_order`/`to_order`
    are little|big|network|host: network is big-endian, host resolves to the
    platform's sys.byteorder — so on a little-endian box from_order=host
    to_order=network is htonl/htons. `width` (bytes) sets a fixed field size: a
    shorter buffer is left zero-padded up to `width`, a longer one is split into
    `width`-byte groups each swapped independently (array semantics); omit it to
    swap the whole buffer as one field. Differing orders reverse each field; equal
    orders only apply the width normalization. Returns {result, from_order,
    to_order, width, output_format}; `result` is rendered via `output_format`.
    """
    raw = _to_bytes(data, input_format)
    src = _resolve_byte_order(from_order)
    dst = _resolve_byte_order(to_order)

    if width is None:
        w = len(raw)
        padded = raw
    else:
        if width <= 0:
            raise ValueError(f"width must be positive, got {width}")
        if width > _MAX_ALLOC:
            raise ValueError(f"width must be <= {_MAX_ALLOC}, got {width}")
        w = width
        if len(raw) <= width:
            padded = raw.rjust(width, b"\x00")  # left zero-pad a short value
        elif len(raw) % width == 0:
            padded = raw  # an array of width-byte fields
        else:
            raise ValueError(
                f"data length {len(raw)} is not a multiple of width {width}"
            )

    if w == 0:  # empty buffer with no width: nothing to group or reverse
        out = padded
    else:
        fields = [padded[i : i + w] for i in range(0, len(padded), w)]
        if src != dst:
            fields = [field[::-1] for field in fields]
        out = b"".join(fields)

    return {
        "result": _render(out, output_format),
        "from_order": from_order,
        "to_order": to_order,
        "width": w,
        "output_format": output_format,
    }


# --- hash / crc / fast_hash (§2.1.1, merges §1.1.1-7) --------------------------
_CRYPTO = frozenset(
    {
        "md5",
        "sha1",
        "sha224",
        "sha256",
        "sha384",
        "sha512",
        "sha3_256",
        "sha3_512",
        "blake2b",
        "blake2s",
    }
)
_SHAKE = frozenset({"shake_128", "shake_256"})
_CRC = frozenset({"crc8", "crc16", "crc32", "crc32c", "crc64"})
_XXH = frozenset({"xxh32", "xxh64", "xxh3_64", "xxh3_128"})
_FNV = frozenset({"fnv1a_32", "fnv1a_64"})

HashAlgorithm = Literal[
    "md5",
    "sha1",
    "sha224",
    "sha256",
    "sha384",
    "sha512",
    "sha3_256",
    "sha3_512",
    "shake_128",
    "shake_256",
    "blake2b",
    "blake2s",
    "crc8",
    "crc16",
    "crc32",
    "crc32c",
    "crc64",
    "xxh32",
    "xxh64",
    "xxh3_64",
    "xxh3_128",
    "fnv1a_32",
    "fnv1a_64",
]

# width, poly, init, refin, refout, xorout — canonical params (reveng catalogue).
_CRC_SPECS = {
    "crc8": (8, 0x07, 0x00, False, False, 0x00),
    "crc16": (16, 0x8005, 0x0000, True, True, 0x0000),
    "crc32c": (32, 0x1EDC6F41, 0xFFFFFFFF, True, True, 0xFFFFFFFF),
    "crc64": (
        64,
        0x42F0E1EBA9EA3693,
        0xFFFFFFFFFFFFFFFF,
        True,
        True,
        0xFFFFFFFFFFFFFFFF,
    ),
}
_XXH_BITS = {"xxh32": 32, "xxh64": 64, "xxh3_64": 64, "xxh3_128": 128}


def _crc_byte_len(name: str) -> int:
    return 4 if name == "crc32" else _CRC_SPECS[name][0] // 8


def _reflect(value: int, bits: int) -> int:
    result = 0
    for _ in range(bits):
        result = (result << 1) | (value & 1)
        value >>= 1
    return result


def _crc(name: str, data: bytes) -> int:
    if name == "crc32":
        return zlib.crc32(data) & 0xFFFFFFFF
    width, poly, init, refin, refout, xorout = _CRC_SPECS[name]
    mask, topbit = (1 << width) - 1, 1 << (width - 1)
    crc = init
    for byte in data:
        crc ^= (_reflect(byte, 8) if refin else byte) << (width - 8)
        crc &= mask
        for _ in range(8):
            crc = ((crc << 1) ^ poly) & mask if crc & topbit else (crc << 1) & mask
    if refout:
        crc = _reflect(crc, width)
    return crc ^ xorout


def _fnv1a(data: bytes, bits: int, seed: int | None) -> int:
    if bits == 32:
        h, prime, mask = (
            seed if seed is not None else 0x811C9DC5,
            0x01000193,
            0xFFFFFFFF,
        )
    else:
        h = seed if seed is not None else 0xCBF29CE484222325
        prime, mask = 0x100000001B3, 0xFFFFFFFFFFFFFFFF
    for byte in data:
        h = ((h ^ byte) * prime) & mask
    return h


def _xxh(name: str, data: bytes, seed: int) -> int:
    try:
        import xxhash
    except ImportError as exc:
        raise ValueError(
            f"algorithm {name!r} requires the 'encoding' extra (xxhash)"
        ) from exc
    fn = {
        "xxh32": xxhash.xxh32,
        "xxh64": xxhash.xxh64,
        "xxh3_64": xxhash.xxh3_64,
        "xxh3_128": xxhash.xxh3_128,
    }[name]
    return fn(data, seed=seed).intdigest()


def _crypto_digest(name: str, data: bytes, key: bytes | None) -> bytes:
    if name == "blake2b":
        return hashlib.blake2b(data, key=key or b"").digest()
    if name == "blake2s":
        return hashlib.blake2s(data, key=key or b"").digest()
    h = hashlib.new(name)
    h.update(data)
    return h.digest()


def hash(
    data: str,
    algorithm: HashAlgorithm,
    input_format: Literal["text", "hex", "base64"] = "text",
    output_format: Literal["hex", "base64"] = "hex",
    length: int | None = None,
    key: str | None = None,
    seed: int | None = None,
) -> dict:
    """Compute a cryptographic, CRC, or fast non-crypto digest of bytes.

    `length` (output bytes) is required for shake_*; `key` keys blake2b/blake2s
    (decoded with `input_format`); `seed` reseeds xxh*/fnv1a_*. CRC and fast
    hashes additionally report their integer value as `int`.
    """
    raw = _to_bytes(data, input_format)
    keyb = _to_bytes(key, input_format) if key is not None else None

    if length is not None and algorithm not in _SHAKE:
        raise ValueError("`length` is only valid for shake_128/shake_256")
    if keyb is not None and algorithm not in ("blake2b", "blake2s"):
        raise ValueError("`key` is only valid for blake2b/blake2s")
    if seed is not None and algorithm not in (_XXH | _FNV):
        raise ValueError("`seed` is only valid for xxh*/fnv1a_* algorithms")

    int_value: int | None = None
    if algorithm in _CRYPTO:
        digest = _crypto_digest(algorithm, raw, keyb)
    elif algorithm in _SHAKE:
        if length is None:
            raise ValueError(f"`length` (output bytes) is required for {algorithm}")
        if length < 0:
            raise ValueError(f"`length` must be non-negative, got {length}")
        if length > _MAX_ALLOC:
            raise ValueError(f"`length` must be <= {_MAX_ALLOC}, got {length}")
        shake = hashlib.shake_128 if algorithm == "shake_128" else hashlib.shake_256
        digest = shake(raw).digest(length)
    elif algorithm in _CRC:
        int_value = _crc(algorithm, raw)
        digest = int_value.to_bytes(_crc_byte_len(algorithm), "big")
    elif algorithm in _XXH:
        int_value = _xxh(algorithm, raw, seed or 0)
        digest = int_value.to_bytes(_XXH_BITS[algorithm] // 8, "big")
    elif algorithm in _FNV:
        bits = 32 if algorithm == "fnv1a_32" else 64
        int_value = _fnv1a(raw, bits, seed)
        digest = int_value.to_bytes(bits // 8, "big")
    else:
        raise ValueError(f"unknown algorithm {algorithm!r}")

    result = {
        "algorithm": algorithm,
        "digest": _render(digest, output_format),
        "output_format": output_format,
        "bits": len(digest) * 8,
    }
    if int_value is not None:
        result["int"] = int_value
    return result


# --- encode (§2.2.1, merges §1.4.1-9,14, 1.5.5, 1.12.2, 1.15.6) ----------------
# Byte string -> text representation. Stdlib covers the base16/32/64 families,
# Ascii85/base85, and URL percent-encoding; base62/Crockford-base32/z85/bech32/
# hexdump/bytes32 are hand-rolled (plan L.1.10); base58/base58check/base45/idna
# come from the `encoding` extra and raise a helpful error when it is absent.
EncodeScheme = Literal[
    "base16",
    "base32",
    "base32hex",
    "base32crockford",
    "base45",
    "base58",
    "base58check",
    "base62",
    "base64",
    "base64url",
    "ascii85",
    "base85",
    "z85",
    "url",
    "url_form",
    "idna",
    "bech32",
    "bech32m",
    "hexdump",
    "bytes32",
]

_CROCKFORD_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
_BASE62_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
_Z85_ALPHABET = (
    "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    ".-:+=^!/*?&<>()[]{}@%$#"
)
_BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_BECH32_CONST = {"bech32": 1, "bech32m": 0x2BC830A3}


def _strip_padding(text: str, padding: bool) -> str:
    """Drop trailing '=' padding when `padding` is false (base32/base64 family)."""
    return text if padding else text.rstrip("=")


def _base32_crockford_encode(raw: bytes) -> str:
    """Crockford base32: 5 bits/symbol, big-endian, zero-padded, no '=' (no I/L/O/U)."""
    if not raw:
        return ""
    bits = len(raw) * 8
    nsym = (bits + 4) // 5  # ceil(bits / 5)
    num = int.from_bytes(raw, "big") << (nsym * 5 - bits)  # right-pad with zero bits
    return "".join(
        _CROCKFORD_ALPHABET[(num >> (shift * 5)) & 0x1F]
        for shift in range(nsym - 1, -1, -1)
    )


def _base_n_encode(raw: bytes, alphabet: str) -> str:
    """Big-integer base-N encode preserving leading zero bytes as leading symbols."""
    base = len(alphabet)
    pad = len(raw) - len(raw.lstrip(b"\x00"))  # leading 0x00 -> leading zero-symbols
    num = int.from_bytes(raw, "big")
    out: list[str] = []
    while num:
        num, rem = divmod(num, base)
        out.append(alphabet[rem])
    return alphabet[0] * pad + "".join(reversed(out))


def _z85_encode(raw: bytes) -> str:
    """ZeroMQ Z85: each 4-byte group -> 5 chars; input length must be a 4-multiple."""
    if len(raw) % 4 != 0:
        raise ValueError("z85 input length must be a multiple of 4 bytes")
    out: list[str] = []
    for i in range(0, len(raw), 4):
        num = int.from_bytes(raw[i : i + 4], "big")
        block = [""] * 5
        for j in range(4, -1, -1):
            num, rem = divmod(num, 85)
            block[j] = _Z85_ALPHABET[rem]
        out.append("".join(block))
    return "".join(out)


def _convertbits(
    data: list[int] | bytes, frombits: int, tobits: int, pad: bool = True
) -> list[int]:
    """Regroup a bit stream into `tobits`-wide groups (BIP-173).

    Encoding (8->5) zero-pads the tail; decoding (5->8) sets pad=False, which
    instead rejects a leftover group or non-zero padding bits — the strict check
    that makes a malformed bech32 payload fail rather than silently truncate.
    """
    acc = bits = 0
    maxv = (1 << tobits) - 1
    ret: list[int] = []
    for value in data:
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or (acc << (tobits - bits)) & maxv:
        raise ValueError("invalid padding bits in bech32 data")
    return ret


def _bech32_polymod(values: list[int]) -> int:
    gen = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
    chk = 1
    for v in values:
        top = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            chk ^= gen[i] if (top >> i) & 1 else 0
    return chk


def _bech32_encode(hrp: str, raw: bytes, spec: str) -> str:
    """Encode raw bytes as a bech32/bech32m string under human-readable part `hrp`."""
    if not hrp or any(ord(c) < 33 or ord(c) > 126 for c in hrp):
        raise ValueError(f"invalid bech32 hrp: {hrp!r}")
    if hrp != hrp.lower():
        raise ValueError("bech32 hrp must be lowercase")
    data = _convertbits(raw, 8, 5)
    expanded = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]
    polymod = _bech32_polymod(expanded + data + [0] * 6) ^ _BECH32_CONST[spec]
    checksum = [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(_BECH32_CHARSET[d] for d in data + checksum)


def _hexdump(raw: bytes, width: int) -> str:
    """Canonical `hexdump -C` layout: offset, hex bytes (8+8 grouped), ASCII gutter."""
    if width <= 0:
        raise ValueError(f"hexdump width must be positive, got {width}")
    if width > _MAX_ALLOC:
        raise ValueError(f"hexdump width must be <= {_MAX_ALLOC}, got {width}")
    lines: list[str] = []
    for off in range(0, len(raw), width):
        chunk = raw[off : off + width]
        cells = ""
        for i in range(width):
            if i and i % 8 == 0:
                cells += " "
            cells += f"{chunk[i]:02x} " if i < len(chunk) else "   "
        gutter = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{off:08x}  {cells} |{gutter}|")
    lines.append(f"{len(raw):08x}")
    return "\n".join(lines)


def _encode_extra(scheme: str) -> Any:
    """Import a codec from the `encoding` extra, or raise a guiding error."""
    try:
        if scheme in ("base58", "base58check"):
            import base58

            return base58
        if scheme == "base45":
            import base45

            return base45
        import idna

        return idna
    except ImportError as exc:
        raise ValueError(
            f"scheme {scheme!r} requires the 'encoding' extra "
            f"(install mcp-bytesmith[encoding])"
        ) from exc


def encode(
    data: str,
    scheme: EncodeScheme,
    input_format: Literal["text", "hex", "base64"] = "text",
    options: dict[str, Any] | None = None,
) -> dict:
    """Encode bytes/text into a string form (base-N, URL, IDNA, bech32, hexdump, bytes32).

    `data` is decoded to bytes via `input_format` (text|hex|base64). `options`
    is a per-scheme dict: `padding` (bool, default true — base32/base64 family),
    `alphabet` (custom symbol set — base58/base62), `hrp` (required for
    bech32/bech32m), `width` (bytes per line — hexdump, default 16). idna and
    bytes32 read `data` as a text string / short string respectively. bytes32 is
    a fixed-width 32-byte EVM word: inputs of <32 bytes are right-padded with
    0x00; decode returns all 32 bytes (it does NOT strip trailing nulls, so the
    round-trip is lossless — rstrip them yourself for a short string).
    """
    opts = json.loads(options) if isinstance(options, str) else (options or {})
    if not isinstance(opts, dict):
        raise ValueError("`options` must be an object")
    padding = bool(opts.get("padding", True))
    raw = _to_bytes(data, input_format)

    if scheme == "base16":
        encoded = base64.b16encode(raw).decode("ascii")
    elif scheme == "base32":
        encoded = _strip_padding(base64.b32encode(raw).decode("ascii"), padding)
    elif scheme == "base32hex":
        encoded = _strip_padding(base64.b32hexencode(raw).decode("ascii"), padding)
    elif scheme == "base32crockford":
        encoded = _base32_crockford_encode(raw)
    elif scheme == "base45":
        encoded = _encode_extra("base45").b45encode(raw).decode("ascii")
    elif scheme == "base58":
        alphabet = opts.get("alphabet")
        kwargs = {"alphabet": alphabet.encode("ascii")} if alphabet else {}
        encoded = _encode_extra("base58").b58encode(raw, **kwargs).decode("ascii")
    elif scheme == "base58check":
        encoded = _encode_extra("base58check").b58encode_check(raw).decode("ascii")
    elif scheme == "base62":
        alphabet = opts.get("alphabet", _BASE62_ALPHABET)
        if len(set(alphabet)) != 62:
            raise ValueError("base62 alphabet must be 62 distinct characters")
        encoded = _base_n_encode(raw, alphabet)
    elif scheme == "base64":
        encoded = _strip_padding(base64.b64encode(raw).decode("ascii"), padding)
    elif scheme == "base64url":
        encoded = _strip_padding(base64.urlsafe_b64encode(raw).decode("ascii"), padding)
    elif scheme == "ascii85":
        encoded = base64.a85encode(raw).decode("ascii")
    elif scheme == "base85":
        encoded = base64.b85encode(raw).decode("ascii")
    elif scheme == "z85":
        encoded = _z85_encode(raw)
    elif scheme == "url":
        encoded = quote(raw, safe="")
    elif scheme == "url_form":
        encoded = quote_plus(raw)
    elif scheme == "idna":
        encoded = _encode_extra("idna").encode(raw.decode("utf-8")).decode("ascii")
    elif scheme in ("bech32", "bech32m"):
        hrp = opts.get("hrp")
        if not hrp:
            raise ValueError(f"scheme {scheme!r} requires an 'hrp' option")
        encoded = _bech32_encode(hrp, raw, scheme)
    elif scheme == "hexdump":
        encoded = _hexdump(raw, int(opts.get("width", 16)))
    elif scheme == "bytes32":
        if len(raw) > 32:
            raise ValueError(f"bytes32 requires at most 32 bytes, got {len(raw)}")
        encoded = "0x" + raw.ljust(32, b"\x00").hex()
    else:
        raise ValueError(f"unknown scheme {scheme!r}")

    return {"scheme": scheme, "encoded": encoded}


# --- decode (§2.2.2, inverse of encode; same scheme set) -----------------------
# String representation -> bytes, then rendered per output_format. Every branch
# reuses encode's alphabets/tables so the pair stays in lockstep. Stripped '='
# padding is re-added before the stdlib base codecs; the hand-rolled inverses
# (Crockford/base62/z85/bech32/hexdump) mirror their encode counterparts.
def _render_bytes(raw: bytes, output_format: str) -> str:
    """Render decoded bytes as text (UTF-8), bare hex, or base64."""
    if output_format == "text":
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError(
                "decoded bytes are not valid UTF-8; use output_format='hex' or 'base64'"
            ) from exc
    return _render(raw, output_format)


def _readd_padding(text: str, block: int) -> str:
    """Restore '=' padding to a multiple of `block` chars (encode may have stripped it)."""
    body = text.rstrip("=")
    return body + "=" * (-len(body) % block)


def _base32_crockford_decode(text: str) -> bytes:
    """Inverse of Crockford base32: case-insensitive, I/L->1, O->0, hyphens ignored."""
    table = {c: i for i, c in enumerate(_CROCKFORD_ALPHABET)}
    table.update({"I": 1, "L": 1, "O": 0})
    symbols = text.upper().replace("-", "")
    num = 0
    for ch in symbols:
        if ch not in table:
            raise ValueError(f"invalid Crockford base32 character: {ch!r}")
        num = (num << 5) | table[ch]
    nbytes = len(symbols) * 5 // 8  # drop the right-pad bits the encoder added
    num >>= len(symbols) * 5 - nbytes * 8
    return num.to_bytes(nbytes, "big")


def _base_n_decode(text: str, alphabet: str) -> bytes:
    """Inverse of _base_n_encode: leading zero-symbols become leading zero bytes."""
    base = len(alphabet)
    table = {c: i for i, c in enumerate(alphabet)}
    pad = len(text) - len(text.lstrip(alphabet[0]))  # leading zero-symbols
    num = 0
    for ch in text:
        if ch not in table:
            raise ValueError(f"invalid base{base} character: {ch!r}")
        num = num * base + table[ch]
    body = num.to_bytes((num.bit_length() + 7) // 8, "big") if num else b""
    return b"\x00" * pad + body


def _z85_decode(text: str) -> bytes:
    """Inverse of Z85: each 5 chars -> 4 bytes; length must be a 5-multiple."""
    if len(text) % 5 != 0:
        raise ValueError("z85 input length must be a multiple of 5 characters")
    table = {c: i for i, c in enumerate(_Z85_ALPHABET)}
    out = bytearray()
    for i in range(0, len(text), 5):
        num = 0
        for ch in text[i : i + 5]:
            if ch not in table:
                raise ValueError(f"invalid Z85 character: {ch!r}")
            num = num * 85 + table[ch]
        if num > 0xFFFFFFFF:
            raise ValueError("Z85 group overflows 32 bits")
        out += num.to_bytes(4, "big")
    return bytes(out)


def _bech32_decode(text: str, spec: str) -> tuple[str, bytes]:
    """Decode a bech32/bech32m string -> (hrp, data bytes); verifies the checksum."""
    if text != text.lower() and text != text.upper():
        raise ValueError("bech32 string must not be mixed case")
    text = text.lower()
    pos = text.rfind("1")
    if pos < 1 or pos + 7 > len(text):
        raise ValueError("invalid bech32 separator (1) position")
    hrp, body = text[:pos], text[pos + 1 :]
    try:
        data = [_BECH32_CHARSET.index(c) for c in body]
    except ValueError as exc:
        raise ValueError("invalid bech32 data character") from exc
    expanded = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]
    if _bech32_polymod(expanded + data) != _BECH32_CONST[spec]:
        raise ValueError(f"invalid {spec} checksum")
    raw = bytes(_convertbits(data[:-6], 5, 8, pad=False))
    return hrp, raw


def _hexdump_decode(text: str) -> bytes:
    """Recover bytes from a `hexdump -C` listing (offset + hex cells; gutter ignored)."""
    out = bytearray()
    for line in text.splitlines():
        if "|" not in line:
            continue  # the trailing end-offset line has no ASCII gutter
        cells = line.split("|", 1)[0].split()  # offset + hex pairs, before the gutter
        for token in cells[1:]:  # drop the leading offset column
            out += bytes.fromhex(token)
    return bytes(out)


def decode(
    data: str,
    scheme: EncodeScheme,
    output_format: Literal["text", "hex", "base64"] = "text",
    options: dict[str, Any] | None = None,
) -> dict:
    """Decode a base-N/URL/IDNA/bech32/hexdump string back to bytes or text.

    The inverse of `encode` over the same scheme set. The recovered bytes are
    rendered per `output_format` (text=UTF-8 | hex=bare, no 0x | base64); pick
    hex/base64 for binary payloads that are not valid UTF-8. `options` carries
    `alphabet` for base58/base62. bech32/bech32m additionally return their `hrp`.
    base58/base58check/base45/idna need the `encoding` extra.
    """
    opts = json.loads(options) if isinstance(options, str) else (options or {})
    if not isinstance(opts, dict):
        raise ValueError("`options` must be an object")

    hrp: str | None = None
    if scheme == "base16":
        raw = base64.b16decode(data, casefold=True)
    elif scheme == "base32":
        raw = base64.b32decode(_readd_padding(data, 8), casefold=True)
    elif scheme == "base32hex":
        raw = base64.b32hexdecode(_readd_padding(data, 8), casefold=True)
    elif scheme == "base32crockford":
        raw = _base32_crockford_decode(data)
    elif scheme == "base45":
        raw = _encode_extra("base45").b45decode(data)
    elif scheme == "base58":
        alphabet = opts.get("alphabet")
        kwargs = {"alphabet": alphabet.encode("ascii")} if alphabet else {}
        raw = _encode_extra("base58").b58decode(data, **kwargs)
    elif scheme == "base58check":
        raw = _encode_extra("base58check").b58decode_check(data)
    elif scheme == "base62":
        alphabet = opts.get("alphabet", _BASE62_ALPHABET)
        if len(set(alphabet)) != 62:
            raise ValueError("base62 alphabet must be 62 distinct characters")
        raw = _base_n_decode(data, alphabet)
    elif scheme == "base64":
        raw = base64.b64decode(_readd_padding(data, 4), validate=True)
    elif scheme == "base64url":
        raw = base64.urlsafe_b64decode(_readd_padding(data, 4))
    elif scheme == "ascii85":
        raw = base64.a85decode(data)
    elif scheme == "base85":
        raw = base64.b85decode(data)
    elif scheme == "z85":
        raw = _z85_decode(data)
    elif scheme == "url":
        raw = unquote_to_bytes(data)
    elif scheme == "url_form":
        raw = unquote_to_bytes(data.replace("+", " "))
    elif scheme == "idna":
        raw = _encode_extra("idna").decode(data).encode("utf-8")
    elif scheme in ("bech32", "bech32m"):
        hrp, raw = _bech32_decode(data, scheme)
    elif scheme == "hexdump":
        raw = _hexdump_decode(data)
    elif scheme == "bytes32":
        # bytes32 is a fixed-width 32-byte EVM word: return all 32 bytes so the
        # round-trip is lossless (stripping trailing 0x00 would be ambiguous —
        # encode-padding and genuine data nulls are indistinguishable, CR.1).
        # Callers wanting a short string back can rstrip b"\x00" themselves.
        raw = _to_bytes(data, "hex")
        if len(raw) != 32:
            raise ValueError(f"bytes32 requires exactly 32 bytes, got {len(raw)}")
    else:
        raise ValueError(f"unknown scheme {scheme!r}")

    result = {
        "scheme": scheme,
        "decoded": _render_bytes(raw, output_format),
        "output_format": output_format,
    }
    if hrp is not None:
        result["hrp"] = hrp
    return result


# --- data_uri (§2.2.3, §1.4.13 — RFC 2397) -------------------------------------
# data:[<mediatype>][;base64],<payload>. build wraps a payload (base64 or
# percent-encoded) into a URI; parse splits one back into media type, the ;k=v
# parameters, the base64 flag, and the decoded payload. The `base64` bool param
# shadows the stdlib module name inside this function, so base64 work goes
# through _render (encode side) and _b64decode (decode side) instead.
def _b64decode(text: str) -> bytes:
    """Lenient base64 decode: tolerate embedded whitespace and missing padding."""
    return base64.b64decode(_readd_padding("".join(text.split()), 4))


def data_uri(
    action: Literal["build", "parse"],
    media_type: str | None = None,
    data: str | None = None,
    base64: bool = True,
    uri: str | None = None,
    input_format: Literal["text", "hex", "base64"] = "text",
    output_format: Literal["text", "hex", "base64"] = "text",
) -> dict:
    """Build a data: URI from a payload, or parse one into its parts (RFC 2397).

    action=build (needs `data`, read via `input_format`): wraps it as
    `data:[media_type][;base64],<payload>`; `base64`=true base64-encodes the
    payload, else it is percent-encoded. action=parse (needs `uri`): returns
    `media_type` (defaulting to text/plain when absent), the `;k=v` `parameters`,
    `is_base64`, and the decoded `data` rendered via `output_format`.
    """
    if action == "build":
        if data is None:
            raise ValueError("action=build requires `data`")
        raw = _to_bytes(data, input_format)
        mt = media_type or ""
        if base64:
            payload = _render(raw, "base64")
            return {"action": "build", "uri": f"data:{mt};base64,{payload}"}
        return {"action": "build", "uri": f"data:{mt},{quote(raw, safe='')}"}

    if action == "parse":
        if uri is None:
            raise ValueError("action=parse requires `uri`")
        if not uri.startswith("data:"):
            raise ValueError("not a data: URI (must start with 'data:')")
        meta, sep, payload = uri[len("data:") :].partition(",")
        if not sep:
            raise ValueError("data: URI is missing the ',' payload separator")

        segs = meta.split(";") if meta else []
        media: str = "text/plain"  # RFC 2397 default when no media type is given
        params: dict[str, str] = {}
        is_base64 = False
        if segs and "/" in segs[0]:
            media = segs[0]
            segs = segs[1:]
        for seg in segs:
            if seg == "base64":
                is_base64 = True
            elif "=" in seg:
                key, _, val = seg.partition("=")
                params[key] = val
            elif seg:
                params[seg] = ""

        raw = _b64decode(payload) if is_base64 else unquote_to_bytes(payload)
        return {
            "action": "parse",
            "media_type": media,
            "parameters": params,
            "is_base64": is_base64,
            "data": _render_bytes(raw, output_format),
            "output_format": output_format,
        }

    raise ValueError(f"unknown action {action!r}; expected 'build' or 'parse'")


# --- bytes_edit (§2.2.8, merges §1.5.8: pad/trim/slice/concat/size/prefix) -----
# General byte glue over a hex buffer — no ethereum dep. One `action` selects the
# edit; the byte view is canonical (input is hex with an optional 0x, output is
# 0x-prefixed) so a chain of edits composes. The classic use is address (20 B) ->
# 32-byte log topic: pad length=32 side=left, and the inverse slice start=12.
def _hex_to_bytes(data: str) -> bytes:
    """Decode a hex buffer (optional 0x), reusing _to_bytes' validation."""
    return _to_bytes(data, "hex")


def _fill_byte(fill: str) -> bytes:
    """Parse the `fill`/strip pattern as exactly one hex byte (default '00')."""
    body = fill[2:] if fill[:2].lower() == "0x" else fill
    try:
        raw = bytes.fromhex(body)
    except ValueError as exc:
        raise ValueError(f"invalid fill byte: {fill!r}") from exc
    if len(raw) != 1:
        raise ValueError(f"fill must be exactly one byte, got {len(raw)}: {fill!r}")
    return raw


def bytes_edit(
    action: Literal["pad", "trim", "slice", "concat", "size", "prefix"],
    data: str,
    length: int | None = None,
    start: int | None = None,
    end: int | None = None,
    parts: list[str] | None = None,
    side: Literal["left", "right"] = "left",
    fill: str = "00",
) -> dict:
    """Edit a hex byte-buffer: pad/trim to width, slice, concat, size, or 0x-prefix.

    `data` is hex (a leading 0x is optional). Actions:
    - pad: widen to `length` bytes with the `fill` byte on `side` (left=prepend,
      right=append); never truncates if already wider.
    - trim: strip the `fill` byte (default 00) from `side` (left=leading,
      right=trailing) — the inverse of pad.
    - slice: take `data[start:end]` (Python indexing; negatives allowed).
    - concat: append each hex buffer in `parts` to `data`.
    - size: report the byte length, buffer unchanged.
    - prefix: side=left adds a 0x prefix, side=right strips it.

    Returns {action, result, size}: `result` is the 0x-prefixed hex buffer (bare
    hex when prefix-stripping), `size` its byte length.
    """
    raw = _hex_to_bytes(data)

    if action == "pad":
        if length is None:
            raise ValueError("action=pad requires `length` (target byte width)")
        if length < 0:
            raise ValueError(f"`length` must be non-negative, got {length}")
        if length > _MAX_ALLOC:
            raise ValueError(f"`length` must be <= {_MAX_ALLOC}, got {length}")
        pad = _fill_byte(fill) * max(0, length - len(raw))
        out = (pad + raw) if side == "left" else (raw + pad)
    elif action == "trim":
        strip = _fill_byte(fill)
        out = raw.lstrip(strip) if side == "left" else raw.rstrip(strip)
    elif action == "slice":
        lo = start if start is not None else 0
        hi = end if end is not None else len(raw)
        out = raw[lo:hi]
    elif action == "concat":
        out = raw + b"".join(_hex_to_bytes(p) for p in (parts or []))
    elif action == "size":
        out = raw
    elif action == "prefix":
        body = raw.hex()
        result = "0x" + body if side == "left" else body
        return {"action": action, "result": result, "size": len(raw)}
    else:
        raise ValueError(
            f"unknown action {action!r}; expected pad|trim|slice|concat|size|prefix"
        )

    return {"action": action, "result": "0x" + out.hex(), "size": len(out)}


# --- unicode_normalize (§2.3.1 / §1.5.4) ---------------------------------------
# Map text onto one of the four Unicode normalization forms. NFC/NFD are the
# canonical (de)composition pair; NFKC/NFKD additionally fold compatibility
# variants (ﬁ -> fi, ① -> 1, full-width -> ASCII). `changed` flags whether the
# input was already in the requested form — handy for "is this string canonical?"
# checks before hashing/comparing identifiers.
def unicode_normalize(
    text: str,
    form: Literal["NFC", "NFD", "NFKC", "NFKD"] = "NFC",
) -> dict:
    """Normalize text to a Unicode normalization form (NFC/NFD/NFKC/NFKD).

    NFC/NFD are canonical compose/decompose; NFKC/NFKD also fold compatibility
    characters (ligatures, full-width, circled digits) to their plain forms.
    `changed` is true when `result` differs from the input — i.e. the text was
    not already in `form`.
    """
    if form not in ("NFC", "NFD", "NFKC", "NFKD"):
        raise ValueError(f"unknown form {form!r}; expected NFC|NFD|NFKC|NFKD")
    result = unicodedata.normalize(form, text)
    return {"form": form, "result": result, "changed": result != text}


# --- charset_transcode (§2.3.2 / §1.5.6) --------------------------------------
# Reinterpret text from one byte-encoding as another — the canonical fix for
# mojibake (utf-8 bytes mis-read as cp1252 give "cafÃ©"; from_charset=cp1252,
# to_charset=utf-8 restores "café"). The input str is encoded under from_charset
# to recover its byte stream, then decoded under to_charset. When those bytes
# don't form valid to_charset text (e.g. utf-8 -> ascii), we surface them as hex
# rather than raising, flagged via `output_format`. `errors` (strict|replace|
# ignore|backslashreplace|…) governs both legs; strict is the safe default.
def charset_transcode(
    text: str,
    from_charset: str,
    to_charset: str,
    errors: str = "strict",
) -> dict:
    """Convert text between character encodings (e.g. latin-1/cp1252 <-> utf-8).

    The input is encoded under `from_charset` to recover its raw bytes, which are
    then decoded under `to_charset`. If the bytes aren't valid `to_charset` text
    they're returned as bare hex with `output_format='hex'` (otherwise 'text').
    `errors` selects the codec error handler (strict|replace|ignore|…).
    """
    for name in (from_charset, to_charset):
        try:
            codecs.lookup(name)
        except LookupError as exc:
            raise ValueError(f"unknown charset {name!r}") from exc
    try:  # validate the handler now — encode/decode only check it when it fires.
        codecs.lookup_error(errors)
    except LookupError as exc:
        raise ValueError(f"unknown errors handler {errors!r}") from exc
    try:
        raw = text.encode(from_charset, errors)
    except UnicodeEncodeError as exc:
        raise ValueError(
            f"text not representable in {from_charset!r} under errors={errors!r}: {exc}"
        ) from exc
    try:
        result, output_format = raw.decode(to_charset, errors), "text"
    except UnicodeDecodeError:
        result, output_format = raw.hex(), "hex"
    return {
        "from_charset": from_charset,
        "to_charset": to_charset,
        "result": result,
        "output_format": output_format,
    }


# --- string_escape (§2.3.3 / §1.4.10-12, §1.5.1-2) ----------------------------
# Escape text for a source-code or markup context. The json/js/python/c/backslash
# family shares one backslash-escaper (`_escape_backslashy`), differing only in
# which quotes they protect and whether stragglers go octal (C) or \xNN. The
# remaining styles delegate to a purpose-built stdlib codec: html/xml entities,
# quopri (RFC 2045 quoted-printable), MIME encoded-word (=?UTF-8?B?...?=), and
# shlex for a paste-safe shell token. Output is the escaped *content* (no wrapping
# quotes) except shell/mime_word, whose delimiters are part of the encoding.
# NB: URL %-escaping is intentionally absent — use encode(scheme='url'), §2.2.1.
_ESC_NAMED = {  # backslash sequences shared by every backslashy style
    "\\": "\\\\",
    "\n": "\\n",
    "\r": "\\r",
    "\t": "\\t",
    "\b": "\\b",
    "\f": "\\f",
    "\v": "\\v",
}
_XML_ENTITIES = {"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&apos;"}


def _escape_backslashy(
    text: str,
    quotes: str,
    *,
    octal: bool = False,
    js_line_sep: bool = False,
    extra: dict[str, str] | None = None,
) -> str:
    """Backslash-escape `text`, protecting `quotes` and any control characters.

    `octal` renders stray control chars as \\NNN (C, unambiguous next to digits);
    otherwise \\xNN. `js_line_sep` escapes U+2028/U+2029, which terminate JS
    string literals. `extra` supplies style-specific named escapes (e.g. C's \\a).
    """
    out = []
    for ch in text:
        o = ord(ch)
        if extra and ch in extra:
            out.append(extra[ch])
        elif ch in _ESC_NAMED:
            out.append(_ESC_NAMED[ch])
        elif ch in quotes:
            out.append("\\" + ch)
        elif js_line_sep and o in (0x2028, 0x2029):
            out.append("\\u%04x" % o)
        elif o < 0x20 or o == 0x7F:
            out.append("\\%03o" % o if octal else "\\x%02x" % o)
        else:
            out.append(ch)
    return "".join(out)


_ESCAPERS = {
    # JSON only blesses \b \f \n \r \t \uXXXX, so let the stdlib do it (and strip
    # json.dumps' surrounding quotes to return bare content).
    "json": lambda t: json.dumps(t, ensure_ascii=False)[1:-1],
    "js": lambda t: _escape_backslashy(t, "\"'`", js_line_sep=True),
    "python": lambda t: _escape_backslashy(t, "\"'"),
    "c": lambda t: _escape_backslashy(t, '"', octal=True, extra={"\a": "\\a"}),
    "backslash": lambda t: _escape_backslashy(t, ""),
    "shell": shlex.quote,
    "html": html.escape,
    "xml": lambda t: "".join(_XML_ENTITIES.get(c, c) for c in t),
    "unicode_escape": lambda t: t.encode("unicode_escape").decode("ascii"),
    "quoted_printable": lambda t: quopri.encodestring(t.encode("utf-8")).decode(
        "ascii"
    ),
    "mime_word": lambda t: (
        "=?UTF-8?B?" + base64.b64encode(t.encode("utf-8")).decode("ascii") + "?="
    ),
}


def string_escape(
    text: str,
    style: Literal[
        "json",
        "js",
        "python",
        "c",
        "shell",
        "html",
        "xml",
        "backslash",
        "unicode_escape",
        "quoted_printable",
        "mime_word",
    ],
) -> dict:
    """Escape text for a source-code or markup context (JSON/JS/C/shell/HTML/...).

    `style` picks the convention: json|js|python|c|backslash (backslash escapes),
    html|xml (entities), unicode_escape (\\uXXXX/\\xNN), quoted_printable, or
    mime_word (=?UTF-8?B?...?=). shell yields a paste-safe single-quoted token.
    For URL %-escaping use encode(scheme='url') instead. Inverse: string_unescape.
    """
    escaper = _ESCAPERS.get(style)
    if escaper is None:
        raise ValueError(
            f"unknown style {style!r}; expected one of {', '.join(_ESCAPERS)}"
        )
    return {"style": style, "result": escaper(text)}


# --- string_unescape (§2.3.4 / §1.4.10-12, §1.5.1-2) --------------------------
# Inverse of string_escape, style-for-style. The backslash family shares one
# sequence parser (`_unescape_backslashy`) whose flags select which forms a style
# admits: \xNN (js/python/backslash, exactly two hex) vs C's greedy \xH+; octal
# \NNN (c/python); \uXXXX/\UXXXXXXXX/\u{...}; and the per-style named set. Unknown
# `\<ch>` drops the backslash, recovering escaped quotes (\" \' \`). The rest
# delegate to the same stdlib codecs as escape, run backwards.
_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")
_OCT_DIGITS = frozenset("01234567")
_UNESC_NAMED = {
    "n": "\n",
    "r": "\r",
    "t": "\t",
    "b": "\b",
    "f": "\f",
    "v": "\v",
    "a": "\a",
    "0": "\0",
}


def _named(*keys: str) -> dict[str, str]:
    """Project the shared named-escape table down to the keys a style admits."""
    return {k: _UNESC_NAMED[k] for k in keys}


def _unescape_backslashy(
    text: str,
    *,
    named: dict[str, str],
    octal: bool = False,
    hex2: bool = False,
    hex_greedy: bool = False,
    u4: bool = False,
    u8: bool = False,
    u_brace: bool = False,
) -> str:
    """Decode backslash escape sequences; flags pick which forms are recognized."""
    out: list[str] = []
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if ch != "\\":
            out.append(ch)
            i += 1
            continue
        i += 1
        if i >= n:  # trailing lone backslash — keep it literal
            out.append("\\")
            break
        e = text[i]
        if e == "\\":
            out.append("\\")
            i += 1
        elif e in named:
            out.append(named[e])
            i += 1
        elif hex_greedy and e == "x":
            i += 1
            j = i
            while j < n and text[j] in _HEX_DIGITS:
                j += 1
            if j == i:
                raise ValueError(r"\x needs at least one hex digit")
            out.append(chr(int(text[i:j], 16)))
            i = j
        elif hex2 and e == "x":
            h = text[i + 1 : i + 3]
            if len(h) < 2 or any(c not in _HEX_DIGITS for c in h):
                raise ValueError(r"\x needs two hex digits")
            out.append(chr(int(h, 16)))
            i += 3
        elif u_brace and e == "u" and i + 1 < n and text[i + 1] == "{":
            close = text.find("}", i)
            if close < 0:
                raise ValueError(r"unterminated \u{...}")
            out.append(chr(int(text[i + 2 : close], 16)))
            i = close + 1
        elif u4 and e == "u":
            h = text[i + 1 : i + 5]
            if len(h) < 4 or any(c not in _HEX_DIGITS for c in h):
                raise ValueError(r"\u needs four hex digits")
            out.append(chr(int(h, 16)))
            i += 5
        elif u8 and e == "U":
            h = text[i + 1 : i + 9]
            if len(h) < 8 or any(c not in _HEX_DIGITS for c in h):
                raise ValueError(r"\U needs eight hex digits")
            out.append(chr(int(h, 16)))
            i += 9
        elif octal and e in _OCT_DIGITS:
            j, k = i, 0
            while j < n and k < 3 and text[j] in _OCT_DIGITS:
                j, k = j + 1, k + 1
            out.append(chr(int(text[i:j], 8)))
            i = j
        else:  # unknown escape: drop the backslash (recovers \" \' \`)
            out.append(e)
            i += 1
    return "".join(out)


_UNESCAPERS = {
    "json": lambda t: json.loads('"' + t + '"'),
    "js": lambda t: _unescape_backslashy(
        t,
        named=_named("n", "r", "t", "b", "f", "v", "0"),
        hex2=True,
        u4=True,
        u_brace=True,
    ),
    "python": lambda t: _unescape_backslashy(
        t,
        named=_named("n", "r", "t", "b", "f", "v", "a"),
        hex2=True,
        octal=True,
        u4=True,
        u8=True,
    ),
    "c": lambda t: _unescape_backslashy(
        t, named=_named("n", "r", "t", "b", "f", "v", "a"), octal=True, hex_greedy=True
    ),
    "backslash": lambda t: _unescape_backslashy(
        t, named=_named("n", "r", "t", "b", "f", "v"), hex2=True
    ),
    # shlex.quote yields one shell word; split it back and rejoin the (possibly
    # concatenated) segments into the original token.
    "shell": lambda t: "".join(shlex.split(t)),
    "html": html.unescape,
    "xml": html.unescape,  # superset: handles &apos; and numeric refs too
    "unicode_escape": lambda t: t.encode("ascii").decode("unicode_escape"),
    "quoted_printable": lambda t: quopri.decodestring(t.encode("ascii")).decode(
        "utf-8"
    ),
    "mime_word": lambda t: str(make_header(decode_header(t))),
}


def string_unescape(
    text: str,
    style: Literal[
        "json",
        "js",
        "python",
        "c",
        "shell",
        "html",
        "xml",
        "backslash",
        "unicode_escape",
        "quoted_printable",
        "mime_word",
    ],
) -> dict:
    """Reverse a source-code or markup escaping back to the original text.

    Style-for-style inverse of string_escape (json|js|python|c|backslash escape
    sequences, html|xml entities, unicode_escape, quoted_printable, mime_word,
    and shell). Malformed escape sequences raise ValueError.
    """
    unescaper = _UNESCAPERS.get(style)
    if unescaper is None:
        raise ValueError(
            f"unknown style {style!r}; expected one of {', '.join(_UNESCAPERS)}"
        )
    return {"style": style, "result": unescaper(text)}


# --- random (§2.5.1 / §1.11.4, merges random_bytes + random_token + passphrase)
# All entropy comes from `secrets` (the CSPRNG), never `random`. The byte-derived
# kinds (bytes/hex/urlsafe) are sized by `nbytes`; `token` is sized by character
# `length`; `passphrase` by `words`. entropy_bits is reported honestly per kind.
#
# The default passphrase wordlist is the EFF "large" diceware list (7776 words ->
# log2(7776) ~= 12.9 bits/word), bundled under wordlists/. It is the work of the
# Electronic Frontier Foundation, licensed CC BY 3.0 US (see README).
_EFF_WORDLIST: tuple[str, ...] | None = None


def _eff_wordlist() -> tuple[str, ...]:
    """Load (and cache) the bundled EFF large wordlist as one word per line."""
    global _EFF_WORDLIST
    if _EFF_WORDLIST is None:
        text = (files("mcp_bytesmith") / "wordlists" / "eff_large.txt").read_text(
            "utf-8"
        )
        _EFF_WORDLIST = tuple(w for w in text.split() if w)
    return _EFF_WORDLIST


def random(
    kind: Literal["bytes", "hex", "urlsafe", "token", "passphrase"] = "urlsafe",
    length: int | None = None,
    nbytes: int = 32,
    words: int = 6,
    separator: str = "-",
    wordlist: list[str] | None = None,
    output_format: Literal["hex", "base64"] = "hex",
) -> dict:
    """Generate cryptographically secure random bytes, a token, or a passphrase.

    All randomness is drawn from the OS CSPRNG (`secrets`). `kind` selects the
    shape and which sizing arg applies: bytes|hex|urlsafe draw `nbytes` (default
    32) random bytes — bytes renders them via `output_format` (hex/base64), hex
    is the same bytes as hex, urlsafe is RFC 4648 url-safe base64; token is a
    `length`-character (default 32) alphanumeric [A-Za-z0-9] string; passphrase
    joins `words` (default 6) words with `separator` (default '-'), drawn from
    `wordlist` or the bundled EFF large diceware list. Returns {kind, value,
    entropy_bits}; the value is the only secret and is never logged elsewhere.
    """
    if kind in ("bytes", "hex", "urlsafe"):
        if nbytes <= 0:
            raise ValueError(f"nbytes must be positive, got {nbytes}")
        if kind == "bytes":
            value = _render(secrets.token_bytes(nbytes), output_format)
        elif kind == "hex":
            value = secrets.token_hex(nbytes)
        else:
            value = secrets.token_urlsafe(nbytes)
        return {"kind": kind, "value": value, "entropy_bits": nbytes * 8}

    if kind == "token":
        n = 32 if length is None else length
        if n <= 0:
            raise ValueError(f"length must be positive, got {n}")
        alphabet = string.ascii_letters + string.digits
        value = "".join(secrets.choice(alphabet) for _ in range(n))
        return {
            "kind": kind,
            "value": value,
            "entropy_bits": math.floor(n * math.log2(len(alphabet))),
        }

    if kind == "passphrase":
        if words <= 0:
            raise ValueError(f"words must be positive, got {words}")
        wl = _eff_wordlist() if wordlist is None else tuple(wordlist)
        if len(wl) < 2:
            raise ValueError("wordlist must contain at least 2 words")
        value = separator.join(secrets.choice(wl) for _ in range(words))
        return {
            "kind": kind,
            "value": value,
            "entropy_bits": math.floor(words * math.log2(len(wl))),
        }

    raise ValueError(
        f"unknown kind {kind!r}; expected bytes|hex|urlsafe|token|passphrase"
    )


def register(mcp) -> None:
    """Register the always-on stdlib tools against the FastMCP app."""
    mcp.tool()(num_convert)
    mcp.tool()(byte_order)
    mcp.tool()(hash)
    mcp.tool()(encode)
    mcp.tool()(decode)
    mcp.tool()(data_uri)
    mcp.tool()(bytes_edit)
    mcp.tool()(unicode_normalize)
    mcp.tool()(charset_transcode)
    mcp.tool()(string_escape)
    mcp.tool()(string_unescape)
    mcp.tool()(random)
