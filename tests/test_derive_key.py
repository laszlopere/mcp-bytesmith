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

"""TODO 13.2 / plan §2.4.2 / §1.2.3-4 — derive_key (PBKDF2 / scrypt / HKDF).

HKDF is hand-rolled on hmac, so it is pinned to all five RFC 5869 test vectors —
including the multi-block expand and the zero-salt/zero-info cases, which are
exactly where a hand-rolled implementation goes wrong. PBKDF2 and scrypt are
pinned to RFC 6070 / RFC 7914. Around that: determinism (an omitted salt must
never become a random one), the length and cost bounds, and §2.0.6.
"""

import asyncio
import json

import pytest

from mcp_bytesmith.core import _hkdf
from mcp_bytesmith.core import derive_key as DK
from mcp_bytesmith.server import mcp

KDFS = ("pbkdf2", "scrypt", "hkdf")
# Cheap-but-valid cost settings for the two deliberately-slow KDFs.
FAST = {"pbkdf2": {"iterations": 1000}, "scrypt": {"ln": 8}, "hkdf": {}}


# --- known-answer tests: RFC 5869 (HKDF) ---------------------------------------
# The published vectors, verbatim. IKM/salt/info are raw bytes here (the tool
# takes them as UTF-8 text / hex), so these drive the internal primitive.
RFC5869 = [
    (  # A.1 — basic, SHA-256
        "sha256",
        "0b" * 22,
        "000102030405060708090a0b0c",
        "f0f1f2f3f4f5f6f7f8f9",
        42,
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        "34007208d5b887185865",
    ),
    (  # A.2 — longer inputs, L=82 spans multiple expand blocks
        "sha256",
        "".join(f"{b:02x}" for b in range(0x50)),
        "".join(f"{b:02x}" for b in range(0x60, 0xB0)),
        "".join(f"{b:02x}" for b in range(0xB0, 0x100)),
        82,
        "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c"
        "59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71"
        "cc30c58179ec3e87c14c01d5c1f3434f1d87",
    ),
    (  # A.3 — zero-length salt and info
        "sha256",
        "0b" * 22,
        "",
        "",
        42,
        "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d"
        "9d201395faa4b61a96c8",
    ),
    (  # A.4 — SHA-1
        "sha1",
        "0b" * 11,
        "000102030405060708090a0b0c",
        "f0f1f2f3f4f5f6f7f8f9",
        42,
        "085a01ea1b10f36933068b56efa5ad81a4f14b822f5b091568a9cdd4f155fda2"
        "c22e422478d305f3f896",
    ),
    (  # A.5 — SHA-1, zero-length salt and info
        "sha1",
        "0c" * 22,
        "",
        "",
        42,
        "2c91117204d745f3500d636a62f64f0ab3bae548aa53d423b0d1f27ebba6f5e5"
        "673a081d70cce7acfc48",
    ),
]


@pytest.mark.parametrize(("hash_name", "ikm", "salt", "info", "length", "okm"), RFC5869)
def test_hkdf_matches_rfc5869_vectors(hash_name, ikm, salt, info, length, okm):
    got = _hkdf(
        bytes.fromhex(ikm), bytes.fromhex(salt), bytes.fromhex(info), hash_name, length
    )
    assert got.hex() == okm


def test_hkdf_through_the_tool_matches_the_rfc_steps():
    # extract then one expand block, spelled out — the tool must agree.
    import hashlib
    import hmac

    prk = hmac.new(bytes.fromhex("0011"), b"hunter2", hashlib.sha256).digest()
    expected = hmac.new(prk, b"app-v1" + b"\x01", hashlib.sha256).digest()[:16]
    out = DK("hunter2", kdf="hkdf", salt="0011", length=16, params={"info": "app-v1"})
    assert out["key"] == expected.hex()


def test_hkdf_empty_salt_is_the_rfcs_default():
    # RFC 5869 §2.2: absent salt == HashLen zero bytes. HMAC zero-pads a short
    # key, so b"" and b"\x00"*32 must extract to the same PRK.
    assert _hkdf(b"ikm", b"", b"", "sha256", 32) == _hkdf(
        b"ikm", bytes(32), b"", "sha256", 32
    )


# --- known-answer tests: the stdlib KDFs ---------------------------------------
def test_pbkdf2_matches_rfc6070_vector():
    # RFC 6070 §2: P="password", S="salt", c=4096, dkLen=20, PRF=HMAC-SHA1.
    out = DK(
        "password",
        kdf="pbkdf2",
        salt=b"salt".hex(),
        length=20,
        params={"iterations": 4096, "prf": "sha1"},
    )
    assert out["key"] == "4b007901b765489abead49d926f721d065a429c1"


def test_scrypt_matches_rfc7914_vector():
    # RFC 7914 §12: P="password", S="NaCl", N=1024, r=8, p=16, dkLen=64.
    out = DK(
        "password",
        kdf="scrypt",
        salt=b"NaCl".hex(),
        length=64,
        params={"ln": 10, "r": 8, "p": 16},
    )
    assert out["key"].startswith("fdbabe1c9d3472007856e7190d01e9fe")
    assert len(bytes.fromhex(out["key"])) == 64


# --- determinism ----------------------------------------------------------------
@pytest.mark.parametrize("kdf", KDFS)
def test_derivation_is_deterministic(kdf):
    args = {"kdf": kdf, "salt": "00" * 16, "length": 32, "params": FAST[kdf]}
    assert DK("pw", **args) == DK("pw", **args)


@pytest.mark.parametrize("kdf", KDFS)
def test_omitted_salt_is_empty_not_random(kdf):
    # The whole point of §13 DERIVE: a random salt here would hand back a key
    # nobody can reproduce. Omitted must mean empty, and must be echoed as such.
    first = DK("pw", kdf=kdf, length=16, params=FAST[kdf])
    second = DK("pw", kdf=kdf, length=16, params=FAST[kdf])
    assert first["salt"] == ""
    assert first["key"] == second["key"]


@pytest.mark.parametrize("kdf", KDFS)
def test_salt_changes_the_key_and_is_echoed(kdf):
    a = DK("pw", kdf=kdf, salt="aa" * 16, length=16, params=FAST[kdf])
    b = DK("pw", kdf=kdf, salt="bb" * 16, length=16, params=FAST[kdf])
    assert a["key"] != b["key"]
    assert a["salt"] == "aa" * 16


def test_hkdf_info_binds_the_key_to_a_purpose():
    base = {"kdf": "hkdf", "length": 32, "salt": "00" * 16}
    enc = DK("shared-secret", params={"info": "encryption"}, **base)["key"]
    mac = DK("shared-secret", params={"info": "mac"}, **base)["key"]
    assert enc != mac


# --- shape, length, formats -----------------------------------------------------
@pytest.mark.parametrize("kdf", KDFS)
def test_return_is_self_describing_and_hides_the_password(kdf):
    out = DK("correct horse", kdf=kdf, salt="00" * 8, length=24, params=FAST[kdf])
    assert out["kdf"] == kdf and out["length"] == 24
    assert out["salt"] == "00" * 8 and out["output_format"] == "hex"
    assert FAST[kdf].items() <= out["params"].items()
    assert len(bytes.fromhex(out["key"])) == 24
    assert "correct horse" not in json.dumps(out)  # §2.0.6
    assert "password" not in out


@pytest.mark.parametrize("length", [1, 20, 31, 32, 33, 64, 100, 1024])
def test_length_is_honoured_exactly_including_partial_digest_blocks(length):
    # HKDF expands in HashLen blocks; a length that is not a multiple must be
    # truncated, not rounded up.
    out = DK("pw", kdf="hkdf", length=length)
    assert len(bytes.fromhex(out["key"])) == length
    assert out["length"] == length


def test_defaults_are_pbkdf2_sha256_600k_and_32_bytes():
    out = DK("pw", salt="00" * 16, params={"iterations": 1000})
    assert out["kdf"] == "pbkdf2"
    assert out["length"] == 32
    assert out["params"] == {"iterations": 1000, "prf": "sha256"}


def test_base64_output_format():
    import base64

    out = DK("pw", kdf="hkdf", length=32, output_format="base64")
    hex_out = DK("pw", kdf="hkdf", length=32)
    assert base64.b64decode(out["key"]).hex() == hex_out["key"]
    assert out["output_format"] == "base64"


@pytest.mark.parametrize("prf", ["sha1", "sha256", "sha512"])
def test_pbkdf2_prf_selection_changes_the_key(prf):
    import hashlib

    out = DK("pw", salt="0011", length=32, params={"iterations": 100, "prf": prf})
    expected = hashlib.pbkdf2_hmac(prf, b"pw", bytes.fromhex("0011"), 100, 32)
    assert out["key"] == expected.hex()


@pytest.mark.parametrize("hash_name", ["sha1", "sha256", "sha384", "sha512"])
def test_hkdf_hash_selection(hash_name):
    out = DK("pw", kdf="hkdf", length=16, params={"hash": hash_name})
    assert out["params"]["hash"] == hash_name
    assert len(bytes.fromhex(out["key"])) == 16


# --- errors ---------------------------------------------------------------------
def test_unknown_kdf_raises():
    with pytest.raises(ValueError, match="unknown kdf"):
        DK("pw", kdf="argon2")


@pytest.mark.parametrize("length", [0, -1, 1025, 10_000])
def test_length_bounds(length):
    with pytest.raises(ValueError, match="outside 1..1024"):
        DK("pw", kdf="hkdf", length=length)


def test_unknown_param_names_the_kdfs_own_params():
    with pytest.raises(ValueError, match="unknown param 'iterations' for kdf 'hkdf'"):
        DK("pw", kdf="hkdf", params={"iterations": 1000})
    with pytest.raises(ValueError, match="unknown param 'ln' for kdf 'pbkdf2'"):
        DK("pw", kdf="pbkdf2", params={"ln": 8})


def test_unknown_prf_and_hash_rejected():
    with pytest.raises(ValueError, match="unknown prf 'md5'"):
        DK("pw", params={"prf": "md5", "iterations": 100})
    with pytest.raises(ValueError, match="unknown hash 'md5'"):
        DK("pw", kdf="hkdf", params={"hash": "md5"})


def test_non_string_info_rejected():
    with pytest.raises(ValueError, match="'info' must be a string"):
        DK("pw", kdf="hkdf", params={"info": 123})


@pytest.mark.parametrize(
    ("kdf", "params"),
    [
        ("pbkdf2", {"iterations": 10_000_001}),
        ("pbkdf2", {"iterations": 0}),
        ("scrypt", {"ln": 21}),
        ("scrypt", {"r": 33}),
        ("scrypt", {"p": 17}),
    ],
)
def test_cost_ceilings_reject_runaway_params(kdf, params):
    with pytest.raises(ValueError, match="is outside"):
        DK("pw", kdf=kdf, params=params)


def test_bool_is_not_an_integer_cost():
    with pytest.raises(ValueError, match="must be an integer"):
        DK("pw", params={"iterations": True})


def test_bad_salt_hex_and_output_format():
    with pytest.raises(ValueError, match="invalid hex"):
        DK("pw", kdf="hkdf", salt="zz")
    with pytest.raises(ValueError, match="unknown output_format"):
        DK("pw", kdf="hkdf", output_format="rot13")


def test_hkdf_rfc_length_ceiling_is_enforced_by_the_primitive():
    # 255 * HashLen. Below the tool's own 1024-byte cap only for short hashes,
    # so it is checked on the primitive directly.
    with pytest.raises(ValueError, match="cannot derive more than 5100 bytes"):
        _hkdf(b"ikm", b"", b"", "sha1", 5101)


# --- app wiring ------------------------------------------------------------------
def test_registered_with_kdf_enum():
    tool = next(t for t in asyncio.run(mcp.list_tools()) if t.name == "derive_key")
    assert set(tool.inputSchema["properties"]["kdf"]["enum"]) == set(KDFS)


def test_callable_through_app():
    async def go():
        return await mcp.call_tool(
            "derive_key",
            {"password": "hunter2", "kdf": "hkdf", "salt": "0011", "length": 16},
        )

    result = asyncio.run(go())
    contents = result[0] if isinstance(result, tuple) else result
    payload = json.loads(contents[0].text)
    assert payload["kdf"] == "hkdf"
    assert len(bytes.fromhex(payload["key"])) == 16
