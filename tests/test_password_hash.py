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

"""TODO 13.1 / plan §2.4.1 / §1.2.1-4 — password_hash (hash + verify).

The stdlib schemes are pinned to their RFC vectors (PBKDF2 = RFC 6070, scrypt =
RFC 7914) and our bcrypt salt encoder to OpenBSD's radix-64, so a refactor that
silently changes what we compute fails here. Around that: round-trips for all six
schemes, the soft-vs-raise boundary (§2.0.5), the cost ceilings, and §2.0.6 (the
password never comes back out).

Cost params are turned down throughout — these are deliberately slow functions.
"""

import asyncio
import base64
import json

import pytest

from mcp_bytesmith.core import _bcrypt_salt
from mcp_bytesmith.core import password_hash as PH
from mcp_bytesmith.server import mcp

# Cheap-but-valid cost settings, one per scheme.
FAST = {
    "bcrypt": {"rounds": 4},
    "argon2i": {"time_cost": 1, "memory_cost": 256, "parallelism": 1},
    "argon2d": {"time_cost": 1, "memory_cost": 256, "parallelism": 1},
    "argon2id": {"time_cost": 1, "memory_cost": 256, "parallelism": 1},
    "scrypt": {"ln": 8},
    "pbkdf2": {"iterations": 1000},
}
SCHEMES = tuple(FAST)


def _hash(scheme, password="hunter2", **kw):
    return PH("hash", password, scheme=scheme, params=FAST[scheme], **kw)["encoded"]


def _digest(encoded):
    """The trailing base64 field of a PHC-shaped string, as raw bytes."""
    body = encoded.rsplit("$", 1)[1]
    return base64.b64decode(body + "=" * (-len(body) % 4))


# --- known-answer tests --------------------------------------------------------
def test_pbkdf2_matches_rfc6070_vector():
    # RFC 6070 §2: P="password", S="salt", c=4096, dkLen=20, PRF=HMAC-SHA1.
    encoded = PH(
        "hash",
        "password",
        scheme="pbkdf2",
        salt=b"salt".hex(),
        params={"iterations": 4096, "prf": "sha1", "dklen": 20},
    )["encoded"]
    assert encoded.startswith("$pbkdf2-sha1$i=4096$")
    assert _digest(encoded).hex() == "4b007901b765489abead49d926f721d065a429c1"


def test_scrypt_matches_rfc7914_vector():
    # RFC 7914 §12: P="password", S="NaCl", N=1024, r=8, p=16, dkLen=64.
    encoded = PH(
        "hash",
        "password",
        scheme="scrypt",
        salt=b"NaCl".hex(),
        params={"ln": 10, "r": 8, "p": 16, "dklen": 64},
    )["encoded"]
    assert encoded.startswith("$scrypt$ln=10,r=8,p=16$")
    assert _digest(encoded).hex().startswith("fdbabe1c9d3472007856e7190d01e9fe")


def test_bcrypt_salt_encoder_matches_openbsd_radix64():
    # bcrypt's alphabet is "./A-Za-z0-9"; the packing is standard base64's, so a
    # straight re-alphabet must reproduce OpenBSD's encode_base64() exactly.
    b64 = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

    def reference(data):  # transliteration of the C, one 3-byte group at a time
        out, i = [], 0
        while i < len(data):
            c1 = data[i]
            i += 1
            out.append(b64[(c1 >> 2) & 0x3F])
            c1 = (c1 & 0x03) << 4
            if i >= len(data):
                out.append(b64[c1 & 0x3F])
                break
            c2 = data[i]
            i += 1
            c1 |= (c2 >> 4) & 0x0F
            out.append(b64[c1 & 0x3F])
            c1 = (c2 & 0x0F) << 2
            if i >= len(data):
                out.append(b64[c1 & 0x3F])
                break
            c2 = data[i]
            i += 1
            c1 |= (c2 >> 6) & 0x03
            out.append(b64[c1 & 0x3F])
            out.append(b64[c2 & 0x3F])
        return "".join(out)

    for raw in (bytes(16), bytes(range(16)), bytes(range(240, 256)), b"\xff" * 16):
        assert _bcrypt_salt(raw, 12).decode() == f"$2b$12${reference(raw)}"


def test_bcrypt_hash_is_accepted_by_the_bcrypt_library():
    # The real cross-check: our salt+string must satisfy the reference verifier.
    import bcrypt

    encoded = _hash("bcrypt", salt="00112233445566778899aabbccddeeff")
    assert bcrypt.checkpw(b"hunter2", encoded.encode())
    assert not bcrypt.checkpw(b"hunter3", encoded.encode())


# --- round-trips ---------------------------------------------------------------
@pytest.mark.parametrize("scheme", SCHEMES)
def test_hash_then_verify_round_trip(scheme):
    encoded = _hash(scheme)
    out = PH("verify", "hunter2", encoded=encoded)
    assert out["action"] == "verify"
    assert out["valid"] is True
    assert out["scheme"] == scheme


@pytest.mark.parametrize("scheme", SCHEMES)
def test_wrong_password_is_soft_invalid(scheme):
    # §2.0.5 — a failed verify is a RESULT, not an error.
    out = PH("verify", "wrong", encoded=_hash(scheme))
    assert out["valid"] is False
    assert out["reason"]


@pytest.mark.parametrize("scheme", SCHEMES)
def test_scheme_is_recovered_from_the_encoded_string(scheme):
    # verify needs no `scheme` argument; a matching one is allowed, a wrong one is not.
    encoded = _hash(scheme)
    assert PH("verify", "hunter2", encoded=encoded, scheme=scheme)["valid"] is True
    other = "scrypt" if scheme != "scrypt" else "pbkdf2"
    with pytest.raises(ValueError, match="but `scheme` says"):
        PH("verify", "hunter2", encoded=encoded, scheme=other)


@pytest.mark.parametrize("scheme", SCHEMES)
def test_hash_echoes_scheme_and_params_but_never_the_password(scheme):
    # §2.0.3 self-describing; §2.0.6 secrets never leave the box.
    out = PH("hash", "correct horse", scheme=scheme, params=FAST[scheme])
    assert out["action"] == "hash" and out["scheme"] == scheme
    assert FAST[scheme].items() <= out["params"].items()
    assert "correct horse" not in json.dumps(out)
    assert "password" not in out


def test_same_salt_is_deterministic_and_omitted_salt_is_not():
    fixed = {"iterations": 1000}
    a = PH("hash", "pw", scheme="pbkdf2", salt="00" * 16, params=fixed)["encoded"]
    b = PH("hash", "pw", scheme="pbkdf2", salt="00" * 16, params=fixed)["encoded"]
    assert a == b
    fresh = {
        PH("hash", "pw", scheme="pbkdf2", params=fixed)["encoded"] for _ in range(3)
    }
    assert len(fresh) == 3  # a fresh CSPRNG salt each call


def test_defaults_apply_when_params_omitted():
    out = PH("hash", "pw", scheme="scrypt", params={"ln": 8})
    assert out["params"] == {"ln": 8, "r": 8, "p": 1, "dklen": 32}
    assert len(_digest(out["encoded"])) == 32


def test_pbkdf2_prf_and_dklen_are_carried_by_the_string():
    encoded = PH(
        "hash",
        "pw",
        scheme="pbkdf2",
        params={"iterations": 1000, "prf": "sha512", "dklen": 64},
    )["encoded"]
    assert encoded.startswith("$pbkdf2-sha512$")
    out = PH("verify", "pw", encoded=encoded)
    assert out["valid"] is True
    assert out["params"] == {"iterations": 1000, "prf": "sha512", "dklen": 64}


def test_argon2_variants_are_distinct_and_report_their_costs():
    encodings = {s: _hash(s) for s in ("argon2i", "argon2d", "argon2id")}
    for scheme, encoded in encodings.items():
        assert encoded.startswith(f"${scheme}$v=19$m=256,t=1,p=1$")
        out = PH("verify", "hunter2", encoded=encoded)
        assert out["scheme"] == scheme and out["valid"] is True
        assert out["params"] == {
            "memory_cost": 256,
            "time_cost": 1,
            "parallelism": 1,
            "version": 19,
        }
    assert len(set(encodings.values())) == 3


# --- arguments and cost ceilings ------------------------------------------------
def test_hash_requires_scheme_and_verify_requires_encoded():
    with pytest.raises(ValueError, match="requires `scheme`"):
        PH("hash", "pw")
    with pytest.raises(ValueError, match="requires `encoded`"):
        PH("verify", "pw")


def test_unknown_action_raises():
    with pytest.raises(ValueError, match="unknown action"):
        PH("frobnicate", "pw", scheme="pbkdf2")


def test_unknown_param_names_the_valid_ones():
    with pytest.raises(ValueError, match="unknown param 'rounds'.*iterations"):
        PH("hash", "pw", scheme="pbkdf2", params={"rounds": 12})


def test_unknown_prf_rejected():
    with pytest.raises(ValueError, match="unknown prf 'md5'"):
        PH("hash", "pw", scheme="pbkdf2", params={"prf": "md5"})


@pytest.mark.parametrize(
    ("scheme", "params"),
    [
        ("pbkdf2", {"iterations": 10_000_001}),
        ("pbkdf2", {"dklen": 129}),
        ("scrypt", {"ln": 21}),
        ("bcrypt", {"rounds": 17}),
        ("bcrypt", {"rounds": 3}),
        ("argon2id", {"memory_cost": (1 << 20) + 1}),
        ("argon2id", {"parallelism": 17}),
    ],
)
def test_cost_ceilings_reject_runaway_params(scheme, params):
    # An over-large cost is not a slow answer, it is a hung server / an OOM.
    with pytest.raises(ValueError, match="is outside"):
        PH("hash", "pw", scheme=scheme, params=params)


def test_bool_is_not_an_integer_cost():
    with pytest.raises(ValueError, match="must be an integer"):
        PH("hash", "pw", scheme="bcrypt", params={"rounds": True})


def test_salt_size_rules_per_scheme():
    with pytest.raises(ValueError, match="16-byte salt"):
        PH("hash", "pw", scheme="bcrypt", salt="00", params=FAST["bcrypt"])
    with pytest.raises(ValueError, match=">=8 bytes"):
        PH("hash", "pw", scheme="argon2id", salt="0011", params=FAST["argon2id"])
    with pytest.raises(ValueError, match="invalid hex"):
        PH("hash", "pw", scheme="pbkdf2", salt="zz")


@pytest.mark.parametrize("scheme", SCHEMES)
def test_empty_salt_is_rejected_not_silently_randomized(scheme):
    # An empty salt must not read as "absent" — that would quietly hand back a
    # random salt to a caller who asked for a deterministic hash.
    with pytest.raises(ValueError, match="`salt` is empty"):
        PH("hash", "pw", scheme=scheme, salt="", params=FAST[scheme])


def test_bcrypt_rejects_a_password_past_its_72_byte_truncation():
    with pytest.raises(ValueError, match="72 bytes"):
        PH("hash", "x" * 73, scheme="bcrypt", params=FAST["bcrypt"])
    assert PH("hash", "x" * 72, scheme="bcrypt", params=FAST["bcrypt"])["encoded"]


def test_argon2_memory_cost_floor_relative_to_parallelism():
    with pytest.raises(ValueError, match="memory_cost >= 8 \\* parallelism"):
        PH("hash", "pw", scheme="argon2id", params={"memory_cost": 8, "parallelism": 4})


# --- malformed `encoded` raises (it is input, not a result) ---------------------
@pytest.mark.parametrize(
    "encoded",
    [
        "notahash",
        "",
        "$md5$deadbeef",
        "$scrypt$ln=8$c2FsdA",  # too few fields
        "$scrypt$ln,r=8,p=1$c2FsdA$aGFzaA",  # parameter without '='
        "$scrypt$ln=8,r=8$c2FsdA$aGFzaA",  # missing p
        "$scrypt$ln=x,r=8,p=1$c2FsdA$aGFzaA",  # non-integer cost
        "$scrypt$ln=30,r=8,p=1$c2FsdA$aGFzaA",  # cost past the ceiling
        "$scrypt$ln=8,r=8,p=1$sa*lt$aGFzaA",  # junk base64
        "$pbkdf2-md5$i=1000$c2FsdA$aGFzaA",  # unknown prf
        "$2b$zz$short",  # bcrypt with a bad cost
        "$argon2id$v=19$m=8$YWFhYWFhYWFh",  # argon2, too few fields
        "$argon2id$v=19$m=256,t=1,p=1$YWFhYWFhYWFh$!!!",  # argon2, junk digest
    ],
)
def test_malformed_encoded_raises(encoded):
    with pytest.raises(ValueError):
        PH("verify", "pw", encoded=encoded)


# --- app wiring ----------------------------------------------------------------
def test_registered_with_action_and_scheme_enums():
    tool = next(t for t in asyncio.run(mcp.list_tools()) if t.name == "password_hash")
    props = tool.inputSchema["properties"]
    assert set(props["action"]["enum"]) == {"hash", "verify"}
    # `scheme` is an optional enum, so pydantic nests it under anyOf.
    schemes = {s for branch in props["scheme"]["anyOf"] for s in branch.get("enum", [])}
    assert schemes == set(SCHEMES)


def test_callable_through_app():
    encoded = _hash("pbkdf2")

    async def go():
        return await mcp.call_tool(
            "password_hash",
            {"action": "verify", "password": "hunter2", "encoded": encoded},
        )

    result = asyncio.run(go())
    contents = result[0] if isinstance(result, tuple) else result
    payload = json.loads(contents[0].text)
    assert payload["valid"] is True and payload["scheme"] == "pbkdf2"
