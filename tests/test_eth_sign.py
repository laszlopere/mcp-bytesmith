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

"""eth_sign — secp256k1 sign (key from a file only), verify, recover, convert.

Signatures are cross-checked against eth_account's sign_hash for the well-known
Hardhat/Anvil default accounts, whose private keys are published fixtures (never
use them for real funds). RFC 6979 makes signing deterministic, so the vectors
are exact."""

import asyncio
import json

import pytest

pytest.importorskip("Crypto", reason="ethereum extra (pycryptodome) not installed")

from mcp_bytesmith.eth import eth_hash, eth_sign  # noqa: E402
from mcp_bytesmith.server import mcp  # noqa: E402

KEY0 = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
ADDR0 = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
KEY1 = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
ADDR1 = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"

HELLO_KECCAK = "0x1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8"
HELLO_EIP191 = "0x50b2c43fd39106bafbba0da34fc430e1f91e3c96ea2acee2bc34119f92b37750"

# (key, digest, 65-byte signature) from eth_account.Account.unsafe_sign_hash.
VECTORS = [
    (
        KEY0,
        HELLO_KECCAK,
        "0x73eebf81a611136662d65778960c853fdcaf6eca86793ed9cabc30f2195937af"
        "78a07e601627da5b4cc80c0ab35f6894da19b4a01759d90c101d9c9dd1c6745d1b",
    ),
    (
        KEY0,
        "0x" + "00" * 31 + "01",
        "0xa60a6906512e182138437a161eebd743f725438c71210b926fcd721b9a7c4bfa"
        "151b0de4e4103d8b44f1539c214dc5b85a2c217c93d3f3c69dd7f9d0a93ac3061c",
    ),
    (
        KEY0,
        "0x" + "ff" * 32,  # digest >= n: reduced mod n inside the math
        "0x8f7d3763cc1e1ef6f5c21011f04f80c0ae51c33c6018a30355a4c47a58c3bd17"
        "626e3b4df5956744a6f073e3401b54c350c26abd2804f52261abded6afaf4dec1b",
    ),
    (
        KEY0,
        HELLO_EIP191,
        "0xf16ea9a3478698f695fd1401bfe27e9e4a7e8e3da94aa72b021125e31fa899cc"
        "573c48ea3fe1d4ab61a9db10c19032026e3ed2dbccba5a178235ac27f94504311c",
    ),
    (
        KEY1,
        HELLO_KECCAK,
        "0xf89f6ef35202d9275142d9b7108460e5476aa06cb830f3aaef018ba99142cb6c"
        "07dc319c829f3c386479b29967148acf43bfcf3834bd6cb17f83b5ce250a4b4c1b",
    ),
    (
        KEY1,
        "0x" + "00" * 31 + "01",
        "0xa3eb8a3051b84c92c81278bac5dc78fd5e2ac6a81052422e66857cce4f8db5ed"
        "1fb707adf6fffd4da49a83cd6b99708ef135fda19abb51a38afc6c8aa7d032161b",
    ),
]

SECP_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
SECP_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F


@pytest.fixture
def key_file(tmp_path):
    def make(key=KEY0, name="key"):
        f = tmp_path / name
        f.write_text(key + "\n")
        return str(f)

    return make


def _sign(key_file, digest=HELLO_KECCAK, key=KEY0):
    return eth_sign("sign", message_hash=digest, private_key_file=key_file(key))


def _split(sig65: str) -> tuple[int, int, int]:
    raw = bytes.fromhex(sig65[2:])
    return int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:64], "big"), raw[64]


def _sig65(r: int, s: int, v: int) -> str:
    return "0x" + (r.to_bytes(32, "big") + s.to_bytes(32, "big") + bytes([v])).hex()


# --- sign: known-answer vectors -------------------------------------------------
@pytest.mark.parametrize("key,digest,expected", VECTORS)
def test_sign_matches_eth_account(key_file, key, digest, expected):
    assert _sign(key_file, digest, key)["signature"] == expected


def test_personal_sign_end_to_end(key_file):
    # eth_hash(eip191) + eth_sign == eth_account's sign_message(encode_defunct("hello"))
    digest = eth_hash("eip191", "hello")["hash"]
    assert digest == HELLO_EIP191
    assert _sign(key_file, digest)["signature"] == VECTORS[3][2]


def test_sign_is_deterministic(key_file):
    assert _sign(key_file) == _sign(key_file)


def test_sign_result_shape(key_file):
    out = _sign(key_file)
    assert set(out) == {
        "action",
        "signature",
        "r",
        "s",
        "v",
        "yParity",
        "eip2098",
        "address",
    }
    r, s, v = _split(out["signature"])
    assert out["r"] == "0x" + r.to_bytes(32, "big").hex()
    assert out["s"] == "0x" + s.to_bytes(32, "big").hex()
    assert out["v"] == v and out["yParity"] == v - 27
    assert out["address"] == ADDR0


@pytest.mark.parametrize("key,digest,expected", VECTORS)
def test_sign_is_low_s_with_legacy_v(key_file, key, digest, expected):
    out = _sign(key_file, digest, key)
    _, s, v = _split(out["signature"])
    assert s <= SECP_N // 2 and v in (27, 28)


def test_sign_eip2098_packs_parity_into_s(key_file):
    out = _sign(key_file, VECTORS[1][1])  # a v=28 vector, so the top bit is set
    compact = bytes.fromhex(out["eip2098"][2:])
    assert len(compact) == 64
    assert compact[:32].hex() == out["r"][2:]
    vs = int.from_bytes(compact[32:], "big")
    assert vs >> 255 == out["yParity"] == 1
    assert vs & ((1 << 255) - 1) == int(out["s"], 16)


# --- sign: the key stays out of the conversation --------------------------------
def test_key_not_echoed(key_file):
    payload = json.dumps(_sign(key_file)).lower()
    assert KEY0[2:] not in payload


def test_no_inline_key_argument():
    with pytest.raises(TypeError):
        eth_sign("sign", message_hash=HELLO_KECCAK, private_key=KEY0)


def test_sign_needs_key_file():
    with pytest.raises(ValueError, match="private_key_file"):
        eth_sign("sign", message_hash=HELLO_KECCAK)


def test_malformed_key_file_error_does_not_quote_contents(key_file):
    path = key_file(KEY0[:-1] + "z")  # one typo'd digit: still nearly the key
    with pytest.raises(ValueError) as exc:
        eth_sign("sign", message_hash=HELLO_KECCAK, private_key_file=path)
    assert "32-byte key" in str(exc.value)
    assert KEY0[2:20] not in str(exc.value).lower()


def test_missing_key_file(tmp_path):
    with pytest.raises(ValueError, match="not found"):
        eth_sign(
            "sign", message_hash=HELLO_KECCAK, private_key_file=str(tmp_path / "x")
        )


# --- message_hash validation ----------------------------------------------------
@pytest.mark.parametrize("action", ["sign", "verify", "recover"])
def test_message_hash_required(key_file, action):
    with pytest.raises(ValueError, match="message_hash"):
        eth_sign(
            action,
            private_key_file=key_file(),
            signature=VECTORS[0][2],
            address=ADDR0,
        )


@pytest.mark.parametrize("bad", ["0x00", "00" * 31, "00" * 33])
def test_message_hash_must_be_32_bytes(key_file, bad):
    with pytest.raises(ValueError, match="32 bytes"):
        eth_sign("sign", message_hash=bad, private_key_file=key_file())


# --- recover --------------------------------------------------------------------
@pytest.mark.parametrize("key,digest,expected", VECTORS)
def test_recover_vectors(key, digest, expected):
    out = eth_sign("recover", message_hash=digest, signature=expected)
    assert out["address"] == (ADDR0 if key == KEY0 else ADDR1)
    assert out["low_s"] is True


def test_recover_accepts_every_form(key_file):
    out = _sign(key_file)
    forms = [
        out["signature"],
        out["eip2098"],
        {"r": out["r"], "s": out["s"], "v": out["v"]},
        {"r": out["r"], "s": out["s"], "yParity": out["yParity"]},
        {"r": int(out["r"], 16), "s": str(int(out["s"], 16)), "v": out["yParity"]},
    ]
    for sig in forms:
        got = eth_sign("recover", message_hash=HELLO_KECCAK, signature=sig)
        assert got["address"] == ADDR0


def test_recover_accepts_v_0_and_1():
    r, s, v = _split(VECTORS[0][2])
    out = eth_sign("recover", message_hash=HELLO_KECCAK, signature=_sig65(r, s, v - 27))
    assert out["address"] == ADDR0


def test_recover_high_s_twin_gives_same_signer():
    # (r, n - s) with the parity flipped is the malleable twin: same signer.
    r, s, v = _split(VECTORS[0][2])
    twin = _sig65(r, SECP_N - s, 55 - v)  # 27 <-> 28
    out = eth_sign("recover", message_hash=HELLO_KECCAK, signature=twin)
    assert out["address"] == ADDR0 and out["low_s"] is False


def test_eip155_v_rejected():
    r, s, _ = _split(VECTORS[0][2])
    with pytest.raises(ValueError, match="EIP-155"):
        eth_sign("recover", message_hash=HELLO_KECCAK, signature=_sig65(r, s, 37))


@pytest.mark.parametrize("length", [63, 66, 0])
def test_signature_wrong_length(length):
    with pytest.raises(ValueError, match="65 bytes"):
        eth_sign("recover", message_hash=HELLO_KECCAK, signature="0x" + "11" * length)


@pytest.mark.parametrize("r,s", [(0, 1), (SECP_N, 1), (1, 0), (1, SECP_N)])
def test_signature_r_s_out_of_range(r, s):
    with pytest.raises(ValueError, match="out of range"):
        eth_sign("recover", message_hash=HELLO_KECCAK, signature=_sig65(r, s, 27))


def test_signature_object_needs_v_or_yparity():
    with pytest.raises(ValueError, match="`v` or `yParity`"):
        eth_sign("recover", message_hash=HELLO_KECCAK, signature={"r": 1, "s": 1})


def test_signature_object_bad_yparity():
    with pytest.raises(ValueError, match="yParity"):
        eth_sign(
            "recover",
            message_hash=HELLO_KECCAK,
            signature={"r": 1, "s": 1, "yParity": 27},
        )


def test_recover_needs_signature():
    with pytest.raises(ValueError, match="needs `signature`"):
        eth_sign("recover", message_hash=HELLO_KECCAK)


# --- verify ---------------------------------------------------------------------
def test_verify_valid_any_casing():
    for addr in (ADDR0, ADDR0.lower(), ADDR0[2:].upper()):
        out = eth_sign(
            "verify", message_hash=HELLO_KECCAK, signature=VECTORS[0][2], address=addr
        )
        assert out == {
            "action": "verify",
            "valid": True,
            "recovered": ADDR0,
            "low_s": True,
        }


def test_verify_wrong_signer():
    out = eth_sign(
        "verify", message_hash=HELLO_KECCAK, signature=VECTORS[0][2], address=ADDR1
    )
    assert out["valid"] is False and out["recovered"] == ADDR0


def test_verify_tampered_digest():
    out = eth_sign(
        "verify",
        message_hash="0x" + "00" * 31 + "02",
        signature=VECTORS[0][2],
        address=ADDR0,
    )
    assert out["valid"] is False and out["recovered"] != ADDR0


def test_verify_unrecoverable_signature_is_soft():
    # An r with no curve point (x^3 + 7 is not a square mod p) recovers no key.
    r = next(
        x
        for x in range(1, 100)
        if pow((x**3 + 7) % SECP_P, (SECP_P - 1) // 2, SECP_P) != 1
    )
    out = eth_sign(
        "verify",
        message_hash=HELLO_KECCAK,
        signature=_sig65(r, 1, 27),
        address=ADDR0,
    )
    assert out["valid"] is False and out["recovered"] is None and out["reason"]


def test_verify_needs_address():
    with pytest.raises(ValueError, match="needs `address`"):
        eth_sign("verify", message_hash=HELLO_KECCAK, signature=VECTORS[0][2])


# --- convert --------------------------------------------------------------------
def test_convert_round_trips(key_file):
    out = _sign(key_file, VECTORS[1][1])
    for source in (out["signature"], out["eip2098"]):
        assert (
            eth_sign("convert", signature=source, signature_format="packed65")["result"]
            == out["signature"]
        )
        assert (
            eth_sign("convert", signature=source, signature_format="eip2098")["result"]
            == out["eip2098"]
        )
        assert eth_sign("convert", signature=source, signature_format="rsv")[
            "result"
        ] == {"r": out["r"], "s": out["s"], "v": out["v"], "yParity": out["yParity"]}


def test_convert_default_is_packed65():
    r, s, v = _split(VECTORS[0][2])
    out = eth_sign("convert", signature=_sig65(r, s, v - 27))
    assert out["format"] == "packed65" and out["result"] == VECTORS[0][2]


def test_convert_high_s_has_no_eip2098_form():
    r, s, v = _split(VECTORS[0][2])
    twin = _sig65(r, SECP_N - s, 55 - v)
    assert eth_sign("convert", signature=twin)["low_s"] is False
    with pytest.raises(ValueError, match="high-s"):
        eth_sign("convert", signature=twin, signature_format="eip2098")


# --- app registration -----------------------------------------------------------
def test_registered():
    names = {t.name for t in asyncio.run(mcp.list_tools())}
    assert "eth_sign" in names


def test_schema_has_no_inline_key():
    tool = next(t for t in asyncio.run(mcp.list_tools()) if t.name == "eth_sign")
    props = set(tool.input_schema["properties"])
    assert "private_key_file" in props and "private_key" not in props


def test_sign_through_app(key_file):
    path = key_file()

    async def go():
        return await mcp.call_tool(
            "eth_sign",
            {"action": "sign", "message_hash": HELLO_KECCAK, "private_key_file": path},
        )

    text = asyncio.run(go()).content[0].text
    assert json.loads(text)["signature"] == VECTORS[0][2]
    assert KEY0[2:] not in text
