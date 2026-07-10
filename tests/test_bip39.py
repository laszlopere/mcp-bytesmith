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

"""TODO 13.6 / plan §2.4.6 — bip39 (mnemonic generate / validate / to_seed).

The (entropy, mnemonic, seed) triples are the official BIP-39 English vectors from
trezor/python-mnemonic's vectors.json, whose seeds all use the passphrase "TREZOR".
The 15- and 21-word lengths have no official vector, so they are round-tripped."""

import asyncio
import json

import pytest

pytest.importorskip("Crypto", reason="ethereum extra (pycryptodome) not installed")

from mcp_bytesmith.eth import bip39  # noqa: E402
from mcp_bytesmith.server import mcp  # noqa: E402

TREZOR = "TREZOR"

# (entropy, mnemonic, seed-with-passphrase-"TREZOR") — official BIP-39 vectors.
VECTORS = [
    (
        "00000000000000000000000000000000",
        "abandon abandon abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon about",
        "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d1"
        "8264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
    ),
    (
        "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
        "legal winner thank year wave sausage worth useful legal winner thank yellow",
        "2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6fa457fe12961065"
        "59a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607",
    ),
    (
        "ffffffffffffffffffffffffffffffff",
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
        "ac27495480225222079d7be181583751e86f571027b0497b5b5d11218e0a8a13332572917f0f8e"
        "5a589620c6f15b11c61dee327651a14c34e18231052e48c069",
    ),
    (
        "808080808080808080808080808080808080808080808080",
        "letter advice cage absurd amount doctor acoustic avoid letter advice "
        "cage absurd amount doctor acoustic avoid letter always",
        "107d7c02a5aa6f38c58083ff74f04c607c2d2c0ecc55501dadd72d025b751bc27fe913ffb796f8"
        "41c49b1d33b610cf0e91d3aa239027f5e99fe4ce9e5088cd65",
    ),
    (
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo "
        "zoo zoo zoo zoo zoo zoo vote",
        "dd48c104698c30cfe2b6142103248622fb7bb0ff692eebb00089b32d22484e1613912f0a5b6944"
        "07be899ffd31ed3992c456cdf60f5d4564b8ba3f05a69890ad",
    ),
    (
        "9f6a2878b2520799a44ef18bc7df394e7061a224d2c33cd015b157d746869863",
        "panda eyebrow bullet gorilla call smoke muffin taste mesh discover "
        "soft ostrich alcohol speed nation flash devote level hobby quick inner "
        "drive ghost inside",
        "72be8e052fc4919d2adf28d5306b5474b0069df35b02303de8c1729c9538dbb6fc2d731d5f8321"
        "93cd9fb6aeecbc469594a70e3dd50811b5067f3b88b28c3e8d",
    ),
]

# The all-abandon mnemonic's seed with NO passphrase — the most-quoted BIP-39 seed.
ABANDON = VECTORS[0][1]
ABANDON_SEED_NO_PASSPHRASE = (
    "0x5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1"
    "9a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"
)

# The Hardhat/Anvil default mnemonic and its account-0 address.
ANVIL_MNEMONIC = "test test test test test test test test test test test junk"
ANVIL_ADDRESS = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"


# --- official vectors ----------------------------------------------------------
@pytest.mark.parametrize("entropy,mnemonic,seed", VECTORS)
def test_generate_matches_official_vector(entropy, mnemonic, seed):
    out = bip39("generate", entropy=entropy)
    assert out["mnemonic"] == mnemonic
    assert out["word_count"] == len(mnemonic.split())
    assert out["strength"] == len(entropy) * 4  # hex chars -> bits


@pytest.mark.parametrize("entropy,mnemonic,seed", VECTORS)
def test_to_seed_matches_official_vector(entropy, mnemonic, seed):
    assert bip39("to_seed", mnemonic=mnemonic, passphrase=TREZOR)["seed"] == "0x" + seed


@pytest.mark.parametrize("entropy,mnemonic,seed", VECTORS)
def test_official_vectors_validate(entropy, mnemonic, seed):
    assert bip39("validate", mnemonic=mnemonic) == {
        "action": "validate",
        "valid": True,
        "word_count": len(mnemonic.split()),
    }


def test_seed_without_passphrase():
    assert bip39("to_seed", mnemonic=ABANDON)["seed"] == ABANDON_SEED_NO_PASSPHRASE


# --- every legal length round-trips (15 and 21 have no official vector) ---------
@pytest.mark.parametrize(
    "nbytes,words", [(16, 12), (20, 15), (24, 18), (28, 21), (32, 24)]
)
def test_all_lengths_round_trip(nbytes, words):
    entropy = "".join(f"{i % 256:02x}" for i in range(nbytes))
    out = bip39("generate", entropy=entropy)
    assert out["word_count"] == words
    assert out["strength"] == nbytes * 8
    assert bip39("validate", mnemonic=out["mnemonic"])["valid"]
    assert len(bip39("to_seed", mnemonic=out["mnemonic"])["seed"]) == 2 + 128


# --- generate without entropy ---------------------------------------------------
@pytest.mark.parametrize(
    "strength,words", [(128, 12), (160, 15), (192, 18), (224, 21), (256, 24)]
)
def test_strength_controls_word_count(strength, words):
    out = bip39("generate", strength=strength)
    assert out["word_count"] == words and out["strength"] == strength
    assert bip39("validate", mnemonic=out["mnemonic"])["valid"]


def test_generate_default_is_12_words():
    assert bip39("generate")["word_count"] == 12


def test_generate_is_random_without_entropy():
    assert bip39("generate")["mnemonic"] != bip39("generate")["mnemonic"]


def test_strength_ignored_when_entropy_given():
    # 16 bytes of entropy -> 12 words, whatever `strength` says.
    out = bip39("generate", entropy=VECTORS[0][0], strength=256)
    assert out["mnemonic"] == VECTORS[0][1] and out["strength"] == 128


def test_generate_accepts_0x_entropy():
    assert bip39("generate", entropy="0x" + VECTORS[0][0])["mnemonic"] == VECTORS[0][1]


@pytest.mark.parametrize("bad", ["00" * 15, "00" * 17, "00" * 33, ""])
def test_bad_entropy_length_rejected(bad):
    with pytest.raises(ValueError, match="16, 20, 24, 28, or 32 bytes"):
        bip39("generate", entropy=bad)


# --- validate: a bad mnemonic is a soft result, not an error (§2.0.5) -----------
def test_validate_wrong_word_count():
    out = bip39("validate", mnemonic="abandon abandon about")
    assert out["valid"] is False and out["word_count"] == 3
    assert "expected 12, 15, 18, 21, or 24" in out["reason"]


def test_validate_unknown_word_reports_position_not_the_word():
    words = ABANDON.split()
    words[3] = "notaword"
    out = bip39("validate", mnemonic=" ".join(words))
    assert out["valid"] is False
    assert "position(s) [4]" in out["reason"]
    assert "notaword" not in out["reason"]  # never echo mnemonic content (§2.0.6)


def test_validate_bad_checksum():
    # A wordlist-valid sentence whose final word carries the wrong checksum bits.
    out = bip39("validate", mnemonic="abandon " * 11 + "abandon")
    assert out["valid"] is False and "checksum" in out["reason"]


def test_validate_valid_result_has_no_reason():
    assert "reason" not in bip39("validate", mnemonic=ABANDON)


# --- to_seed rejects what validate merely reports -------------------------------
def test_to_seed_raises_on_bad_checksum():
    with pytest.raises(ValueError, match="invalid mnemonic: checksum"):
        bip39("to_seed", mnemonic="abandon " * 11 + "abandon")


def test_to_seed_raises_on_unknown_word():
    with pytest.raises(ValueError, match="not in the BIP-39 English wordlist"):
        bip39("to_seed", mnemonic=ABANDON.replace("about", "notaword"))


# --- passphrase ------------------------------------------------------------------
def test_passphrase_changes_the_seed():
    plain = bip39("to_seed", mnemonic=ABANDON)["seed"]
    salted = bip39("to_seed", mnemonic=ABANDON, passphrase=TREZOR)["seed"]
    assert plain != salted


def test_empty_passphrase_is_the_default():
    assert (
        bip39("to_seed", mnemonic=ABANDON, passphrase="")["seed"]
        == (bip39("to_seed", mnemonic=ABANDON)["seed"])
    )


def test_any_passphrase_is_accepted():
    # The "25th word": a wrong passphrase opens a different wallet, it never errors.
    assert bip39("to_seed", mnemonic=ABANDON, passphrase="typo")["seed"].startswith(
        "0x"
    )


# --- input forgiveness ------------------------------------------------------------
def test_casing_and_whitespace_are_normalized():
    messy = "  ABANDON\tabandon\n" + "abandon " * 9 + " AbOuT  "
    assert bip39("validate", mnemonic=messy)["valid"]
    assert bip39("to_seed", mnemonic=messy)["seed"] == ABANDON_SEED_NO_PASSPHRASE


# --- feeds bip32_derive -----------------------------------------------------------
def test_seed_drives_bip32_derive_to_the_anvil_account():
    from mcp_bytesmith.eth import bip32_derive

    seed = bip39("to_seed", mnemonic=ANVIL_MNEMONIC)["seed"]
    assert bip32_derive(seed, "m/44'/60'/0'/0/0")["address"] == ANVIL_ADDRESS


def test_generated_mnemonic_derives_a_usable_address():
    from mcp_bytesmith.eth import bip32_derive

    seed = bip39("to_seed", mnemonic=bip39("generate")["mnemonic"])["seed"]
    assert bip32_derive(seed, "m/44'/60'/0'/0/0")["address"].startswith("0x")


# --- secrets policy (§2.0.6) -------------------------------------------------------
def test_mnemonic_and_passphrase_never_echoed():
    payload = json.dumps(bip39("to_seed", mnemonic=ABANDON, passphrase="hunter2"))
    assert "abandon" not in payload and "hunter2" not in payload


def test_generate_does_not_echo_supplied_entropy():
    payload = json.dumps(bip39("generate", entropy=VECTORS[5][0]))
    assert VECTORS[5][0] not in payload


def test_validate_does_not_echo_the_mnemonic():
    payload = json.dumps(bip39("validate", mnemonic=ABANDON))
    assert "abandon" not in payload


# --- error paths --------------------------------------------------------------------
@pytest.mark.parametrize("action", ["validate", "to_seed"])
def test_mnemonic_required(action):
    with pytest.raises(ValueError, match="requires `mnemonic`"):
        bip39(action)


def test_unknown_action_rejected():
    with pytest.raises(ValueError, match="unknown action"):
        bip39("to_entropy", mnemonic=ABANDON)


# --- wordlist integrity ---------------------------------------------------------------
def test_wordlist_is_2048_sorted_unique_words():
    from mcp_bytesmith.eth import _bip39_wordlist

    words = _bip39_wordlist()
    assert len(words) == 2048 == len(set(words))
    assert list(words) == sorted(words)  # BIP-39 mandates a sorted list
    assert words[0] == "abandon" and words[-1] == "zoo"


def test_wordlist_first_four_letters_are_unique():
    from mcp_bytesmith.eth import _bip39_wordlist

    # BIP-39: the first four letters identify a word unambiguously.
    prefixes = [w[:4] for w in _bip39_wordlist()]
    assert len(set(prefixes)) == 2048


# --- app registration -----------------------------------------------------------------
def test_registered():
    names = {t.name for t in asyncio.run(mcp.list_tools())}
    assert "bip39" in names


def test_callable_through_app():
    async def go():
        return await mcp.call_tool("bip39", {"action": "to_seed", "mnemonic": ABANDON})

    result = asyncio.run(go())
    contents = result[0] if isinstance(result, tuple) else result
    payload = json.loads(contents[0].text)
    assert payload["seed"] == ABANDON_SEED_NO_PASSPHRASE
