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

"""TODO 12.1 / plan §2.3.1 / §1.5.4 — unicode_normalize.

Covers the canonical NFC/NFD compose/decompose pair, the compatibility-folding
NFKC/NFKD forms, the `changed` flag, idempotence, and the form-validation
rejection."""

import asyncio
import json
import unicodedata

import pytest

from mcp_bytesmith.core import unicode_normalize as UN  # noqa: E402
from mcp_bytesmith.server import mcp  # noqa: E402

# "é" as a single precomposed codepoint (NFC) vs. base "e" + combining acute (NFD).
NFC_E = "é"  # é
NFD_E = "é"  # e + ́


# --- canonical compose / decompose ---------------------------------------------
def test_nfc_composes():
    out = UN(NFD_E, form="NFC")
    assert out == {"form": "NFC", "result": NFC_E, "changed": True}


def test_nfd_decomposes():
    out = UN(NFC_E, form="NFD")
    assert out == {"form": "NFD", "result": NFD_E, "changed": True}


def test_nfc_is_default_form():
    out = UN(NFD_E)
    assert out["form"] == "NFC"
    assert out["result"] == NFC_E


# --- changed flag --------------------------------------------------------------
def test_changed_false_when_already_normalized():
    out = UN(NFC_E, form="NFC")
    assert out["result"] == NFC_E
    assert out["changed"] is False


def test_plain_ascii_never_changes():
    out = UN("hello", form="NFKC")
    assert out == {"form": "NFKC", "result": "hello", "changed": False}


# --- compatibility folding (NFKC/NFKD) -----------------------------------------
def test_nfkc_folds_ligature():
    out = UN("ﬁle", form="NFKC")  # ﬁle -> file
    assert out["result"] == "file"
    assert out["changed"] is True


def test_nfkc_folds_circled_digit():
    out = UN("①", form="NFKC")  # ① -> 1
    assert out["result"] == "1"


def test_nfc_leaves_compatibility_char_untouched():
    out = UN("ﬁ", form="NFC")  # ﬁ stays a ligature under canonical NFC
    assert out["result"] == "ﬁ"
    assert out["changed"] is False


# --- idempotence ---------------------------------------------------------------
def test_normalization_is_idempotent():
    once = UN(NFD_E, form="NFKC")["result"]
    twice = UN(once, form="NFKC")
    assert twice["result"] == once
    assert twice["changed"] is False


def test_empty_string():
    out = UN("", form="NFC")
    assert out == {"form": "NFC", "result": "", "changed": False}


# --- errors / app --------------------------------------------------------------
def test_unknown_form_rejected():
    with pytest.raises(ValueError):
        UN("x", form="NFX")


def test_registered_with_form_enum():
    tool = next(
        t for t in asyncio.run(mcp.list_tools()) if t.name == "unicode_normalize"
    )
    forms = tool.inputSchema["properties"]["form"]["enum"]
    assert set(forms) == {"NFC", "NFD", "NFKC", "NFKD"}


def test_callable_through_app():
    async def go():
        return await mcp.call_tool(
            "unicode_normalize", {"text": NFD_E, "form": "NFC"}
        )

    result = asyncio.run(go())
    contents = result[0] if isinstance(result, tuple) else result
    payload = json.loads(contents[0].text)
    assert payload["result"] == NFC_E
    assert payload["changed"] is True


def test_matches_stdlib_for_all_forms():
    sample = "Ångström ﬁ ① ½ café"
    for form in ("NFC", "NFD", "NFKC", "NFKD"):
        assert UN(sample, form=form)["result"] == unicodedata.normalize(form, sample)
