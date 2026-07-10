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

"""TODO 11.4 / plan §2.2.4 / §1.7.3 — otpauth_uri (Key URI Format).

build/parse are checked against the canonical Google Authenticator examples,
round-tripped, and exercised on the totp/hotp validation rules and the
malformed-input rejections."""

import asyncio
import json

import pytest

from mcp_bytesmith.core import otpauth_uri as OU  # noqa: E402
from mcp_bytesmith.server import mcp  # noqa: E402


def _build(**kw):
    return OU("build", **kw)["uri"]


def _parse(uri, **kw):
    return OU("parse", uri=uri, **kw)


# --- build ---------------------------------------------------------------------
def test_build_totp_canonical():
    uri = _build(label="alice@example.com", secret="JBSWY3DPEHPK3PXP", issuer="Example")
    assert uri == (
        "otpauth://totp/Example:alice@example.com"
        "?secret=JBSWY3DPEHPK3PXP&issuer=Example"
    )


def test_build_minimal_no_issuer():
    uri = _build(label="alice@example.com", secret="JBSWY3DPEHPK3PXP")
    assert uri == "otpauth://totp/alice@example.com?secret=JBSWY3DPEHPK3PXP"


def test_build_issuer_prefix_not_duplicated():
    # A label that already carries an 'issuer:' prefix is left untouched.
    uri = _build(label="ACME:bob", secret="JBSWY3DPEHPK3PXP", issuer="ACME")
    assert uri.startswith("otpauth://totp/ACME:bob?")


def test_build_percent_encodes_issuer_and_label():
    uri = _build(
        label="john.doe@email.com", secret="JBSWY3DPEHPK3PXP", issuer="ACME Co"
    )
    assert uri == (
        "otpauth://totp/ACME%20Co:john.doe@email.com"
        "?secret=JBSWY3DPEHPK3PXP&issuer=ACME%20Co"
    )


def test_build_all_totp_params():
    uri = _build(
        label="a", secret="JBSWY3DPEHPK3PXP", digits=8, period=60, algorithm="sha256"
    )
    assert uri == (
        "otpauth://totp/a?secret=JBSWY3DPEHPK3PXP&algorithm=SHA256&digits=8&period=60"
    )


def test_build_hotp_with_counter():
    uri = _build(type="hotp", label="a", secret="JBSWY3DPEHPK3PXP", counter=5)
    assert uri == "otpauth://hotp/a?secret=JBSWY3DPEHPK3PXP&counter=5"


def test_build_normalizes_secret_spaces_and_padding():
    uri = _build(label="a", secret="jbsw y3dp ehpk 3pxp===")
    assert uri == "otpauth://totp/a?secret=JBSWY3DPEHPK3PXP"


def test_build_requires_secret():
    with pytest.raises(ValueError):
        OU("build", label="a")


def test_build_hotp_requires_counter():
    with pytest.raises(ValueError):
        OU("build", type="hotp", label="a", secret="JBSWY3DPEHPK3PXP")


def test_build_totp_rejects_counter():
    with pytest.raises(ValueError):
        OU("build", type="totp", label="a", secret="JBSWY3DPEHPK3PXP", counter=1)


def test_build_hotp_rejects_period():
    with pytest.raises(ValueError):
        OU(
            "build",
            type="hotp",
            label="a",
            secret="JBSWY3DPEHPK3PXP",
            counter=1,
            period=30,
        )


def test_build_rejects_non_base32_secret():
    with pytest.raises(ValueError):
        OU("build", label="a", secret="not-base32!")  # '-', '!', lower '1'/'0' etc.


def test_build_rejects_unknown_algorithm():
    with pytest.raises(ValueError):
        OU("build", label="a", secret="JBSWY3DPEHPK3PXP", algorithm="md5")


# --- parse ---------------------------------------------------------------------
def test_parse_canonical():
    out = _parse(
        "otpauth://totp/Example:alice@example.com"
        "?secret=JBSWY3DPEHPK3PXP&issuer=Example"
    )
    assert out["type"] == "totp"
    assert out["label"] == "Example:alice@example.com"
    assert out["issuer"] == "Example"
    assert out["account"] == "alice@example.com"
    assert out["secret"] == "JBSWY3DPEHPK3PXP"
    assert out["algorithm"] == "SHA1"  # RFC default
    assert out["digits"] == 6  # RFC default
    assert out["period"] == 30  # RFC default


def test_parse_percent_decodes_label():
    out = _parse("otpauth://totp/ACME%20Co:john.doe@email.com?secret=AAAA")
    assert out["label"] == "ACME Co:john.doe@email.com"
    assert out["issuer"] == "ACME Co"  # from the label prefix
    assert out["account"] == "john.doe@email.com"


def test_parse_query_issuer_overrides_label():
    out = _parse("otpauth://totp/Wrong:alice?secret=AAAA&issuer=Right")
    assert out["issuer"] == "Right"


def test_parse_hotp_counter():
    out = _parse("otpauth://hotp/a?secret=AAAA&counter=42")
    assert out["type"] == "hotp"
    assert out["counter"] == 42
    assert "period" not in out


def test_parse_custom_params():
    out = _parse("otpauth://totp/a?secret=AAAA&algorithm=SHA512&digits=8&period=60")
    assert out["algorithm"] == "SHA512"
    assert out["digits"] == 8
    assert out["period"] == 60


def test_parse_no_issuer():
    out = _parse("otpauth://totp/alice?secret=AAAA")
    assert out["issuer"] is None
    assert out["account"] == "alice"


def test_parse_rejects_non_otpauth():
    with pytest.raises(ValueError):
        OU("parse", uri="https://example.com")


def test_parse_rejects_unknown_type():
    with pytest.raises(ValueError):
        OU("parse", uri="otpauth://xotp/a?secret=AAAA")


def test_parse_requires_secret():
    with pytest.raises(ValueError):
        OU("parse", uri="otpauth://totp/a")


def test_parse_requires_uri():
    with pytest.raises(ValueError):
        OU("parse")


# --- round-trips ---------------------------------------------------------------
def test_round_trip_totp():
    uri = _build(
        label="alice@example.com",
        secret="JBSWY3DPEHPK3PXP",
        issuer="Example",
        digits=8,
        period=60,
        algorithm="SHA256",
    )
    out = _parse(uri)
    assert out["issuer"] == "Example"
    assert out["account"] == "alice@example.com"
    assert out["secret"] == "JBSWY3DPEHPK3PXP"
    assert out["digits"] == 8
    assert out["period"] == 60
    assert out["algorithm"] == "SHA256"


def test_round_trip_hotp():
    uri = _build(type="hotp", label="acct", secret="JBSWY3DPEHPK3PXP", counter=7)
    out = _parse(uri)
    assert out["type"] == "hotp"
    assert out["counter"] == 7


# --- errors / app --------------------------------------------------------------
def test_unknown_action_raises():
    with pytest.raises(ValueError):
        OU("frobnicate", secret="JBSWY3DPEHPK3PXP")


def test_registered_with_action_enum():
    tool = next(t for t in asyncio.run(mcp.list_tools()) if t.name == "otpauth_uri")
    actions = tool.inputSchema["properties"]["action"]["enum"]
    assert set(actions) == {"build", "parse"}


def test_callable_through_app():
    async def go():
        return await mcp.call_tool(
            "otpauth_uri",
            {"action": "parse", "uri": "otpauth://totp/a?secret=JBSWY3DPEHPK3PXP"},
        )

    result = asyncio.run(go())
    contents = result[0] if isinstance(result, tuple) else result
    payload = json.loads(contents[0].text)
    assert payload["secret"] == "JBSWY3DPEHPK3PXP"
