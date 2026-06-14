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

"""TODO 18.6 / §2.9.6 — time_convert (textual time formats & time zones).

A stdlib (always-on) tool — datetime + zoneinfo + email.utils, no extra.
The IANA tz db is read from the OS, which is present on the CI/dev Linux box."""

import asyncio
import json
from datetime import datetime, timezone

import pytest

from mcp_bytesmith.core import time_convert
from mcp_bytesmith.server import mcp

# Canonical reference instant: 2024-06-14T12:00:00Z. Derive the epoch rather than
# hardcoding it so the tests stay correct regardless of the host's local zone.
REF_UTC = datetime(2024, 6, 14, 12, 0, 0, tzinfo=timezone.utc)
EPOCH = int(REF_UTC.timestamp())  # 1718366400


def _r(*args, **kwargs):
    return time_convert(*args, **kwargs)["result"]


# --- unix epoch <-> ISO 8601 ---------------------------------------------------
def test_unix_to_iso_utc():
    out = time_convert(str(EPOCH), "iso8601", from_format="unix")
    assert out["result"] == "2024-06-14T12:00:00+00:00"
    assert out["zone"] == "UTC"
    assert out["from_format"] == "unix"
    assert out["unix"] == EPOCH


def test_unix_to_iso_in_iana_zone():
    out = time_convert(
        str(EPOCH), "iso8601", from_format="unix", to_zone="Europe/Budapest"
    )
    assert out["result"] == "2024-06-14T14:00:00+02:00"  # CEST, +02:00 in June
    assert out["zone"] == "Europe/Budapest"


def test_iso_with_offset_to_unix():
    assert _r("2024-06-14T14:00:00+02:00", "unix", from_format="iso8601") == str(EPOCH)


def test_iso_zulu_suffix_to_unix():
    assert _r("2024-06-14T12:00:00Z", "unix", from_format="iso8601") == str(EPOCH)


def test_iso_lowercase_z_suffix():
    assert _r("2024-06-14T12:00:00z", "unix", from_format="iso8601") == str(EPOCH)


def test_iso_with_microseconds_round_trip():
    out = time_convert(str(EPOCH * 1000 + 123), "iso8601", from_format="unix_ms")
    assert out["result"] == "2024-06-14T12:00:00.123000+00:00"


# --- naive input + from_zone ---------------------------------------------------
def test_naive_iso_default_from_zone_is_utc():
    assert _r("2024-06-14T12:00:00", "unix", from_format="iso8601") == str(EPOCH)


def test_naive_iso_with_from_zone():
    # 14:00 in Budapest (+02:00) is the same instant as 12:00 UTC.
    out = _r(
        "2024-06-14T14:00:00",
        "unix",
        from_format="iso8601",
        from_zone="Europe/Budapest",
    )
    assert out == str(EPOCH)


def test_naive_iso_space_separator():
    assert _r("2024-06-14 12:00:00", "unix", from_format="iso8601") == str(EPOCH)


def test_aware_input_ignores_from_zone():
    # The +02:00 offset in the string wins; from_zone must not shift it.
    out = _r(
        "2024-06-14T14:00:00+02:00",
        "unix",
        from_format="iso8601",
        from_zone="America/New_York",
    )
    assert out == str(EPOCH)


# --- RFC 2822 / HTTP-date ------------------------------------------------------
def test_rfc2822_to_http():
    out = time_convert("Fri, 14 Jun 2024 12:00:00 +0000", "http", from_format="rfc2822")
    assert out["result"] == "Fri, 14 Jun 2024 12:00:00 GMT"


def test_rfc2822_with_offset_to_http_is_gmt():
    # 14:00 +0200 normalizes to 12:00 GMT.
    assert _r("Fri, 14 Jun 2024 14:00:00 +0200", "http", from_format="rfc2822") == (
        "Fri, 14 Jun 2024 12:00:00 GMT"
    )


def test_http_to_rfc2822():
    out = time_convert("Fri, 14 Jun 2024 12:00:00 GMT", "rfc2822", from_format="http")
    assert out["result"] == "Fri, 14 Jun 2024 12:00:00 +0000"


def test_rfc2822_to_unix():
    assert _r("Fri, 14 Jun 2024 12:00:00 +0000", "unix", from_format="rfc2822") == str(
        EPOCH
    )


def test_unix_to_rfc2822():
    assert (
        _r(str(EPOCH), "rfc2822", from_format="unix")
        == "Fri, 14 Jun 2024 12:00:00 +0000"
    )


# --- auto detection ------------------------------------------------------------
def test_auto_detects_unix():
    out = time_convert(str(EPOCH), "iso8601")
    assert out["from_format"] == "unix"
    assert out["result"] == "2024-06-14T12:00:00+00:00"


def test_auto_detects_iso():
    out = time_convert("2024-06-14T12:00:00Z", "unix")
    assert out["from_format"] == "iso8601"
    assert out["result"] == str(EPOCH)


def test_auto_detects_rfc2822():
    out = time_convert("Fri, 14 Jun 2024 12:00:00 +0000", "unix")
    assert out["from_format"] == "rfc2822"
    assert out["result"] == str(EPOCH)


def test_auto_detects_http_as_rfc2822():
    # HTTP-date parses through the same email machinery; auto labels it rfc2822.
    out = time_convert("Fri, 14 Jun 2024 12:00:00 GMT", "unix")
    assert out["from_format"] == "rfc2822"
    assert out["result"] == str(EPOCH)


# --- strftime (both directions) ------------------------------------------------
def test_strftime_parse():
    out = time_convert(
        "14/06/2024 12:00",
        "unix",
        from_format="strftime",
        format_pattern="%d/%m/%Y %H:%M",
    )
    assert out["result"] == str(EPOCH)


def test_strftime_render():
    out = time_convert(
        str(EPOCH), "strftime", from_format="unix", format_pattern="%Y-%m-%d %H:%M %Z"
    )
    assert out["result"] == "2024-06-14 12:00 UTC"


def test_strftime_render_in_offset_zone():
    out = time_convert(
        str(EPOCH),
        "strftime",
        from_format="unix",
        format_pattern="%Y-%m-%d %H:%M %Z",
        to_zone="+05:30",
    )
    assert out["result"] == "2024-06-14 17:30 UTC+05:30"
    assert out["zone"] == "UTC+05:30"


def test_strftime_round_trip_through_pattern():
    pattern = "%Y%m%dT%H%M%S"
    rendered = time_convert(
        str(EPOCH), "strftime", from_format="unix", format_pattern=pattern
    )
    back = time_convert(
        rendered["result"], "unix", from_format="strftime", format_pattern=pattern
    )
    assert back["result"] == str(EPOCH)


# --- unix scale conversions ----------------------------------------------------
def test_unix_to_unix_ms():
    assert _r(str(EPOCH), "unix_ms", from_format="unix") == str(EPOCH * 1000)


def test_unix_ms_to_unix_drops_fraction():
    assert _r(str(EPOCH * 1000 + 123), "unix", from_format="unix_ms") == str(EPOCH)


def test_unix_ms_round_trip():
    assert _r(str(EPOCH * 1000 + 123), "unix_ms", from_format="unix_ms") == str(
        EPOCH * 1000 + 123
    )


def test_unix_us_to_unix():
    assert _r(str(EPOCH * 1_000_000), "unix", from_format="unix_us") == str(EPOCH)


def test_unix_ns_to_unix():
    assert _r(str(EPOCH * 1_000_000_000), "unix", from_format="unix_ns") == str(EPOCH)


def test_unix_float_seconds():
    assert _r(f"{EPOCH}.0", "unix", from_format="unix") == str(EPOCH)


# --- time zones ----------------------------------------------------------------
def test_dst_winter_offset():
    # January in Budapest is CET (+01:00).
    out = time_convert("2024-01-14T12:00:00", "iso8601", to_zone="Europe/Budapest")
    assert out["result"] == "2024-01-14T13:00:00+01:00"


def test_dst_summer_offset():
    # July in Budapest is CEST (+02:00).
    out = time_convert("2024-07-14T12:00:00", "iso8601", to_zone="Europe/Budapest")
    assert out["result"] == "2024-07-14T14:00:00+02:00"


def test_negative_offset_iana_zone():
    # 12:00 UTC in New York (EDT, -04:00) is 08:00.
    out = time_convert(
        str(EPOCH), "iso8601", from_format="unix", to_zone="America/New_York"
    )
    assert out["result"] == "2024-06-14T08:00:00-04:00"


def test_fixed_offset_without_colon():
    out = time_convert(
        str(EPOCH),
        "strftime",
        from_format="unix",
        format_pattern="%H:%M",
        to_zone="+0530",
    )
    assert out["result"] == "17:30"
    assert out["zone"] == "UTC+05:30"


def test_negative_fixed_offset():
    out = time_convert(
        str(EPOCH),
        "strftime",
        from_format="unix",
        format_pattern="%H:%M",
        to_zone="-05:00",
    )
    assert out["result"] == "07:00"
    assert out["zone"] == "UTC-05:00"


def test_utc_aliases():
    for alias in ("UTC", "GMT", "Z", "utc", "+00:00"):
        out = time_convert(str(EPOCH), "iso8601", from_format="unix", to_zone=alias)
        assert out["zone"] == "UTC"
        assert out["result"] == "2024-06-14T12:00:00+00:00"


def test_http_output_ignores_to_zone():
    # HTTP-date is always GMT even when a non-UTC to_zone is requested.
    out = time_convert(
        str(EPOCH), "http", from_format="unix", to_zone="Europe/Budapest"
    )
    assert out["result"] == "Fri, 14 Jun 2024 12:00:00 GMT"
    assert out["zone"] == "UTC"


# --- full payload --------------------------------------------------------------
def test_full_payload():
    assert time_convert(
        str(EPOCH), "iso8601", from_format="unix", to_zone="Europe/Budapest"
    ) == {
        "result": "2024-06-14T14:00:00+02:00",
        "from_format": "unix",
        "to_format": "iso8601",
        "zone": "Europe/Budapest",
        "unix": EPOCH,
    }


def test_unix_anchor_present_on_every_conversion():
    out = time_convert("Fri, 14 Jun 2024 12:00:00 GMT", "iso8601")
    assert out["unix"] == EPOCH


# --- error paths ---------------------------------------------------------------
def test_strftime_to_without_pattern_raises():
    with pytest.raises(ValueError):
        time_convert(str(EPOCH), "strftime", from_format="unix")


def test_strftime_from_without_pattern_raises():
    with pytest.raises(ValueError):
        time_convert("whatever", "unix", from_format="strftime")


def test_invalid_iso_raises():
    with pytest.raises(ValueError):
        time_convert("not-a-date", "unix", from_format="iso8601")


def test_invalid_unix_raises():
    with pytest.raises(ValueError):
        time_convert("abc", "iso8601", from_format="unix")


def test_invalid_rfc2822_raises():
    with pytest.raises(ValueError):
        time_convert("definitely not a date", "unix", from_format="rfc2822")


def test_unknown_from_format_raises():
    with pytest.raises(ValueError):
        time_convert("x", "unix", from_format="bogus")


def test_unknown_to_format_raises():
    with pytest.raises(ValueError):
        time_convert(str(EPOCH), "bogus", from_format="unix")


def test_unknown_to_zone_raises():
    with pytest.raises(ValueError):
        time_convert(str(EPOCH), "iso8601", from_format="unix", to_zone="Mars/Phobos")


def test_unknown_from_zone_on_naive_raises():
    with pytest.raises(ValueError):
        time_convert(
            "2024-06-14T12:00:00",
            "unix",
            from_format="iso8601",
            from_zone="Mars/Phobos",
        )


def test_auto_cannot_detect_raises():
    with pytest.raises(ValueError):
        time_convert("definitely not a date", "unix")


def test_strftime_pattern_mismatch_raises():
    with pytest.raises(ValueError):
        time_convert(
            "2024", "unix", from_format="strftime", format_pattern="%d/%m/%Y %H:%M"
        )


# --- app registration / schema -------------------------------------------------
def test_registered_with_enum_schema():
    tool = next(t for t in asyncio.run(mcp.list_tools()) if t.name == "time_convert")
    props = tool.inputSchema["properties"]
    assert "auto" in props["from_format"]["enum"]
    assert "auto" not in props["to_format"]["enum"]
    assert "iso8601" in props["to_format"]["enum"]
    assert "unix_ns" in props["to_format"]["enum"]


def test_callable_through_app():
    async def go():
        return await mcp.call_tool(
            "time_convert",
            {"value": str(EPOCH), "to_format": "iso8601", "from_format": "unix"},
        )

    result = asyncio.run(go())
    contents = result[0] if isinstance(result, tuple) else result
    payload = json.loads(contents[0].text)
    assert payload["result"] == "2024-06-14T12:00:00+00:00"
