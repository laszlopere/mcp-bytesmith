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

"""§7.2 — assert the `info` tool's return payload (called directly)."""

from importlib.metadata import version

from mcp_bytesmith.server import info


def test_info_returns_dict_and_is_available():
    # §7.2.1 — returns a dict; status == "available".
    payload = info()
    assert isinstance(payload, dict)
    assert payload["status"] == "available"


def test_info_name():
    # §7.2.2 — name == "mcp-bytesmith".
    assert info()["name"] == "mcp-bytesmith"


def test_info_version_matches_metadata():
    # §7.2.3 — version is a non-empty string AND matches package metadata.
    payload = info()
    assert isinstance(payload["version"], str)
    assert payload["version"]
    assert payload["version"] == version("mcp-bytesmith")


def test_info_python_and_mcp_sdk_present():
    # §7.2.4 — python and mcp_sdk fields present + non-empty.
    payload = info()
    assert isinstance(payload["python"], str) and payload["python"]
    assert isinstance(payload["mcp_sdk"], str) and payload["mcp_sdk"]


def test_info_toolsets_is_list():
    # §7.2.5 — toolsets is a list reporting live optional extras (plan §2.0.7).
    from mcp_bytesmith import eth, serialize

    expected = sorted(
        (["ethereum"] if eth.available() else [])
        + (["serialize"] if serialize.available() else [])
    )
    payload = info()
    assert isinstance(payload["toolsets"], list)
    assert payload["toolsets"] == expected
