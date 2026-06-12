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

"""§7.3 — prove the `info` tool is wired into the FastMCP app, not merely
importable. Introspect and invoke it through the MCP layer (end-to-end)."""

import asyncio
import json

from mcp_bytesmith.server import mcp


def _call_info_via_app() -> dict:
    """Invoke `info` through the app and return its parsed JSON payload."""

    async def go():
        return await mcp.call_tool("info", {})

    result = asyncio.run(go())
    # call_tool returns a list of content blocks; the payload is JSON text.
    contents = result[0] if isinstance(result, tuple) else result
    return json.loads(contents[0].text)


def test_info_tool_is_registered():
    # §7.3.1 — the always-on `info` tool is exposed (gated toolsets add more).
    names = {t.name for t in asyncio.run(mcp.list_tools())}
    assert "info" in names


def test_tool_has_description_and_input_schema():
    # §7.3.2 — non-empty description (docstring) + generated input schema.
    tool = next(t for t in asyncio.run(mcp.list_tools()) if t.name == "info")
    assert tool.description and tool.description.strip()
    assert isinstance(tool.inputSchema, dict)
    assert tool.inputSchema.get("type") == "object"


def test_invoke_through_app_matches_payload():
    # §7.3.3 — invoke through the MCP layer; payload matches §7.2.
    from importlib.metadata import version

    from mcp_bytesmith import eth

    payload = _call_info_via_app()
    assert payload["status"] == "available"
    assert payload["name"] == "mcp-bytesmith"
    assert payload["version"] == version("mcp-bytesmith")
    assert payload["python"]
    assert payload["mcp_sdk"]
    # toolsets reflects which optional extras are live (plan §2.0.7).
    assert payload["toolsets"] == (["ethereum"] if eth.available() else [])


def test_info_survives_missing_sdk_metadata(monkeypatch):
    # CR.7 — version("mcp") can raise PackageNotFoundError; info must not crash.
    from importlib.metadata import PackageNotFoundError

    from mcp_bytesmith import server

    def boom(_name):
        raise PackageNotFoundError

    monkeypatch.setattr(server, "version", boom)
    payload = _call_info_via_app()
    assert payload["status"] == "available"
    assert payload["mcp_sdk"] == "unknown"
