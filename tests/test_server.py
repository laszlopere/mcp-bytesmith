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

"""§7.3 — prove the `info` tool is wired into the MCPServer app, not merely
importable. Introspect and invoke it through the MCP layer (end-to-end)."""

import asyncio
import json
import subprocess
import sys

from mcp_bytesmith.server import mcp


def _call_info_via_app() -> dict:
    """Invoke `info` through the app and return its parsed JSON payload."""

    async def go():
        return await mcp.call_tool("info", {})

    result = asyncio.run(go())
    # call_tool returns a CallToolResult; the payload is JSON text.
    contents = result.content
    return json.loads(contents[0].text)


def test_info_tool_is_registered():
    # §7.3.1 — the always-on `info` tool is exposed (gated toolsets add more).
    names = {t.name for t in asyncio.run(mcp.list_tools())}
    assert "info" in names


def test_tool_has_description_and_input_schema():
    # §7.3.2 — non-empty description (docstring) + generated input schema.
    tool = next(t for t in asyncio.run(mcp.list_tools()) if t.name == "info")
    assert tool.description and tool.description.strip()
    assert isinstance(tool.input_schema, dict)
    assert tool.input_schema.get("type") == "object"


def test_invoke_through_app_matches_payload():
    # §7.3.3 — invoke through the MCP layer; payload matches §7.2.
    from importlib.metadata import version

    from mcp_bytesmith import eth, serialize

    expected = sorted(
        (["ethereum"] if eth.available() else [])
        + (["serialize"] if serialize.available() else [])
    )
    payload = _call_info_via_app()
    assert payload["status"] == "available"
    assert payload["name"] == "mcp-bytesmith"
    assert payload["version"] == version("mcp-bytesmith")
    assert payload["python"]
    assert payload["mcp_sdk"]
    # toolsets reflects which optional extras are live (plan §2.0.7).
    assert payload["toolsets"] == expected


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


def test_tool_value_error_keeps_its_message():
    # A tool's ValueError is deliberate feedback for the model, so its text must
    # survive; MCPServer alone would reduce it to "Error executing tool <name>".
    import pytest
    from mcp.server.mcpserver.exceptions import ToolError, UnexpectedToolError

    async def go():
        return await mcp.call_tool(
            "num_convert", {"value": "zz", "from_base": "dec", "to_base": "hex"}
        )

    with pytest.raises(ToolError) as info:
        asyncio.run(go())
    assert not isinstance(info.value, UnexpectedToolError)
    assert (
        str(info.value) == "Error executing tool num_convert: invalid dec integer: 'zz'"
    )


# Top-level modules of every optional extra (`ethereum`, `crypto`, `encoding`,
# `serialize`). idna is left out: it is also a dependency of the mcp SDK itself.
_EXTRA_MODULES = (
    "Crypto",
    "xxhash",
    "base58",
    "base45",
    "cbor2",
    "msgpack",
    "asn1crypto",
    "bcrypt",
    "argon2",
)


def test_server_imports_without_optional_extras():
    # A base install (no extras) must still start: the extras only gate
    # toolsets, so nothing may need them at import time.
    code = (
        "import sys\n"
        f"for m in {_EXTRA_MODULES!r}:\n"
        "    sys.modules[m] = None\n"
        "import mcp_bytesmith.server as s\n"
        "print(s._TOOLSETS)\n"
    )
    proc = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, timeout=60
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == "[]"
