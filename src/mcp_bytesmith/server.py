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

"""FastMCP application singleton — all tools register against this `mcp` app.

Transport is stdio (FastMCP default), which is what Claude Code / Desktop launch
(TODO 4.4). No HTTP/SSE in the skeleton.
"""

import platform
from collections.abc import Sequence as AbcSequence
from importlib.metadata import PackageNotFoundError, version
from typing import Any

from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.exceptions import ToolError
from mcp.types import ContentBlock
from pydantic import ValidationError

from mcp_bytesmith import __version__, core, eth, serialize
from mcp_bytesmith.errors import format_validation_error


class _BytesmithFastMCP(FastMCP):
    """FastMCP that reshapes argument-validation errors for the model.

    FastMCP wraps a failed pydantic argument validation as a ToolError whose
    `__cause__` is the ValidationError. We catch that one case and re-raise with
    a concise, field-naming message (errors.format_validation_error); the SDK
    still returns it as an `isError` result. Tool-body failures (a tool's own
    ValueError, etc.) carry a different cause or none, so they fall through
    unchanged.
    """

    async def call_tool(
        self, name: str, arguments: dict[str, Any]
    ) -> AbcSequence[ContentBlock] | dict[str, Any]:
        try:
            return await super().call_tool(name, arguments)
        except ToolError as exc:
            if isinstance(exc.__cause__, ValidationError):
                raise ToolError(
                    format_validation_error(name, exc.__cause__)
                ) from exc.__cause__
            raise


# TODO 4.1 — the singleton app. Every tool registers here.
mcp = _BytesmithFastMCP(
    "mcp-bytesmith",
    instructions=(
        "Pure-Python, offline toolbox for byte/string encoding & decoding, hashing "
        "& HMAC, number/time conversion, Ethereum/EVM primitives, and schemaless "
        "structured serialization (CBOR/MessagePack/bencode/protobuf). No network "
        "calls; every tool is deterministic and local."
    ),
)

# Always-on stdlib tools (gate: stdlib) — registered unconditionally.
core.register(mcp)

# --- opt-in toolset gating (TODO 4.5 / plan §2.0.7) -----------------------------
# Each optional toolset registers only when its extra's deps are importable.
# info() reports the live ones so a client sees what is actually callable.
_TOOLSETS: list[str] = []

if eth.available():
    eth.register(mcp)
    _TOOLSETS.append("ethereum")

if serialize.available():
    serialize.register(mcp)
    _TOOLSETS.append("serialize")
# -------------------------------------------------------------------------------

# Tools register below.


@mcp.tool()
def info() -> dict:
    """Discovery / health-check entrypoint: report availability and enabled toolsets.

    Returns six keys: `status` ("available"), `name`, `version` (package version),
    `python` (runtime version), `mcp_sdk` (MCP SDK version, or "unknown"), and
    `toolsets` (sorted list of live optional toolsets).
    Example: {"status":"available","name":"mcp-bytesmith","version":"0.1.0",
    "python":"3.12.3","mcp_sdk":"1.2.0","toolsets":["ethereum","serialize"]}
    """
    try:  # CR.7 — metadata may be absent (uninstalled SDK); never crash info()
        mcp_sdk = version("mcp")
    except PackageNotFoundError:
        mcp_sdk = "unknown"
    return {
        "status": "available",
        "name": "mcp-bytesmith",
        "version": __version__,
        "python": platform.python_version(),
        "mcp_sdk": mcp_sdk,
        "toolsets": sorted(_TOOLSETS),  # live optional toolsets (plan §2.0.7)
    }
