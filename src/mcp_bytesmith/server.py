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
from importlib.metadata import PackageNotFoundError, version

from mcp.server.fastmcp import FastMCP

from mcp_bytesmith import __version__, core, eth

# TODO 4.1 — the singleton app. Every tool registers here.
mcp = FastMCP("mcp-bytesmith")

# Always-on stdlib tools (gate: stdlib) — registered unconditionally.
core.register(mcp)

# --- opt-in toolset gating (TODO 4.5 / plan §2.0.7) -----------------------------
# Each optional toolset registers only when its extra's deps are importable.
# info() reports the live ones so a client sees what is actually callable.
_TOOLSETS: list[str] = []

if eth.available():
    eth.register(mcp)
    _TOOLSETS.append("ethereum")
# -------------------------------------------------------------------------------

# Tools register below.


@mcp.tool()
def info() -> dict:
    """Report mcp-bytesmith availability, version, and enabled toolsets."""
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
