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

"""mcp-bytesmith — pure-Python MCP server for encoding/hashing/crypto-primitives."""

from importlib.metadata import PackageNotFoundError, version

try:  # TODO 4.3 — version from installed package metadata
    __version__ = version("mcp-bytesmith")
except PackageNotFoundError:  # editable / unbuilt checkout: metadata absent
    __version__ = "0.0.0+unknown"

__all__ = ["__version__"]
