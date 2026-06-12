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

"""§7.4 — import / packaging smoke tests."""

import importlib


def test_import_and_version_defined():
    # §7.4.1 — import succeeds; __version__ is defined and non-empty.
    import mcp_bytesmith

    assert isinstance(mcp_bytesmith.__version__, str)
    assert mcp_bytesmith.__version__


def test_version_fallback_does_not_raise(monkeypatch):
    # §7.4.2 — the editable/unbuilt fallback (§4.3) does not raise when the
    # package metadata is absent; __version__ becomes the sentinel.
    import importlib.metadata as md

    import mcp_bytesmith

    def _raise(_name):
        raise md.PackageNotFoundError

    monkeypatch.setattr(md, "version", _raise)
    reloaded = importlib.reload(mcp_bytesmith)
    try:
        assert reloaded.__version__ == "0.0.0+unknown"
    finally:
        # Restore real metadata so later tests see the true version.
        monkeypatch.undo()
        importlib.reload(mcp_bytesmith)
