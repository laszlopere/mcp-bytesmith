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

"""Console-script / `python -m` entry point.

Importing the app from server.py also registers every tool as a side effect
(TODO 4.2), so the server is fully wired by the time `main()` runs.
"""

import sys

from mcp_bytesmith.server import mcp


def main() -> None:
    """Start the mcp-bytesmith server over stdio."""
    try:  # CR.8 — don't leak raw tracebacks from the transport loop
        mcp.run()
    except KeyboardInterrupt:  # Ctrl-C / client shutdown is a clean exit
        pass
    except Exception as exc:  # noqa: BLE001 — top-level guard; report and fail
        print(f"mcp-bytesmith: fatal error: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
