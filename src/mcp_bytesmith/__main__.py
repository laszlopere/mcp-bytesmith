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

The default stdio read stream is piped through `process_incoming`: a tool call
whose `arguments` arrive as a malformed JSON string is repaired before the SDK's
strict validation rejects it, and one that cannot be parsed at all is answered
with an actionable JSON-RPC parse error.
"""

import sys

import anyio
from mcp.server.stdio import stdio_server
from mcp.shared.message import SessionMessage

from mcp_bytesmith.jsonfix import process_incoming
from mcp_bytesmith.server import mcp


async def _run_stdio_repaired() -> None:
    """Run the server over stdio with the argument-repair interposer."""
    async with stdio_server() as (read_stream, write_stream):
        send, recv = anyio.create_memory_object_stream[SessionMessage | Exception](0)

        async def _pump() -> None:
            async with send:
                async for item in read_stream:
                    if isinstance(item, SessionMessage):
                        outcome = process_incoming(item)
                        if outcome.reply is not None:
                            await write_stream.send(outcome.reply)
                            continue
                        assert outcome.forward is not None
                        item = outcome.forward
                    await send.send(item)

        async with anyio.create_task_group() as tg, recv:
            tg.start_soon(_pump)
            await mcp._mcp_server.run(
                recv,
                write_stream,
                mcp._mcp_server.create_initialization_options(),
            )
            tg.cancel_scope.cancel()


def main() -> None:
    """Start the mcp-bytesmith server over stdio (with argument repair)."""
    try:  # CR.8 — don't leak raw tracebacks from the transport loop
        anyio.run(_run_stdio_repaired)
    except KeyboardInterrupt:  # Ctrl-C / client shutdown is a clean exit
        pass
    except Exception as exc:  # noqa: BLE001 — top-level guard; report and fail
        print(f"mcp-bytesmith: fatal error: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
