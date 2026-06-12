# mcp-bytesmith

A pure-Python [Model Context Protocol](https://modelcontextprotocol.io) server,
built on the official MCP SDK (FastMCP), exposing byte-wrangling utilities
(encoding, hashing, IDs, and more — coming later).

Distribution name: `mcp-bytesmith` · import package: `mcp_bytesmith`.

## Status

Bootstrapping the skeleton — see [`TODO`](./TODO). The first milestone is a
stdio MCP server exposing exactly one tool, `info`, that reports availability
and version information.

## Development

```sh
uv sync                 # create venv + install (incl. dev extras)
uv run mcp-bytesmith    # start the server over stdio
uv run pytest           # run the test suite
```

## License

GPLv3 — see [`LICENSE`](./LICENSE).

The bundled passphrase wordlist
([`src/mcp_bytesmith/wordlists/eff_large.txt`](./src/mcp_bytesmith/wordlists/eff_large.txt),
used by the `random` tool's `passphrase` kind) is the EFF "large" wordlist by the
[Electronic Frontier Foundation](https://www.eff.org/dice), licensed
[CC BY 3.0 US](https://creativecommons.org/licenses/by/3.0/us/).
