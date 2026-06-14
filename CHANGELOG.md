# Changelog

All notable changes to **mcp-bytesmith** are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-06-14

Feature release: a new **serialize** toolset plus several new Core and Ethereum
tools, with a major test-coverage and documentation pass.

### Added
- **serialize toolset** (opt-in via the `serialize` extra): `serialize_codec` —
  schemaless structured serialization across CBOR, MessagePack, bencode, and protobuf.
- `byte_order` — host↔network endianness / fixed-width field byte-swapping.
- `time_convert` — textual time-format and time-zone conversion.
- `hash_file` — file checksum with soft-verify.
- `hmac` — keyed-hash MAC compute & verify.
- `codepoints` — per-scalar Unicode inspection.
- `ens_namehash` — EIP-137 namehash & labelhash (Ethereum toolset).

### Changed
- Documented parameters, returns, and examples for every tool (Glama tool-quality),
  and added server-level usage instructions.

### Fixed
- CI `ruff format` check (wrapped multi-line `Field` descriptions).
- Synced `uv.lock` with the `cbor2` / `msgpack` dependencies.
- Bumped release artifact actions to v5 (Node 24) ahead of the Node 20 deprecation.

### Tests
- Strengthened the suite with reference vectors and error-path coverage:
  core.py 99%, eth.py 99%, serialize.py 100%.

## [0.1.0] - 2026-06-12

Maintenance and distribution release. No changes to the tool surface since v0.0.1 —
same Core and Ethereum/EVM toolsets.

### Added
- First release published to PyPI via GitHub Actions Trusted Publishing.
- `glama.json` ownership claim for Glama indexing.

### Fixed
- Applied `ruff format` to satisfy the CI format check.

## [0.0.1] - 2026-06-12

First public release — a pure-Python MCP server (built on the official SDK /
FastMCP) exposing a local toolbox of byte-wrangling utilities. All computation is
done locally, with no network calls.

### Added
- **Core toolset** (standard library only, always on): `encode` / `decode` across
  many schemes (hex, Base64/Base32 family, Base58/Base58check, Base45…), `hash`
  (cryptographic + CRC + fast non-crypto), `num_convert`, `bytes_edit`, `data_uri`,
  `unicode_normalize`, `charset_transcode`, `string_escape` / `string_unescape`, and
  `random` (CSPRNG bytes, tokens, passphrases).
- **Ethereum/EVM toolset** (opt-in via the `ethereum` extra): `eth_hash` (keccak-256,
  EIP-191, EIP-712), `abi_codec`, `rlp_codec`, `eth_selector`, `eth_tx_codec`,
  `eth_storage_slot`, `eth_address_case` (EIP-55).

[0.2.0]: https://github.com/laszlopere/mcp-bytesmith/releases/tag/v0.2.0
[0.1.0]: https://github.com/laszlopere/mcp-bytesmith/releases/tag/v0.1.0
[0.0.1]: https://github.com/laszlopere/mcp-bytesmith/releases/tag/v0.0.1
