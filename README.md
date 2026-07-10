# mcp-bytesmith

[![CI](https://github.com/laszlopere/mcp-bytesmith/actions/workflows/ci.yml/badge.svg)](https://github.com/laszlopere/mcp-bytesmith/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/mcp-bytesmith.svg)](https://pypi.org/project/mcp-bytesmith/)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![License: GPLv3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)
[![Sponsor](https://img.shields.io/badge/Sponsor-%E2%9D%A4-db61a2.svg)](https://github.com/sponsors/laszlopere)
[![mcp-bytesmith MCP server](https://glama.ai/mcp/servers/laszlopere/mcp-bytesmith/badges/score.svg)](https://glama.ai/mcp/servers/laszlopere/mcp-bytesmith)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)
[![Checked with mypy](https://www.mypy-lang.org/static/mypy_badge.svg)](https://mypy-lang.org/)
[![Last commit](https://img.shields.io/github/last-commit/laszlopere/mcp-bytesmith.svg)](https://github.com/laszlopere/mcp-bytesmith/commits)

A pure-Python [Model Context Protocol](https://modelcontextprotocol.io) server,
built on the official MCP SDK (FastMCP), exposing a toolbox of byte-wrangling
utilities — encoding, hashing, number crunching, and Ethereum primitives — all
computed locally and for real, with no network calls or remote APIs.

Distribution name: `mcp-bytesmith` · import package: `mcp_bytesmith`.

## Tools

mcp-bytesmith ships an always-on **core toolset** built entirely on the Python
standard library, so it works out of the box with no extra dependencies. This
covers the everyday primitives: `encode` and `decode` move data between a wide
set of schemes (hex, the Base64/Base32 family, Base58/Base58check, Base45, and
more), `hash` computes cryptographic, CRC, and fast non-cryptographic digests,
`hash_file` checksums a file on disk and soft-verifies it against an expected
digest, `hmac` computes and verifies keyed-hash authentication tags, and
`num_convert` translates integers between bases. Rounding out the core are
`bytes_edit` (pad/trim/slice/concat byte glue), `data_uri` (build and parse
`data:` URIs), `otpauth_uri` (build and parse `otpauth://` authenticator
provisioning URIs), `unicode_normalize` and `charset_transcode` for text and
character-set work, `string_escape`/`string_unescape` for JSON/JS/Python/C
escaping, `codepoints` for per-scalar Unicode inspection, and `random` for
CSPRNG-backed bytes, tokens, and passphrases. `password_hash` turns a password
into a verifiable storage string and checks one back — scrypt and PBKDF2 out of
the box, bcrypt and the argon2 variants with the `crypto` extra — while
`derive_key` derives raw key bytes from a password or secret via PBKDF2, scrypt,
or HKDF.

An opt-in **Ethereum/EVM toolset** (enabled via the `ethereum` extra) adds the
primitives you reach for when working on-chain: `eth_hash` for keccak-256,
EIP-191, and EIP-712 typed-data hashing, `abi_codec` and `rlp_codec` for ABI and
RLP encode/decode, `eth_selector` for function and event selectors, `eth_tx_codec`
for transactions, `eth_storage_slot` for storage layout, `eth_address_case`
for EIP-55 checksums, `ens_namehash` for EIP-137 ENS namehash/labelhash,
`bip32_derive` for BIP-32/44 HD key and address derivation from a seed,
`eth_eoa_address` for the address and public key behind a private key, and
`eth_contract_address` for CREATE and CREATE2 deployment addresses. An
always-available `info` tool reports which toolsets are
active along with version information.

An opt-in **serialization toolset** (enabled via the `serialize` extra) adds
`serialize_codec`, a single tool multiplexed by `format`. It encodes and decodes
schemaless structured data across CBOR, MessagePack, bencode, and ASN.1 DER/BER
(a tag-length-value tree; the `crypto` extra's asn1crypto is needed for ASN.1);
it encodes and decodes SSZ (Simple Serialize) driven by an `options.schema`,
also returning the `hash_tree_root`; and it decodes raw protobuf wire format
(protobuf is decode-only — without a `.proto` schema it surfaces field numbers,
wire types, and values rather than field names).

Further toolsets (the rest of crypto, IDs, validation) are on the roadmap — see
[`TODO`](./TODO).

## Development

```sh
uv sync                 # create venv + install (incl. dev extras)
uv run mcp-bytesmith    # start the server over stdio
uv run pytest           # run the test suite
```

## Sponsoring

mcp-bytesmith is free, open-source software developed in my spare time.
Sponsorships are what keep the project alive and actively maintained — they fund
new toolsets, bug fixes, and ongoing support, and they're a direct signal that
the work is worth continuing.

If the project is useful to you, please consider sponsoring it through
**[GitHub Sponsors](https://github.com/sponsors/laszlopere)**. Click the
**Sponsor** button at the top of the repository, or visit the link directly, and
pick a one-time or recurring tier. Every contribution, large or small, is hugely
appreciated and goes straight back into keeping mcp-bytesmith healthy.

## License

GPLv3 — see [`LICENSE`](./LICENSE).

The bundled passphrase wordlist
([`src/mcp_bytesmith/wordlists/eff_large.txt`](./src/mcp_bytesmith/wordlists/eff_large.txt),
used by the `random` tool's `passphrase` kind) is the EFF "large" wordlist by the
[Electronic Frontier Foundation](https://www.eff.org/dice), licensed
[CC BY 3.0 US](https://creativecommons.org/licenses/by/3.0/us/).
