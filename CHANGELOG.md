# Changelog

All notable changes to **mcp-bytesmith** are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `password_hash` — hash a password into a verifiable storage string, or verify
  one against it (`action=hash|verify`). Six schemes: `bcrypt` and `argon2i` /
  `argon2d` / `argon2id` (from the `crypto` extra, which now also installs
  `bcrypt` and `argon2-cffi`), plus stdlib `scrypt` and `pbkdf2`, which work
  with no extra installed. Emits bcrypt's `$2b$…` and argon2's PHC string
  verbatim; scrypt and PBKDF2 get PHC-shaped strings of their own
  (`$scrypt$ln=14,r=8,p=1$<salt>$<hash>`, `$pbkdf2-sha256$i=600000$…`), which
  `verify` parses back — so the scheme and its cost parameters need not be
  passed again. A wrong password returns `{"valid": false}` rather than raising;
  only a malformed hash string raises. Cost parameters are bounded (argon2 to
  1 GiB, PBKDF2 to 10M iterations, bcrypt to cost 16) so a runaway parameter is
  rejected instead of hanging the server, and the password is never echoed back.
- `serialize_codec` gains its final two formats, completing the six-format codec:
  - `asn1` — schemaless ASN.1 DER/BER as a tag-length-value tree (encode +
    decode). Each node is `{class, tag, [type], constructed}` plus `children`
    (constructed) or `value`/`value_hex` (primitive); common UNIVERSAL types
    (INTEGER, OID, BOOLEAN, NULL, the string types) are interpreted, and BER
    indefinite-length input re-encodes to definite-length DER. Needs the new
    `crypto` extra (asn1crypto), checked per call.
  - `ssz` — Simple Serialize (Ethereum consensus layer), schema-driven via
    `options.schema` (encode + decode). Supports uintN/boolean, vector/list,
    container, bitvector/bitlist, and bytevector/bytelist, and returns the
    32-byte `hash_tree_root` for both actions. Pure-Python (SHA-256
    merkleization is stdlib); roots verified against the `remerkleable`
    reference implementation.
- `crypto` extra now installs `asn1crypto` (for the `asn1` serialize format).
- `otpauth_uri` — build or parse an `otpauth://` provisioning URI (the Key URI
  Format that QR-code authenticator apps consume). A structured-URI codec like
  `data_uri`: it assembles/splits the URI and carries the base32 `secret`
  through verbatim; it does not compute OTP codes. Enforces the totp/hotp rules
  (HOTP needs a `counter`; `counter`/`period` must match the type) and fills the
  RFC defaults (SHA1 / 6 digits / 30 s period) on parse.
- `bip32_derive` — derive an HD child key and its Ethereum address from a seed
  along a BIP-32/44 path (e.g. `m/44'/60'/0'/0/0`). Pure-Python secp256k1
  (reuses the existing curve math) with HMAC-SHA512 CKDpriv; supports hardened
  (`'`/`h`) and normal steps. Returns `{path, depth, private_key, public_key,
  chain_code, address}` — the derived child key is returned, but the input seed
  is never echoed (§2.0.6). Key material verified against BIP-32 Test Vector 1
  and the standard Hardhat/Anvil dev accounts.

## [0.3.0] - 2026-06-19

Robustness release: the server now tolerates and clearly diagnoses malformed
tool calls from LLM clients.

### Added
- Tolerant handling of LLM-mangled tool-call `arguments`: a `tools/call` whose
  `arguments` arrive as a JSON *string* (the common double-encoding offender) —
  including single quotes, trailing commas, or unquoted barewords — is repaired
  before the SDK's strict validation rejects it (via a stdio read-stream
  interposer in `jsonfix.py`, backed by `json-repair`). Unparseable arguments
  get an actionable JSON-RPC `-32700` parse error instead of a bare "Invalid
  request parameters".
- Argument-validation failures (missing field, wrong type) are reshaped into a
  concise, field-naming message that drops pydantic's multi-line preamble and
  `errors.pydantic.dev` URL, so the model self-corrects in one turn
  (`errors.py`, wired via a `FastMCP` subclass).

### Changed
- New runtime dependency: `json-repair>=0.30`.

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

[0.3.0]: https://github.com/laszlopere/mcp-bytesmith/releases/tag/v0.3.0
[0.2.0]: https://github.com/laszlopere/mcp-bytesmith/releases/tag/v0.2.0
[0.1.0]: https://github.com/laszlopere/mcp-bytesmith/releases/tag/v0.1.0
[0.0.1]: https://github.com/laszlopere/mcp-bytesmith/releases/tag/v0.0.1
