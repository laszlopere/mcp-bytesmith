# Changelog

All notable changes to **mcp-bytesmith** are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `eth_bytecode` — read deployed EVM bytecode three ways: `disassemble` it into
  instructions, scrape the function `selectors` out of its dispatcher, or parse
  the trailing solc CBOR `metadata`. All three rest on one property — bytecode
  has exactly one irregularity, `PUSH1`..`PUSH32` carrying their immediate
  inline, and everything else follows from walking that correctly. Grepping the
  raw hex for `63` + four bytes also matches the *middle* of some other push's
  immediate, which is how a naive scraper invents functions that do not exist, so
  the selector scrape runs over a real decode: a `PUSH4 0xa9059cbb EQ` pattern
  buried inside a `PUSH32` is correctly seen as data. A selector is a `PUSH4`
  that a comparison then consumes — `EQ`, or `GT`/`LT`, because solc's
  binary-search dispatcher pivots on genuine selector values (a pivot is deduped
  in `selectors` and shows up twice in `sites`, which reports the `pc` and
  comparison behind every hit). The `0x00000000`/`0xffffffff` sentinels are
  dropped, and this stays an honest heuristic rather than a decompile: an ERC-165
  interface id is also a `PUSH4` compared with `EQ`, and nothing in the bytecode
  distinguishes the two. Feed the results to `abi_inspect`'s `selectors` map to
  name them. The metadata trailer is peeled off *first* and excluded from both
  the disassembly and the scrape — it is data, not code — and reported as
  `metadata_offset` so nothing is silently dropped; it yields the compiler
  version and, when present, the source's IPFS CID. Code compiled with metadata
  stripped reports `present: false` rather than erroring, and a trailer is only
  believed when it is a CBOR map ending exactly where its 2-byte length claims,
  so a coincidental pair of trailing bytes cannot fake one. Disassembly is capped
  at `limit` instructions (0 removes the cap) with `next_offset` for paging — a
  24 KB contract is some twelve thousand instructions. Unassigned bytes come back
  as `name: null` with `unknown` rather than an invented mnemonic, and code
  ending mid-immediate is flagged `truncated`. Adds no dependency and still the
  `ethereum` extra: `cbor2` lives behind the `serialize` extra and `base58`
  behind `encoding`, so the CBOR subset and base58btc are hand-rolled here and
  cross-checked against both libraries in the tests.
- `abi_inspect` — list a contract ABI's entries with their canonical signatures,
  4-byte selectors and event topic0s, and convert the ABI between its two
  representations. It accepts either form — a JSON ABI (the array in a compiled
  artifact, where a struct is spelled `{"type": "tuple", "components": […]}`) or
  human-readable Solidity declarations (`function transfer(address to, uint256
  amount)`, what a person actually pastes) — and returns *both* for every entry,
  so it converts in whichever direction you needed: read `inputs`/`outputs` for
  human → JSON ABI, read `human` for the reverse. Round-tripping is a fixed
  point, including nested tuples, arrays of structs, `indexed`, mutability and a
  `returns (…)` clause. The `selectors` and `topics` maps are the practical
  payload: they are exactly the lookup table `eth_calldata`, `eth_log_decode` and
  `eth_revert_decode` want as input, so an artifact goes to a decodable
  signature in one call. Two distinct signatures sharing a selector are reported
  under `collisions` rather than silently overwriting each other in the map —
  a real hazard when a proxy's function set meets its implementation's.
  `constructor`, `fallback` and `receive` carry no signature or selector, having
  none, and an `anonymous` event is excluded from `topics` because it never emits
  one. It shares the signature parser with the decoding tools, so a selector it
  reports and one `eth_selector` computes cannot disagree. Adds no dependency;
  still the `ethereum` extra.
- `eth_revert_decode` — turn a failed call's revert data into a human-readable
  reason. Revert data has calldata's shape — a 4-byte selector plus ABI-encoded
  arguments — and the result is discriminated by `kind`: `error` for
  `Error(string)` (`0x08c379a0`, what `require`/`revert("…")` produce) carrying
  the message as `reason`; `panic` for `Panic(uint256)` (`0x4e487b71`, the
  compiler's own checks) carrying the `code` and a `meaning` drawn from
  Solidity's documented table — `0x11` overflow, `0x12` division by zero, `0x32`
  array index out of bounds, `0x51` a zero-initialized internal function call,
  and the rest — with an undocumented code reported as `meaning: null` rather
  than an invented gloss; `custom` for a user-declared error, which needs its
  `signature` and comes back with named `args` exactly as `eth_calldata` reports
  them; `unknown` for an unrecognized selector with no signature given, which
  says so and names the selector instead of guessing; and `empty` for revert data
  that is genuinely empty — a bare `revert()`, or a failure that returned nothing
  at all. Both built-in selectors are derived by keccak from their signatures
  rather than hardcoded, so the module cannot drift from the constants. A
  `signature` that does not match the data is soft (`selector_matches: false`
  plus `data_selector` and `reason`, arguments still decoded), except that a
  recognized built-in wins over a non-matching guess — "this is a standard
  `Error(string)`" is more useful than forcing your candidate onto it — and a
  guess that cannot decode the tail at all degrades to `unknown` rather than
  raising. Adds no dependency; still the `ethereum` extra.
- `eth_log_decode` — turn a receipt log's `topics` and `data` into named event
  arguments, given the human-readable event signature. The `indexed` modifier is
  what splits the two halves, and the arguments come back **interleaved in
  declaration order** with an `indexed` flag on each, rather than sorted into two
  buckets — a log is read against its source, and the source declares them in one
  order. The subtlety it exists to handle is what a topic actually holds: only a
  value type (`uintN`/`intN`/`bool`/`address`/`bytesN`) sits there verbatim, while
  every array — **including a static `uint256[3]`** — every struct — **including a
  fully static `(uint256,bool)`** — and `bytes`/`string` are keccak-hashed into
  their topic. Those return `"value": null` alongside `hashed: true` and `hash`
  (the topic word), which is still enough to match against `keccak` of a candidate
  preimage, but is honestly not the value. An event declared `anonymous` in
  Solidity carries no topic0 and may index up to four arguments; it is signalled
  by an explicit `anonymous` flag rather than inferred from the topic count,
  because inference would silently shift every indexed argument by one word when a
  topic list is truncated, and would make a topic0 mismatch unreportable. A
  `topics[0]` that is not the signature's topic0 is soft — `topic0_matches: false`
  plus `log_topic0` and `reason`, arguments still decoded, since probing candidate
  signatures is legitimate — but a topic *count* that contradicts the signature
  raises, because ERC-20 and ERC-721 `Transfer` hash to the identical topic0 and
  differ only in how many arguments are indexed, so the count is the real identity
  check. Data shorter than the non-indexed head is rejected rather than decoded as
  zeros off the end of the buffer; trailing bytes are tolerated. It shares the ABI
  engine and value conventions with `abi_codec` and `eth_calldata` and adds no
  dependency — still the `ethereum` extra.
- `eth_calldata` — split a transaction's calldata into named, typed arguments
  (`action=decode`), or build calldata from them (`action=encode`). It takes the
  human-readable signature you already have — `transfer(address to, uint256
  amount)` — and does what `abi_codec` cannot: peels off the 4-byte selector and
  carries the *parameter names* through to the result, as
  `args: [{name, type, value}]`. A parameter the signature does not name comes
  back as `"name": null` rather than a synthesized `arg0`; a struct argument also
  carries `components` naming its members, in JSON ABI shape, while its value
  stays a nested list. Data locations (`calldata`/`memory`/`storage`), `payable`
  and `indexed`, type aliases (`uint` → `uint256`), and a trailing Solidity
  `external returns (...)` clause are all tolerated in the input signature, so a
  line pasted from source or from Etherscan works; the returned `signature` is
  the canonical, name-free form, so it remains a valid `eth_selector` input and a
  valid dictionary key. A leading selector that is *not* the signature's is a
  soft `selector_matches: false` plus `data_selector` and `reason` — identifying
  an unknown selector by trying candidate signatures is a legitimate use, so the
  arguments are still decoded — but a mismatch whose body also fails to decode
  raises, naming the mismatch as the cause rather than leaking an error from deep
  inside the ABI decoder. Calldata shorter than the argument head is rejected
  instead of silently decoding to zeros off the end of the buffer; trailing bytes
  past the arguments are tolerated. A zero-argument signature needs no `values`.
  It shares its ABI engine and value conventions with `abi_codec` (ints as
  decimal strings, addresses EIP-55 checksummed) and adds no dependency — still
  the `ethereum` extra.
- `id_generate` — generate one or more identifiers: a UUID (`version` 1, 4, 5 or
  7), a ULID, or a nanoid. Entirely stdlib, so the `ids` extra stays empty —
  `uuid` supplies v1/v4/v5, while v7 (RFC 9562 §5.7), ULID and nanoid are a few
  CSPRNG draws each. v7 and ULID share a 48-bit millisecond timestamp, so both
  sort lexicographically by creation time; v5 hashes a `name` within a
  `namespace` (`dns`/`url`/`oid`/`x500` or a literal UUID) and is therefore
  deterministic, which makes a `count` above 1 repeat the same ID. v1 is given a
  random node ID with the multicast bit set (RFC 9562 §6.10) rather than the
  host's MAC address, so generating one never leaks host identity. nanoid draws
  `size` (default 21) symbols from `alphabet` (default the 64 url-safe chars).
  Batches are bounded to 1000 IDs and a nanoid to 1024 characters.
- `bip39` — generate, validate, or convert a BIP-39 mnemonic to a seed
  (`action=generate|validate|to_seed`). `generate` builds a mnemonic from supplied
  `entropy` (deterministic) or from fresh CSPRNG entropy of `strength` bits
  (128→12 words … 256→24 words); `to_seed` runs PBKDF2-HMAC-SHA512 for 2048
  rounds over the NFKD mnemonic with salt `"mnemonic" + passphrase`, yielding the
  64-byte seed that `bip32_derive` consumes. Casing and stray whitespace in a
  mnemonic are forgiven. A mnemonic that fails its checksum is a soft
  `{"valid": false, "reason": …}` from `validate` but an error from `to_seed`,
  since a typo there silently derives a different wallet; for the same reason the
  passphrase is accepted unvalidated (it is the "25th word" — any value is legal
  and opens a different wallet). Unknown words are reported by position rather
  than quoted back, and neither mnemonic, entropy, nor passphrase is ever echoed.
  Checked against all 24 official BIP-39 English test vectors. The canonical
  2048-word English wordlist is now bundled (see README for attribution).
- `eth_contract_address` — compute a contract's `create` or `create2` deployment
  address. `create` hashes `rlp([deployer, nonce])`, so the address depends on
  how many times the deployer has deployed; `create2` (EIP-1014) hashes
  `0xff ++ deployer ++ salt ++ keccak256(init_code)`, which is counterfactual —
  computable before the contract exists. The `salt` must be exactly 32 bytes and
  the `nonce` is bounded to EIP-2681's `0..2^64-1`; `init_code` is the creation
  bytecode (constructor plus its encoded arguments), not the deployed runtime
  code. Returns the EIP-55 checksummed `address` and deploys nothing. Checked
  against all seven worked examples in EIP-1014.
- `eth_eoa_address` — derive an externally-owned account's address and public key
  from its private key: the public key is the curve point `k*G` serialized
  uncompressed, and the address is the EIP-55 checksummed keccak-256 tail of its
  `X || Y` body. The EOA counterpart to `eth_contract_address` — it derives, it
  does not create an account. Keys outside the secp256k1 range `0 < k < n` are
  rejected rather than silently reduced. The private key is never echoed back.
- `derive_key` — derive raw key bytes from a password or secret via `pbkdf2`
  (default), `scrypt`, or `hkdf` (RFC 5869, hand-rolled on `hmac`), rendered as
  hex or base64. Entirely stdlib, so no extra is needed. Deterministic by
  construction: an omitted `salt` means an empty one rather than a fresh random
  one — a random salt would return a key nobody could reproduce — and the salt
  actually used is echoed back alongside the `kdf`, `length` and `params`.
  HKDF's `info` parameter binds a derived key to a purpose. Key `length` is
  bounded to 1..1024 bytes and cost parameters share `password_hash`'s ceilings.
  The password is never echoed back. Use `password_hash` instead when the goal
  is a string to store and compare.
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
