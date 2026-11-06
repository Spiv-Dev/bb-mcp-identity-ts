# Changelog

## [Unreleased]

## [0.1.2] - 2026-11-06

### Added
- `UsageLedger`, `redactQuestion` and `userSlug` (`src/usage.ts`) for fleet tool-usage tracking: one JSON line per tool call in `<dir>/usage-YYYY-MM-DD.jsonl` (UTC day, mode 0600, pruned after 14 days), set by `<PREFIX>_USAGE_DIR` and off when it is unset. Events carry call metadata and argument names only, never argument values or results; a question is kept only after redaction (emails, phones, long numbers, Salesforce Ids, URLs, amounts). `record` never throws. The event schema and the redaction fixtures (`spec/`) are shared byte for byte with bb-mcp-identity-py 0.1.3. The module imports nothing from the auth code.

## [0.1.1] - 2026-10-29

### Fixed
- A first sign-in is no longer refused as `unknown_subject` for up to a minute: when a validly signed token's user is missing from the snapshot (or has no tier), the verifier refetches the snapshot once and re-checks, at most once per `<PFX>_IDENTITY_MISS_REFRESH_S` (default 5, `0` = off); concurrent misses share one fetch. Found in the A2 spike.

## [0.1.0] - 2026-10-28

### Added
- Initial verifier library for node:http MCP servers: `configFromEnv`
  (`<PFX>_IDENTITY_*`), `KeySet` (pinned or fetched ES256 JWKS, one refetch per
  unknown `kid`), `SnapshotStore` (ETag polling, disk cache, staleness),
  `ServicePrincipals`, `Verifier` (the deny rules of VERIFIER_PROTOCOL.md
  section 4, including `auth_time <= not_before`), protected-resource metadata
  and the 401 challenge, and `IdentityGate` for `node:http` servers with the
  `legacyBearerOk` and `mintInternalToken` adapters. Same settings, rules and
  reason strings as the Python library bb-mcp-identity-py 0.1.0.
- Hardening from the first review pass: `VERIFIER_TOKEN` is required unless
  the mode is off and the broker URLs must be https (plain http for loopback
  only); an empty setting counts as unset and integers are parsed strictly;
  the fetched key set is replaced on every successful JWKS fetch so a rotated
  out key stops verifying, and JWKS members marked for encryption are ignored;
  a malformed snapshot entry is treated as absent; the WWW-Authenticate realm
  and error values cannot carry quotes or line breaks; a throwing verifier or
  callback answers 500 instead of hanging the request; service principal files
  reject impossible dates, duplicate names and reused tokens, and a configured
  but missing file is reported through `warn`; `mcpPath: '/'` gates every path.
- Integration guide for the two TypeScript servers (`docs/INTEGRATION_NODE_HTTP.md`).
