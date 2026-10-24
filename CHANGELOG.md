# Changelog

## [Unreleased]

- Initial verifier library for node:http MCP servers: `configFromEnv`
  (`<PFX>_IDENTITY_*`), `KeySet` (pinned or fetched ES256 JWKS, one refetch per
  unknown `kid`), `SnapshotStore` (ETag polling, disk cache, staleness),
  `ServicePrincipals`, `Verifier` (the deny rules of VERIFIER_PROTOCOL.md
  section 4, including `auth_time <= not_before`), protected-resource metadata
  and the 401 challenge, and `IdentityGate` for `node:http` servers with the
  `legacyBearerOk` and `mintInternalToken` adapters. Same settings, rules and
  reason strings as the Python library bb-mcp-identity-py 0.1.0.
