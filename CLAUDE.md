# CLAUDE.md — bb-mcp-identity-ts

The TypeScript verifier for the Baker Baynes identity broker. The contract it
implements is `docs/VERIFIER_PROTOCOL.md` in `Spiv-Dev/bb-identity`; the
Python twin is `Spiv-Dev/bb-mcp-identity-py`. The two libraries must keep the
same settings names, the same deny rules and the same reason strings.

## Hard rules

1. **ES256 only.** Never add another algorithm, a symmetric fallback or an
   unverified decode path. A token whose header is not ES256 is "not ours"
   and is refused (or, in `enabled` mode, handed to the server's legacy check).
2. **The snapshot decides.** Every verified token still passes the snapshot
   rules in `src/verifier.ts`: fresh snapshot, subject present and active,
   tier present, `auth_time > not_before`. Tier and scopes come from the
   snapshot, never from the token. Do not add a bypass, a dev mode or an
   "allow when the broker is unreachable" branch: the library fails closed.
3. **Reasons, not tokens.** A `Deny.reason` is a short stable string that is
   safe to log. No bearer, header or claim value is ever logged or returned to
   the client; the client only sees the 401 challenge.
4. **Contract changes bump the version** here, in the Python library and in
   the broker's protocol document, in one change.
5. **Tests use keys generated per run.** No private key, token or secret is
   ever committed, not even a "test" one.
6. **PR-only to main**, with a `[Unreleased]` bullet in `CHANGELOG.md`.

## Gate

`npm run gate-a` (eslint on src and test, tsc on both tsconfigs, vitest). It
runs in CI on every pull request and on main.
