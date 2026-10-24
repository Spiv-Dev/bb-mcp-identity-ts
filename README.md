# bb-mcp-identity (TypeScript)

The verifier side of the Baker Baynes identity broker
([bb-identity](https://github.com/Spiv-Dev/bb-identity)) for the TypeScript MCP
servers (`node:http` transports such as bb-salesforce-mcp and bb-sage-mcp). An
MCP server adds this library, names the broker in its protected-resource
metadata, and verifies the broker's tokens plus the entitlement snapshot on
every request. It stops being an authorization server.

The contract is `docs/VERIFIER_PROTOCOL.md` in the bb-identity repo. The
Python servers use the sibling library
[bb-mcp-identity-py](https://github.com/Spiv-Dev/bb-mcp-identity-py); the two
implement the same rules, the same reason strings and the same settings.

## Install

```bash
npm install github:Spiv-Dev/bb-mcp-identity-ts#v0.1.0
```

The package builds itself on install (`prepare` runs tsup); the single
runtime dependency is `jose`.

## Wire it in (node:http)

```ts
import { createServer } from 'node:http';
import { configFromEnv, IdentityGate, Verifier } from 'bb-mcp-identity';

const verifier = new Verifier(configFromEnv('SF')); // SF_IDENTITY_* settings
await verifier.start(); // JWKS + snapshot poller (unref'd interval)

const gate = new IdentityGate(verifier, {
  mcpPath: '/mcp',
  legacyBearerOk: (bearer) => legacyValidator(bearer) !== null, // enabled mode: today's tokens still work
  mintInternalToken: (p) => signInternalJwt(p), // optional: keep the inner validator untouched
  scopesSupported: ['sf:read', 'sf:write'],
  log: (msg, fields) => logger.info(fields, msg),
});

createServer(async (req, res) => {
  const outcome = await gate.handle(req, res);
  if (outcome.kind === 'handled') return; // metadata document or 401 already written
  if (outcome.kind === 'principal') {
    // outcome.principal.sub is the 18-char Salesforce User Id; .username, .tier, .scopes come from the snapshot
  }
  // ...the server's existing request handling; `gate.principalOf(req)` returns the principal later on
});
```

`gate.handle` returns one of four outcomes:

| Outcome | Meaning |
|---|---|
| `pass` | identity mode is `off`, or a path the gate does not own: carry on exactly as before |
| `handled` | the gate wrote the response (the metadata document, or a 401 with `WWW-Authenticate`) |
| `legacy` | enabled mode: not a broker token, and `legacyBearerOk` accepted it; the request is untouched |
| `principal` | a broker token verified against the keys and the snapshot; with `mintInternalToken` the `Authorization` header now carries the server's own internal token |

`gate.wrap(inner)` composes the gate with an existing handler for servers that
do not want to switch on the outcome.

## Settings

| Variable (prefix `SF_`) | Meaning |
|---|---|
| `SF_IDENTITY_MODE` | `off` (default), `enabled` (broker tokens plus legacy), `required` (broker tokens and service principals only) |
| `SF_IDENTITY_ISSUER` | `https://id.bakerbaynes.com/r/salesforce` |
| `SF_IDENTITY_RESOURCE` | this server's MCP URL, the token audience |
| `SF_IDENTITY_VERIFIER_TOKEN` | from `npm run verifier-token -- salesforce` on the broker |
| `SF_IDENTITY_SNAPSHOT_URL` | default `<issuer>/snapshot`; on the broker's VM use `http://127.0.0.1:8775/r/salesforce/snapshot` |
| `SF_IDENTITY_JWKS_URL` | default `<broker>/.well-known/jwks.json`; loopback on the broker's VM |
| `SF_IDENTITY_SNAPSHOT_CACHE` | file path; restored on boot so a restart never starts blind |
| `SF_IDENTITY_PINNED_JWKS` | optional JWKS JSON for offline verification |
| `SF_IDENTITY_SERVICE_PRINCIPALS` | optional file of `svc-<name>:<tier>:<owner sub>:<expires>:<token>` lines |
| `SF_IDENTITY_POLL_INTERVAL_S`, `_JWKS_TTL_S`, `_LEEWAY_S`, `_HTTP_TIMEOUT_S` | 60, 300, 30, 5 |

## Deny rules (all 401)

No bearer; not an ES256 token with a known `kid`; wrong `iss` or `aud`;
expired; no snapshot or a stale one; subject unknown, inactive or frozen; no
tier for this app; `auth_time` at or before the subject's `not_before`. In
`enabled` mode a bearer that is not a broker token at all is handed to
`legacyBearerOk`. The refusal reason is logged through `log`, never sent to
the client.

## Health

`verifier.health()` returns the identity mode, issuer, resource, the pinned or
fetched `kid`s, and the snapshot version, age and freshness for the server's
health endpoint. `gate.verified` and `gate.denied` are plain counters for
metrics.

## Develop

```bash
npm install
npm run gate-a   # eslint + tsc (src and test) + vitest
npm run build    # dist/ with type declarations
```

Tests run against an in-process stub broker with a key pair generated per
run; no key material is committed.
