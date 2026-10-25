# Integrating a node:http MCP server (Wave C: bb-salesforce-mcp, bb-sage-mcp)

Both TypeScript servers share one transport shape: a `createServer` handler in
`src/transport/http_server.ts` that answers the open OAuth routes
(`/.well-known/*`, `/oauth/register`, `/oauth/authorize`, `/oauth/token`),
then requires a bearer on the MCP path, validates it with `validateBearer`
(an HS256 JWT the server minted itself, or a legacy token-file entry) and runs
the request inside `runWithPrincipal`. The integration adds the gate in front
of that bearer check and leaves everything behind it alone until cut-over.

This page is the per-repo checklist of the fleet plan (section 6) made
concrete for that shape. Nothing here is done until the Phase 0 spike has
passed and the broker is live; it is written now so the two PRs are
mechanical when their turn comes.

## 1. Broker registration

Add the app to the broker's `config/resources.json`. The tier names must be
the ones the server already uses, because `principal.tier` replaces the
server's allowlist lookup:

| Server | app key | resource | tiers |
|---|---|---|---|
| bb-salesforce-mcp | `salesforce` | `https://salesforce-mcp.bakerbaynes.com/mcp` | `Admin`, `EXCO`, `User` (today `MCP_ADMIN_USERS` / `MCP_EXCO_USERS` / the user allowlist) |
| bb-sage-mcp | `sage` | the server's public MCP URL | the server's tier map behind `access.isUserAllowed` |

Mint the verifier token with `npm run verifier-token -- <app>` on the broker
and put its hash in the registry entry.

## 2. Settings

Each server gets the standard block, prefix `SF_` for bb-salesforce-mcp and
`SAGE_` for bb-sage-mcp (README, "Settings"). Start with `MODE=off` in
production; the gate is inert and nothing changes. On VM-A point
`SNAPSHOT_URL` and `JWKS_URL` at `http://127.0.0.1:8775/...`.

## 3. Wiring

```ts
// http_server.ts, once at startup
const identity = new Verifier(configFromEnv('SF'));
await identity.start();
const gate = new IdentityGate(identity, {
  mcpPath: opts.path,
  legacyBearerOk: (bearer) => validateBearer(bearer, legacyOpts) !== null, // enabled mode only
  scopesSupported: [],
  log: (msg, fields) => logger.info(fields, msg),
});

// in the request handler, BEFORE the existing open OAuth routes
const outcome = await gate.handle(req, res);
if (outcome.kind === 'handled') return;
if (outcome.kind === 'principal') {
  const p = outcome.principal;
  principal = {
    user: userKeyFromSfUsername(p.username), // bb-salesforce-mcp; bb-sage-mcp uses its own user key
    source: 'sf',
    sfUserId: p.sub,
    sfUsername: p.username,
  };
  tier = p.tier; // replaces the MCP_ADMIN_USERS / MCP_EXCO_USERS lookup for this request
  // continue to the body read and runWithPrincipal exactly as today
}
// outcome.kind === 'legacy' or 'pass': fall through to the existing code unchanged
```

Why before the open routes: in `required` mode the gate answers the
metadata document itself, so the server's own
`/.well-known/oauth-protected-resource` handler must not run first. The
server's `/.well-known/oauth-authorization-server`, `/oauth/register`,
`/oauth/authorize` and `/oauth/token` keep working underneath for legacy
clients while the mode is `enabled`; they are deleted at cut-over.

The gate never replaces `runWithPrincipal`, the cache partitioning, the access
tiers or the write guards. It only decides who the caller is.

## 4. What the principal means in bb-salesforce-mcp

`principal.sub` is the caller's 18-char Salesforce User Id and
`principal.username` their Salesforce username, the same two values the
server's own "Sign in with Salesforce" leg produces today, so the per-user
Salesforce session (`currentSfUser`), the cache partition and the audit key
work unchanged. The tier comes from the snapshot (a Salesforce custom
permission `BB_MCP_Salesforce_<Tier>`), so moving a user between Admin, EXCO
and User becomes a permission-set change in Salesforce rather than an env
edit and a restart.

## 5. Mode progression

1. `off`: gate inert. Ship the dependency and the wiring; nothing changes.
2. `enabled`: broker tokens work alongside today's tokens. Connectors re-add
   the server and sign in through the broker. Watch `legacy` outcomes in the
   logs.
3. `required`: broker tokens and service principals only. Delete the
   embedded authorize, register, token and sign-in routes, the HS256 signing
   key and the token file. The health endpoint reports
   `identity.mode = required` and `legacy_open = false`.

Non-human callers (routines, n8n) move to a `svc-<name>` line in the service
principals file, owned by a named person's 18-char id, before step 3.

## 6. Health and selftest

Add `identity: verifier.health()` to the health body and the two counters
`gate.verified` / `gate.denied` to metrics. Selftest probes:
`identity_snapshot_fresh` (health.snapshot.fresh), `identity_required`
(health.mode), `legacy_traffic_14d` (no `legacy` outcome in the last 14 days
of audit rows).

## 7. Tests the PR must carry

- The gate's three outcomes on the real handler (`handled` with the challenge,
  `principal` reaching `runWithPrincipal` with `source: 'sf'`, `legacy`
  reaching the old validator), using this package's stub broker pattern.
- `required` mode refusing a token the server minted itself.
- The health block and the two selftest probes.
