/**
 * bb-mcp-identity: the verifier side of the Baker Baynes identity broker
 * for node:http MCP servers.
 *
 *   import { configFromEnv, IdentityGate, Verifier } from 'bb-mcp-identity';
 *
 *   const verifier = new Verifier(configFromEnv('SF'));
 *   await verifier.start();
 *   const gate = new IdentityGate(verifier, { mcpPath: '/mcp' });
 *   createServer(async (req, res) => {
 *     if ((await gate.handle(req, res)).kind === 'handled') return;
 *     ...
 *   });
 */
export { ConfigError, configFromEnv, isEnabled, isRequired, issuerParts } from './config.js';
export type { FromEnvOptions, IdentityConfig, Mode, PinnedJwks } from './config.js';
export { ALG, KeySet } from './jwks.js';
export type { KeySetHealth, KeySetOptions } from './jwks.js';
export { scopesOf, SnapshotStore } from './snapshot.js';
export type { SnapshotDocument, SnapshotHealth, SnapshotStoreOptions, SubjectEntry } from './snapshot.js';
export { isCalendarDate, parseLines, ServicePrincipals, todayUtc } from './service_principals.js';
export type { ServicePrincipal } from './service_principals.js';
export { Deny, scopeString, Verifier } from './verifier.js';
export type { Principal, PrincipalKind, VerifierHealth, VerifierOptions } from './verifier.js';
export { protectedResourceMetadata, resourceMetadataUrl, wwwAuthenticate } from './metadata.js';
export type { ProtectedResourceMetadata } from './metadata.js';
export { extractBearer, IdentityGate, pathOnly, PRM_PATH } from './http.js';
export type { GateOptions, GateOutcome, LegacyCheck, Minter } from './http.js';

export const VERSION = '0.1.0';
