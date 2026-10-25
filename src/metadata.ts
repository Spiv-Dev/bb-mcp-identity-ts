/**
 * The two things the MCP server must say to clients: the protected-resource
 * metadata document (RFC 9728) and the 401 challenge header.
 */
import type { IdentityConfig } from './config.js';

export interface ProtectedResourceMetadata {
  resource: string;
  authorization_servers: string[];
  scopes_supported: string[];
  bearer_methods_supported: string[];
}

export function protectedResourceMetadata(config: IdentityConfig, scopesSupported: readonly string[] = []): ProtectedResourceMetadata {
  return {
    resource: config.resource,
    authorization_servers: [config.issuer],
    scopes_supported: ['mcp', ...scopesSupported.filter((s) => s !== 'mcp')],
    bearer_methods_supported: ['header'],
  };
}

/** `https://host/.well-known/oauth-protected-resource` for the resource's origin. */
export function resourceMetadataUrl(config: IdentityConfig): string {
  let base: string;
  try {
    base = new URL(config.resource).origin;
  } catch {
    const parts = config.resource.split('/');
    base = parts.length >= 3 ? parts.slice(0, 3).join('/') : config.resource;
  }
  return `${base}/.well-known/oauth-protected-resource`;
}

/** A value safe inside a quoted-string header parameter: no quotes, backslashes or control characters. */
function quotable(value: string): string {
  // eslint-disable-next-line no-control-regex
  return value.replace(/["\\\x00-\x1f\x7f]/g, '');
}

export function wwwAuthenticate(config: IdentityConfig, options: { error?: string | null } = {}): string {
  const parts = [`Bearer realm="${quotable(config.realm)}"`, `resource_metadata="${quotable(resourceMetadataUrl(config))}"`];
  if (options.error) parts.push(`error="${quotable(options.error)}"`);
  return parts.join(', ');
}
