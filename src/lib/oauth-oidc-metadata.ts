export const OPENID_CONFIGURATION_PATH = "/.well-known/openid-configuration"

function normalizeIssuer(value: string) {
  return new URL(value).origin
}

export function buildOpenIdConfiguration(issuerValue: string) {
  const issuer = normalizeIssuer(issuerValue)

  return {
    issuer,
    authorization_endpoint: `${issuer}/oauth/authorize`,
    token_endpoint: `${issuer}/oauth/token`,
    userinfo_endpoint: `${issuer}/oauth/userinfo`,
    jwks_uri: `${issuer}/.well-known/jwks.json`,
    revocation_endpoint: `${issuer}/oauth/revoke`,
    response_types_supported: ["code"],
    response_modes_supported: ["query"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    subject_types_supported: ["public"],
    scopes_supported: ["openid", "profile", "email"],
    claims_supported: ["sub", "name", "preferred_username", "picture", "updated_at", "email", "email_verified"],
    token_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post"],
    id_token_signing_alg_values_supported: ["HS256"],
    code_challenge_methods_supported: ["S256"],
  }
}
