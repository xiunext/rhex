import assert from "node:assert/strict"
import { createHmac } from "node:crypto"
import test from "node:test"

import { createOAuthIdToken } from "@/lib/oauth-oidc"
import { buildOpenIdConfiguration } from "@/lib/oauth-oidc-metadata"

test("OIDC discovery publishes issuer endpoints and supported security features", () => {
  const metadata = buildOpenIdConfiguration("https://rhex.example.test/")

  assert.equal(metadata.issuer, "https://rhex.example.test")
  assert.equal(metadata.authorization_endpoint, "https://rhex.example.test/oauth/authorize")
  assert.equal(metadata.token_endpoint, "https://rhex.example.test/oauth/token")
  assert.equal(metadata.userinfo_endpoint, "https://rhex.example.test/oauth/userinfo")
  assert.equal(metadata.jwks_uri, "https://rhex.example.test/.well-known/jwks.json")
  assert.deepEqual(metadata.code_challenge_methods_supported, ["S256"])
  assert.deepEqual(metadata.id_token_signing_alg_values_supported, ["HS256"])
  assert.deepEqual(metadata.scopes_supported, ["openid", "profile", "email"])
})

test("OIDC ID Token contains required claims, nonce, and an HS256 signature", () => {
  const clientSecret = "test-oauth-client-secret"
  const token = createOAuthIdToken({
    issuer: "https://rhex.example.test/",
    clientId: "client-123",
    subject: 42,
    clientSecret,
    expiresIn: 600,
    nonce: "nonce-abc",
    now: 1_700_000_000_000,
  })
  const [header, payload, signature] = token.split(".")
  const signingInput = `${header}.${payload}`
  const expectedSignature = createHmac("sha256", clientSecret).update(signingInput).digest("base64url")
  const claims = JSON.parse(Buffer.from(payload, "base64url").toString("utf8")) as Record<string, unknown>

  assert.equal(JSON.parse(Buffer.from(header, "base64url").toString("utf8")).alg, "HS256")
  assert.equal(signature, expectedSignature)
  assert.deepEqual(claims, {
    iss: "https://rhex.example.test",
    sub: "42",
    aud: "client-123",
    iat: 1_700_000_000,
    exp: 1_700_000_600,
    nonce: "nonce-abc",
  })
})
