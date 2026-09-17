import { createHmac } from "node:crypto"

export function createOAuthIdToken(input: {
  issuer: string
  clientId: string
  subject: string | number
  clientSecret: string
  expiresIn: number
  nonce?: string | null
  now?: number
}) {
  if (!input.clientSecret) {
    throw new Error("OIDC ID Token 需要客户端密钥")
  }

  const now = input.now ?? Date.now()
  const issuedAt = Math.floor(now / 1000)
  const header = Buffer.from(JSON.stringify({ alg: "HS256", typ: "JWT" })).toString("base64url")
  const claims = {
    iss: new URL(input.issuer).origin,
    sub: String(input.subject),
    aud: input.clientId,
    iat: issuedAt,
    exp: issuedAt + Math.max(60, Math.floor(input.expiresIn)),
    ...(input.nonce ? { nonce: input.nonce } : {}),
  }
  const payload = Buffer.from(JSON.stringify(claims)).toString("base64url")
  const signingInput = `${header}.${payload}`
  const signature = createHmac("sha256", input.clientSecret).update(signingInput).digest("base64url")

  return `${signingInput}.${signature}`
}
