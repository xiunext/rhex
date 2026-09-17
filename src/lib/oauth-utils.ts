import { createHash, randomBytes, timingSafeEqual } from "node:crypto"

export const OAUTH_SUPPORTED_SCOPES = ["openid", "profile", "email"] as const
export type OAuthScope = (typeof OAUTH_SUPPORTED_SCOPES)[number]

const OAUTH_SUPPORTED_SCOPE_SET = new Set<string>(OAUTH_SUPPORTED_SCOPES)

export function isOAuthSupportedScope(value: unknown): value is OAuthScope {
  return OAUTH_SUPPORTED_SCOPE_SET.has(String(value ?? ""))
}

export function parseOAuthScopeList(value: unknown) {
  const rawItems = Array.isArray(value)
    ? value
    : String(value ?? "")
        .split(/[\s,]+/)

  const requested = Array.from(new Set(
    rawItems
      .map((item) => String(item ?? "").trim())
      .filter(Boolean),
  ))

  return {
    requested,
    supported: requested.filter(isOAuthSupportedScope) as OAuthScope[],
    unsupported: requested.filter((item) => !isOAuthSupportedScope(item)),
  }
}

export function normalizeOAuthScopes(value: unknown, fallback: OAuthScope[] = ["openid", "profile"]): OAuthScope[] {
  const normalized = parseOAuthScopeList(value).supported

  const scopes = normalized.length > 0 ? normalized : fallback
  return scopes.includes("openid") ? scopes : ["openid", ...scopes]
}

export function serializeOAuthScopes(scopes: readonly string[]) {
  return scopes.join(" ")
}

export function normalizeOAuthRedirectUris(value: unknown) {
  const rawItems = Array.isArray(value)
    ? value
    : String(value ?? "")
        .split(/\r?\n|,/)

  return Array.from(new Set(
    rawItems
      .map((item) => normalizeOAuthRedirectUri(item))
      .filter((item): item is string => Boolean(item)),
  ))
}

export function normalizeOAuthRedirectUri(value: unknown) {
  const raw = String(value ?? "").trim()
  if (!raw || raw.length > 2048) {
    return null
  }

  try {
    const url = new URL(raw)
    if (url.hash) {
      return null
    }

    if (url.protocol !== "https:" && !["localhost", "127.0.0.1"].includes(url.hostname)) {
      return null
    }

    return url.toString()
  } catch {
    return null
  }
}

export function isOAuthRedirectUriAllowed(registeredUris: readonly string[], requestedUri: string) {
  const normalizedRequested = normalizeOAuthRedirectUri(requestedUri)
  if (!normalizedRequested) {
    return false
  }

  return registeredUris.some((item) => normalizeOAuthRedirectUri(item) === normalizedRequested)
}

export function createOAuthOpaqueToken(prefix: string, byteLength = 32) {
  return `${prefix}_${randomBytes(byteLength).toString("base64url")}`
}

export function hashOAuthToken(token: string) {
  return createHash("sha256").update(token, "utf8").digest("hex")
}

export function isValidPkceCodeVerifier(value: unknown): value is string {
  const verifier = String(value ?? "")
  return /^[A-Za-z0-9._~-]{43,128}$/.test(verifier)
}

export function isValidPkceS256Challenge(value: unknown): value is string {
  return /^[A-Za-z0-9_-]{43}$/.test(String(value ?? ""))
}

export function isOAuthPkceRequired(clientSecretHash: string | null | undefined) {
  return !clientSecretHash
}

export function readOAuthFormValue(formData: FormData, key: string) {
  const value = formData.get(key)
  return typeof value === "string" ? value.trim() : undefined
}

export function parseOAuthPkceParameters(input: {
  codeChallenge: unknown
  codeChallengeMethod: unknown
}) {
  const codeChallenge = typeof input.codeChallenge === "string" ? input.codeChallenge.trim() : ""
  const codeChallengeMethod = typeof input.codeChallengeMethod === "string" ? input.codeChallengeMethod.trim() : ""
  const isPresent = (input.codeChallenge !== undefined && input.codeChallenge !== null)
    || (input.codeChallengeMethod !== undefined && input.codeChallengeMethod !== null)

  if (!isPresent) {
    return {
      isPresent: false,
      isValid: true,
      codeChallenge: null,
      codeChallengeMethod: null,
    } as const
  }

  if (codeChallengeMethod !== "S256" || !isValidPkceS256Challenge(codeChallenge)) {
    return {
      isPresent: true,
      isValid: false,
      codeChallenge: null,
      codeChallengeMethod: null,
    } as const
  }

  return {
    isPresent: true,
    isValid: true,
    codeChallenge,
    codeChallengeMethod: "S256",
  } as const
}

export function createPkceS256Challenge(verifier: string) {
  return createHash("sha256").update(verifier, "ascii").digest("base64url")
}

export function verifyPkceChallenge(input: {
  verifier: string
  challenge: string
  method: string
}) {
  if (!isValidPkceCodeVerifier(input.verifier)) {
    return false
  }

  if (input.method !== "S256") {
    return false
  }

  const expected = createPkceS256Challenge(input.verifier)
  const left = Buffer.from(expected)
  const right = Buffer.from(input.challenge)
  return left.length === right.length && timingSafeEqual(left, right)
}

export function safeOAuthClientSecretHashCompare(input: {
  secret: string
  secretHash: string | null | undefined
}) {
  if (!input.secret || !input.secretHash) {
    return false
  }

  const expected = Buffer.from(hashOAuthToken(input.secret))
  const actual = Buffer.from(input.secretHash)
  return expected.length === actual.length && timingSafeEqual(expected, actual)
}
