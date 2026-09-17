import { oauthJsonResponse } from "@/lib/oauth-route"

export const dynamic = "force-dynamic"

// ID Tokens use HS256 with each OAuth client's secret. Symmetric keys must
// remain private, so the public JWK Set intentionally contains no keys.
export function GET() {
  return oauthJsonResponse({ keys: [] })
}
