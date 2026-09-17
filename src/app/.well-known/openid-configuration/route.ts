import { buildOpenIdConfiguration } from "@/lib/oauth-oidc-metadata"
import { oauthJsonResponse } from "@/lib/oauth-route"
import { resolveSiteOrigin } from "@/lib/site-origin"

export const dynamic = "force-dynamic"

export async function GET() {
  return oauthJsonResponse(buildOpenIdConfiguration(await resolveSiteOrigin()))
}
