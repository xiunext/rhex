import { redirect } from "next/navigation"

import { getSessionActorFromRequest } from "@/lib/auth"
import { buildLoginHrefWithRedirect, normalizeAuthRedirectTarget } from "@/lib/auth-redirect"
import {
  buildOAuthRedirectWithCode,
  buildOAuthRedirectWithError,
  issueOAuthAuthorizationCode,
  OAuthProtocolError,
  resolveOAuthAuthorizationRequest,
} from "@/lib/oauth-server"
import { readOAuthFormValue } from "@/lib/oauth-utils"

function getFormValue(formData: FormData, key: string) {
  const value = formData.get(key)
  return typeof value === "string" ? value.trim() : ""
}

export async function POST(request: Request) {
  const formData = await request.formData()
  const currentUser = await getSessionActorFromRequest(request)
  const continuePath = normalizeAuthRedirectTarget(getFormValue(formData, "continue"), "/oauth/authorize")

  if (!currentUser) {
    redirect(buildLoginHrefWithRedirect(continuePath))
  }

  if (currentUser.status !== "ACTIVE") {
    redirect("/")
  }

  const params = {
    clientId: getFormValue(formData, "client_id"),
    redirectUri: getFormValue(formData, "redirect_uri"),
    responseType: getFormValue(formData, "response_type"),
    scope: getFormValue(formData, "scope"),
    state: getFormValue(formData, "state"),
    nonce: getFormValue(formData, "nonce"),
    codeChallenge: readOAuthFormValue(formData, "code_challenge"),
    codeChallengeMethod: readOAuthFormValue(formData, "code_challenge_method"),
  }

  const resolved = await resolveOAuthAuthorizationRequest({
    ...params,
    currentUserId: currentUser.id,
  })

  if (!resolved.ok) {
    if (resolved.redirectUri) {
      redirect(buildOAuthRedirectWithError({
        redirectUri: resolved.redirectUri,
        error: resolved.error,
        errorDescription: resolved.errorDescription,
        state: resolved.state,
      }))
    }

    redirect(continuePath)
  }

  if (getFormValue(formData, "decision") !== "approve") {
    redirect(buildOAuthRedirectWithError({
      redirectUri: resolved.redirectUri,
      error: "access_denied",
      errorDescription: "用户拒绝授权",
      state: resolved.state,
    }))
  }

  try {
    const result = await issueOAuthAuthorizationCode({
      currentUserId: currentUser.id,
      ...params,
    })

    redirect(buildOAuthRedirectWithCode({
      redirectUri: result.redirectUri,
      code: result.code,
      state: result.state,
    }))
  } catch (error) {
    if (error instanceof OAuthProtocolError) {
      redirect(buildOAuthRedirectWithError({
        redirectUri: resolved.redirectUri,
        error: error.error,
        errorDescription: error.description,
        state: resolved.state,
      }))
    }

    throw error
  }
}
