import { OAuthClientStatus, UserStatus } from "@/db/types"

import { executeAddonActionHook } from "@/addons-host/runtime/hooks"
import {
  countOAuthClientsForAdmin,
  createOAuthAuthorizationCode,
  createOAuthClientRecord,
  consumeOAuthAuthorizationCodeAndCreateTokenPair,
  findOAuthAccessTokenByHash,
  findOAuthAuthorizationCodeByHash,
  findOAuthClientById,
  findOAuthClientByClientId,
  findOAuthClientByOwnerAndId,
  findOAuthClientSecretByClientId,
  findOAuthClientsByOwner,
  findOAuthClientsForAdmin,
  findOAuthConsent,
  findOAuthConsentsByUser,
  findOAuthRefreshTokenByHash,
  getOAuthClientSummary,
  revokeOAuthConsentByUser,
  revokeOAuthTokenByHash,
  rotateOAuthRefreshToken,
  updateOAuthClientByAdmin as updateOAuthClientByAdminRecord,
  updateOAuthClientByOwner,
  updateOAuthClientReview,
  updateOAuthClientSecret,
  upsertOAuthConsent,
} from "@/db/oauth-queries"
import { apiError } from "@/lib/api-route"
import { getServerSiteSettings } from "@/lib/site-settings"
import { createOAuthIdToken } from "@/lib/oauth-oidc"
import { normalizeHttpUrl } from "@/lib/shared/url"
import { normalizePageSize, normalizePositiveInteger, normalizeTrimmedText } from "@/lib/shared/normalizers"
import { resolveSiteOrigin } from "@/lib/site-origin"
import { getUserDisplayName } from "@/lib/user-display"
import {
  createOAuthOpaqueToken,
  hashOAuthToken,
  isOAuthPkceRequired,
  isOAuthRedirectUriAllowed,
  isValidPkceCodeVerifier,
  normalizeOAuthRedirectUri,
  normalizeOAuthRedirectUris,
  normalizeOAuthScopes,
  parseOAuthPkceParameters,
  parseOAuthScopeList,
  safeOAuthClientSecretHashCompare,
  serializeOAuthScopes,
  verifyPkceChallenge,
  type OAuthScope,
} from "@/lib/oauth-utils"
import { createSystemNotification } from "@/lib/notification-writes"

type OAuthClientPublicRecord = NonNullable<Awaited<ReturnType<typeof findOAuthClientByClientId>>>

export class OAuthProtocolError extends Error {
  error: string
  status: number
  description?: string

  constructor(error: string, description?: string, status = 400) {
    super(description ?? error)
    this.name = "OAuthProtocolError"
    this.error = error
    this.description = description
    this.status = status
  }
}

export type OAuthAuthorizeError = {
  ok: false
  error: string
  errorDescription: string
  redirectUri?: string
  state?: string
}

export type OAuthAuthorizeSuccess = {
  ok: true
  client: NonNullable<Awaited<ReturnType<typeof findOAuthClientByClientId>>>
  redirectUri: string
  responseType: "code"
  scope: string
  scopes: OAuthScope[]
  state: string | null
  nonce: string | null
  codeChallenge: string | null
  codeChallengeMethod: "S256" | null
  consentRequired: boolean
}

export type OAuthAuthorizeResolution = OAuthAuthorizeSuccess | OAuthAuthorizeError

export interface OAuthClientListItem {
  id: string
  clientId: string
  name: string
  description: string
  homepageUrl: string
  logoUrl: string
  redirectUris: string[]
  scopes: string[]
  status: OAuthClientStatus
  reviewNote: string
  reviewedAt: string | null
  secretRotatedAt: string | null
  createdAt: string
  updatedAt: string
  owner?: {
    id: number
    username: string
    displayName: string
    email: string | null
    status: UserStatus
  }
  reviewer?: {
    id: number
    username: string
    displayName: string
  } | null
}

export interface OAuthClientApplicationResult {
  client: OAuthClientListItem
  clientSecret: string
}

export interface OAuthAuthorizedSiteListItem {
  id: string
  clientId: string
  name: string
  description: string
  homepageUrl: string
  logoUrl: string
  scopes: string[]
  status: OAuthClientStatus
  authorizedAt: string
  updatedAt: string
  activeAccessTokenCount: number
  activeRefreshTokenCount: number
}

export interface OAuthClientAdminPageData {
  clients: OAuthClientListItem[]
  filters: {
    keyword: string
    status: "ALL" | OAuthClientStatus
    page: number
    pageSize: number
  }
  summary: {
    total: number
    pending: number
    approved: number
    rejected: number
    disabled: number
  }
  pagination: {
    page: number
    pageSize: number
    total: number
    totalPages: number
    hasPrevPage: boolean
    hasNextPage: boolean
  }
}

const OAUTH_AUTHORIZATION_CODE_TTL_MS = 10 * 60 * 1000
const CLIENT_NAME_MAX_LENGTH = 80
const CLIENT_DESCRIPTION_MAX_LENGTH = 500
const CLIENT_URL_MAX_LENGTH = 500
const CLIENT_REVIEW_NOTE_MAX_LENGTH = 1000

function ensureOAuthServerEnabled(settings: Awaited<ReturnType<typeof getServerSiteSettings>>) {
  if (!settings.oauthServerEnabled) {
    apiError(403, "OAuth 授权服务未开启")
  }
}

function ensureOAuthApplicationEnabled(settings: Awaited<ReturnType<typeof getServerSiteSettings>>) {
  ensureOAuthServerEnabled(settings)
  if (!settings.oauthClientApplicationEnabled) {
    apiError(403, "当前站点未开放 OAuth 应用申请")
  }
}

function normalizeOptionalUrl(value: unknown) {
  const raw = normalizeTrimmedText(value, CLIENT_URL_MAX_LENGTH)
  if (!raw) {
    return null
  }

  return normalizeHttpUrl(raw, { allowCredentials: false, clearHash: true })
}

function ensureOAuthClientPayload(input: {
  name: unknown
  description?: unknown
  homepageUrl?: unknown
  logoUrl?: unknown
  redirectUris: unknown
  scopes?: unknown
}) {
  const name = normalizeTrimmedText(input.name, CLIENT_NAME_MAX_LENGTH)
  const description = normalizeTrimmedText(input.description, CLIENT_DESCRIPTION_MAX_LENGTH) || null
  const homepageUrl = normalizeOptionalUrl(input.homepageUrl)
  const logoUrl = normalizeOptionalUrl(input.logoUrl)
  const redirectUris = normalizeOAuthRedirectUris(input.redirectUris).slice(0, 20)
  const scopes = normalizeOAuthScopes(input.scopes, ["openid", "profile", "email"])

  if (!name) {
    apiError(400, "应用名称不能为空")
  }

  if (input.homepageUrl && !homepageUrl) {
    apiError(400, "应用主页地址格式不正确")
  }

  if (input.logoUrl && !logoUrl) {
    apiError(400, "应用 Logo 地址格式不正确")
  }

  if (redirectUris.length === 0) {
    apiError(400, "至少填写一个合法的回调地址")
  }

  return {
    name,
    description,
    homepageUrl,
    logoUrl,
    redirectUris,
    scopes,
  }
}

function mapOAuthClient(item: OAuthClientPublicRecord): OAuthClientListItem {
  return {
    id: item.id,
    clientId: item.clientId,
    name: item.name,
    description: item.description ?? "",
    homepageUrl: item.homepageUrl ?? "",
    logoUrl: item.logoUrl ?? "",
    redirectUris: item.redirectUris,
    scopes: item.scopes,
    status: item.status,
    reviewNote: item.reviewNote ?? "",
    reviewedAt: item.reviewedAt?.toISOString() ?? null,
    secretRotatedAt: item.secretRotatedAt?.toISOString() ?? null,
    createdAt: item.createdAt.toISOString(),
    updatedAt: item.updatedAt.toISOString(),
    owner: item.owner
      ? {
          id: item.owner.id,
          username: item.owner.username,
          displayName: getUserDisplayName(item.owner),
          email: item.owner.email ?? null,
          status: item.owner.status,
        }
      : undefined,
    reviewer: item.reviewer
      ? {
          id: item.reviewer.id,
          username: item.reviewer.username,
          displayName: getUserDisplayName(item.reviewer),
        }
      : null,
  }
}

async function executeOAuthClientApplicationChangedHook(input: {
  action: "create" | "resubmit" | "admin-update" | "review" | "rotate-secret"
  client: OAuthClientPublicRecord
  actorUserId?: number
  previousStatus?: OAuthClientStatus
  reviewAction?: "approve" | "reject" | "disable"
}) {
  await executeAddonActionHook("oauth.client.application.changed", {
    action: input.action,
    applicationId: input.client.id,
    clientId: input.client.clientId,
    ownerId: input.client.ownerId,
    actorUserId: input.actorUserId,
    name: input.client.name,
    homepageUrl: input.client.homepageUrl,
    redirectUris: [...input.client.redirectUris],
    scopes: [...input.client.scopes],
    status: input.client.status,
    previousStatus: input.previousStatus,
    nextStatus: input.client.status,
    reviewAction: input.reviewAction,
    reviewedById: input.client.reviewedById,
    occurredAt: new Date().toISOString(),
  })
}

function normalizeAdminStatus(value: unknown): "ALL" | OAuthClientStatus {
  if (value === OAuthClientStatus.PENDING || value === OAuthClientStatus.APPROVED || value === OAuthClientStatus.REJECTED || value === OAuthClientStatus.DISABLED) {
    return value
  }

  return "ALL"
}

function generateClientCredentials() {
  const clientId = createOAuthOpaqueToken("app", 18)
  const clientSecret = createOAuthOpaqueToken("key", 36)

  return {
    clientId,
    clientSecret,
    clientSecretHash: hashOAuthToken(clientSecret),
  }
}

export async function getOAuthClientApplicationPageData(userId: number) {
  const [settings, clients, authorizedSites] = await Promise.all([
    getServerSiteSettings(),
    findOAuthClientsByOwner(userId),
    findOAuthConsentsByUser(userId),
  ])

  return {
    enabled: settings.oauthServerEnabled && settings.oauthClientApplicationEnabled,
    oauthServerEnabled: settings.oauthServerEnabled,
    oauthClientApplicationEnabled: settings.oauthClientApplicationEnabled,
    clients: clients.map(mapOAuthClient),
    authorizedSites: authorizedSites.map((item): OAuthAuthorizedSiteListItem => ({
      id: item.id,
      clientId: item.clientId,
      name: item.client.name,
      description: item.client.description ?? "",
      homepageUrl: item.client.homepageUrl ?? "",
      logoUrl: item.client.logoUrl ?? "",
      scopes: item.scopes,
      status: item.client.status,
      authorizedAt: item.createdAt.toISOString(),
      updatedAt: item.updatedAt.toISOString(),
      activeAccessTokenCount: item.client._count.accessTokens,
      activeRefreshTokenCount: item.client._count.refreshTokens,
    })),
    supportedScopes: ["openid", "profile", "email"] as const,
  }
}

export async function revokeOwnOAuthConsent(input: {
  userId: number
  clientId: unknown
}) {
  const clientId = normalizeTrimmedText(input.clientId, 200)
  if (!clientId) {
    apiError(400, "缺少 OAuth 应用 ID")
  }

  const count = await revokeOAuthConsentByUser({
    userId: input.userId,
    clientId,
  })

  if (count < 1) {
    apiError(404, "授权记录不存在")
  }
}

export async function applyForOAuthClient(input: {
  ownerId: number
  name: unknown
  description?: unknown
  homepageUrl?: unknown
  logoUrl?: unknown
  redirectUris: unknown
  scopes?: unknown
}): Promise<OAuthClientApplicationResult> {
  ensureOAuthApplicationEnabled(await getServerSiteSettings())

  const payload = ensureOAuthClientPayload(input)
  const credentials = generateClientCredentials()
  const client = await createOAuthClientRecord({
    ownerId: input.ownerId,
    clientId: credentials.clientId,
    clientSecretHash: credentials.clientSecretHash,
    name: payload.name,
    description: payload.description,
    homepageUrl: payload.homepageUrl,
    logoUrl: payload.logoUrl,
    redirectUris: payload.redirectUris,
    scopes: payload.scopes,
    status: OAuthClientStatus.PENDING,
  })
  await executeOAuthClientApplicationChangedHook({
    action: "create",
    client,
    actorUserId: input.ownerId,
  })

  return {
    client: mapOAuthClient(client),
    clientSecret: credentials.clientSecret,
  }
}

export async function updateOwnOAuthClient(input: {
  ownerId: number
  id: string
  name: unknown
  description?: unknown
  homepageUrl?: unknown
  logoUrl?: unknown
  redirectUris: unknown
  scopes?: unknown
}) {
  ensureOAuthApplicationEnabled(await getServerSiteSettings())

  const existing = await findOAuthClientByOwnerAndId(input.ownerId, input.id)
  if (!existing) {
    apiError(404, "OAuth 应用不存在")
  }

  if (existing.status !== OAuthClientStatus.PENDING && existing.status !== OAuthClientStatus.REJECTED) {
    apiError(400, "只有待审核或已驳回的应用可以由申请人修改")
  }

  const payload = ensureOAuthClientPayload(input)
  const updated = await updateOAuthClientByOwner({
    id: input.id,
    ownerId: input.ownerId,
    data: {
      ...payload,
      status: OAuthClientStatus.PENDING,
      reviewNote: null,
      reviewedById: null,
      reviewedAt: null,
    },
  })

  if (updated.count !== 1) {
    apiError(409, "应用状态已变化，请刷新后重试")
  }

  const updatedClient = await findOAuthClientById(input.id)
  if (updatedClient) {
    await executeOAuthClientApplicationChangedHook({
      action: "resubmit",
      client: updatedClient,
      actorUserId: input.ownerId,
      previousStatus: existing.status,
    })
  }
}

export async function rotateOwnOAuthClientSecret(input: {
  ownerId: number
  id: string
}) {
  ensureOAuthApplicationEnabled(await getServerSiteSettings())

  const existing = await findOAuthClientByOwnerAndId(input.ownerId, input.id)
  if (!existing) {
    apiError(404, "OAuth 应用不存在")
  }

  const clientSecret = createOAuthOpaqueToken("key", 36)
  const updated = await updateOAuthClientSecret({
    id: input.id,
    ownerId: input.ownerId,
    secretHash: hashOAuthToken(clientSecret),
  })

  if (updated.count !== 1) {
    apiError(409, "应用状态已变化，请刷新后重试")
  }

  await executeOAuthClientApplicationChangedHook({
    action: "rotate-secret",
    client: existing,
    actorUserId: input.ownerId,
    previousStatus: existing.status,
  })

  return { clientSecret }
}

export async function getAdminOAuthClientPageData(input: {
  keyword?: unknown
  status?: unknown
  page?: unknown
  pageSize?: unknown
} = {}): Promise<OAuthClientAdminPageData> {
  const keyword = normalizeTrimmedText(input.keyword, 100)
  const status = normalizeAdminStatus(input.status)
  const pageSize = normalizePageSize(input.pageSize, [20, 50, 100], 20)
  const requestedPage = normalizePositiveInteger(input.page, 1)
  const [total, summaryRows] = await Promise.all([
    countOAuthClientsForAdmin({ keyword, status }),
    getOAuthClientSummary(),
  ])
  const totalPages = Math.max(1, Math.ceil(total / pageSize))
  const page = Math.min(requestedPage, totalPages)
  const clients = await findOAuthClientsForAdmin({
    keyword,
    status,
    skip: (page - 1) * pageSize,
    take: pageSize,
  })
  const summary = {
    total: 0,
    pending: 0,
    approved: 0,
    rejected: 0,
    disabled: 0,
  }

  for (const row of summaryRows) {
    summary.total += row._count._all
    if (row.status === OAuthClientStatus.PENDING) {
      summary.pending += row._count._all
    } else if (row.status === OAuthClientStatus.APPROVED) {
      summary.approved += row._count._all
    } else if (row.status === OAuthClientStatus.REJECTED) {
      summary.rejected += row._count._all
    } else if (row.status === OAuthClientStatus.DISABLED) {
      summary.disabled += row._count._all
    }
  }

  return {
    clients: clients.map(mapOAuthClient),
    filters: {
      keyword,
      status,
      page,
      pageSize,
    },
    summary,
    pagination: {
      page,
      pageSize,
      total,
      totalPages,
      hasPrevPage: page > 1,
      hasNextPage: page < totalPages,
    },
  }
}

export async function reviewOAuthClient(input: {
  id: string
  reviewerId: number
  action: "approve" | "reject" | "disable"
  reviewNote?: unknown
}) {
  ensureOAuthServerEnabled(await getServerSiteSettings())

  const client = await findOAuthClientById(input.id)
  if (!client) {
    apiError(404, "OAuth 应用不存在")
  }

  const reviewNote = normalizeTrimmedText(input.reviewNote, CLIENT_REVIEW_NOTE_MAX_LENGTH) || null
  const nextStatus = input.action === "approve"
    ? OAuthClientStatus.APPROVED
    : input.action === "reject"
      ? OAuthClientStatus.REJECTED
      : OAuthClientStatus.DISABLED

  if (input.action === "approve" && client.status !== OAuthClientStatus.PENDING) {
    apiError(400, "只有待审核应用可以通过")
  }

  if (input.action === "reject" && client.status !== OAuthClientStatus.PENDING) {
    apiError(400, "只有待审核应用可以驳回")
  }

  if (input.action === "disable" && client.status !== OAuthClientStatus.APPROVED) {
    apiError(400, "只有已通过应用可以禁用")
  }

  const updated = await updateOAuthClientReview({
    id: input.id,
    reviewerId: input.reviewerId,
    status: nextStatus,
    reviewNote,
  })

  await createSystemNotification({
    userId: updated.ownerId,
    senderId: input.reviewerId,
    relatedType: "ANNOUNCEMENT",
    relatedId: updated.id,
    title: input.action === "approve"
      ? "你的 OAuth 应用已通过审核"
      : input.action === "reject"
        ? "你的 OAuth 应用未通过审核"
        : "你的 OAuth 应用已被禁用",
    content: input.action === "approve"
      ? `你提交的 OAuth 应用“${updated.name}”已通过审核，现在可以用于第三方授权登录。`
      : input.action === "reject"
        ? `你提交的 OAuth 应用“${updated.name}”未通过审核。${reviewNote ? `审核备注：${reviewNote}` : "请修改后重新提交。"}`
        : `你的 OAuth 应用“${updated.name}”已被管理员禁用。${reviewNote ? `原因：${reviewNote}` : ""}`,
    url: "/settings?tab=oauth-apps",
  })
  await executeOAuthClientApplicationChangedHook({
    action: "review",
    client: updated,
    actorUserId: input.reviewerId,
    previousStatus: client.status,
    reviewAction: input.action,
  })

  return mapOAuthClient(updated)
}

export async function rotateOAuthClientSecretByAdmin(input: {
  id: string
}) {
  const existing = await findOAuthClientById(input.id)
  if (!existing) {
    apiError(404, "OAuth 应用不存在")
  }

  const clientSecret = createOAuthOpaqueToken("key", 36)
  const updated = await updateOAuthClientSecret({
    id: input.id,
    secretHash: hashOAuthToken(clientSecret),
  })

  if (updated.count !== 1) {
    apiError(404, "OAuth 应用不存在")
  }

  await executeOAuthClientApplicationChangedHook({
    action: "rotate-secret",
    client: existing,
    previousStatus: existing.status,
  })

  return { clientSecret }
}

export async function updateOAuthClientByAdmin(input: {
  id: string
  name: unknown
  description?: unknown
  homepageUrl?: unknown
  logoUrl?: unknown
  redirectUris: unknown
  scopes?: unknown
}) {
  ensureOAuthServerEnabled(await getServerSiteSettings())

  const id = normalizeTrimmedText(input.id, 200)
  if (!id) {
    apiError(400, "缺少 OAuth 应用 ID")
  }

  const existing = await findOAuthClientById(id)
  if (!existing) {
    apiError(404, "OAuth 应用不存在")
  }

  const payload = ensureOAuthClientPayload(input)
  const updated = await updateOAuthClientByAdminRecord({
    id,
    data: payload,
  })
  await executeOAuthClientApplicationChangedHook({
    action: "admin-update",
    client: updated,
    previousStatus: existing.status,
  })

  return mapOAuthClient(updated)
}

function validateAuthorizationScopes(input: {
  requestedScope: unknown
  clientScopes: readonly string[]
}) {
  const parsed = parseOAuthScopeList(input.requestedScope)
  if (parsed.unsupported.length > 0) {
    throw new OAuthProtocolError("invalid_scope", `不支持的 scope：${parsed.unsupported.join(" ")}`)
  }

  const scopes: OAuthScope[] = normalizeOAuthScopes(input.requestedScope)
  const allowed = new Set(input.clientScopes)
  const notAllowed = scopes.filter((scope) => !allowed.has(scope))
  if (notAllowed.length > 0) {
    throw new OAuthProtocolError("invalid_scope", `应用未被允许请求 scope：${notAllowed.join(" ")}`)
  }

  return scopes
}

function buildAuthorizeError(options: {
  error: string
  errorDescription: string
  redirectUri?: string
  state?: string | null
}): OAuthAuthorizeError {
  return {
    ok: false,
    error: options.error,
    errorDescription: options.errorDescription,
    ...(options.redirectUri ? { redirectUri: options.redirectUri } : {}),
    ...(options.state ? { state: options.state } : {}),
  }
}

export async function resolveOAuthAuthorizationRequest(input: {
  clientId: unknown
  redirectUri: unknown
  responseType: unknown
  scope: unknown
  state?: unknown
  nonce?: unknown
  codeChallenge: unknown
  codeChallengeMethod: unknown
  currentUserId?: number | null
}): Promise<OAuthAuthorizeResolution> {
  const settings = await getServerSiteSettings()
  if (!settings.oauthServerEnabled) {
    return buildAuthorizeError({
      error: "server_error",
      errorDescription: "OAuth 授权服务未开启",
    })
  }

  const clientId = normalizeTrimmedText(input.clientId, 200)
  const requestedRedirectUri = normalizeTrimmedText(input.redirectUri, 2048)
  const state = normalizeTrimmedText(input.state, 500) || null
  const nonce = normalizeTrimmedText(input.nonce, 500) || null
  const pkce = parseOAuthPkceParameters(input)

  if (!clientId) {
    return buildAuthorizeError({ error: "invalid_request", errorDescription: "缺少 client_id" })
  }

  const client = await findOAuthClientByClientId(clientId)
  if (!client || client.status !== OAuthClientStatus.APPROVED) {
    return buildAuthorizeError({ error: "unauthorized_client", errorDescription: "OAuth 应用不存在或未通过审核" })
  }

  const redirectUri = normalizeOAuthRedirectUri(requestedRedirectUri)
  if (!redirectUri || !isOAuthRedirectUriAllowed(client.redirectUris, redirectUri)) {
    return buildAuthorizeError({ error: "invalid_request", errorDescription: "redirect_uri 不匹配" })
  }

  if (input.responseType !== "code") {
    return buildAuthorizeError({ error: "unsupported_response_type", errorDescription: "仅支持 response_type=code", redirectUri, state })
  }

  if (!pkce.isValid) {
    return buildAuthorizeError({ error: "invalid_request", errorDescription: "必须使用 PKCE S256", redirectUri, state })
  }

  if (!pkce.isPresent) {
    const clientAuthentication = await findOAuthClientSecretByClientId(clientId)
    if (!clientAuthentication || clientAuthentication.status !== OAuthClientStatus.APPROVED) {
      return buildAuthorizeError({ error: "unauthorized_client", errorDescription: "OAuth 应用不存在或未通过审核", redirectUri, state })
    }

    if (isOAuthPkceRequired(clientAuthentication.clientSecretHash)) {
      return buildAuthorizeError({ error: "invalid_request", errorDescription: "公共客户端必须使用 PKCE S256", redirectUri, state })
    }
  }

  try {
    const scopes = validateAuthorizationScopes({
      requestedScope: input.scope,
      clientScopes: client.scopes,
    })
    const consent = input.currentUserId ? await findOAuthConsent(client.clientId, input.currentUserId) : null
    const consentScopes = new Set(consent?.scopes ?? [])
    const consentRequired = !input.currentUserId || scopes.some((scope) => !consentScopes.has(scope))

    return {
      ok: true,
      client,
      redirectUri,
      responseType: "code",
      scope: serializeOAuthScopes(scopes),
      scopes,
      state,
      nonce,
      codeChallenge: pkce.codeChallenge,
      codeChallengeMethod: pkce.codeChallengeMethod,
      consentRequired,
    }
  } catch (error) {
    if (error instanceof OAuthProtocolError) {
      return buildAuthorizeError({
        error: error.error,
        errorDescription: error.description ?? error.error,
        redirectUri,
        state,
      })
    }

    throw error
  }
}

export async function issueOAuthAuthorizationCode(input: {
  currentUserId: number
  clientId: unknown
  redirectUri: unknown
  responseType: unknown
  scope: unknown
  state?: unknown
  nonce?: unknown
  codeChallenge: unknown
  codeChallengeMethod: unknown
}) {
  const resolved = await resolveOAuthAuthorizationRequest({
    ...input,
    currentUserId: input.currentUserId,
  })

  if (!resolved.ok) {
    throw new OAuthProtocolError(resolved.error, resolved.errorDescription)
  }

  const code = createOAuthOpaqueToken("code", 32)
  await createOAuthAuthorizationCode({
    codeHash: hashOAuthToken(code),
    clientId: resolved.client.clientId,
    userId: input.currentUserId,
    redirectUri: resolved.redirectUri,
    scopes: resolved.scopes,
    codeChallenge: resolved.codeChallenge,
    codeChallengeMethod: resolved.codeChallengeMethod,
    nonce: resolved.nonce,
    state: resolved.state,
    expiresAt: new Date(Date.now() + OAUTH_AUTHORIZATION_CODE_TTL_MS),
  })
  await upsertOAuthConsent({
    clientId: resolved.client.clientId,
    userId: input.currentUserId,
    scopes: resolved.scopes,
  })

  return {
    code,
    redirectUri: resolved.redirectUri,
    state: resolved.state,
  }
}

function parseBasicClientCredentials(authorizationHeader: string | null) {
  if (!authorizationHeader?.toLowerCase().startsWith("basic ")) {
    return null
  }

  try {
    const decoded = Buffer.from(authorizationHeader.slice("basic ".length), "base64").toString("utf8")
    const separatorIndex = decoded.indexOf(":")
    if (separatorIndex < 0) {
      return null
    }

    return {
      clientId: decodeURIComponent(decoded.slice(0, separatorIndex)),
      clientSecret: decodeURIComponent(decoded.slice(separatorIndex + 1)),
    }
  } catch {
    return null
  }
}

function getFormValue(formData: FormData, key: string) {
  const value = formData.get(key)
  return typeof value === "string" ? value.trim() : ""
}

async function authenticateTokenClient(input: {
  authorizationHeader: string | null
  formData: FormData
}) {
  const basic = parseBasicClientCredentials(input.authorizationHeader)
  const clientId = basic?.clientId || getFormValue(input.formData, "client_id")
  const clientSecret = basic?.clientSecret || getFormValue(input.formData, "client_secret")

  if (!clientId) {
    throw new OAuthProtocolError("invalid_client", "缺少 client_id", 401)
  }

  const client = await findOAuthClientSecretByClientId(clientId)
  if (!client || client.status !== OAuthClientStatus.APPROVED) {
    throw new OAuthProtocolError("invalid_client", "客户端不存在或未启用", 401)
  }

  if (client.clientSecretHash && !clientSecret) {
    throw new OAuthProtocolError("invalid_client", "缺少 client_secret", 401)
  }

  if (client.clientSecretHash && !safeOAuthClientSecretHashCompare({ secret: clientSecret, secretHash: client.clientSecretHash })) {
    throw new OAuthProtocolError("invalid_client", "client_secret 不正确", 401)
  }

  return {
    clientId: client.clientId,
    clientSecret: client.clientSecretHash ? clientSecret || null : null,
  }
}

function buildTokenResponse(input: {
  accessToken: string
  refreshToken: string
  expiresIn: number
  scopes: readonly string[]
  idToken?: string
}) {
  return {
    access_token: input.accessToken,
    token_type: "Bearer",
    expires_in: input.expiresIn,
    refresh_token: input.refreshToken,
    scope: serializeOAuthScopes(input.scopes),
    ...(input.idToken ? { id_token: input.idToken } : {}),
  }
}

export async function exchangeOAuthToken(input: {
  authorizationHeader: string | null
  formData: FormData
}) {
  const settings = await getServerSiteSettings()
  if (!settings.oauthServerEnabled) {
    throw new OAuthProtocolError("server_error", "OAuth 授权服务未开启", 503)
  }

  const grantType = getFormValue(input.formData, "grant_type")
  const authenticatedClient = await authenticateTokenClient(input)

  if (grantType === "authorization_code") {
    return exchangeAuthorizationCode({
      formData: input.formData,
      clientId: authenticatedClient.clientId,
      clientSecret: authenticatedClient.clientSecret,
      settings,
    })
  }

  if (grantType === "refresh_token") {
    return exchangeRefreshToken({
      formData: input.formData,
      clientId: authenticatedClient.clientId,
      clientSecret: authenticatedClient.clientSecret,
      settings,
    })
  }

  throw new OAuthProtocolError("unsupported_grant_type", "仅支持 authorization_code 和 refresh_token")
}

async function exchangeAuthorizationCode(input: {
  formData: FormData
  clientId: string
  clientSecret: string | null
  settings: Awaited<ReturnType<typeof getServerSiteSettings>>
}) {
  const code = getFormValue(input.formData, "code")
  const redirectUri = getFormValue(input.formData, "redirect_uri")
  const codeVerifier = getFormValue(input.formData, "code_verifier")

  if (!code || !redirectUri) {
    throw new OAuthProtocolError("invalid_request", "缺少 code 或 redirect_uri")
  }

  const authorizationCode = await findOAuthAuthorizationCodeByHash(hashOAuthToken(code))
  if (!authorizationCode || authorizationCode.clientId !== input.clientId) {
    throw new OAuthProtocolError("invalid_grant", "授权码无效")
  }

  if (authorizationCode.consumedAt || authorizationCode.expiresAt.getTime() <= Date.now()) {
    throw new OAuthProtocolError("invalid_grant", "授权码已过期或已使用")
  }

  if (authorizationCode.redirectUri !== normalizeOAuthRedirectUri(redirectUri)) {
    throw new OAuthProtocolError("invalid_grant", "redirect_uri 不匹配")
  }

  if (authorizationCode.client.status !== OAuthClientStatus.APPROVED) {
    throw new OAuthProtocolError("invalid_client", "客户端已停用", 401)
  }

  if (authorizationCode.codeChallenge || authorizationCode.codeChallengeMethod) {
    if (!authorizationCode.codeChallenge || authorizationCode.codeChallengeMethod !== "S256") {
      throw new OAuthProtocolError("invalid_grant", "授权码 PKCE 参数无效")
    }

    if (!codeVerifier) {
      throw new OAuthProtocolError("invalid_request", "缺少 code_verifier")
    }

    if (!isValidPkceCodeVerifier(codeVerifier)) {
      throw new OAuthProtocolError("invalid_grant", "code_verifier 格式不正确")
    }

    if (!verifyPkceChallenge({
      verifier: codeVerifier,
      challenge: authorizationCode.codeChallenge,
      method: authorizationCode.codeChallengeMethod,
    })) {
      throw new OAuthProtocolError("invalid_grant", "PKCE 校验失败")
    }
  } else if (codeVerifier) {
    throw new OAuthProtocolError("invalid_grant", "授权码未启用 PKCE")
  }

  const accessToken = createOAuthOpaqueToken("atk", 32)
  const refreshToken = createOAuthOpaqueToken("rtk", 36)
  const expiresIn = Math.max(60, Math.floor(input.settings.oauthAccessTokenTtlMinutes * 60))
  const accessTokenExpiresAt = new Date(Date.now() + expiresIn * 1000)
  const refreshTokenExpiresAt = new Date(Date.now() + input.settings.oauthRefreshTokenTtlDays * 24 * 60 * 60 * 1000)
  let idToken: string | undefined
  if (authorizationCode.scopes.includes("openid")) {
    if (!input.clientSecret) {
      throw new OAuthProtocolError("invalid_client", "OIDC 登录需要配置客户端密钥", 401)
    }

    idToken = createOAuthIdToken({
      issuer: await resolveSiteOrigin(),
      clientId: authorizationCode.clientId,
      subject: authorizationCode.userId,
      clientSecret: input.clientSecret,
      expiresIn,
      nonce: authorizationCode.nonce,
    })
  }

  const created = await consumeOAuthAuthorizationCodeAndCreateTokenPair({
    authorizationCodeId: authorizationCode.id,
    accessTokenHash: hashOAuthToken(accessToken),
    refreshTokenHash: hashOAuthToken(refreshToken),
    clientId: authorizationCode.clientId,
    userId: authorizationCode.userId,
    scopes: authorizationCode.scopes,
    accessTokenExpiresAt,
    refreshTokenExpiresAt,
  })

  if (!created) {
    throw new OAuthProtocolError("invalid_grant", "授权码已使用")
  }

  return buildTokenResponse({
    accessToken,
    refreshToken,
    expiresIn,
    scopes: authorizationCode.scopes,
    idToken,
  })
}

async function exchangeRefreshToken(input: {
  formData: FormData
  clientId: string
  clientSecret: string | null
  settings: Awaited<ReturnType<typeof getServerSiteSettings>>
}) {
  const refreshTokenValue = getFormValue(input.formData, "refresh_token")
  if (!refreshTokenValue) {
    throw new OAuthProtocolError("invalid_request", "缺少 refresh_token")
  }

  const refreshToken = await findOAuthRefreshTokenByHash(hashOAuthToken(refreshTokenValue))
  if (!refreshToken || refreshToken.clientId !== input.clientId) {
    throw new OAuthProtocolError("invalid_grant", "refresh_token 无效")
  }

  if (refreshToken.revokedAt || refreshToken.rotatedAt || refreshToken.expiresAt.getTime() <= Date.now()) {
    throw new OAuthProtocolError("invalid_grant", "refresh_token 已失效")
  }

  if (refreshToken.client.status !== OAuthClientStatus.APPROVED) {
    throw new OAuthProtocolError("invalid_client", "客户端已停用", 401)
  }

  const accessToken = createOAuthOpaqueToken("atk", 32)
  const nextRefreshToken = createOAuthOpaqueToken("rtk", 36)
  const expiresIn = Math.max(60, Math.floor(input.settings.oauthAccessTokenTtlMinutes * 60))
  const accessTokenExpiresAt = new Date(Date.now() + expiresIn * 1000)
  const refreshTokenExpiresAt = new Date(Date.now() + input.settings.oauthRefreshTokenTtlDays * 24 * 60 * 60 * 1000)
  let idToken: string | undefined
  if (refreshToken.scopes.includes("openid")) {
    if (!input.clientSecret) {
      throw new OAuthProtocolError("invalid_client", "OIDC 登录需要配置客户端密钥", 401)
    }

    idToken = createOAuthIdToken({
      issuer: await resolveSiteOrigin(),
      clientId: refreshToken.clientId,
      subject: refreshToken.userId,
      clientSecret: input.clientSecret,
      expiresIn,
    })
  }
  const rotated = await rotateOAuthRefreshToken({
    oldRefreshTokenId: refreshToken.id,
    oldAccessTokenId: refreshToken.accessTokenId,
    accessTokenHash: hashOAuthToken(accessToken),
    refreshTokenHash: hashOAuthToken(nextRefreshToken),
    clientId: refreshToken.clientId,
    userId: refreshToken.userId,
    scopes: refreshToken.scopes,
    accessTokenExpiresAt,
    refreshTokenExpiresAt,
  })

  if (!rotated) {
    throw new OAuthProtocolError("invalid_grant", "refresh_token 已被使用")
  }

  return buildTokenResponse({
    accessToken,
    refreshToken: nextRefreshToken,
    expiresIn,
    scopes: refreshToken.scopes,
    idToken,
  })
}

export async function revokeOAuthToken(input: {
  authorizationHeader: string | null
  formData: FormData
}) {
  const settings = await getServerSiteSettings()
  if (!settings.oauthServerEnabled) {
    throw new OAuthProtocolError("server_error", "OAuth 授权服务未开启", 503)
  }

  const authenticatedClient = await authenticateTokenClient(input)
  const token = getFormValue(input.formData, "token")
  const tokenTypeHint = getFormValue(input.formData, "token_type_hint")

  if (!token) {
    throw new OAuthProtocolError("invalid_request", "缺少 token")
  }

  await revokeOAuthTokenByHash(hashOAuthToken(token), authenticatedClient.clientId, tokenTypeHint)
}

export async function resolveOAuthUserinfo(input: {
  authorizationHeader: string | null
}) {
  const settings = await getServerSiteSettings()
  if (!settings.oauthServerEnabled) {
    throw new OAuthProtocolError("server_error", "OAuth 授权服务未开启", 503)
  }

  const header = input.authorizationHeader ?? ""
  const matched = header.match(/^Bearer\s+(.+)$/i)
  if (!matched?.[1]) {
    throw new OAuthProtocolError("invalid_token", "缺少 Bearer token", 401)
  }

  const accessToken = await findOAuthAccessTokenByHash(hashOAuthToken(matched[1].trim()))
  if (!accessToken || accessToken.revokedAt || accessToken.expiresAt.getTime() <= Date.now()) {
    throw new OAuthProtocolError("invalid_token", "access_token 无效或已过期", 401)
  }

  if (accessToken.client.status !== OAuthClientStatus.APPROVED || accessToken.user.status !== UserStatus.ACTIVE) {
    throw new OAuthProtocolError("invalid_token", "token 当前不可用", 401)
  }

  const scopes = new Set(accessToken.scopes)
  const response: Record<string, unknown> = {
    sub: String(accessToken.user.id),
  }

  if (scopes.has("profile")) {
    response.name = getUserDisplayName(accessToken.user)
    response.preferred_username = accessToken.user.username
    response.picture = accessToken.user.avatarPath ?? null
    response.updated_at = Math.floor(accessToken.user.updatedAt.getTime() / 1000)
  }

  if (scopes.has("email")) {
    response.email = accessToken.user.email ?? null
    response.email_verified = Boolean(accessToken.user.emailVerifiedAt)
  }

  return response
}

export function buildOAuthRedirectWithError(input: {
  redirectUri: string
  error: string
  errorDescription?: string
  state?: string | null
}) {
  const url = new URL(input.redirectUri)
  url.searchParams.set("error", input.error)
  if (input.errorDescription) {
    url.searchParams.set("error_description", input.errorDescription)
  }
  if (input.state) {
    url.searchParams.set("state", input.state)
  }
  return url.toString()
}

export function buildOAuthRedirectWithCode(input: {
  redirectUri: string
  code: string
  state?: string | null
}) {
  const url = new URL(input.redirectUri)
  url.searchParams.set("code", input.code)
  if (input.state) {
    url.searchParams.set("state", input.state)
  }
  return url.toString()
}
