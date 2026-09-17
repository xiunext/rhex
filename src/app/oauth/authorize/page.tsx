import type { Metadata } from "next"
import Link from "next/link"
import { redirect } from "next/navigation"
import { ArrowRight, Check, ExternalLink, ShieldCheck, TriangleAlert, X } from "lucide-react"

import {
  Avatar,
  AvatarFallback,
  AvatarImage,
} from "@/components/ui/avatar"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import { getCurrentUser } from "@/lib/auth"
import { buildLoginHrefWithRedirect } from "@/lib/auth-redirect"
import {
  buildOAuthRedirectWithError,
  resolveOAuthAuthorizationRequest,
  type OAuthAuthorizeError,
  type OAuthAuthorizeSuccess,
} from "@/lib/oauth-server"
import { readSearchParam } from "@/lib/search-params"
import { resolveSiteMarkImagePath } from "@/lib/site-branding"
import { getSiteSettings } from "@/lib/site-settings"

type OAuthAuthorizeSearchParams = Record<string, string | string[] | undefined>

export async function generateMetadata(): Promise<Metadata> {
  const settings = await getSiteSettings()

  return {
    title: `OAuth 授权 - ${settings.siteName}`,
  }
}

export default async function OAuthAuthorizePage(props: { searchParams: Promise<OAuthAuthorizeSearchParams> }) {
  const [searchParams, user, settings] = await Promise.all([
    props.searchParams,
    getCurrentUser(),
    getSiteSettings(),
  ])
  const currentPath = `/oauth/authorize?${new URLSearchParams(toStringSearchParams(searchParams)).toString()}`

  if (!user) {
    redirect(buildLoginHrefWithRedirect(currentPath))
  }

  if (user.status !== "ACTIVE") {
    return (
      <main className="mx-auto flex min-h-[calc(100dvh-8rem)] w-full max-w-md items-center px-4 py-6">
        <Card className="w-full">
          <CardHeader className="border-b">
            <CardTitle>账号状态不可授权</CardTitle>
            <CardDescription>当前账号不是正常状态，无法继续 OAuth 授权。</CardDescription>
          </CardHeader>
          <CardFooter className="justify-end">
            <Button type="button" variant="outline" nativeButton={false} render={<Link href="/" />}>返回首页</Button>
          </CardFooter>
        </Card>
      </main>
    )
  }

  const resolved = await resolveOAuthAuthorizationRequest({
    clientId: readSearchParam(searchParams.client_id),
    redirectUri: readSearchParam(searchParams.redirect_uri),
    responseType: readSearchParam(searchParams.response_type),
    scope: readSearchParam(searchParams.scope),
    state: readSearchParam(searchParams.state),
    nonce: readSearchParam(searchParams.nonce),
    codeChallenge: readSearchParam(searchParams.code_challenge),
    codeChallengeMethod: readSearchParam(searchParams.code_challenge_method),
    currentUserId: user.id,
  })

  return (
    <main className="mx-auto flex min-h-[calc(100dvh-8rem)] w-full max-w-2xl items-center px-4 py-6">
      {resolved.ok ? (
        <AuthorizeCard
          resolved={resolved}
          currentPath={currentPath}
          site={{
            name: settings.siteName,
            logoText: settings.siteLogoText,
            logoPath: settings.siteLogoPath,
            iconPath: settings.siteIconPath,
          }}
          user={{
            username: user.username,
            displayName: user.nickname ?? user.username,
            avatarPath: user.avatarPath,
          }}
        />
      ) : (
        <AuthorizeErrorCard resolved={resolved} />
      )}
    </main>
  )
}

function AuthorizeCard({
  resolved,
  currentPath,
  site,
  user,
}: {
  resolved: OAuthAuthorizeSuccess
  currentPath: string
  site: {
    name: string
    logoText: string
    logoPath?: string | null
    iconPath?: string | null
  }
  user: {
    username: string
    displayName: string
    avatarPath?: string | null
  }
}) {
  const homepageHost = resolved.client.homepageUrl ? getUrlHost(resolved.client.homepageUrl) : null
  const appInitial = getInitial(resolved.client.name)
  const siteMarkPath = resolveSiteMarkImagePath(site.logoPath, site.iconPath)
  const siteInitial = getInitial(site.logoText || site.name)

  return (
    <Card size="sm" className="w-full">
      <CardContent className="grid gap-4 py-3 md:grid-cols-[minmax(0,1fr)_220px]">
        <div className="flex flex-col gap-3">
          <section className="flex items-center justify-between gap-3 rounded-lg border border-border bg-muted/25 px-3 py-2">
            <div className="min-w-0">
              <p className="text-xs text-muted-foreground">当前账号</p>
              <p className="truncate text-sm font-medium">{user.displayName}</p>
              <p className="truncate text-xs text-muted-foreground">@{user.username}</p>
            </div>
            <ShieldCheck className="shrink-0 text-muted-foreground" />
          </section>

          <section className="flex flex-col gap-2">
            <p className="text-sm font-medium">将允许访问</p>
            <div className="flex flex-col gap-1.5">
              {resolved.scopes.map((scope) => (
                <div key={scope} className="flex items-center gap-2 rounded-lg border border-border px-3 py-1.5 text-sm">
                  <Check className="shrink-0 text-muted-foreground" />
                  <p className="min-w-0 truncate font-medium">{getScopeTitle(scope)}</p>
                </div>
              ))}
            </div>
          </section>

          <p className="text-xs leading-5 text-muted-foreground">
            授权不会暴露登录密码，之后可在设置里取消授权。
          </p>
        </div>

        <aside className="flex flex-col gap-3 rounded-lg border border-border bg-muted/25 px-3 py-3 text-xs leading-5 text-muted-foreground">
          <div className="flex items-center justify-center gap-2">
                        <SiteLogo name={site.name} logoUrl={siteMarkPath} fallback={siteInitial} />

            <div className="flex size-7 items-center justify-center rounded-full border border-border bg-background text-muted-foreground">
              <ArrowRight />
            </div>
                        <AppLogo name={resolved.client.name} logoUrl={resolved.client.logoUrl} fallback={appInitial} />

          </div>

          <div className="flex flex-col items-center gap-2 text-center">
            <CardTitle>授权 {resolved.client.name}</CardTitle>

            <Badge variant={resolved.consentRequired ? "secondary" : "outline"}>
              {resolved.consentRequired ? "需要确认" : "已授权过"}
            </Badge>
          </div>

          <div>
            <p className="font-medium text-foreground">应用详情</p>
            <p className="mt-1 line-clamp-4">
              {resolved.client.description || `${resolved.client.name} 请求使用你的 ${site.name} 账号登录。`}
            </p>
          </div>
          {resolved.client.homepageUrl ? (
            <p>
              主页：
              <Link href={resolved.client.homepageUrl} target="_blank" rel="noreferrer" className="inline-flex max-w-full items-center gap-1 text-foreground hover:underline">
                <span className="truncate">{homepageHost ?? resolved.client.homepageUrl}</span>
                <ExternalLink data-icon="inline-end" />
              </Link>
            </p>
          ) : null}
          <div>
            <p className="font-medium text-foreground">回调</p>
            <p className="mt-1">同意后会返回发起登录的应用。</p>
          </div>
          <p>不认识这个应用时请拒绝。</p>
        </aside>
      </CardContent>

      <CardFooter>
        <form action="/oauth/authorize/confirm" method="post" className="grid w-full grid-cols-2 gap-2">
          {buildHiddenFields(resolved, currentPath).map(([name, value]) => (
            <input key={name} type="hidden" name={name} value={value} />
          ))}
          <Button type="submit" name="decision" value="deny" variant="outline">
            <X data-icon="inline-start" />
            拒绝
          </Button>
          <Button type="submit" name="decision" value="approve">
            <Check data-icon="inline-start" />
            同意
          </Button>
        </form>
      </CardFooter>
    </Card>
  )
}

function AppLogo({
  name,
  logoUrl,
  fallback,
}: {
  name: string
  logoUrl: string | null | undefined
  fallback: string
}) {
  return (
    <Avatar className="size-10 rounded-xl">
      {logoUrl ? <AvatarImage src={logoUrl} alt={name} className="rounded-xl" /> : null}
      <AvatarFallback className="rounded-xl font-semibold">{fallback}</AvatarFallback>
    </Avatar>
  )
}

function SiteLogo({
  name,
  logoUrl,
  fallback,
}: {
  name: string
  logoUrl: string
  fallback: string
}) {
  return (
    <Avatar className="size-10 rounded-xl">
      <AvatarImage src={logoUrl} alt={`${name} Logo`} className="rounded-xl object-contain p-1.5" />
      <AvatarFallback className="rounded-xl font-semibold">{fallback}</AvatarFallback>
    </Avatar>
  )
}

function AuthorizeErrorCard({ resolved }: { resolved: OAuthAuthorizeError }) {
  const callbackHref = resolved.redirectUri
    ? buildOAuthRedirectWithError({
        redirectUri: resolved.redirectUri,
        error: resolved.error,
        errorDescription: resolved.errorDescription,
        state: resolved.state,
      })
    : null

  return (
    <Card className="w-full">
      <CardHeader className="border-b">
        <CardTitle>授权请求无效</CardTitle>
        <CardDescription>客户端发起的 OAuth 授权请求无法继续处理。</CardDescription>
      </CardHeader>
      <CardContent className="py-4">
        <div className="flex gap-3 rounded-xl border border-dashed border-border bg-muted/25 px-4 py-3">
          <TriangleAlert className="mt-0.5 shrink-0 text-muted-foreground" />
          <div className="min-w-0">
            <p className="break-all text-sm font-medium">{resolved.error}</p>
            <p className="mt-1 text-sm leading-6 text-muted-foreground">{resolved.errorDescription}</p>
          </div>
        </div>
      </CardContent>
      <CardFooter className="justify-end gap-2">
        <Button type="button" variant="outline" nativeButton={false} render={<Link href="/" />}>返回首页</Button>
        {callbackHref ? (
          <Button type="button" nativeButton={false} render={<Link href={callbackHref} />}>返回应用</Button>
        ) : null}
      </CardFooter>
    </Card>
  )
}

function buildHiddenFields(resolved: OAuthAuthorizeSuccess, currentPath: string): Array<[string, string]> {
  return [
    ["client_id", resolved.client.clientId],
    ["redirect_uri", resolved.redirectUri],
    ["response_type", resolved.responseType],
    ["scope", resolved.scope],
    ...(resolved.codeChallenge && resolved.codeChallengeMethod
      ? [
          ["code_challenge", resolved.codeChallenge] as [string, string],
          ["code_challenge_method", resolved.codeChallengeMethod] as [string, string],
        ]
      : []),
    ["continue", currentPath],
    ...(resolved.state ? [["state", resolved.state] as [string, string]] : []),
    ...(resolved.nonce ? [["nonce", resolved.nonce] as [string, string]] : []),
  ]
}

function getScopeTitle(scope: string) {
  if (scope === "openid") {
    return "确认你的身份"
  }

  if (scope === "profile") {
    return "读取公开资料"
  }

  if (scope === "email") {
    return "读取邮箱信息"
  }

  return scope
}

function getInitial(value: string) {
  const trimmed = value.trim()
  return (Array.from(trimmed)[0] ?? "?").toUpperCase()
}

function getUrlHost(value: string) {
  try {
    return new URL(value).host
  } catch {
    return null
  }
}

function toStringSearchParams(searchParams: OAuthAuthorizeSearchParams) {
  const entries: Array<[string, string]> = []

  for (const [key, value] of Object.entries(searchParams)) {
    if (typeof value === "string") {
      entries.push([key, value])
    } else if (Array.isArray(value)) {
      for (const item of value) {
        entries.push([key, item])
      }
    }
  }

  return entries
}
