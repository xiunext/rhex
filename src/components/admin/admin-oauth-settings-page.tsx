"use client"

import Link from "next/link"
import { useState } from "react"

import { OAuthServerAdminPage } from "@/components/admin/oauth-server-admin-page"
import { PaymentApplicationsAdminPage } from "@/components/admin/payment-applications-admin-page"
import {
  AdminBooleanSelectField,
  SettingsInputField as TextField,
  SettingsSection,
} from "@/components/admin/admin-settings-fields"
import { Button } from "@/components/ui/rbutton"
import { useAdminMutation } from "@/hooks/use-admin-mutation"
import { adminPost } from "@/lib/admin-client"
import type { OAuthClientAdminPageData } from "@/lib/oauth-server"
import type { PaymentApplicationAdminPageData } from "@/lib/payment-applications"
import { buildOpenIdConfiguration, OPENID_CONFIGURATION_PATH } from "@/lib/oauth-oidc-metadata"

interface AdminOAuthSettingsInitialSettings {
  oauthServerEnabled: boolean
  oauthClientApplicationEnabled: boolean
  paymentApplicationEnabled: boolean
  paymentPlatformFeePercent: number
  oauthAccessTokenTtlMinutes: number
  oauthRefreshTokenTtlDays: number
}

interface AdminOAuthSettingsPageProps {
  activeSubTab?: string
  initialSettings: AdminOAuthSettingsInitialSettings
  initialClients?: OAuthClientAdminPageData | null
  initialPaymentApplications?: PaymentApplicationAdminPageData | null
  oidcIssuer?: string
}

export function AdminOAuthSettingsPage({
  activeSubTab = "settings",
  initialSettings,
  initialClients,
  initialPaymentApplications,
  oidcIssuer,
}: AdminOAuthSettingsPageProps) {
  if (activeSubTab === "clients") {
    if (!initialClients) {
      return null
    }

    return (
      <OAuthServerAdminPage
        initialData={initialClients}
        basePath="/admin/settings/oauth/clients"
        settingsHref="/admin/settings/oauth/settings"
      />
    )
  }

  if (activeSubTab === "payment") {
    if (!initialPaymentApplications) {
      return null
    }

    return (
      <PaymentApplicationsAdminPage
        initialData={initialPaymentApplications}
        basePath="/admin/settings/oauth/payment"
        settingsHref="/admin/settings/oauth/settings"
      />
    )
  }

  return <AdminOAuthSettingsForm initialSettings={initialSettings} oidcIssuer={oidcIssuer ?? ""} />
}

function AdminOAuthSettingsForm({
  initialSettings,
  oidcIssuer,
}: {
  initialSettings: AdminOAuthSettingsInitialSettings
  oidcIssuer: string
}) {
  const [draft, setDraft] = useState(() => ({
    oauthServerEnabled: Boolean(initialSettings.oauthServerEnabled),
    oauthClientApplicationEnabled: Boolean(initialSettings.oauthClientApplicationEnabled),
    paymentApplicationEnabled: Boolean(initialSettings.paymentApplicationEnabled),
    paymentPlatformFeePercent: String(initialSettings.paymentPlatformFeePercent ?? 0),
    oauthAccessTokenTtlMinutes: String(initialSettings.oauthAccessTokenTtlMinutes ?? 60),
    oauthRefreshTokenTtlDays: String(initialSettings.oauthRefreshTokenTtlDays ?? 30),
  }))
  const { isPending, runMutation } = useAdminMutation()
  const oidcMetadata = oidcIssuer ? buildOpenIdConfiguration(oidcIssuer) : null

  function updateDraft<Key extends keyof typeof draft>(field: Key, value: (typeof draft)[Key]) {
    setDraft((current) => ({ ...current, [field]: value }))
  }

  return (
    <form
      className="flex flex-col gap-5"
      onSubmit={(event) => {
        event.preventDefault()
        runMutation({
          mutation: () =>
            adminPost(
              "/api/admin/site-settings",
              {
                section: "site-oauth",
                oauthServerEnabled: draft.oauthServerEnabled,
                oauthClientApplicationEnabled: draft.oauthClientApplicationEnabled,
                paymentApplicationEnabled: draft.paymentApplicationEnabled,
                paymentPlatformFeePercent: Number(draft.paymentPlatformFeePercent),
                oauthAccessTokenTtlMinutes: Number(draft.oauthAccessTokenTtlMinutes),
                oauthRefreshTokenTtlDays: Number(draft.oauthRefreshTokenTtlDays),
              },
              {
                defaultSuccessMessage: "OAuth 设置已保存",
                defaultErrorMessage: "保存 OAuth 设置失败",
              },
            ),
          successTitle: "保存成功",
          errorTitle: "保存失败",
          refreshRouter: true,
        })
      }}
    >
      <SettingsSection
        title="OAuth 授权服务"
        description="集中控制 OAuth 2.0 授权服务、用户应用申请入口，以及 access_token / refresh_token 生命周期。"
        action={
          <div className="flex flex-wrap gap-2">
            <Link href="/admin/settings/oauth/clients">
              <Button type="button" variant="outline">OAuth 审核</Button>
            </Link>
            <Link href="/admin/settings/oauth/payment">
              <Button type="button" variant="outline">Payment 审核</Button>
            </Link>
          </div>
        }
      >
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
          <AdminBooleanSelectField
            label="开启 OAuth Server"
            checked={draft.oauthServerEnabled}
            onChange={(value) => updateDraft("oauthServerEnabled", value)}
            description="开启后，已审核应用可调用 /oauth/authorize、/oauth/token 和 /oauth/userinfo。"
          />
          <AdminBooleanSelectField
            label="允许用户申请 OAuth 应用"
            checked={draft.oauthClientApplicationEnabled}
            onChange={(value) => updateDraft("oauthClientApplicationEnabled", value)}
            description="关闭后，已有应用仍可继续工作，但用户不能提交新的应用申请。"
          />
          <AdminBooleanSelectField
            label="开启 Payment"
            checked={draft.paymentApplicationEnabled}
            onChange={(value) => updateDraft("paymentApplicationEnabled", value)}
            description="关闭后，用户不能提交 Payment 应用，外部支付接口也会拒绝新的支付请求。"
          />
          <TextField
            label="Payment 平台手续费（%）"
            type="number"
            min={0}
            max={100}
            step={1}
            value={draft.paymentPlatformFeePercent}
            onChange={(value) => updateDraft("paymentPlatformFeePercent", value)}
            placeholder="如 5"
            description="按每笔支付金额计算，0 表示不收取平台手续费。"
          />
          <TextField
            label="access_token 有效期（分钟）"
            type="number"
            min={5}
            max={1440}
            value={draft.oauthAccessTokenTtlMinutes}
            onChange={(value) => updateDraft("oauthAccessTokenTtlMinutes", value)}
            placeholder="如 60"
            description="取值范围 5-1440 分钟。"
          />
          <TextField
            label="refresh_token 有效期（天）"
            type="number"
            min={1}
            max={365}
            value={draft.oauthRefreshTokenTtlDays}
            onChange={(value) => updateDraft("oauthRefreshTokenTtlDays", value)}
            placeholder="如 30"
            description="取值范围 1-365 天。"
          />
        </div>
      </SettingsSection>

      <SettingsSection
        title="OpenID Connect 服务信息"
        description="在 Gitea 的 OpenID Connect 自动发现 URL 中填写发现地址。站点根地址是 Issuer，根页面返回 HTML；发现地址会返回 JSON 配置。"
      >
        <div className="grid gap-4 md:grid-cols-2">
          <OidcInfo label="Issuer（站点根地址）" value={oidcMetadata?.issuer ?? ""} />
          <OidcInfo label="自动发现 URL（Gitea 中填写此项）" value={`${oidcMetadata?.issuer ?? ""}${OPENID_CONFIGURATION_PATH}`} />
          <OidcInfo label="Authorization endpoint" value={oidcMetadata?.authorization_endpoint ?? ""} />
          <OidcInfo label="Token endpoint" value={oidcMetadata?.token_endpoint ?? ""} />
          <OidcInfo label="UserInfo endpoint" value={oidcMetadata?.userinfo_endpoint ?? ""} />
          <OidcInfo label="JWKS endpoint" value={oidcMetadata?.jwks_uri ?? ""} />
          <OidcInfo label="Revocation endpoint" value={oidcMetadata?.revocation_endpoint ?? ""} />
          <OidcInfo label="Scopes" value="openid profile email" />
          <OidcInfo label="PKCE / ID Token" value="S256 / HS256" />
        </div>
      </SettingsSection>

      <div className="flex flex-wrap items-center gap-3">
        <Button type="submit" disabled={isPending}>
          {isPending ? "保存中..." : "保存 OAuth 设置"}
        </Button>
        <span className="text-xs leading-6 text-muted-foreground">
          审核应用、重置 appid/key 请切换到“应用审核”。
        </span>
      </div>
    </form>
  )
}

function OidcInfo({ label, value }: { label: string; value: string }) {
  return (
    <div className="min-w-0 space-y-2">
      <p className="text-sm font-medium">{label}</p>
      <code className="block break-all rounded-xl border border-border bg-muted/40 px-3 py-2 text-xs">{value || "无法解析站点地址"}</code>
    </div>
  )
}
