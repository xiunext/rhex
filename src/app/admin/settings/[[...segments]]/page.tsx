import type { Metadata } from "next"
import { notFound, redirect } from "next/navigation"

import { buildUserLevelThresholdOptions, buildVipLevelThresholdOptions } from "@/lib/access-threshold-options"
import { AdminAppsSettingsForm } from "@/components/admin/admin-apps-settings-form"
import { AdminBasicSettingsForm } from "@/components/admin/admin-basic-settings-form"
import { AdminEditorToolbarSettingsForm } from "@/components/admin/admin-editor-toolbar-settings-form"
import { AdminFooterLinksSettingsForm } from "@/components/admin/admin-footer-links-settings-form"
import { AdminFriendLinksSettingsForm } from "@/components/admin/admin-friend-links-settings-form"
import { AdminMarkdownEmojiSettingsForm } from "@/components/admin/admin-markdown-emoji-settings-form"
import { AdminMessageSettingsForm } from "@/components/admin/admin-message-settings-form"
import { AdminModuleSearch } from "@/components/admin/admin-module-search"
import { AdminOAuthSettingsPage } from "@/components/admin/admin-oauth-settings-page"
import { AdminSettingsWorkspace } from "@/components/admin/admin-settings-workspace"
import { AdminShell } from "@/components/admin/admin-shell"
import { AdminUploadSettingsForm } from "@/components/admin/admin-upload-settings-form"
import { AdminVipSettingsForm } from "@/components/admin/admin-vip-settings-form"
import { getAdminTaskList } from "@/lib/admin-task-center"
import { getBoards } from "@/lib/boards"
import { getInviteCodeList } from "@/lib/invite-codes"
import { getLevelDefinitions } from "@/lib/level-system"
import { getAdminOAuthClientPageData } from "@/lib/oauth-server"
import { resolveSiteOrigin } from "@/lib/site-origin"
import { getAdminPaymentApplicationPageData } from "@/lib/payment-applications"
import { getRedeemCodeList } from "@/lib/redeem-codes"
import { readSearchParam } from "@/lib/search-params"
import {
  getAdminSettingsHref,
  getDefaultAdminSettingsHref,
  resolveAdminSettingsRouteFromSegments,
} from "@/lib/admin-settings-navigation"
import {
  canAdminTierWithEffectivePermissions,
  canAccessAdminSettingsSection,
  getDefaultAdminSettingsSection,
  sectionsRequiringSiteSettings,
} from "@/lib/admin-navigation"
import { resolveAdminPermissionState } from "@/lib/admin-permission-overrides"
import { getAdminFriendLinkPageData } from "@/lib/friend-links"
import { getServerSiteSettings } from "@/lib/site-settings"
import { requireAdminActor } from "@/lib/moderator-permissions"

interface AdminSettingsPageProps {
  params: Promise<{
    segments?: string[]
  }>
  searchParams: Promise<Record<string, string | string[] | undefined>>
}

function buildSettingsPath(segments?: string[]) {
  return segments && segments.length > 0
    ? `/admin/settings/${segments.join("/")}`
    : "/admin/settings"
}

export async function generateMetadata(
  props: AdminSettingsPageProps
): Promise<Metadata> {
  const params = await props.params
  const resolved = resolveAdminSettingsRouteFromSegments(params.segments)
  const settings = await getServerSiteSettings()

  return {
    title: `${resolved?.subTabLabel ?? resolved?.sectionLabel ?? "站点设置"} - ${settings.siteName}`,
  }
}

export default async function AdminSettingsPage(
  props: AdminSettingsPageProps
) {
  const [params, searchParams] = await Promise.all([props.params, props.searchParams])
  const currentPath = buildSettingsPath(params.segments)
  const admin = await requireAdminActor()

  if (!admin) {
    redirect(`/login?redirect=${currentPath}`)
  }

  const permissionState = await resolveAdminPermissionState(admin)
  const adminTier = permissionState.tier
  const effectivePermissionSet = new Set(permissionState.effectivePermissions)
  const canAccess = (permission: Parameters<typeof canAdminTierWithEffectivePermissions>[1]) =>
    canAdminTierWithEffectivePermissions(adminTier, permission, effectivePermissionSet)

  if (!canAccess("admin.operations.manage") && !canAccess("admin.siteSettings.manage")) {
    redirect("/admin")
  }

  const resolved = resolveAdminSettingsRouteFromSegments(params.segments)
  if (!resolved) {
    notFound()
  }

  if (!canAccessAdminSettingsSection(adminTier, resolved.section, effectivePermissionSet)) {
    const defaultSection = getDefaultAdminSettingsSection(adminTier, effectivePermissionSet)
    redirect(defaultSection ? getAdminSettingsHref(defaultSection) : "/admin")
  }

  if (currentPath !== resolved.href) {
    redirect(resolved.href)
  }

  const [
    siteSettings,
    inviteCodes,
    redeemCodes,
    tasks,
    taskBoards,
    friendLinks,
    levelDefinitions,
    oauthClients,
    paymentApplications,
  ] = await Promise.all([
    sectionsRequiringSiteSettings.has(resolved.section)
      ? getServerSiteSettings()
      : Promise.resolve<Awaited<ReturnType<typeof getServerSiteSettings>> | null>(null),
    resolved.section === "registration"
      ? getInviteCodeList()
      : Promise.resolve<Awaited<ReturnType<typeof getInviteCodeList>>>([]),
    resolved.section === "vip"
      ? getRedeemCodeList()
      : Promise.resolve<Awaited<ReturnType<typeof getRedeemCodeList>>>([]),
    resolved.section === "vip"
      ? getAdminTaskList()
      : Promise.resolve<Awaited<ReturnType<typeof getAdminTaskList>>>([]),
    resolved.section === "vip"
      ? getBoards()
      : Promise.resolve<Awaited<ReturnType<typeof getBoards>>>([]),
    resolved.section === "friend-links"
      ? getAdminFriendLinkPageData()
      : Promise.resolve<Awaited<ReturnType<typeof getAdminFriendLinkPageData>> | null>(null),
    resolved.section === "upload"
      ? getLevelDefinitions()
      : Promise.resolve<Awaited<ReturnType<typeof getLevelDefinitions>>>([]),
    resolved.section === "oauth" && resolved.subTab === "clients"
      ? getAdminOAuthClientPageData({
          keyword: readSearchParam(searchParams?.keyword),
          status: readSearchParam(searchParams?.status),
          page: readSearchParam(searchParams?.page),
          pageSize: readSearchParam(searchParams?.pageSize),
        })
      : Promise.resolve<Awaited<ReturnType<typeof getAdminOAuthClientPageData>> | null>(null),
    resolved.section === "oauth" && resolved.subTab === "payment"
      ? getAdminPaymentApplicationPageData({
          keyword: readSearchParam(searchParams?.keyword),
          status: readSearchParam(searchParams?.status),
          page: readSearchParam(searchParams?.page),
          pageSize: readSearchParam(searchParams?.pageSize),
          orderKeyword: readSearchParam(searchParams?.orderKeyword),
          orderStatus: readSearchParam(searchParams?.orderStatus),
          orderPage: readSearchParam(searchParams?.orderPage),
          orderPageSize: readSearchParam(searchParams?.orderPageSize),
        })
      : Promise.resolve<Awaited<ReturnType<typeof getAdminPaymentApplicationPageData>> | null>(null),
  ])

  const uploadLevelOptions = buildUserLevelThresholdOptions(levelDefinitions)
  const uploadVipLevelOptions = buildVipLevelThresholdOptions()
  const oauthIssuer = resolved.section === "oauth" ? await resolveSiteOrigin() : undefined
  const defaultSettingsSection = getDefaultAdminSettingsSection(adminTier, effectivePermissionSet)
  const breadcrumbs: Array<{ label: string; href?: string }> = [
    { label: "后台控制台", href: "/admin" },
    { label: "站点设置", href: defaultSettingsSection ? getAdminSettingsHref(defaultSettingsSection) : getDefaultAdminSettingsHref() },
    { label: resolved.sectionLabel, href: getAdminSettingsHref(resolved.section) },
  ]

  if (resolved.subTabLabel && resolved.subTabLabel !== resolved.sectionLabel) {
    breadcrumbs.push({ label: resolved.subTabLabel })
  }

  return (
    <AdminShell
      currentKey={resolved.section === "vip" && resolved.subTab === "tasks" ? "tasks" : "settings"}
      adminName={admin.nickname ?? admin.username}
      adminRole={admin.role}
      adminTier={adminTier}
      effectivePermissions={permissionState.effectivePermissions}
      headerDescription={resolved.subTabLabel ?? resolved.sectionLabel}
      headerSearch={<AdminModuleSearch className="w-full" />}
      breadcrumbs={breadcrumbs}
    >
      <AdminSettingsWorkspace
        currentSection={resolved.section}
        currentSectionLabel={resolved.sectionLabel}
        currentSubTab={resolved.subTab}
        currentSubTabLabel={resolved.subTabLabel}
        adminTier={adminTier}
        effectivePermissions={permissionState.effectivePermissions}
      >
        {resolved.section === "profile" ? (
          <AdminBasicSettingsForm
            initialSettings={siteSettings!}
            mode="profile"
            initialSubTab={resolved.subTab}
            subTabRouteSection="profile"
          />
        ) : null}

        {resolved.section === "markdown-emoji" ? (
          <AdminMarkdownEmojiSettingsForm initialItems={siteSettings!.markdownEmojiMap} />
        ) : null}

        {resolved.section === "editor-toolbar" ? (
          <AdminEditorToolbarSettingsForm initialSettings={siteSettings!.editorToolbar} />
        ) : null}

        {resolved.section === "footer-links" ? (
          <AdminFooterLinksSettingsForm initialLinks={siteSettings!.footerLinks} />
        ) : null}

        {resolved.section === "apps" ? (
          <AdminAppsSettingsForm
            initialLinks={siteSettings!.headerAppLinks}
            initialIconName={siteSettings!.headerAppIconName}
            initialTopLinks={siteSettings!.topHeaderAppLinks}
          />
        ) : null}

        {resolved.section === "registration" ? (
          <AdminBasicSettingsForm
            initialSettings={siteSettings!}
            mode="registration"
            initialSubTab={resolved.subTab}
            subTabRouteSection="registration"
            initialInviteCodes={inviteCodes}
          />
        ) : null}

        {resolved.section === "board-applications" ? (
          <AdminBasicSettingsForm
            initialSettings={siteSettings!}
            mode="board-applications"
            initialSubTab={resolved.subTab}
            subTabRouteSection="board-applications"
          />
        ) : null}

        {resolved.section === "interaction" ? (
          <AdminBasicSettingsForm
            initialSettings={siteSettings!}
            mode="interaction"
            initialSubTab={resolved.subTab}
            subTabRouteSection="interaction"
          />
        ) : null}

        {resolved.section === "messages" ? (
          <AdminMessageSettingsForm
            initialSettings={{
              messageEnabled: Boolean(siteSettings!.messageEnabled),
              messageImageUploadEnabled: Boolean(siteSettings!.messageImageUploadEnabled),
              messageFileUploadEnabled: Boolean(siteSettings!.messageFileUploadEnabled),
              messagePromptAudioPath: siteSettings!.messagePromptAudioPath,
              messageRealtimeEnabled: Boolean(siteSettings!.messageRealtimeEnabled),
              messageRealtimeHeartbeatSeconds: siteSettings!.messageRealtimeHeartbeatSeconds,
            }}
          />
        ) : null}

        {resolved.section === "friend-links" ? (
          <AdminFriendLinksSettingsForm
            initialSettings={friendLinks!.settings}
            items={friendLinks!.items}
            pendingCount={friendLinks!.pendingCount}
          />
        ) : null}

        {resolved.section === "vip" ? (
          <AdminVipSettingsForm
            initialSettings={siteSettings!}
            initialSubTab={resolved.subTab}
            tabRouteSection="vip"
            initialRedeemCodes={redeemCodes}
            initialTasks={tasks}
            initialTaskBoards={taskBoards.map((item) => ({
              id: item.id,
              name: item.name,
              slug: item.slug,
            }))}
          />
        ) : null}

        {resolved.section === "upload" ? (
          <AdminUploadSettingsForm
            initialSettings={{
              uploadProvider: siteSettings!.uploadProvider,
              uploadLocalPath: siteSettings!.uploadLocalPath,
              uploadBaseUrl: siteSettings!.uploadBaseUrl,
              uploadOssBucket: siteSettings!.uploadOssBucket,
              uploadOssRegion: siteSettings!.uploadOssRegion,
              uploadOssEndpoint: siteSettings!.uploadOssEndpoint,
              uploadS3CredentialsConfigured: Boolean(siteSettings!.uploadS3AccessKeyId && siteSettings!.uploadS3SecretAccessKey),
              uploadS3ForcePathStyle: Boolean(siteSettings!.uploadS3ForcePathStyle),
              uploadRequireLogin: Boolean(siteSettings!.uploadRequireLogin),
              uploadAllowedImageTypes:
                Array.isArray(siteSettings!.uploadAllowedImageTypes) && siteSettings!.uploadAllowedImageTypes.length > 0
                  ? siteSettings!.uploadAllowedImageTypes
                  : ["jpg", "jpeg", "png", "gif", "webp"],
              uploadMaxFileSizeMb: siteSettings!.uploadMaxFileSizeMb,
              uploadAvatarMaxFileSizeMb: siteSettings!.uploadAvatarMaxFileSizeMb,
              markdownImageUploadEnabled: Boolean(siteSettings!.markdownImageUploadEnabled),
              imageWatermarkEnabled: Boolean(siteSettings!.imageWatermarkEnabled),
              imageWatermarkTextEnabled: Boolean(siteSettings!.imageWatermarkTextEnabled),
              imageWatermarkText: siteSettings!.imageWatermarkText,
              imageWatermarkTextPosition: siteSettings!.imageWatermarkTextPosition,
              imageWatermarkTextTiled: Boolean(siteSettings!.imageWatermarkTextTiled),
              imageWatermarkTextOpacity: Number(siteSettings!.imageWatermarkTextOpacity ?? 22),
              imageWatermarkTextFontSize: Number(siteSettings!.imageWatermarkTextFontSize ?? 24),
              imageWatermarkTextFontFamily: siteSettings!.imageWatermarkTextFontFamily ?? "",
              imageWatermarkFontAssets: siteSettings!.imageWatermarkFontAssets ?? [],
              imageWatermarkTextMargin: Number(siteSettings!.imageWatermarkTextMargin ?? 24),
              imageWatermarkTextColor: siteSettings!.imageWatermarkTextColor,
              imageWatermarkLogoEnabled: Boolean(siteSettings!.imageWatermarkLogoEnabled),
              imageWatermarkLogoPath: siteSettings!.imageWatermarkLogoPath,
              imageWatermarkLogoPosition: siteSettings!.imageWatermarkLogoPosition,
              imageWatermarkLogoTiled: Boolean(siteSettings!.imageWatermarkLogoTiled),
              imageWatermarkLogoOpacity: Number(siteSettings!.imageWatermarkLogoOpacity ?? 22),
              imageWatermarkLogoMargin: Number(siteSettings!.imageWatermarkLogoMargin ?? 24),
              imageWatermarkLogoScalePercent: Number(siteSettings!.imageWatermarkLogoScalePercent ?? 16),
              attachmentUploadEnabled: Boolean(siteSettings!.attachmentUploadEnabled),
              attachmentDownloadEnabled: Boolean(siteSettings!.attachmentDownloadEnabled),
              attachmentMinUploadLevel: Number(siteSettings!.attachmentMinUploadLevel ?? 0),
              attachmentMinUploadVipLevel: Number(siteSettings!.attachmentMinUploadVipLevel ?? 0),
              attachmentAllowedExtensions:
                Array.isArray(siteSettings!.attachmentAllowedExtensions) && siteSettings!.attachmentAllowedExtensions.length > 0
                  ? siteSettings!.attachmentAllowedExtensions
                  : ["zip", "rar", "7z", "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt"],
              attachmentMaxFileSizeMb: Number(siteSettings!.attachmentMaxFileSizeMb ?? 20),
            }}
            levelOptions={uploadLevelOptions}
            vipLevelOptions={uploadVipLevelOptions}
            initialSubTab={resolved.subTab}
            tabRouteSection="upload"
          />
        ) : null}

        {resolved.section === "oauth" ? (
          <AdminOAuthSettingsPage
            activeSubTab={resolved.subTab}
            initialSettings={{
              oauthServerEnabled: Boolean(siteSettings!.oauthServerEnabled),
              oauthClientApplicationEnabled: Boolean(siteSettings!.oauthClientApplicationEnabled),
              paymentApplicationEnabled: Boolean(siteSettings!.paymentApplicationEnabled),
              paymentPlatformFeePercent: Number(siteSettings!.paymentPlatformFeePercent ?? 0),
              oauthAccessTokenTtlMinutes: Number(siteSettings!.oauthAccessTokenTtlMinutes ?? 60),
              oauthRefreshTokenTtlDays: Number(siteSettings!.oauthRefreshTokenTtlDays ?? 30),
            }}
            initialClients={oauthClients}
            initialPaymentApplications={paymentApplications}
            oidcIssuer={oauthIssuer}
          />
        ) : null}
      </AdminSettingsWorkspace>
    </AdminShell>
  )
}
