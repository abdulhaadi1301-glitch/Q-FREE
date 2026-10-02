<div align="center">
<img width="1200" height="475" alt="GHBanner" src="https://ai.google.dev/static/site-assets/images/share-ais-513315318.png" />
</div>

# Run and deploy your AI Studio app

This contains everything you need to run your app locally.

View your app in AI Studio: https://ai.studio/apps/ff1452f9-afdd-4080-bf64-77342e1d7ea0

## Run Locally

**Prerequisites:**  Node.js


1. Install dependencies:
   `npm install`
2. Set the `GEMINI_API_KEY` in [.env.local](.env.local) to your Gemini API key
3. Run the app:
   `npm run dev`

## Super Admin Control Center (Promotions, Announcements, Feature Control)

A modular layer on top of QFree. It does not change queue, token, patient/provider workflow or auth logic.

- **Open it at `/super-admin`** (also works while Maintenance Mode is ON). Only the `SUPER_ADMIN` role can change anything; `ADMIN`, `PATIENT` and `PROVIDER` are rejected by the API.
- **Tabs:** Overview (platform status), Providers, Users, Queues, Promotions & Announcements, Feature Control, Branding, Support & Contact, Platform Settings, Audit Logs.
- **Feature flags** live in one registry: `src/core/types/platform.ts` (`FEATURE_DEFINITIONS` + `DEFAULT_PLATFORM_FEATURES`). To add a flag: add the key to `PlatformFeatureSettings`, one entry in the registry and its default. The API, the Feature Control panel and the audit trail pick it up automatically. Defaults equal the previous behaviour (everything ON, maintenance OFF, provider approval required).
- **Storage:** settings and announcements are two new collections (`platformSettings`, `announcements`) in the existing JSON repository. Older database files load fine; missing values fall back to the defaults. Banner images are stored in the announcements collection only and served from `/api/announcements/:id/image`.
- **Audit:** every config/announcement change writes an entry with admin, action, setting, previous value, new value and timestamp (visible in Audit Logs).
- **Super Admin bootstrap:** if the database contains no `SUPER_ADMIN`, the account in `SUPER_ADMIN_EMAILS` (default `ops@qfree.health`) is promoted once and audited. If a `SUPER_ADMIN` exists, no `ADMIN` is ever promoted automatically.
- **Behaviour notes:** Remote Token OFF blocks patient booking only (provider walk-in tokens keep working). Doctor Delay OFF blocks starting a delay; an active delay can still be cleared. Notifications OFF skips non-critical notifications (`APPLICATION_UPDATE` is always sent). Provider Approval Required OFF auto-activates only new applications from signed-in applicants; existing pending ones are untouched.

New files: `src/core/types/platform.ts`, `src/core/platform/PlatformConfigContext.tsx`, `src/components/platform/*`, `src/modules/superadmin/{FeatureControlPanel,PromotionsManager,PlatformStatusSummary,PlatformIdentitySettings}.tsx`, `server/platform/platformRoutes.ts`.
