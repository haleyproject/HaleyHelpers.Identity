# Haley.Helpers.Identity

Reusable account storage and identity operations for .NET 8 applications. The same `IIdentity` contract supports an embedded engine, a private Haley Identity server, or Kida. Kida uses the shared engine locally; it does not call a second identity service.

## Projects and dependencies

| Project | Responsibility |
| --- | --- |
| HaleyHelpersIdentity | `Haley.Helpers.Identity`: public requests/results, numeric status enums, DI registration, and the single Haley.Rest client implementation |
| HaleyHelpersIdentity.Server | Shared account, password, login protection, TOTP, recovery-code, verification/recovery, session and MariaDB engine; shared HTTP endpoints |
| HaleyIdentityHost | Private ASP.NET Core host with Identity, Applications and Federation administration and password-based management sessions |
| HaleyIdentityAdmin.Web | Shared Svelte identity components used by Haley and Kida; Haley branding, application registration and federation administration |
| HaleyIdentity.Cred | Offline password-hash, lockout reset and secret-protection key tooling, bundled with and callable through HaleyIdentityHost |
| HaleyHelpersIdentity.Tests | Behavior, transport, transaction and isolated MariaDB integration tests |

Use `HaleyHelpers.Identity_Ref.sln` while developing beside the Haley source repositories. `HaleyHelpers.Identity.sln` uses the approved Haley packages. The two new library packages are version 0.1.0. The host is deployed, not packaged as an SDK.

Release builds generate signed `.nupkg` and `.snupkg` files for both libraries, following the existing Haley packaging workflow. See [packaging and publication](PACKAGING.md) for prerequisites, versioning and `CopyCorePackages.bat` usage. Until the required versions are available on your package feed, use the source-reference solution or a local feed. Building and collecting packages does not publish them.

## Admin console and hosting

Set `HaleyIdentityHost` as the startup project in `HaleyHelpers.Identity_Ref.sln`. The host serves the UI at `http://127.0.0.1:7430/admin/` and its admin backend at `/admin/api`. That backend calls the shared identity engine directly. Applications use the separate trusted API at `/api/identity`, in the same process. Kida retains its separate Admin and Service hosts.

The host project's `AdminConsole` folder links to the shared Svelte source. With Node/npm installed, building generates the UI in `wwwroot/admin`; publishing includes it. The host uses normal ASP.NET configuration: `appsettings.json`, environment-specific settings, development User Secrets and environment variables. Publishing includes `appsettings.json` and excludes `appsettings.local.json`. Set deployment values in the published settings before building the container image, or supply the file through the Config volume. The container links this file to its Config volume. Complete the connection, management password hash, keys and private-network setup in [the quick deployment guide](initialization.md) before starting the host.

The host also includes the offline credential utility. Run `dotnet Haley.Identity.Host.dll hash-admin-password` from its output directory to generate the management password hash, or use `--help` for all credential commands. These commands reuse `Haley.Identity.Cred` and finish before the web server or database initialization starts.

## Registration

Set `Haley:Identity:Server:IssuerLabel` in the host's `appsettings.json` to your hosting identity name, for example `"EPBIM"` or `"Learn Desk"`. This global name appears in new authenticator QR entries, the console login/sidebar, and the console title when `identity-admin.config.json:title` is empty. Explicit console titles still override the title. An absent or blank issuer label uses `Haley Identity`. Restart the host after changing it.

The name belongs to the shared identity deployment, not to a registered calling application. Renaming it does not change user IDs, application IDs, keys, TOTP secrets or token issuers. Existing authenticator entries retain their locally saved name; rename them in the authenticator app or use a new enrollment to import the updated name.

Password-free authenticator login is available through `IIdentity.AuthenticateTotpAsync` for active accounts with verified email and enrolled TOTP. Enable `Server:TotpLogin:Enabled` and optionally restrict `ApplicationIds`. Kida reuses the engine and enforces its explicit MFA policies. Sessions record one factor only. See [authentication and recovery](AUTHENTICATION.md) for setup, routes and recovery codes.

Import `Haley.Extensions` and `Haley.Abstractions`. Choose one backend per service collection.

```csharp
services.AddHaleyIdentity(configuration, identity => identity.UseRemote());
```

Configure `Haley:Identity:Url` with a Haley.Rest endpoint descriptor such as `base=http://haley-identity:5000/;`. Register the calling backend in the standalone admin console's Applications page or with `register-application` in the bundled credential tool. Set `ApplicationId`, `SessionKeyId` and `SessionBindingSecret` from the issued credential. Every standalone application API operation requires these credentials, including account management and MFA. The default `ApiPath` is `api/identity`. Existing callers must update their SDK and credentials when upgrading from the earlier session-only key check.

The UI and CLI share application registration, overlapping key rotation, individual key revocation, application revocation and reactivation. Reactivation keeps the application ID and issues a fresh credential without restoring revoked keys. Changes persist directly in `appsettings.json` and are picked up by the running host's one-second reload check. The host uses its content-root settings file; Cred defaults to the file beside its executable and accepts `--settings` for another host location. Neither reads a second settings file from Config. Podman's symlink handles the volume location, and persistence preserves that link. No application registry database or OAuth client is needed. See [application management](initialization.md#applications) for configuration merging and rotation steps. This registry is specific to standalone hosting; Kida continues to authenticate its own OAuth clients.

For direct database access inside the trusted owning application, reference the Server package and select the embedded engine:

```csharp
services.AddHaleyIdentity(configuration, identity => identity.UseEmbedded(configuration));
```

The embedded host registers its existing `IAdapterGateway`, with the adapter named in `Haley:Identity:Server:Adapter`. Configure the application GUID in `Haley:Identity:ApplicationId`. Embedded operation does not require an HTTP host, OAuth, a session binding header, or a second service.

For the secured Kida API, also reference `Kida.Service.Client` and import `Kida.Service.Client`:

```csharp
services.AddHaleyIdentity(configuration, identity => identity.UseKida(configuration));
```

This reuses `AddKidaClient` and its cached machine token. Configure the existing `Kida:Client` section: URL, ClientId, ClientIdentifier, ClientSecret, and UserAudience. The shared SDK calls `api/kida/identity/foundation` through that URL's `api/` suffix. Do not configure a standalone session key for Kida. If `AddKidaClient` is already registered, its registration is reused.

Inject `IIdentity`. Operations return the established Haley `IFeedback`/`IFeedback<T>` types. Inspect `Status`, `Result`, `Code`, `Key`, `Message`, and `Trace`. HTTP failures preserve the status and ProblemDetails information. Cancellation flows through the REST request and persistence calls; state-changing requests are not automatically retried.

## Account and authentication behavior

- One database has one shared account namespace. Email is normalized; applications linking the same email resolve the same account. An application's optional source identifier is hashed and retained as provenance.
- `EnsureAccountAsync` creates a minimal active account without a password by default. Pass `InitialStatus: IdentityStatus.Pending` to require onboarding before login; ensuring an existing account never changes its status. It does not verify email ownership or enable password recovery for an unverified contact. Creating an account by trusted application assertion is an explicit privilege in Kida.
- `SetPasswordAsync` provisions/replaces a password. `ChangePasswordAsync` requires the current password. Password history and account state are enforced; changing the password revokes sessions in the same transaction. Kida also revokes its refresh families through its transaction extension.
- `AuthenticatePasswordAsync` verifies a local username or email and applies login protection. Enrolled factors are enforced in standalone operation. Kida additionally applies its existing client, resource, user-override and domain MFA policies.
- `CreateApplicationSessionAsync` is for a backend that has already authenticated a person, for example by SAML. The standalone service trusts that backend boundary. Kida requires the explicit `identity.sessions.issue` scope, checks client/resource authority, and still verifies MFA when policy requires it. `CreateIfMissing` additionally requires `identity.accounts.ensure` in Kida.
- Sessions use random opaque tokens. Only a SHA-256 verifier is stored. Default lifetime is 1,800 seconds with fixed expiry. The response exposes the session identifier, token and expiry, with no account claims. The database retains the account association. The application owns its browser cookie and UI state.
- `ValidateSessionAsync` and `RevokeSessionAsync` require the same application binding. Kida also binds the session to its original resource audience. Opaque sessions have no JWT and no refresh family. Existing Kida OAuth/JWT/refresh endpoints retain their contracts.
- MFA enrollment and verification work for accounts without passwords. Enrollment tickets, recovery codes and reset grants have their existing expiry and replay protections. MFA secrets use the configured AES-GCM key ring. Existing Kida data continues using the original `kida.identity.mfa.totp` protection purpose.
- `BeginVerificationAsync` and `CompleteVerificationAsync` support email verification, pending-account onboarding, direct password reset and email OTP/link login. Applications receive an opaque token or numeric code, own delivery, and construct their own links. The verifier is single-use and bound to its account/contact, application, owner context, purpose and optional application context. Only hashes are stored. `GetEmailVerificationAsync` reports current contact verification and recovery eligibility.
- Email verification marks the exact contact verified and recovery-enabled, without activating a pending account. Onboarding verifies that contact and activates a pending account, optionally setting its initial password. Password reset requires the verifier and new password together, enforces password history, and revokes existing sessions. Email login requires an active account with a verified recovery contact and still enforces enrolled MFA or Kida's client policy. Completion and its password/session changes share one transaction.
- Opaque-token lifetime can be selected per challenge, including three days (`ValiditySeconds: 259200`), within `Verification.MaximumTokenValiditySeconds` (default seven days). Numeric codes default to five minutes and cannot exceed `MaximumCodeValiditySeconds` (default one hour). See [verification workflows](VERIFICATION.md) for examples and exact behavior.
- `BeginPasswordResetAsync`, `VerifyPasswordResetCodeAsync`, and `CompletePasswordResetAsync` share the recovery engine with Kida. Request application/context fields are bound by the facade to the configured caller. Use `Guid.Empty` and an empty context when composing a portable request. Reset initiation returns delivery material only for an active account with an eligible verified recovery contact; applications own email/SMS delivery. Return URLs require a configured allowlist in standalone or Kida's existing resource policy.
- Lifecycle status uses numeric flag values. Exactly one lifecycle state is accepted: 1 Pending, 2 Active, 4 Retired, 8 Locked, 16 Suspended. Combined states, including 3, are rejected.

## Ownership

Haley owns account/profile/contact, credentials/password history, provenance, account locks/login history, MFA/recovery codes, generic verification challenges/grants, SAML and signed corporate federation, provider discovery and external links, base sessions and the shared outbox. The shared SQL is embedded directly from the architecture repository. It is not copied into Kida's canonical schema.

Kida owns OAuth clients/secrets/scopes/grants, client identity policy, tenant-specific provider association, JWT/signing/token revocation and refresh families. `oauth_session_ctx` stores the Kida client and audience for either session protocol. `oauth_mfa_enroll_ctx` retains Kida's enrollment audience. The dependency direction is Kida to Haley. No other Kida capability is called by the shared engine.

A standalone deployment normally has its own identity database. The current prototype baseline is a fresh install. Historical migrations do not upgrade existing databases to the federation extraction. Do not run an unauthenticated standalone host against a Kida-managed database; doing so bypasses Kida's boundary and its transaction extensions.

## API and deployment

See [corporate authentication](FEDERATION.md), [API reference](API.md), [initialization](initialization.md), and [migration guide](MIGRATION.md). The canonical shared schema is `Architecture/Haley/Identity/Database/MariaDB/schema.sql`; Kida's extension is `Architecture/Kida/Database/Security/Identity/MariaDB/schema.draft.sql`.

## Verification

The Identity area includes shared Accounts, Verification & onboarding, Recovery codes, Authentication & sessions, and Account & profile tabs. These same screens are consumed by Kida; API adapters retain each host's administration boundary.

Choose an active registered application for application-bound operations. Haley does not require OAuth clients, scopes or resource audiences for these workflows. Profile and recovery administration also support account UUID lookup, including accounts with non-email usernames.

Verification supports numeric email codes and one-time links for email ownership, onboarding activation, password recovery and passwordless sign-in. Choose the publicly reachable recipient-page URL or use the configured per-application/default URL. Codes and links are prepared for manual delivery. The existing recipient page completes the purpose-bound proof without an administrator login. Email verification preserves lifecycle state; onboarding activates a Pending account.

Recovery-code replacement invalidates the previous set and displays the new codes once. The authentication tools call the normal password, primary-authenticator and application-asserted sign-in operations, then permit opaque-session validation and revocation. Server account state, MFA, login protection and application authority continue to apply. Full profile editing includes display, given, family and preferred names, locale, time zone and avatar URL.

Management writes require the operator session and antiforgery. Application-bound management routes reject revoked, unregistered or keyless applications. Normal application signatures and bindings are still enforced on the separate application API. No schema change or package publication is needed for the console additions.

Rebuild and deploy Haley.Identity.Host with its frontend. The same shared-source change should also be included when rebuilding Kida Admin.

Run `dotnet test HaleyHelpersIdentity.Tests/HaleyHelpersIdentity.Tests.csproj -p:HaleyIdentityUseSourceReferences=true` for available checks. Database tests require `HALEY_IDENTITY_TEST_CONNECTION` pointing to a disposable MariaDB server. They create and remove only uniquely named `hi_test_` databases. Do not point this setting at a persistent environment. The migration was additionally exercised against empty and populated copies of the pre-extraction schema in an isolated MariaDB process.

## Prune unused MFA methods

In Accounts, open a user's MFA posture and choose **Prune unused**. After confirmation, the console permanently removes all retired methods for that account that were never confirmed or used, together with their secret data and enrollment tickets. Methods referenced by another enrollment are retained. The screen refreshes and reports the actual number removed. Active and pending enrollments remain available. This control is shared by Haley Identity Admin and Kida Admin and requires the normal management session and CSRF token. No automatic pruning or schema migration runs at startup.

## Configurable request rate limits

`Haley:Identity:Server:RateLimit` defaults to 120 requests per 60 seconds with
`Scope: "ip-user"`. Account reads and session checks count too. Each account at one
IP receives its own allowance. `Haley:Identity:Management:RateLimit` controls admin
login separately (10 requests per 60 seconds, `Scope: "ip"`). All defaults are in C#;
missing sections/fields keep them. Both policies support `Enabled`, `PermitLimit`,
`WindowSeconds`, and `Scope` (`ip` or `ip-user`).

See [the deployment guide](initialization.md#configurable-request-rate-limits) for
subject resolution, anonymous fallback, configuration reload, HTTP 429 behavior, and
persistent Config-volume updates. The new shared limiter API is in Haley.Helpers.Web;
package publication/version changes are separate from this source change.
