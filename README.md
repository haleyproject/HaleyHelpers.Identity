# Haley.Helpers.Identity

Reusable account storage and identity operations for .NET 8 applications. The same `IIdentity` contract supports an embedded engine, a private Haley Identity server, or Kida. Kida uses the shared engine locally; it does not call a second identity service.

## Projects and dependencies

| Project | Responsibility |
| --- | --- |
| HaleyHelpersIdentity | `Haley.Helpers.Identity`: public requests/results, numeric status enums, DI registration, and the single Haley.Rest client implementation |
| HaleyHelpersIdentity.Server | Shared account, password, login protection, TOTP, recovery-code, verification/recovery, session and MariaDB engine; shared HTTP endpoints |
| HaleyIdentityHost | Small private-network ASP.NET Core host using Haley AppMaker and the existing MariaDB instance |
| HaleyHelpersIdentity.Tests | Behavior, transport, transaction and isolated MariaDB integration tests |

Use `HaleyHelpers.Identity_Ref.sln` while developing beside the Haley source repositories. `HaleyHelpers.Identity.sln` uses the approved Haley packages. The two new library packages are version 0.1.0. The host is deployed, not packaged as an SDK.

Release builds generate signed `.nupkg` and `.snupkg` files for both libraries, following the existing Haley packaging workflow. See [packaging and publication](PACKAGING.md) for prerequisites, versioning and `CopyCorePackages.bat` usage. Until the required versions are available on your package feed, use the source-reference solution or a local feed. Building and collecting packages does not publish them.

## Registration

Import `Haley.Extensions` and `Haley.Abstractions`. Choose one backend per service collection.

```csharp
services.AddHaleyIdentity(configuration, identity => identity.UseRemote());
```

Configure `Haley:Identity:Url` with a Haley.Rest endpoint descriptor such as `base=http://haley-identity:5000/;`. Set `ApplicationId` to a stable application GUID. For session operations, set `SessionKeyId` and `SessionBindingSecret` to a configured application binding key. The default `ApiPath` is `api/identity`.

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
- `EnsureAccountAsync` creates a minimal active account without a password. It does not verify email ownership or enable password recovery for an unverified contact. Creating an account by trusted application assertion is an explicit privilege in Kida.
- `SetPasswordAsync` provisions/replaces a password. `ChangePasswordAsync` requires the current password. Password history and account state are enforced; changing the password revokes sessions in the same transaction. Kida also revokes its refresh families through its transaction extension.
- `AuthenticatePasswordAsync` verifies a local username or email and applies login protection. Enrolled factors are enforced in standalone operation. Kida additionally applies its existing client, resource, user-override and domain MFA policies.
- `CreateApplicationSessionAsync` is for a backend that has already authenticated a person, for example by SAML. The standalone service trusts that backend boundary. Kida requires the explicit `identity.sessions.issue` scope, checks client/resource authority, and still verifies MFA when policy requires it. `CreateIfMissing` additionally requires `identity.accounts.ensure` in Kida.
- Sessions use random opaque tokens. Only a SHA-256 verifier is stored. Default lifetime is 1,800 seconds with fixed expiry. The response exposes the session identifier, token and expiry, with no account claims. The database retains the account association. The application owns its browser cookie and UI state.
- `ValidateSessionAsync` and `RevokeSessionAsync` require the same application binding. Kida also binds the session to its original resource audience. Opaque sessions have no JWT and no refresh family. Existing Kida OAuth/JWT/refresh endpoints retain their contracts.
- MFA enrollment and verification work for accounts without passwords. Enrollment tickets, recovery codes and reset grants have their existing expiry and replay protections. MFA secrets use the configured AES-GCM key ring. Existing Kida data continues using the original `kida.identity.mfa.totp` protection purpose.
- `BeginPasswordResetAsync`, `VerifyPasswordResetCodeAsync`, and `CompletePasswordResetAsync` share the recovery engine with Kida. Request application/context fields are bound by the facade to the configured caller. Use `Guid.Empty` and an empty context when composing a portable request. Reset initiation returns delivery material only for an active account with an eligible verified recovery contact; applications own email/SMS delivery. Return URLs require a configured allowlist in standalone or Kida's existing resource policy.
- Lifecycle status uses numeric flag values. Exactly one lifecycle state is accepted: 1 Pending, 2 Active, 4 Retired, 8 Locked, 16 Suspended. Combined states, including 3, are rejected.

## Ownership

Haley owns account/profile/contact, credentials/password history, provenance, account locks/login history, MFA/recovery codes, generic verification challenges/grants, base sessions and the shared outbox. The shared SQL is embedded directly from the architecture repository. It is not copied into Kida's canonical schema.

Kida owns OAuth clients/secrets/scopes/grants, client identity policy, provider/federation/SAML orchestration, JWT/signing/token revocation and refresh families. `oauth_session_ctx` stores the Kida client and audience for either session protocol. `oauth_mfa_enroll_ctx` retains Kida's enrollment audience. The dependency direction is Kida to Haley. No other Kida capability is called by the shared engine.

A standalone deployment normally has its own identity database. Existing Kida is upgraded in place by applying the manual migration and deploying the composed Kida binaries. Do not run an unauthenticated standalone host against a Kida-managed database; doing so bypasses Kida's boundary and its transaction extensions.

## API and deployment

See [API reference](API.md), [initialization](initialization.md), and [migration guide](MIGRATION.md). The canonical shared schema is `Architecture/Haley/Identity/Database/MariaDB/schema.sql`; Kida's extension is `Architecture/Kida/Database/Security/Identity/MariaDB/schema.draft.sql`.

## Verification

Run `dotnet test HaleyHelpersIdentity.Tests/HaleyHelpersIdentity.Tests.csproj -p:HaleyIdentityUseSourceReferences=true` for available checks. Database tests require `HALEY_IDENTITY_TEST_CONNECTION` pointing to a disposable MariaDB server. They create and remove only uniquely named `hi_test_` databases. Do not point this setting at a persistent environment. The migration was additionally exercised against empty and populated copies of the pre-extraction schema in an isolated MariaDB process.
