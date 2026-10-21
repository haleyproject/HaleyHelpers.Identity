# Haley Identity quick deployment

1. Open `HaleyHelpers.Identity_Ref.sln` beside the Haley source and architecture repositories and set `HaleyIdentityHost` as the startup project. Install Node/npm: both normal builds and publishing prepare the admin UI. In Solution Explorer, `AdminConsole` links to the frontend source in `HaleyIdentityAdmin.Web`; `wwwroot/admin` contains its generated output. Publish `HaleyIdentityHost` with `-p:HaleyIdentityUseSourceReferences=true`. The normal solution uses published Haley dependencies. The host build and publish output includes `Haley.Identity.Cred`; no separate credential-tool publish is needed.
2. The host reads normal `appsettings.json` configuration. Local debugging also loads development User Secrets; environment variables can override settings. Publishing includes `appsettings.json` and excludes `appsettings.local.json`. Set deployment values in the published `appsettings.json` before building the container image, or provide it in the configuration volume. Set the adapter, actual MariaDB address/port, database user and password. Keep credentials out of source control. Podman links `/app/target/appsettings.json` to the Config volume; the application does not load an extra settings file from Config. Use a fresh database. `Initialize=true` installs the shared canonical schema and seed; it does not alter an older database.
3. Place the host inside your private application network, then set `Haley:Identity:Server:TrustedNetwork=true`. The trusted machine API is not an internet-facing account administration API.
4. From the host's output directory, run `dotnet Haley.Identity.Host.dll hash-admin-password`. Put the resulting hash in `Haley:Identity:Management:PasswordHash`. The password is read privately from the terminal; never pass it as a command argument. Login is disabled while the hash is empty. Default admin-session expiry is 30 minutes.
5. Run `Haley.Identity.Cred Set-Secret-Key --Settings "<host-appsettings.json>"`, or `dotnet Haley.Identity.Host.dll Set-Secret-Key --Settings "<host-appsettings.json>"`. The command creates a 32-byte key in `Keys` beside the selected settings file and saves `Haley:Identity:Server:SecretProtection:ActiveKeyId` and `Keys` automatically. Use the source project's appsettings file for F5. Optional `--key-file "<persistent-key-file>"` selects another location or registers an existing valid key. Paths saved in settings are absolute and must be accessible to the host, so run deployment setup in its final runtime environment. Repeating the command retains valid configured keys. Restart the host after setup. Persist and back up the key file with its settings; this key protects MFA and federation handoffs. Missing configured keys must be restored, not replaced.
6. Register each calling backend through the admin console's Applications page after startup, or run `dotnet Haley.Identity.Host.dll register-application "LearnDesk"` before or after startup. Save the returned `ApplicationId`, `SessionKeyId` and `SessionBindingSecret` in the calling backend's private configuration. All standalone application API operations require them. Configure exact callback URLs in `Server:AllowedReturnUris:<application-guid>` for corporate authentication and recovery.
7. Start the host and open `/admin/`. The local default is `http://127.0.0.1:7430/admin/`. `/health` confirms startup after schema initialization. The UI contains Identity, Applications and Federation. User accounts, password changes, MFA and sessions use the shared engine. Configure SAML certificates or signed corporate callbacks under Federation; see [the federation guide](FEDERATION.md).

The admin console includes a backend. The browser calls `/admin/api` on `HaleyIdentityHost`; that backend uses the shared identity engine and its database directly. The same host also exposes `/api/identity` for trusted application backends. No separate admin service is needed. Kida instead runs its Admin backend and Service in separate hosts.

For local F5 runs, configure the connection, trusted-network acknowledgement, management password hash and keys above first. The launch profile opens `/admin/` at port 7430. Do not edit generated `wwwroot/admin` files: edit `HaleyIdentityAdmin.Web` through the linked `AdminConsole` folder and rebuild. An unchanged frontend is not rebuilt on every C# build.

Browser session keys are created automatically in `Management:KeyDirectory` (default `State/AdminKeys`). Preserve that directory and the configured lockout file. Session cookies are HttpOnly, SameSite Strict, fixed expiry, and use CSRF protection. Logout revokes the server-side session; restarting the host or changing the management password hash requires a new login. Browser keys and the database secret-protection key have different purposes.

To clear a management login lockout, run `Haley.Identity.Cred reset-lockout State/admin-login-lockout.json` from the host content root, or pass an absolute path. This does not reset a user's account lock. The tool has no database dependency at runtime for these commands.

The same credential commands are available through `dotnet Haley.Identity.Host.dll <command>` or the bundled `dotnet Haley.Identity.Cred.dll <command>`. The host forwards them to the shared credential implementation before constructing the web application, so they do not open the service port or initialize the database. Run `dotnet Haley.Identity.Host.dll --help` for password hashing, secret-protection key generation, management lockout reset and application registration instructions. Run the host without a credential command to start the service normally.

## Applications

An invalid application entry does not stop the service. Missing or malformed keys, unsupported status flags and invalid metadata disable that application in memory; healthy applications continue authenticating. The Applications page shows the exact configuration error, and the server logs new and cleared errors without credential values. Disabled entries are reported as `Inactive` (`32`) with a `configurationError`; their saved settings and keys are not changed. Correct the settings file and allow the registry reload to recover the application. Changes supplied through development User Secrets or environment variables require a restart. The protected diagnostics endpoint is `GET /admin/api/applications/configuration-issues`.

Host-wide configuration must still be valid. Malformed JSON prevents initial configuration loading. If a running host cannot read or parse a later settings-file edit, it logs the failure and retains the last published registry until the file is repaired.

For manual verification, open **Identity → Verification & onboarding**, choose the application, email, purpose, proof and expiry, then copy the code/link for delivery. Recipients use `/identity/verify/` without an admin login. If the host is private, set `Server:Verification:ApplicationPageUrls:<application-guid>` to the public application's page or enter that URL in the form. [Verification hosting](VERIFICATION.md) explains the shared page and backend proxy mapping; the identity host does not send email.

For password-free authenticator login, set `Haley:Identity:Server:TotpLogin:Enabled=true` and restart. Optionally list application GUIDs under `TotpLogin:ApplicationIds`. Accounts must have verified email and an enrolled authenticator. [Authentication and recovery](AUTHENTICATION.md) explains setup, SDK calls, API routes and recovery codes.

Sign in to the admin console and open **Applications**. Register a name, optionally supplying an existing application GUID, and copy the generated backend configuration. Registration generates the GUID when omitted. The secret is displayed only when issued and is never returned by the list API. The same operations are available from either credential executable:

| Command | Result |
| --- | --- |
| `register-application "LearnDesk"` | Register a backend and print its generated credential. Add `--application-id <guid>` to choose its identifier. |
| `list-applications` | List applications and key IDs without secrets. |
| `rotate-application-key <guid>` | Issue a new key while keeping existing keys active. |
| `revoke-application-key <guid> <key-id>` | Disable an old key after the backend has switched. |
| `revoke-application <guid>` | Disable all keys for the application. |
| `reactivate-application <guid>` | Reactivate the same application ID and print a fresh credential. Previously revoked keys stay invalid. |

For example, prefix a command with `dotnet Haley.Identity.Host.dll` from the host output directory. Every application command accepts `--settings <absolute-path-to-host-settings>`. Use that option when the credential tool is installed separately from the host. The tool operates on the file directly and does not need a running host, an admin cookie, or a database connection; filesystem write access is its administration boundary.

All application registration changes are written directly to `appsettings.json`. The host uses the file in its ASP.NET content root, normally the project directory during Visual Studio F5 and the deployment working directory after publishing. Cred defaults to `appsettings.json` beside its executable; use `--settings <path-to-host-appsettings.json>` when targeting the project file or a separate host installation. There is no additional Config settings source or `ApplicationSettingsPath` overlay. In Podman, the executable-directory file is a symlink into the existing `hi-config` volume. Reads and atomic writes follow the link without replacing it. Keep the settings file writable and persistent, and keep generated credentials outside source control and browser configuration.

Keys remain under `Haley:Identity:Server:SessionBindingKeys:<application-guid>:<key-id>`. Application names and numeric lifecycle states are under `Server:Applications`. Metadata and credentials from normal configuration are joined by application GUID, so names and statuses can be in appsettings while keys are in development User Secrets or environment variables. Both credential executables load the shared host User Secrets when `DOTNET_ENVIRONMENT` or `ASPNETCORE_ENVIRONMENT` selects Development; a Visual Studio launch profile does not automatically set the environment for a separate terminal. Merely loading or listing applications does not copy external secrets into appsettings. Keys without metadata appear by GUID. When the UI or Cred manages an application's credentials, it persists that application's complete key ring and metadata in appsettings; this saved ring becomes authoritative, including revocation. Retain revoked entries so older credentials in other startup sources cannot restore access after a restart.

UI changes update the running registry immediately after persistence succeeds. The host checks the file once per second for CLI or external changes. It validates the complete registry before swapping its in-memory snapshot. Invalid or unavailable files leave the last valid registry active and produce a server diagnostic. Concurrent UI/CLI writes are serialized with a file lock and replaced atomically; unrelated JSON settings are retained. Manual editors should save complete valid files and avoid editing concurrently with management operations. Configuration formatting and comments may be normalized when a management operation saves the file.

Active applications show **Rotate key** and **Revoke application** in the UI. For rotation, copy the new key into the caller's private settings and reload or restart that caller, then revoke its old key through the UI or CLI. The Identity host does not require a restart. Revoking an application prevents further application API calls; it does not delete users or stored session records. Revoked applications show **Reactivate application**. Reactivation retains the application ID and issues a fresh key; save this credential in the caller because revoked keys never become valid again. It returns the status to Active (2). The same action is available as `reactivate-application` in Cred. This live reload applies to the application registry only. Other host settings, such as callback allowlists, still follow their existing startup behavior. Kida's OAuth clients remain managed through Kida.

## Podman

Publish the host, then build `localhost/haley.identity:0.1.0` with the published `podman.cfile`. Supply the deployment settings through the Config volume or environment variables. Copy `haley-identity.container` to `/etc/containers/systemd/`. Create the example network with `podman network create identity-net`, or change `Network` to your existing private network. The Quadlet has no dependency on a particular MariaDB service; arrange for your database to be available before starting the host.

Use your actual database address and port in the deployed settings. For MariaDB on the container host, this can be `host.containers.internal:3306`; for a database container on the same network, use its container name and internal database port. The Quadlet sets Haley's container port to 5000; other containers on that network call `http://haley-identity:5000/`. It publishes host loopback `127.0.0.1:7430` for local access or an explicitly configured reverse proxy.

Persist `hi-config`, `hi-keys`, `hi-state`, and `hi-saml-certs`. The UI is part of the image; there is no wwwroot volume. Both `appsettings.json` and `identity-admin.config.json` are linked to the Config volume. The latter controls the title/API base path. Existing named volumes preserve their configuration across upgrades: a new image does not replace an existing volume's settings. Review that mounted file when changing settings or images. Supply deployment secrets through private mounted configuration or environment variables.

After supplying the host settings, configure secret protection inside the image with `podman run --rm -v hi-config:/app/target/Config:z -v hi-keys:/app/target/Keys:z localhost/haley.identity:0.1.0 Set-Secret-Key --Settings /app/target/appsettings.json`. This follows the settings symlink and saves the key in the persistent Keys volume. Configuration overrides in User Secrets or environment variables still take precedence; do not leave conflicting SecretProtection overrides there.

Run `systemctl daemon-reload`, then `systemctl start haley-identity.service`. Use `systemctl status` and `journalctl -u haley-identity.service` for startup diagnostics. Quadlet's `[Install]` section handles boot startup; do not enable the generated transient service directly.

### Admin path behind a reverse proxy

The Svelte console loads `identity-admin.config.json` from the same browser directory as its page. Edit `HaleyIdentityAdmin.Web/public/identity-admin.config.json` before building, or `Config/identity-admin.config.json` in the deployed Config volume. The default `basePath` is `/admin/` and `apiBasePath` is `api`, producing `/admin/api` requests. Like Kida's admin configuration, these are public browser paths, not the container address.

For this deployment, the public console is `/hi-admin/`. Set `basePath` to `/hi-admin/` and leave `apiBasePath` as `api` in the Config volume's `identity-admin.config.json`. The browser then requests `/hi-admin/api`, which the proxy forwards to `/admin/api`. Map the entire directory so its JavaScript, CSS and configuration file are available too. If `basePath` is omitted, the frontend uses the page's directory automatically. An `apiBasePath` starting with `/` specifies an absolute path on the same origin instead of being joined to `basePath`.

Vite keeps JavaScript and CSS URLs relative (`base: './'`), so those files work under a proxy prefix without rebuilding. The runtime JSON controls API requests after the JavaScript loads; it cannot repair an incorrect page URL or a missing asset mapping. Open the console at a directory URL ending in `/`, such as `/admin/`. When the proxy gives that directory a different name, configure its slashless public URL to redirect to the public URL with the trailing slash.

If a TLS reverse proxy is used, set `Haley:Identity:TrustedProxies` to its actual source IP addresses as seen inside the container so forwarded HTTPS and source addresses are honored. This can be the host's Podman gateway address. Loopback proxies are trusted by the framework default. Route the admin UI only through your administration boundary. External identity-provider callbacks require their own mappings for the exact `/identity/federation/...` callback routes.

### Application API from another server

The solution includes `nginx-haley-identity.conf`, also copied into the host's build and publish output. Include it inside your existing HTTPS Nginx `server` block on the container host. Replace any earlier Haley location blocks rather than defining the same locations twice. Keep the Quadlet's published upstream at `127.0.0.1:7430`; Nginx supplies the externally reachable HTTPS entry point.

The snippet maps these public paths:

| Public path | Haley upstream path |
| --- | --- |
| `/hi-api/` | `http://127.0.0.1:7430/api/identity/` |
| `/hi-admin/` | `http://127.0.0.1:7430/admin/` |
| `/hi-admin/identity/verify/` | `http://127.0.0.1:7430/identity/verify/` |

The application mapping enables authorized backends on other servers to call Haley over HTTPS. Configure the calling backend's existing `Haley:Identity` section with `Url` set to `base=https://identity.example.com/;` using your actual hostname, and `ApiPath` set to `hi-api`. Keep the `ApplicationId`, `SessionKeyId` and `SessionBindingSecret` issued by Cred. These belong in the backend configuration. The SDK sends its generated application authentication headers on every application API request; the proxy preserves them. The browser's `apiBasePath` remains `api` and is separate from this SDK `ApiPath` setting.

For example, `FindAccountAsync` reaches `/hi-api/accounts/resolve`, which Nginx forwards to `/api/identity/accounts/resolve`. Upstream validation, authentication and error responses remain intact. The application proxy does not map the management `/admin/api` routes. The verification mapping also keeps generated recipient links working under `/hi-admin/`.

If the calling backend has an outbound HTTP proxy, include your Identity hostname in its `no_proxy` exceptions when that hostname should be reached directly. Validate the configuration with `nginx -t`, then reload Nginx. Restart Haley if you change its trusted-proxy configuration.

## Kida

Kida still uses its own Service and Admin containers. Do not start the standalone Haley host against a Kida-owned database. Kida embeds the shared engine, installs shared SQL first and its extension second, and enforces its OAuth client/resource rules. This prototype release assumes the owner recreates databases. No live database is reset by the tooling or by these instructions.

## Configurable request rate limits

The standalone API reads `Haley:Identity:Server:RateLimit`. Its C# defaults are
`Enabled: true`, `PermitLimit: 120`, `WindowSeconds: 60`, and `Scope: "ip-user"`.
The admin login reads `Haley:Identity:Management:RateLimit`, with a default limit
of 10 requests, a 60-second window, and `Scope: "ip"` because it has one configured
administrator identity. All defaults live in C#; either configuration section can
be omitted, and a partial section overrides only the supplied fields.

- `ip`: every request in the policy shares the allowance for the observed remote IP.
- `ip-user`: each identified account at that IP has an independent allowance. One
  hundred accounts at one IP do not spend each other's permits. The same account
  at another IP has another allowance.
- `Enabled`: enables or disables that policy.
- `PermitLimit`: requests allowed in one window (1 through 1,000,000).
- `WindowSeconds`: window length in seconds (1 through 86,400), normally 60.

A successful account lookup, account/profile read, MFA read, session check, and
sign-in each consume one permit when they reach a limited API operation. The limit
counts requests, not page visits or only incorrect passwords. A page can make several
requests. The API has one shared allowance per account/IP across its routes;
management reads are separate and do not consume the management-login allowance.

The application credential is checked before account-based partitioning. Account
IDs come from route/body values, email/login inputs are resolved to a canonical
account when present, and opaque sessions are resolved to their account. Account
lookup/session-resolution results are reused by their endpoints. Session validation
still returns only its existing session ID and expiry, without account claims.
Pending verification challenges and federation attempts have their own proof/attempt
allowances until an account can be identified. Operations with no usable subject,
including collection-wide operations, fall back to a shared IP allowance. A rate-limit subject
never grants authorization or changes account lockout/verification-attempt rules.

Invalid scope names, nonpositive limits/windows, or excessive values fail startup
validation. Where the configuration provider supports file reload, changes apply to subsequent
requests. Different limit/window/scope combinations use separate allowances; reloading
unchanged values preserves the existing allowance. Restart the container after editing
mounted configuration to ensure it reloads; environment overrides also require restart. Counters live in the current process, reset on restart, and are not shared
between replicas. HTTP 429 includes `Retry-After`, ProblemDetails code
`rate_limit_exceeded`, and `retryAfterSeconds`. Clients should honor that delay and
retain their sessions.

The IP is the address observed by the service after trusted forwarded-header
processing. Configure `Haley:Identity:TrustedProxies` for the actual proxy source
address; arbitrary forwarded headers are not trusted automatically. Existing deployed
Config volumes must be edited explicitly; rebuilding an image does not overwrite them.

For direct CLI source builds/publishes, use `-p:HaleyIdentityUseSourceReferences=true`.
The updated Haley.Helpers.Web package must be released separately before package-mode
consumers can use the new API.


## One central identity database with Kida

1. Choose one authoritative identity database. Repointing an adapter does not merge
   accounts, local numeric relationships, OAuth clients or sessions from another
   populated database. Back up existing data and plan a separate data migration if
   both databases already contain records that must be retained.
2. Merge `shared-identity.example.json` into both hosts' configuration. Keep each
   host's connection credentials. The `identity` adapter in both processes must
   resolve to the same server and database. In Kida, a shared
   `Haley:Identity:Server:Adapter` selects both foundation and extension storage.
3. Put the common issuer label, password/lockout/MFA policy and protection-key ring
   under `Haley:Identity:Server`. Once this section exists, omitted shared settings
   take Haley defaults; Kida's old shared settings are no longer policy overrides.
   Keep Haley application binding credentials and Kida OAuth clients, signing keys,
   audiences and grants in their respective host configuration.
4. Use the same protection key IDs and material on both hosts, including all keys
   needed by existing encrypted records. File paths may differ. Do not generate a
   new independent key for each host, and do not reuse an existing ID for different
   key material. `set-secret-key` on Kida now selects the Haley protection section
   when this shared section exists, while retaining the existing reuse safeguards.
5. For existing Kida TOTP secrets, retain the original keys and configure
   `PreviousMfaProtectionPurposes: ["kida.identity.mfa.totp"]` on both hosts. This
   explicitly enables old-purpose reads without re-enrollment. New secrets always
   use `haley.identity.mfa.totp` unless the owner sets another common current
   purpose. Existing ciphertext is not rewritten automatically.
6. If the selected database already contains Kida's extension tables, stop writers
   and have the owner apply the canonical Kida migration
   `20261021_shared_identity_lifecycle.sql`. Its orphan-reference pre-check must be
   zero; resolve historical references explicitly if it is not. Test/verify the
   post-checks before restarting. Fresh Kida initialization creates the final
   relationships automatically. Pure Haley installations require no Kida tables.
7. Restart both hosts after changing mounted configuration. A newly built image
   does not replace an existing Config volume. Kida bootstrap rejects old lifecycle
   constraints with the migration filename; it does not run ALTER statements. When
   bootstrap is disabled, verify the migration manually before shared operations.
8. Check sign-in through both configured application boundaries, password changes
   in both directions, MFA/recovery-code use, and retirement/deletion of a test
   account. Password changes revoke shared sessions and prevent Kida refresh. An
   already-issued access token or product cookie still needs its normal validation
   or expiry; this is account sharing, not automatic cross-application token access.

Use the approved Haley source-reference builds until the corresponding package
release is published. These changes do not publish packages or overwrite deployment
configuration, databases or key files.


Identity statistics use the effective shared adapter and recognize both Haley and
Kida account events, including a configured shared event prefix. Existing derived
statistics are reconciled on the configured `Kida:Statistics:RepairIntervalHours`
schedule (24 hours by default). After switching to a different identity database,
allow that projection repair before treating previously stored counters as current;
this does not affect account or credential correctness.
