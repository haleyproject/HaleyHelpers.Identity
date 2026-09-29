# Haley Identity quick deployment

1. Build `HaleyHelpers.Identity_Ref.sln` beside the Haley source and architecture repositories. Publish `HaleyIdentityHost` with `-p:HaleyIdentityUseSourceReferences=true`. Publishing builds the shared Svelte UI, so Node/npm are required. The normal solution uses published Haley dependencies. Publish `HaleyIdentity.Cred` separately for offline setup commands.
2. Set the adapter and MariaDB connection in `Config/appsettings.json`. Use a fresh database. `Initialize=true` installs the shared canonical schema and seed; it does not alter an older database.
3. Place the host inside your private application network, then set `Haley:Identity:Server:TrustedNetwork=true`. The trusted machine API is not an internet-facing account administration API.
4. Run `Haley.Identity.Cred hash-admin-password`. Put the resulting hash in `Haley:Identity:Management:PasswordHash`. The password is read privately from the terminal; never pass it as a command argument. Login is disabled while the hash is empty. Default admin-session expiry is 30 minutes.
5. Run `Haley.Identity.Cred generate-secret-protection-key Keys/identity-2026.key`. Under `Haley:Identity:Server:SecretProtection`, set `ActiveKeyId=identity-2026` and add `{ "KeyId": "identity-2026", "Path": "Keys/identity-2026.key" }` to `Keys`. This key protects MFA and federation handoff payloads. Retain old keys during rotation.
6. Assign each application a stable GUID. Configure `Server:SessionBindingKeys:<application-guid>:<key-id>` with a random secret of at least 32 characters. Configure exact callback URLs in `Server:AllowedReturnUris:<application-guid>` for corporate authentication and recovery. The application GUID by itself cannot issue or redeem a session.
7. Start the host and open `/admin/`. The local default is `http://127.0.0.1:7430/admin/`. `/health` confirms startup after schema initialization. The UI contains Identity and Federation only. User accounts, password changes, MFA and sessions use the shared engine. Configure SAML certificates or signed corporate callbacks under Federation; see [the federation guide](FEDERATION.md).

Browser session keys are created automatically in `Management:KeyDirectory` (default `State/AdminKeys`). Preserve that directory and the configured lockout file. Session cookies are HttpOnly, SameSite Strict, fixed expiry, and use CSRF protection. Logout revokes the server-side session; restarting the host or changing the management password hash requires a new login. Browser keys and the database secret-protection key have different purposes.

To clear a management login lockout, run `Haley.Identity.Cred reset-lockout State/admin-login-lockout.json` from the host content root, or pass an absolute path. This does not reset a user's account lock. The tool has no database dependency at runtime for these commands.

## Podman

Publish the host, then build `localhost/haley.identity:0.1.0` with the published `podman.cfile`. Copy `haley-identity.container` to `/etc/containers/systemd/`. It joins `dlab-net`, depends on your existing `dlab-maria.service`, and listens on container port 5000. Containers call `http://haley-identity:5000/`. The Quadlet publishes host loopback `127.0.0.1:7430` for local access or an explicitly configured reverse proxy.

Persist `hi-config`, `hi-keys`, `hi-state`, and `hi-saml-certs`. The UI is part of the image; there is no wwwroot volume. `identity-admin.config.json` is linked from the Config volume and can change the title/API base path. Existing named volumes preserve their configuration across upgrades; review new keys when changing images.

Run `systemctl daemon-reload`, then `systemctl start haley-identity.service`. Use `systemctl status` and `journalctl -u haley-identity.service` for startup diagnostics. Quadlet's `[Install]` section handles boot startup; do not enable the generated transient service directly.

If a TLS reverse proxy is used, set `Haley:Identity:TrustedProxies` to its actual IP addresses so forwarded HTTPS and source addresses are honored. Loopback proxies are trusted by the framework default. Route the admin UI only through your administration boundary. If external providers need public callbacks, expose only the two exact `/identity/federation/...` callback routes, not the trusted `/api/identity` routes.

## Kida

Kida still uses its own Service and Admin containers. Do not start the standalone Haley host against a Kida-owned database. Kida embeds the shared engine, installs shared SQL first and its extension second, and enforces its OAuth client/resource rules. This prototype release assumes the owner recreates databases. No live database is reset by the tooling or by these instructions.
