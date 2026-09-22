# Haley Identity initialization

## Local or embedded development

1. Build `HaleyHelpers.Identity_Ref.sln` beside the existing Haley and architecture repositories. The normal solution resolves Haley packages.
2. Configure `AdapterStrings:identity` and `ConnectionStrings:identity` using the existing Haley adapter format. The sample uses the existing MariaDB host at `host.containers.internal:3307`, database `haley_identity`. Replace `CHANGE_ME` in your deployment configuration.
3. Set `Haley:Identity:Server:TrustedNetwork` to true for the standalone host only after placing it inside the intended private application network. This is intentional anonymous application API access, not an internet login endpoint.
4. Assign each application a stable GUID. Configure `Haley:Identity:Server:SessionBindingKeys:<application-guid>:<key-id>` with a random secret of at least 32 characters. Multiple key IDs permit rotation; remove the previous key after callers switch. The application GUID alone is not proof for session issuance, validation or revocation.
5. For TOTP, create a 32-byte random protection key in the mounted `Keys` directory. A raw 32-byte file or Base64 representation is supported. Set `SecretProtection:ActiveKeyId`, and add a `Keys` entry with matching `KeyId` and `Path`, such as `Keys/identity-2026.key`. Retain old keys for decryption while rotating. Protect this directory and back it up with the database.
6. `Initialize=true` bootstraps a fresh schema and seed with the existing Haley initializer. It does not ALTER an old Kida schema. Apply the manual migration before upgrading existing Kida.
7. Run the host. Its local default is `127.0.0.1:7430`. `/health` reports readiness after configured database initialization. Other routes are under `/api/identity`. Applications call it with `AddHaleyIdentity(...UseRemote())`.

## Podman Quadlet

Publish `HaleyIdentityHost` and build `localhost/haley.identity:0.1.0` with the published `podman.cfile`. Copy `haley-identity.container` to `/etc/containers/systemd/`.

The container joins the existing `dlab-net` and depends on `dlab-maria.service`. Its internal listener is `0.0.0.0:5000`. No host port is published. Other containers on that network use `http://haley-identity:5000/`. A host process or remote machine requires separately arranged private routing; this Quadlet intentionally does not provide public access.

The named volumes are `hi-config` at `/app/target/Config` and `hi-keys` at `/app/target/Keys`. Edit the copied configuration before enabling trusted-network operation and session issuance. The image's initial configuration deliberately contains placeholders. Image upgrades retain existing volume contents, so review new configuration keys when upgrading.

After editing the Quadlet, run `systemctl daemon-reload`, then `systemctl start haley-identity.service`. The `[Install] WantedBy=multi-user.target` entry supplies the generated unit's boot dependency. Do not run `systemctl enable` on the generated transient unit. Inspect `systemctl status haley-identity.service` and `journalctl -u haley-identity.service` for startup diagnostics.

The service returns binding/validation failures as 400, missing resources as 404 where applicable, unauthorized session bindings as 401, rate limits as 429, and unexpected failures as 500 with a trace identifier. Passwords, opaque tokens, delivery codes and protection keys must stay out of logs.

## Kida

Existing Kida deployments keep their Service and Admin containers. There is no new mandatory container. Apply [the migration](MIGRATION.md), deploy the updated Kida binaries and shared package, then explicitly grant each client the foundation scopes it needs. Catalog registration describes scopes; it does not grant them. Kida Admin continues to call Kida Service and receives no database access.
