# Existing Kida database upgrade

This is a Prototype maintenance-window migration. Old and new writers must not run concurrently. No persistent/local Kida database was altered during implementation.

1. Build and stage the updated Kida deployment, shared package and configuration. Preserve the existing Kida MFA key ring and key identifiers.
2. Stop every writer against the target Identity database. Back up its schema and data, including `__schema_history`, and retain the old binaries and encryption keys.
3. Confirm the existing numeric-status schema is present. Run `Architecture/Kida/Database/Security/Identity/Manual Migrations/MariaDB/20260922_extract_haley_identity.sql` using your database deployment tooling and the intended database selected explicitly.
4. The script checks its preconditions, copies OAuth session and MFA enrollment context, validates the copy, then replaces the base columns. It adds `user_session_token`, `oauth_session_ctx`, and `oauth_mfa_enroll_ctx`. It renames `client_uid` to `application_uid` in `user_origin`, `login_attempt`, `mfa_enroll`, `challenge_ctx`, and `grant_ctx`; `user_session` gains application ownership and a session-kind flag, with existing sessions marked 2 (OAuth). Fresh opaque sessions use kind 1. Existing account GUIDs, status bits, password verifiers, MFA ciphertext and refresh-family verifiers are preserved.
5. MariaDB DDL commits implicitly. The script is a one-time migration with guards, not a resumable transaction. If it stops, keep writers stopped and inspect the failing precondition. Restore the backup for rollback instead of blindly rerunning a partly applied script.
6. Run its post-migration checks. Existing session context and application ownership must match the original clients. Confirm row counts and backup comparisons for credentials, MFA and refresh families.
7. Start the updated Kida Service. Its installer composes the shared schema followed by the Kida extension and records distinct append-only schema-history entries. Existing historical entries are not overwritten. It rejects the pre-extraction session shape instead of silently ALTERing it.
8. Verify existing password/MFA login, existing refresh sessions, password recovery, client retirement and the Admin identity views. Verify the new scoped foundation API with a deliberately granted client. Then reopen traffic.

Fresh standalone databases install only the shared schema/seed. Fresh Kida databases install the shared schema/seed followed by Kida's extension schema. There is one canonical definition of each base table. A copy of the shared schema embedded in the Server package is a build artifact, not a second editable canonical source.

Rollback after new binaries have written data requires restoring the database backup and old binaries together. Never restart old binaries against the transformed schema.
