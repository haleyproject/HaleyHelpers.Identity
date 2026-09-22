# Haley Identity extraction

Status: implemented and verified on 2026-09-22.

## Accepted decisions

- Package name Haley.Helpers.Identity. Shared IIdentity facade; explicit embedded, remote Haley, or remote Kida backend.
- Shared account per database; minimal password-free accounts linked by application origin.
- Opaque application sessions; 30-minute default fixed expiry; binding secrets on standalone session operations.
- Standalone account API uses explicitly configured private-network trust. Kida retains OAuth and client policy enforcement.
- MariaDB, .NET 8, Prototype. No existing local or production database modification. Preserve existing Kida credentials, MFA encryption and sessions.
- Three production projects: client/contracts, Server, Host. Reuse Haley.Rest, Feedback, DB, security and hosting.
- Preserve Kida public contracts through adapters. No duplicate shared implementations or canonical table definitions.

## Delivery checklist

- [x] Shared contracts and registration
- [x] Shared account, credential, MFA and verification engine
- [x] Shared persistence, schema and migration
- [x] Opaque sessions and application binding
- [x] Standalone host and remote SDK
- [x] Kida engine and API integration
- [x] Kida SDK adapter
- [x] Behavioral, database and compatibility verification
- [x] Deployment and architecture documentation

## Baseline

Kida Identity, Common, Service and Haley aggregate repositories were clean at implementation start. Architecture already contains user changes across Kida and other families; preserve them. Canonical Identity schema and seed baseline copies are held outside the repositories in the local temporary extraction workspace.

## Verification results

- 16 shared-library tests passed, including isolated MariaDB integration, opaque session binding, credential races, retired contacts, MFA replay/recovery, transaction rollback, numeric status serialization, configuration binding and REST cancellation/error fidelity.
- 148 Kida Identity tests passed, including preparation of shared and Kida SQL statements against the composed canonical schema.
- 115 Kida Service tests passed, including every foundation endpoint's OAuth policy and UseKida transport integration.
- 12 Kida Admin tests passed. Total: 291 passing tests.
- The new source-reference solution, the normal package solution, the Kida Service package build and the dependent Sanction package build passed.
- Both library packages were packed locally. They were not published.
- A real standalone HTTP host passed health, account binding, rejected missing session key, session issuance and claim-free session validation checks against the disposable database.
- The migration succeeded against empty and populated pre-extraction schemas. Column definitions matched a freshly composed schema. Credential hashes/parameters, refresh verifiers, MFA ciphertext/tickets and existing session client/audience associations were preserved.
- The existing upstream IdentityModel version-alignment warning remains in Haley dependency builds; the added Identity projects have no C# compiler warnings.

The isolated tests used a separate temporary MariaDB process. Existing local Kida databases and the running Kida deployment were not migrated. Apply the documented maintenance-window migration before starting new Kida binaries against an existing database. No Git commit was created.

Only dependency-version entries were changed in the already edited Sanction package manifest; its existing feature work was preserved. Architecture changes also preserve the pre-existing work outside the Identity extraction.
