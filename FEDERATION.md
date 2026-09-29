# Corporate authentication and federation

Haley owns reusable user authentication: passwords, email verification/OTP, MFA, SAML, signed corporate callbacks, provider discovery, external-subject links and one-time federation handoffs. Kida uses this engine in process and adds OAuth clients/scopes, resource authority, tenant associations and OAuth token issuance. Deploying Kida does not require the standalone Haley host.

## Provider selection and trust

A provider has a stable `ProviderId` and `Code`, a display label, a protocol and an expected issuer. The display label can be a company name. It is not a routing or trust identifier. Supported protocols are `Saml` and `SignedCallback`; OIDC ceremonies are not implemented.

`DiscoveryDomains` lets an application find candidate providers from an entered email/domain. Multiple providers can match. The application presents the choice, or starts a known provider code directly. Discovery never proves email ownership. `AuthoritativeDomains` separately permits verified email claims from that provider to link an existing account. Without that trust, an existing email account cannot be taken over through a corporate callback. The durable identity key is the provider plus its case-sensitive stable subject, not the company name or a mutable email address.

Optional `allowedApplicationIds` in provider configuration limits callers. An absent or empty list permits any otherwise authorized application in this deployment. In Kida, a provider associated with a tenant requires a nonempty application allowlist; tenant association alone never grants access. It does not create a tenant membership or license.

## Browser flow

1. The application backend generates a random state and a PKCE verifier (43 to 128 unreserved ASCII characters). Keep both in the application's browser-session state. Send only the SHA-256 base64url challenge to Identity.
2. Call `IIdentityFederation.BeginAsync` with application GUID, context, provider code, registered return URI, state and challenge. Identity stores the attempt and returns `AuthorizationUrl`.
3. Redirect the browser to that URL. SAML uses a compressed AuthnRequest and RelayState. SignedCallback uses `attempt` and the configured `callback` URI. The corporate bridge does not receive or choose the application's return URI.
4. The provider completes interactive authentication and posts its proof to Identity's callback. Identity validates the proof and atomically consumes the attempt. Neither an email address nor the opaque attempt value alone can authenticate a user.
5. Identity posts a short-lived opaque handoff code and the original state to the stored application return URI. It never sends the assertion, password or a session token in this form. The application's callback must accept a form POST and validate state against the initiating browser session. Account for cross-site POST cookie behavior when choosing that session cookie's SameSite policy.
6. The application backend redeems the handoff with its original PKCE verifier and application binding. Identity rechecks provider/application authority, account state and MFA. Missing MFA can be retried before expiry without consuming the handoff. Only one successful redemption consumes it and can issue a session.

The standalone/shared facade returns an `OpaqueSession`. The native Kida OAuth endpoint returns `FederatedIdentityResult` with Kida access/refresh tokens. A Kida foundation call returns the shared opaque session with Kida client/resource ownership. A user subject is never allowed to bypass a locked, suspended, retired or password-change-required account.

## Signed callback contract

Register a provider with protocol `SignedCallback`. Its JSON configuration contains:

| Field | Meaning |
| --- | --- |
| `authorizationUrl` | Corporate browser login entry point. HTTPS, or loopback HTTP during development. |
| `callbackUrl` | Fixed Identity browser callback. The bridge must allowlist it. |
| `audience` | Exact audience expected in the signed assertion. |
| `keys` | Array of `{ "id": "key-id", "pem": "public RSA PEM" }`. Only public keys, at least 2048 bits. |
| `maximumAssertionSeconds` | Maximum assertion age/lifetime, 30 to 300 seconds; default 120. |
| `allowedApplicationIds` | Optional list of application GUIDs. Kida GUIDs are OAuth client IDs. |

The bridge authenticates its user using its own trusted process, preserves the incoming `attempt`, then creates a signed JWT:

- Header: `alg=RS256`, `typ=identity-bridge+jwt`, and a registered `kid`.
- Required claims: exact configured `iss` and `aud`, stable case-sensitive `sub`, unique `jti`, `iat`, `exp`, and `attempt` as the original 32-character GUID without hyphens. `nbf` is optional and enforced when present.
- Optional claims: `name`, `email`, and boolean `email_verified`. Email linking/verification requires both `email_verified=true` and a matching authoritative domain. Keep the payload minimal.
- Keep the RSA private key at the bridge. Identity stores only the public key. There is no network key-discovery URL or shared RSA private key in Identity.
- Form POST `attempt` and `assertion` to `/identity/federation/external/callback` on Haley. Kida's default path is `/api/kida/identity/federation/external/callback`.

Identity enforces the signature, fixed algorithm/type/key, issuer, audience, bounded timestamps, attempt binding and replay protection. It does not accept unsigned JWTs, arbitrary callback URLs or a browser-provided verified email as proof. During key rotation, register old and new public key IDs before switching the bridge, then remove the old key after outstanding attempts have expired.

## SAML configuration

Use protocol `Saml`, expected IdP issuer, `ssoUrl`, `acsUrl`, `spEntityId`, and selected public signing certificate names. Upload the certificates in the Federation page. `emailClaim` and `displayNameClaim` can select provider claim names. Signatures, issuer, audience, lifetime, destination, recipient, InResponseTo and replay validation are mandatory. Clock skew is limited to 120 seconds. Unsafe validation settings are rejected.

Haley ACS: `/identity/federation/saml/acs`. Kida ACS: `/api/kida/identity/federation/saml/acs`. Configure this exact external URL at the IdP and in the provider, including any reverse-proxy prefix. The existing Kida AuthEdge SAML page delegates to the same shared engine.

## SDK and HTTP surface

`AddHaleyIdentity(...UseEmbedded(...))`, `UseRemote()` and Kida's `UseKida(...)` also register `IIdentityFederation`. Inject it alongside `IIdentity`. The request types live in `Haley.Models`; there are no duplicate Kida federation DTOs.

| Operation | Shared route under `/api/identity` |
| --- | --- |
| Discover providers | `POST /federation/discovery` |
| Begin browser attempt | `POST /federation/attempts` |
| Complete SAML proof from a trusted backend | `POST /federation/saml/completion` |
| Complete signed callback from a trusted backend | `POST /federation/external/completion` |
| Redeem handoff for opaque session | `POST /federation/handoffs` |

Kida mounts the shared API at `/api/kida/identity/foundation`, behind machine bearer authentication and operation scopes. Begin/discovery use `identity.authenticate`; proof completion and redemption use `identity.federation.exchange`. The configured resource header remains bound through redemption. Kida's native OAuth start is `/api/kida/identity/federation/attempts`, and redemption is `/api/kida/identity/federation/handoffs`.

For standalone remote calls, set `ApplicationId` in the client and request. Set `Context` to a stable nonempty application context such as `haley.identity`. Configure exact return URIs under `Haley:Identity:Server:AllowedReturnUris:<application-guid>`. Redemption requires that application's session binding key. Browser callbacks are deliberately anonymous because they authenticate the provider proof and only return a PKCE-bound handoff; the rest of the standalone machine API remains inside the trusted deployment boundary.

## Ownership and fresh databases

Shared canonical tables: `identity_provider`, `identity_provider_info`, `provider_domain`, `external_identity`, `external_identity_info`, `federation_request`, `federation_replay`, `federation_handoff`. They are installed by the Haley schema before Kida's extension. `identity_provider_tenant` is Kida-owned. OAuth client IDs are stored as application GUIDs in shared attempts/handoffs, without a shared foreign key to OAuth.

This is a prototype fresh-install change. The old `saml_auth_req`, `saml_replay` and `saml_handoff` definitions are removed from Kida canonical SQL. There is no automatic ALTER path and no new in-place migration. Older extraction migrations do not upgrade to this baseline. Existing deployments must be recreated by the owner as agreed, or require a separately designed migration.
