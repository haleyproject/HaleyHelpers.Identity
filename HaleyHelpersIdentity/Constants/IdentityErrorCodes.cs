using Haley.Abstractions;

namespace Haley.Constants;
public static class IdentityErrorCodes
{
    public const string InvalidRequest = "identity.invalid_request";
    public const string DuplicateIdentity = "identity.duplicate";
    public const string LinkVerificationRequired = "identity.link_verification_required";
    public const string InvalidCredentials = "identity.invalid_credentials";
    public const string IdentityUnavailable = "identity.unavailable";
    public const string SessionUnavailable = "identity.session_unavailable";
    public const string RefreshTokenReplay = "identity.refresh_token_replay";
    public const string SigningUnavailable = "identity.signing_unavailable";
    public const string SecretProtectionUnavailable = "identity.secret_protection_unavailable";
    public const string PasswordChangeRequired = "identity.password_change_required";
    public const string PasswordReuse = "identity.password_reuse";
    public const string InvalidClient = "identity.invalid_client";
    public const string InvalidClientIdentifier = "identity.invalid_client_identifier";
    public const string InvalidClientDisplayName = "identity.invalid_client_display_name";
    public const string InvalidClientLifetime = "identity.invalid_client_lifetime";
    public const string InvalidRedirectUri = "identity.invalid_redirect_uri";
    public const string AudienceNotFound = "identity.audience_not_found";
    public const string AudienceInUse = "identity.audience_in_use";
    public const string InvalidClientResource = "identity.invalid_client_resource";
    public const string InvalidClientScope = "identity.invalid_client_scope";
    public const string ManagementClientConsoleOnly = "identity.management_client_console_only";
    public const string ScopeOwnershipConflict = "identity.scope_ownership_conflict";
    public const string UnsupportedGrantType = "identity.unsupported_grant_type";
    public const string LifecycleConflict = "identity.lifecycle_conflict";
    public const string VerificationRequired = "identity.verification_required";
    public const string VerificationInvalid = "identity.verification_invalid";
    public const string VerificationExhausted = "identity.verification_exhausted";
    public const string MfaRequired = "identity.mfa_required";
    public const string MfaInvalid = "identity.mfa_invalid";
    public const string FederationRejected = "identity.federation_rejected";
    public const string SamlCertificateInvalid = "identity.saml_certificate_invalid";
    public const string SamlCertificateConflict = "identity.saml_certificate_conflict";
    public const string SamlCertificateMissing = "identity.saml_certificate_missing";
}
