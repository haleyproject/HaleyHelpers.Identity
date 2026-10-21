namespace Haley.Models;

public sealed class IdentityServerOptions
{
    public const string SectionName = "Haley:Identity:Server";
    public string Adapter { get; set; } = string.Empty;
    public bool Initialize { get; set; } = true;
    public int SessionSeconds { get; set; } = 1800;
    public int PasswordHashIterations { get; set; } = 210000;
    public int PasswordHistoryCount { get; set; } = 5;
    public int MaximumFailedAttempts { get; set; } = 5;
    public int LockoutSeconds { get; set; } = 900;
    private string _issuerLabel = "Haley Identity";
    /// <summary>Hosting identity's display name in authenticator entries and the admin console, independent of any calling application.</summary>
    public string IssuerLabel
    {
        get => _issuerLabel;
        set => _issuerLabel = string.IsNullOrWhiteSpace(value) ? "Haley Identity" : value.Trim();
    }
    public string MfaEnrollmentPath { get; set; } = "/identity/mfa/enroll";
    public string MfaProtectionPurpose { get; set; } = "haley.identity.mfa.totp";
    /// <summary>Explicit previous encryption contexts accepted when reading existing MFA secrets. New secrets always use MfaProtectionPurpose.</summary>
    public string[] PreviousMfaProtectionPurposes { get; set; } = [];
    public string EventPrefix { get; set; } = "haley.identity";
    public IdentitySecretOptions SecretProtection { get; set; } = new();
    public IdentityFederationOptions Federation { get; set; } = new();
    public IdentityMfaOptions Mfa { get; set; } = new();
    public IdentityTotpLoginOptions TotpLogin { get; set; } = new();
    public string PasswordResetPath { get; set; } = "/identity/password/reset";
    public IdentityVerificationOptions Verification { get; set; } = new();
    public Dictionary<string, string[]> AllowedReturnUris { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    public bool TrustedNetwork { get; set; }
    public Dictionary<string, IdentityApplicationOptions> Applications { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    public Dictionary<string, Dictionary<string, string>> SessionBindingKeys { get; set; } = new(StringComparer.OrdinalIgnoreCase);
}
