namespace Haley.Models;

/// <summary>The trusted application asserts authentication; Identity still checks account eligibility.</summary>
public sealed record ApplicationSessionRequest(string Email, bool CreateIfMissing,
    string? DisplayName = null, string? SourceReference = null, Guid? MfaMethodId = null,
    MfaKind? MfaKind = null, string? MfaCode = null);
