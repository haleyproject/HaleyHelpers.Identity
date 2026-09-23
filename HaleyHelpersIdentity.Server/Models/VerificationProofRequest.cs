namespace Haley.Models;

/// <summary>Server-side challenge material shared by legacy owner ceremonies and the general Identity API.</summary>
public sealed record VerificationProofRequest(Guid ApplicationId, Guid UserId, string Purpose, string Destination,
    byte[] ContextHash, int CodeValiditySeconds, int? TokenValiditySeconds = null, Guid? TenantId = null,
    string PolicyCode = "standard-email-6");
