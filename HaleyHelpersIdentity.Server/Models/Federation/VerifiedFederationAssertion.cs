namespace Haley.Models;

/// <summary>Server-only, encrypted handoff payload produced after provider proof validation.</summary>
public sealed record VerifiedFederationAssertion(Guid ApplicationId, string Context, Guid ProviderId, string ProviderCode,
    string Subject, string? Email, string DisplayName, string ClaimsPayload, string AssertionId,
    DateTimeOffset AuthenticatedAt, string AuthenticationMethod, bool EmailVerified = true);
