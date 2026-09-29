namespace Haley.Models;

/// <summary>Internal composition result. Persistence identifiers are never serialized by endpoints.</summary>
public sealed record VerifiedFederatedAccount(FederatedIdentityLinkResult Account, Guid ApplicationId,
    string Context, IReadOnlyCollection<string> AuthenticationMethods);
