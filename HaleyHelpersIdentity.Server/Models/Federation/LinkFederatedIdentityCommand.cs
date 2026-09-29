namespace Haley.Models;
public sealed record LinkFederatedIdentityCommand(Guid UserId, Guid ProviderId, string Subject, string ClaimsPayload, string? EmailNormalized, string? EmailDisplay, string DisplayName, bool CreateUser, bool AutoLink, bool EmailVerified, DateTimeOffset AuthenticatedAt);
