namespace Haley.Models;

public sealed record StoredVerificationSubject(UserIdentity Identity, Guid ContactId, string Email,
    DateTimeOffset? VerifiedAt, bool RecoveryEnabled, Guid? CredentialId);
