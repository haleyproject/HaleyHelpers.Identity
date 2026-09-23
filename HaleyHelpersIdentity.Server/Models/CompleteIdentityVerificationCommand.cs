namespace Haley.Models;

public sealed record CompleteIdentityVerificationCommand(StoredVerificationChallenge Challenge,
    StoredVerificationSubject Subject, VerificationPurpose Purpose, DateTimeOffset CompletedAt,
    SetCredentialCommand? Password = null, StartOpaqueSessionCommand? Session = null);
