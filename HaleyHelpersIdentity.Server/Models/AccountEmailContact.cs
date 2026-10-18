namespace Haley.Models;

/// <summary>Recorded mailbox for a selected account, exposed only through the administration boundary.</summary>
public sealed record AccountEmailContact(Guid ContactId, string Email, DateTimeOffset? VerifiedAt, bool RecoveryEnabled = false)
{
    public bool IsVerified => VerifiedAt is not null;
}
