namespace Haley.Abstractions;

/// <summary>Owner policy for using one enrolled authenticator as the primary login factor.</summary>
public interface ITotpAuthenticationPolicy
{
    ValueTask<IFeedback> AuthorizeAsync(Guid applicationId, string context,
        StoredVerificationSubject subject, CancellationToken cancellationToken);
}
