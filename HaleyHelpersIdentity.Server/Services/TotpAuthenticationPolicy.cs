namespace Haley.Services;

internal sealed class TotpAuthenticationPolicy : ITotpAuthenticationPolicy
{
    public ValueTask<IFeedback> AuthorizeAsync(Guid applicationId, string context,
        StoredVerificationSubject subject, CancellationToken cancellationToken) =>
        ValueTask.FromResult<IFeedback>(new Feedback(true, "Primary authenticator login is permitted."));
}
