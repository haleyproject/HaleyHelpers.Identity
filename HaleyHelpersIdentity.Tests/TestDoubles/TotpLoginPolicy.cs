using Haley.Abstractions;
using Haley.Models;

namespace Haley.Identity.Tests;

internal sealed class TotpLoginPolicy : ITotpAuthenticationPolicy
{
    public bool RequireMfa { get; set; }
    public ValueTask<IFeedback> AuthorizeAsync(Guid applicationId, string context, StoredVerificationSubject subject, CancellationToken cancellationToken) =>
        ValueTask.FromResult<IFeedback>(new Feedback(!RequireMfa, "Test authenticator policy.") { Key = RequireMfa ? "mfa_required" : null, Code = RequireMfa ? 403 : 200 });
}
