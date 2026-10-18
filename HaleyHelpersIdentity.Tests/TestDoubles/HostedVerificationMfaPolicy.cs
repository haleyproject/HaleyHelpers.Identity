using Haley.Abstractions;
using Haley.Models;

namespace Haley.Tests;

internal sealed class HostedVerificationMfaPolicy : IIdentityVerificationMfaPolicy
{
    public ValueTask<IFeedback<IReadOnlyCollection<string>>> VerifyAsync(VerificationMfaRequest request, CancellationToken ct) =>
        ValueTask.FromResult<IFeedback<IReadOnlyCollection<string>>>(new Feedback<IReadOnlyCollection<string>>(true, "Verified.", []));
}
