using System.Reflection;
using Haley.Abstractions;
using Haley.Models;

namespace Haley.Tests;

public class RecipientIdentityProxy : DispatchProxy
{
    public int Calls { get; private set; }
    public CompleteIdentityVerificationRequest? Submission { get; private set; }
    protected override object? Invoke(MethodInfo? targetMethod, object?[]? args)
    {
        if (targetMethod?.Name != nameof(IIdentity.CompleteVerificationAsync)) throw new NotSupportedException();
        Calls++; Submission = (CompleteIdentityVerificationRequest)args![0]!;
        return ValueTask.FromResult<IFeedback<IdentityVerificationCompletion>>(new Feedback<IdentityVerificationCompletion>(true,
            "Verified.", new(Guid.NewGuid(), Submission.Purpose, true, IdentityStatus.Pending, null)));
    }
}
