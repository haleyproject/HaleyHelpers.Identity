namespace Haley.Abstractions;

/// <summary>An owning host can enforce its client and domain MFA policies before consuming a login proof.</summary>
public interface IIdentityVerificationMfaPolicy
{
    ValueTask<IFeedback<IReadOnlyCollection<string>>> VerifyAsync(VerificationMfaRequest request, CancellationToken cancellationToken);
}
