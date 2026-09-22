using Haley.Abstractions;

namespace Haley.Abstractions;

public interface IPasswordRecoveryService
{
    ValueTask<IFeedback<PasswordResetInitiationResult>> BeginResetAsync(
        BeginPasswordResetRequest request,
        CancellationToken cancellationToken = default);

    ValueTask<IFeedback<PasswordResetGrantReceipt>> VerifyResetCodeAsync(
        VerifyPasswordResetCodeRequest request,
        CancellationToken cancellationToken = default);

    ValueTask<IFeedback<PasswordResetCompletionReceipt>> CompleteResetAsync(
        CompletePasswordResetRequest request,
        CancellationToken cancellationToken = default);
}
