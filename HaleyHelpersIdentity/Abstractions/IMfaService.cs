using Haley.Abstractions;

namespace Haley.Abstractions;
public interface IMfaService
{
    ValueTask<IReadOnlyCollection<MfaMethodInfo>> ListMethodsAsync(Guid userId, CancellationToken cancellationToken = default);
    ValueTask<IFeedback<TotpEnrollmentReceipt>> BeginTotpEnrollmentAsync(BeginTotpEnrollmentRequest request, CancellationToken cancellationToken = default);
    ValueTask<IFeedback<TotpEnrollmentDetails>> InspectTotpEnrollmentAsync(string ticket, CancellationToken cancellationToken = default);
    ValueTask<IFeedback<TotpEnrollmentCompletion>> ConfirmTotpEnrollmentAsync(ConfirmTotpTicketRequest request, CancellationToken cancellationToken = default);
    ValueTask<IFeedback> RetireMethodAsync(Guid userId, Guid methodId, CancellationToken cancellationToken = default);
    ValueTask<IFeedback<RecoveryCodesReceipt>> ReplaceRecoveryCodesAsync(ReplaceRecoveryCodesRequest request, CancellationToken cancellationToken = default);
    ValueTask<IFeedback> VerifyAsync(VerifyMfaRequest request, CancellationToken cancellationToken = default);
}
