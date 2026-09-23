namespace Haley.Abstractions;

/// <summary>One account API for embedded execution and remote Haley or Kida hosts.</summary>
public interface IIdentity
{
    ValueTask<IFeedback<UserIdentity>> GetAccountAsync(Guid userId, CancellationToken cancellationToken = default);
    ValueTask<IFeedback<UserIdentity>> FindAccountAsync(string email, CancellationToken cancellationToken = default);
    ValueTask<IFeedback<UserIdentity>> EnsureAccountAsync(EnsureAccountRequest request, CancellationToken cancellationToken = default);
    ValueTask<IFeedback<UserIdentityPage>> ListAccountsAsync(UserPageRequest request, CancellationToken cancellationToken = default);
    ValueTask<IFeedback<UserProfile>> GetProfileAsync(Guid userId, CancellationToken cancellationToken = default);
    ValueTask<IFeedback<UserProfile>> UpdateProfileAsync(Guid userId, UpdateUserProfileRequest request, CancellationToken cancellationToken = default);
    ValueTask<IFeedback> SetAccountStatusAsync(Guid userId, AccountStatusRequest request, CancellationToken cancellationToken = default);
    ValueTask<IFeedback> SetPasswordAsync(Guid userId, SetPasswordRequest request, CancellationToken cancellationToken = default);
    ValueTask<IFeedback> ChangePasswordAsync(ChangePasswordRequest request, CancellationToken cancellationToken = default);
    ValueTask<IFeedback<OpaqueSession>> AuthenticatePasswordAsync(PasswordAuthenticationRequest request, CancellationToken cancellationToken = default);
    ValueTask<IFeedback<OpaqueSession>> CreateApplicationSessionAsync(ApplicationSessionRequest request, CancellationToken cancellationToken = default);
    ValueTask<IFeedback<SessionValidation>> ValidateSessionAsync(string token, CancellationToken cancellationToken = default);
    ValueTask<IFeedback> RevokeSessionAsync(string token, CancellationToken cancellationToken = default);
    ValueTask<IFeedback<UserLoginAttemptPage>> ListLoginAttemptsAsync(UserLoginAttemptSearchRequest request, CancellationToken cancellationToken = default);
    ValueTask<IFeedback> ReleaseAccountLockAsync(Guid userId, CancellationToken cancellationToken = default);
    ValueTask<IFeedback<IReadOnlyCollection<MfaMethodInfo>>> ListMfaMethodsAsync(Guid userId, CancellationToken cancellationToken = default);
    ValueTask<IFeedback<TotpEnrollmentReceipt>> BeginTotpEnrollmentAsync(BeginTotpEnrollmentRequest request, CancellationToken cancellationToken = default);
    ValueTask<IFeedback<TotpEnrollmentDetails>> InspectTotpEnrollmentAsync(string ticket, CancellationToken cancellationToken = default);
    ValueTask<IFeedback<TotpEnrollmentCompletion>> ConfirmTotpEnrollmentAsync(ConfirmTotpTicketRequest request, CancellationToken cancellationToken = default);
    ValueTask<IFeedback> RetireMfaMethodAsync(Guid userId, Guid methodId, CancellationToken cancellationToken = default);
    ValueTask<IFeedback<RecoveryCodesReceipt>> ReplaceRecoveryCodesAsync(ReplaceRecoveryCodesRequest request, CancellationToken cancellationToken = default);
    ValueTask<IFeedback> VerifyMfaAsync(VerifyMfaRequest request, CancellationToken cancellationToken = default);
    ValueTask<IFeedback<PasswordResetInitiationResult>> BeginPasswordResetAsync(BeginPasswordResetRequest request, CancellationToken cancellationToken = default);
    ValueTask<IFeedback<PasswordResetGrantReceipt>> VerifyPasswordResetCodeAsync(VerifyPasswordResetCodeRequest request, CancellationToken cancellationToken = default);
    ValueTask<IFeedback<PasswordResetCompletionReceipt>> CompletePasswordResetAsync(CompletePasswordResetRequest request, CancellationToken cancellationToken = default);
    ValueTask<IFeedback<EmailVerificationInfo>> GetEmailVerificationAsync(string email, CancellationToken cancellationToken = default);
    ValueTask<IFeedback<IdentityVerificationInitiation>> BeginVerificationAsync(BeginIdentityVerificationRequest request, CancellationToken cancellationToken = default);
    ValueTask<IFeedback<IdentityVerificationCompletion>> CompleteVerificationAsync(CompleteIdentityVerificationRequest request, CancellationToken cancellationToken = default);
}
