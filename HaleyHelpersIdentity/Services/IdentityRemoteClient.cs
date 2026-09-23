using Haley.Enums;
namespace Haley.Services;

public sealed class IdentityRemoteClient(IdentityRemoteTransport transport) : IIdentity
{
    public ValueTask<IFeedback<UserIdentity>> GetAccountAsync(Guid userId, CancellationToken cancellationToken = default) =>
        transport.SendAsync<UserIdentity>("GetAccount", $"accounts/{userId:D}", Method.GET, null, cancellationToken);

    public ValueTask<IFeedback<UserIdentity>> FindAccountAsync(string email, CancellationToken cancellationToken = default) =>
        transport.SendAsync<UserIdentity>("FindAccount", "accounts/resolve", Method.POST, new AccountEmailRequest(email), cancellationToken);

    public ValueTask<IFeedback<UserIdentity>> EnsureAccountAsync(EnsureAccountRequest request, CancellationToken cancellationToken = default) =>
        transport.SendAsync<UserIdentity>("EnsureAccount", "accounts", Method.POST, request, cancellationToken);

    public ValueTask<IFeedback<UserIdentityPage>> ListAccountsAsync(UserPageRequest request, CancellationToken cancellationToken = default) =>
        transport.SendAsync<UserIdentityPage>("ListAccounts", "accounts/search", Method.POST, request, cancellationToken);

    public ValueTask<IFeedback<UserProfile>> GetProfileAsync(Guid userId, CancellationToken cancellationToken = default) =>
        transport.SendAsync<UserProfile>("GetProfile", $"accounts/{userId:D}/profile", Method.GET, null, cancellationToken);

    public ValueTask<IFeedback<UserProfile>> UpdateProfileAsync(Guid userId, UpdateUserProfileRequest request, CancellationToken cancellationToken = default) =>
        transport.SendAsync<UserProfile>("UpdateProfile", $"accounts/{userId:D}/profile", Method.PUT, request, cancellationToken);

    public ValueTask<IFeedback> SetAccountStatusAsync(Guid userId, AccountStatusRequest request, CancellationToken cancellationToken = default) =>
        transport.SendAsync("SetAccountStatus", $"accounts/{userId:D}/status", Method.PATCH, request, cancellationToken);

    public ValueTask<IFeedback> SetPasswordAsync(Guid userId, SetPasswordRequest request, CancellationToken cancellationToken = default) =>
        transport.SendAsync("SetPassword", $"accounts/{userId:D}/password", Method.PUT, request, cancellationToken);

    public ValueTask<IFeedback> ChangePasswordAsync(ChangePasswordRequest request, CancellationToken cancellationToken = default) =>
        transport.SendAsync("ChangePassword", "password/changes", Method.POST, request, cancellationToken);

    public ValueTask<IFeedback<OpaqueSession>> AuthenticatePasswordAsync(PasswordAuthenticationRequest request, CancellationToken cancellationToken = default) =>
        transport.SendAsync<OpaqueSession>("AuthenticatePassword", "sessions/password", Method.POST, request, cancellationToken);

    public ValueTask<IFeedback<OpaqueSession>> CreateApplicationSessionAsync(ApplicationSessionRequest request, CancellationToken cancellationToken = default) =>
        transport.SendAsync<OpaqueSession>("CreateApplicationSession", "sessions/application", Method.POST, request, cancellationToken);

    public ValueTask<IFeedback<SessionValidation>> ValidateSessionAsync(string token, CancellationToken cancellationToken = default) =>
        transport.SendAsync<SessionValidation>("ValidateSession", "sessions/validation", Method.POST, new SessionTokenRequest(token), cancellationToken);

    public ValueTask<IFeedback> RevokeSessionAsync(string token, CancellationToken cancellationToken = default) =>
        transport.SendAsync("RevokeSession", "sessions", Method.DELETE, new SessionTokenRequest(token), cancellationToken);

    public ValueTask<IFeedback<UserLoginAttemptPage>> ListLoginAttemptsAsync(UserLoginAttemptSearchRequest request, CancellationToken cancellationToken = default) =>
        transport.SendAsync<UserLoginAttemptPage>("ListLoginAttempts", "login-attempts/search", Method.POST, request, cancellationToken);

    public ValueTask<IFeedback> ReleaseAccountLockAsync(Guid userId, CancellationToken cancellationToken = default) =>
        transport.SendAsync("ReleaseAccountLock", $"accounts/{userId:D}/lock/release", Method.POST, null, cancellationToken);

    public ValueTask<IFeedback<IReadOnlyCollection<MfaMethodInfo>>> ListMfaMethodsAsync(Guid userId, CancellationToken cancellationToken = default) =>
        transport.SendAsync<IReadOnlyCollection<MfaMethodInfo>>("ListMfaMethods", $"accounts/{userId:D}/mfa-methods", Method.GET, null, cancellationToken);

    public ValueTask<IFeedback<TotpEnrollmentReceipt>> BeginTotpEnrollmentAsync(BeginTotpEnrollmentRequest request, CancellationToken cancellationToken = default) =>
        transport.SendAsync<TotpEnrollmentReceipt>("BeginTotpEnrollment", "mfa/enrollments", Method.POST, request, cancellationToken);

    public ValueTask<IFeedback<TotpEnrollmentDetails>> InspectTotpEnrollmentAsync(string ticket, CancellationToken cancellationToken = default) =>
        transport.SendAsync<TotpEnrollmentDetails>("InspectTotpEnrollment", "mfa/enrollments/inspection", Method.POST, new MfaTicketRequest(ticket), cancellationToken);

    public ValueTask<IFeedback<TotpEnrollmentCompletion>> ConfirmTotpEnrollmentAsync(ConfirmTotpTicketRequest request, CancellationToken cancellationToken = default) =>
        transport.SendAsync<TotpEnrollmentCompletion>("ConfirmTotpEnrollment", "mfa/enrollments/confirmation", Method.POST, request, cancellationToken);

    public ValueTask<IFeedback> RetireMfaMethodAsync(Guid userId, Guid methodId, CancellationToken cancellationToken = default) =>
        transport.SendAsync("RetireMfaMethod", $"accounts/{userId:D}/mfa-methods/{methodId:D}", Method.DELETE, null, cancellationToken);

    public ValueTask<IFeedback<RecoveryCodesReceipt>> ReplaceRecoveryCodesAsync(ReplaceRecoveryCodesRequest request, CancellationToken cancellationToken = default) =>
        transport.SendAsync<RecoveryCodesReceipt>("ReplaceRecoveryCodes", "mfa/recovery-codes", Method.POST, request, cancellationToken);

    public ValueTask<IFeedback> VerifyMfaAsync(VerifyMfaRequest request, CancellationToken cancellationToken = default) =>
        transport.SendAsync("VerifyMfa", "mfa/verification", Method.POST, request, cancellationToken);

    public ValueTask<IFeedback<PasswordResetInitiationResult>> BeginPasswordResetAsync(BeginPasswordResetRequest request, CancellationToken cancellationToken = default) =>
        transport.SendAsync<PasswordResetInitiationResult>("BeginPasswordReset", "password/resets", Method.POST, request, cancellationToken);

    public ValueTask<IFeedback<PasswordResetGrantReceipt>> VerifyPasswordResetCodeAsync(VerifyPasswordResetCodeRequest request, CancellationToken cancellationToken = default) =>
        transport.SendAsync<PasswordResetGrantReceipt>("VerifyPasswordResetCode", "password/resets/verification", Method.POST, request, cancellationToken);

    public ValueTask<IFeedback<PasswordResetCompletionReceipt>> CompletePasswordResetAsync(CompletePasswordResetRequest request, CancellationToken cancellationToken = default) =>
        transport.SendAsync<PasswordResetCompletionReceipt>("CompletePasswordReset", "password/resets/completion", Method.POST, request, cancellationToken);

    public ValueTask<IFeedback<EmailVerificationInfo>> GetEmailVerificationAsync(string email, CancellationToken cancellationToken = default) =>
        transport.SendAsync<EmailVerificationInfo>("GetEmailVerification", "verification/email/status", Method.POST, new AccountEmailRequest(email), cancellationToken);

    public ValueTask<IFeedback<IdentityVerificationInitiation>> BeginVerificationAsync(BeginIdentityVerificationRequest request, CancellationToken cancellationToken = default) =>
        Enum.IsDefined(request.Purpose)
            ? transport.SendAsync<IdentityVerificationInitiation>(IdentityVerificationRoutes.Operation(request.Purpose, false),
                $"verification/{IdentityVerificationRoutes.Segment(request.Purpose)}/challenges", Method.POST, request, cancellationToken)
            : ValueTask.FromResult<IFeedback<IdentityVerificationInitiation>>(new Feedback<IdentityVerificationInitiation>(false, "A single valid purpose is required.") { Key = "invalid_request", Code = 400 });

    public ValueTask<IFeedback<IdentityVerificationCompletion>> CompleteVerificationAsync(CompleteIdentityVerificationRequest request, CancellationToken cancellationToken = default) =>
        Enum.IsDefined(request.Purpose)
            ? transport.SendAsync<IdentityVerificationCompletion>(IdentityVerificationRoutes.Operation(request.Purpose, true),
                $"verification/{IdentityVerificationRoutes.Segment(request.Purpose)}/completion", Method.POST, request, cancellationToken)
            : ValueTask.FromResult<IFeedback<IdentityVerificationCompletion>>(new Feedback<IdentityVerificationCompletion>(false, "A single valid purpose is required.") { Key = "invalid_request", Code = 400 });

}
