using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;
using Haley.Services;

namespace Haley.Extensions;

public static class IdentityEndpoints
{
    public static RouteGroupBuilder MapHaleyIdentityEndpoints(this IEndpointRouteBuilder endpoints,
        string prefix = "/api/identity", Action<IdentityEndpointOptions>? configure = null)
    {
        var options = new IdentityEndpointOptions();
        configure?.Invoke(options);
        var group = endpoints.MapGroup(prefix).WithTags("Identity").AddEndpointFilter<IdentityBoundaryFilter>();
        if (options.Standalone) group.RequireRateLimiting("Haley.Identity");
        Configure(group.MapGet("/accounts/{userId:guid}", async (Guid userId, IIdentity identity, CancellationToken ct) =>
            (await identity.GetAccountAsync(userId, ct).ConfigureAwait(false)).ToMinimalApiResult()), "GetAccount", options);
        Configure(group.MapPost("/accounts/resolve", async (AccountEmailRequest body, IIdentity identity, CancellationToken ct) =>
            (await identity.FindAccountAsync(body.Email, ct).ConfigureAwait(false)).ToMinimalApiResult()), "FindAccount", options);
        Configure(group.MapPost("/accounts", async (EnsureAccountRequest request, IIdentity identity, CancellationToken ct) =>
            (await identity.EnsureAccountAsync(request, ct).ConfigureAwait(false)).ToMinimalApiResult()), "EnsureAccount", options);
        Configure(group.MapPost("/accounts/search", async (UserPageRequest request, IIdentity identity, CancellationToken ct) =>
            (await identity.ListAccountsAsync(request, ct).ConfigureAwait(false)).ToMinimalApiResult()), "ListAccounts", options);
        Configure(group.MapGet("/accounts/{userId:guid}/profile", async (Guid userId, IIdentity identity, CancellationToken ct) =>
            (await identity.GetProfileAsync(userId, ct).ConfigureAwait(false)).ToMinimalApiResult()), "GetProfile", options);
        Configure(group.MapPut("/accounts/{userId:guid}/profile", async (Guid userId, UpdateUserProfileRequest request, IIdentity identity, CancellationToken ct) =>
            (await identity.UpdateProfileAsync(userId, request, ct).ConfigureAwait(false)).ToMinimalApiResult()), "UpdateProfile", options);
        Configure(group.MapPatch("/accounts/{userId:guid}/status", async (Guid userId, AccountStatusRequest request, IIdentity identity, CancellationToken ct) =>
            (await identity.SetAccountStatusAsync(userId, request, ct).ConfigureAwait(false)).ToMinimalApiResult()), "SetAccountStatus", options);
        Configure(group.MapPut("/accounts/{userId:guid}/password", async (Guid userId, SetPasswordRequest request, IIdentity identity, CancellationToken ct) =>
            (await identity.SetPasswordAsync(userId, request, ct).ConfigureAwait(false)).ToMinimalApiResult()), "SetPassword", options);
        Configure(group.MapPost("/password/changes", async (ChangePasswordRequest request, IIdentity identity, CancellationToken ct) =>
            (await identity.ChangePasswordAsync(request, ct).ConfigureAwait(false)).ToMinimalApiResult()), "ChangePassword", options);
        Configure(group.MapPost("/sessions/password", async (PasswordAuthenticationRequest request, IIdentity identity, CancellationToken ct) =>
            (await identity.AuthenticatePasswordAsync(request, ct).ConfigureAwait(false)).ToMinimalApiResult()), "AuthenticatePassword", options);
        Configure(group.MapPost("/sessions/application", async (ApplicationSessionRequest request, IIdentity identity, CancellationToken ct) =>
            (await identity.CreateApplicationSessionAsync(request, ct).ConfigureAwait(false)).ToMinimalApiResult()), "CreateApplicationSession", options);
        Configure(group.MapPost("/sessions/validation", async (SessionTokenRequest body, IIdentity identity, CancellationToken ct) =>
            (await identity.ValidateSessionAsync(body.Token, ct).ConfigureAwait(false)).ToMinimalApiResult()), "ValidateSession", options);
        Configure(group.MapDelete("/sessions", async ([FromBody] SessionTokenRequest body, IIdentity identity, CancellationToken ct) =>
            (await identity.RevokeSessionAsync(body.Token, ct).ConfigureAwait(false)).ToMinimalApiResult()), "RevokeSession", options);
        Configure(group.MapPost("/login-attempts/search", async (UserLoginAttemptSearchRequest request, IIdentity identity, CancellationToken ct) =>
            (await identity.ListLoginAttemptsAsync(request, ct).ConfigureAwait(false)).ToMinimalApiResult()), "ListLoginAttempts", options);
        Configure(group.MapPost("/accounts/{userId:guid}/lock/release", async (Guid userId, IIdentity identity, CancellationToken ct) =>
            (await identity.ReleaseAccountLockAsync(userId, ct).ConfigureAwait(false)).ToMinimalApiResult()), "ReleaseAccountLock", options);
        Configure(group.MapGet("/accounts/{userId:guid}/mfa-methods", async (Guid userId, IIdentity identity, CancellationToken ct) =>
            (await identity.ListMfaMethodsAsync(userId, ct).ConfigureAwait(false)).ToMinimalApiResult()), "ListMfaMethods", options);
        Configure(group.MapPost("/mfa/enrollments", async (BeginTotpEnrollmentRequest request, IIdentity identity, CancellationToken ct) =>
            (await identity.BeginTotpEnrollmentAsync(request, ct).ConfigureAwait(false)).ToMinimalApiResult()), "BeginTotpEnrollment", options);
        Configure(group.MapPost("/mfa/enrollments/inspection", async (MfaTicketRequest body, IIdentity identity, CancellationToken ct) =>
            (await identity.InspectTotpEnrollmentAsync(body.Ticket, ct).ConfigureAwait(false)).ToMinimalApiResult()), "InspectTotpEnrollment", options);
        Configure(group.MapPost("/mfa/enrollments/confirmation", async (ConfirmTotpTicketRequest request, IIdentity identity, CancellationToken ct) =>
            (await identity.ConfirmTotpEnrollmentAsync(request, ct).ConfigureAwait(false)).ToMinimalApiResult()), "ConfirmTotpEnrollment", options);
        Configure(group.MapDelete("/accounts/{userId:guid}/mfa-methods/{methodId:guid}", async (Guid userId, Guid methodId, IIdentity identity, CancellationToken ct) =>
            (await identity.RetireMfaMethodAsync(userId, methodId, ct).ConfigureAwait(false)).ToMinimalApiResult()), "RetireMfaMethod", options);
        Configure(group.MapPost("/mfa/recovery-codes", async (ReplaceRecoveryCodesRequest request, IIdentity identity, CancellationToken ct) =>
            (await identity.ReplaceRecoveryCodesAsync(request, ct).ConfigureAwait(false)).ToMinimalApiResult()), "ReplaceRecoveryCodes", options);
        Configure(group.MapPost("/mfa/verification", async (VerifyMfaRequest request, IIdentity identity, CancellationToken ct) =>
            (await identity.VerifyMfaAsync(request, ct).ConfigureAwait(false)).ToMinimalApiResult()), "VerifyMfa", options);
        Configure(group.MapPost("/password/resets", async (BeginPasswordResetRequest request, IIdentity identity, CancellationToken ct) =>
            (await identity.BeginPasswordResetAsync(request, ct).ConfigureAwait(false)).ToMinimalApiResult()), "BeginPasswordReset", options);
        Configure(group.MapPost("/password/resets/verification", async (VerifyPasswordResetCodeRequest request, IIdentity identity, CancellationToken ct) =>
            (await identity.VerifyPasswordResetCodeAsync(request, ct).ConfigureAwait(false)).ToMinimalApiResult()), "VerifyPasswordResetCode", options);
        Configure(group.MapPost("/password/resets/completion", async (CompletePasswordResetRequest request, IIdentity identity, CancellationToken ct) =>
            (await identity.CompletePasswordResetAsync(request, ct).ConfigureAwait(false)).ToMinimalApiResult()), "CompletePasswordReset", options);
        Configure(group.MapPost("/verification/email/status", async (AccountEmailRequest request, IIdentity identity, CancellationToken ct) =>
            (await identity.GetEmailVerificationAsync(request.Email, ct).ConfigureAwait(false)).ToMinimalApiResult()), "GetEmailVerification", options);
        foreach (var purpose in Enum.GetValues<VerificationPurpose>())
        {
            var segment = IdentityVerificationRoutes.Segment(purpose);
            Configure(group.MapPost($"/verification/{segment}/challenges", async (BeginIdentityVerificationRequest request, IIdentity identity, CancellationToken ct) =>
                request.Purpose != purpose ? Results.Problem(statusCode: 400, detail: "The purpose must match this route.") :
                    (await identity.BeginVerificationAsync(request, ct).ConfigureAwait(false)).ToMinimalApiResult()), IdentityVerificationRoutes.Operation(purpose, false), options);
            Configure(group.MapPost($"/verification/{segment}/completion", async (CompleteIdentityVerificationRequest request, IIdentity identity, CancellationToken ct) =>
                request.Purpose != purpose ? Results.Problem(statusCode: 400, detail: "The purpose must match this route.") :
                    (await identity.CompleteVerificationAsync(request, ct).ConfigureAwait(false)).ToMinimalApiResult()), IdentityVerificationRoutes.Operation(purpose, true), options);
        }
        return group;
    }

    private static void Configure(RouteHandlerBuilder endpoint, string operation, IdentityEndpointOptions options)
    {
        endpoint.WithMetadata(new IdentityOperationMetadata(operation, options.Standalone));
        options.ConfigureEndpoint?.Invoke(endpoint, operation);
    }
}
