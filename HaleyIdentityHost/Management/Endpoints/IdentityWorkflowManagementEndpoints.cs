using Haley.Abstractions;
using Haley.Hosting;
using Haley.Models;
using Haley.Utils;
using Microsoft.AspNetCore.Mvc;

namespace Haley.Extensions;

public static class IdentityWorkflowManagementEndpoints
{
    public static void MapIdentityWorkflowManagement(this IEndpointRouteBuilder endpoints)
    {
        var admin = endpoints.MapGroup("/admin/api")
            .RequireAuthorization(IdentityManagementHosting.Policy)
            .AddEndpointFilter<UnsafeMethodAntiforgeryFilter>()
            .AddEndpointFilter((context, next) =>
            {
                context.HttpContext.Response.Headers.CacheControl = "no-store";
                return next(context);
            });
        admin.MapGet("/users/{userId:guid}", async (Guid userId, [FromServices] IIdentity identity, CancellationToken ct) =>
            (await identity.GetAccountAsync(userId, ct).ConfigureAwait(false)).ToMinimalApiResult());
        admin.MapPut("/users/{userId:guid}/profile", async (Guid userId, UpdateUserProfileRequest request,
            [FromServices] IIdentity identity, CancellationToken ct) =>
            (await identity.UpdateProfileAsync(userId, request, ct).ConfigureAwait(false)).ToMinimalApiResult());
        admin.MapPost("/users/{userId:guid}/mfa/recovery-codes", async (Guid userId, ReplaceRecoveryCodesRequest request,
            [FromServices] IIdentity identity, CancellationToken ct) => userId != request.UserId ? InvalidUserReference() :
            (await identity.ReplaceRecoveryCodesAsync(request, ct).ConfigureAwait(false)).ToMinimalApiResult());
        admin.MapPost("/users/{userId:guid}/mfa/verification", async (Guid userId, VerifyMfaRequest request,
            [FromServices] IIdentity identity, CancellationToken ct) => userId != request.UserId ? InvalidUserReference() :
            (await identity.VerifyMfaAsync(request, ct).ConfigureAwait(false)).ToMinimalApiResult());

        var workflows = admin.MapGroup("/identity/workflows/{applicationId:guid}/{resource}")
            .AddEndpointFilter<IdentityWorkflowApplicationFilter>();
        workflows.MapPost("/accounts/resolve", async (AccountEmailRequest request, [FromServices] IIdentity identity, CancellationToken ct) =>
            (await identity.FindAccountAsync(request.Email, ct).ConfigureAwait(false)).ToMinimalApiResult());
        workflows.MapPost("/accounts", async (EnsureAccountRequest request, [FromServices] IIdentity identity, CancellationToken ct) =>
            (await identity.EnsureAccountAsync(request, ct).ConfigureAwait(false)).ToMinimalApiResult());
        workflows.MapPost("/email/status", async (AccountEmailRequest request, [FromServices] IIdentity identity, CancellationToken ct) =>
            (await identity.GetEmailVerificationAsync(request.Email, ct).ConfigureAwait(false)).ToMinimalApiResult());
        workflows.MapPost("/verification/completion", async (CompleteIdentityVerificationRequest request, [FromServices] IIdentity identity, CancellationToken ct) =>
            (await identity.CompleteVerificationAsync(request, ct).ConfigureAwait(false)).ToMinimalApiResult());
        workflows.MapPost("/password/change", async (ChangePasswordRequest request, [FromServices] IIdentity identity, CancellationToken ct) =>
            (await identity.ChangePasswordAsync(request, ct).ConfigureAwait(false)).ToMinimalApiResult());
        workflows.MapPost("/sessions/password", async (PasswordAuthenticationRequest request, [FromServices] IIdentity identity, CancellationToken ct) =>
            (await identity.AuthenticatePasswordAsync(request, ct).ConfigureAwait(false)).ToMinimalApiResult());
        workflows.MapPost("/sessions/totp", async (TotpAuthenticationRequest request, [FromServices] IIdentity identity, CancellationToken ct) =>
            (await identity.AuthenticateTotpAsync(request, ct).ConfigureAwait(false)).ToMinimalApiResult());
        workflows.MapPost("/sessions/application", async (ApplicationSessionRequest request, [FromServices] IIdentity identity, CancellationToken ct) =>
            (await identity.CreateApplicationSessionAsync(request, ct).ConfigureAwait(false)).ToMinimalApiResult());
        workflows.MapPost("/sessions/validation", async (SessionTokenRequest request, [FromServices] IIdentity identity, CancellationToken ct) =>
            (await identity.ValidateSessionAsync(request.Token, ct).ConfigureAwait(false)).ToMinimalApiResult());
        workflows.MapPost("/sessions/revocation", async (SessionTokenRequest request, [FromServices] IIdentity identity, CancellationToken ct) =>
            (await identity.RevokeSessionAsync(request.Token, ct).ConfigureAwait(false)).ToMinimalApiResult());
    }

    private static IResult InvalidUserReference() => Results.Problem(statusCode: 400,
        detail: "The request identifies a different account than the route.",
        extensions: new Dictionary<string, object?> { ["code"] = "invalid_request" });
}
