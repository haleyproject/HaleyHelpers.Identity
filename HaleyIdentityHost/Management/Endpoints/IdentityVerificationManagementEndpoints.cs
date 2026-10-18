using Haley.Hosting;
using Haley.Abstractions;
using Haley.Models;
using Haley.Services;
using Haley.Utils;
using Microsoft.Extensions.Options;

namespace Haley.Extensions;

public static class IdentityVerificationManagementEndpoints
{
    public static void MapIdentityVerificationManagement(this IEndpointRouteBuilder endpoints)
    {
        var group = endpoints.MapGroup("/admin/api/verification").RequireAuthorization(IdentityManagementHosting.Policy)
            .AddEndpointFilter<UnsafeMethodAntiforgeryFilter>();
        group.MapGet("/accounts/{userId:guid}/email-contacts", async (Guid userId, HttpContext context,
            IdentityAdministrationService administration, CancellationToken ct) =>
        {
            context.Response.Headers.CacheControl = "no-store";
            return Results.Ok(await administration.EmailContactsAsync(userId, ct).ConfigureAwait(false));
        });
        group.MapPut("/accounts/{userId:guid}/email-contacts/{contactId:guid}/verification", async (Guid userId, Guid contactId,
            AdminEmailVerificationAction body, HttpContext context, IdentityAdministrationService administration, CancellationToken ct) =>
        {
            context.Response.Headers.CacheControl = "no-store";
            return (await administration.SetEmailVerificationAsync(userId, contactId, body, context.User.Identity?.Name, ct)
                .ConfigureAwait(false)).ToMinimalApiResult();
        });
        group.MapGet("/settings", (IOptions<IdentityServerOptions> options) => Results.Ok(new
        {
            options.Value.Verification.PageUrl, options.Value.Verification.ApplicationPageUrls,
            options.Value.Verification.CodeLength, options.Value.Verification.MaximumAttempts,
            options.Value.Verification.ResendDelaySeconds,
            options.Value.Verification.MaximumCodeValiditySeconds, options.Value.Verification.MaximumTokenValiditySeconds,
            options.Value.Verification.CodeValiditySeconds, options.Value.Verification.ActivationLinkSeconds,
            options.Value.TotpLogin.Enabled, options.Value.TotpLogin.ApplicationIds,
            minimumPasswordLength = IdentityPolicy.MinimumPasswordLength,
            maximumPasswordLength = IdentityPolicy.MaximumPasswordLength
        }));
        group.MapPost("/challenges", async (CreateAdminVerificationRequest body, HttpContext context,
            IdentityVerificationService verification, IIdentityVerificationStore store, CancellationToken ct) =>
        {
            context.Response.Headers.CacheControl = "no-store";
            if (body.Request is null) return Results.Problem(statusCode: 400, detail: "A verification request is required.");
            if (!Uri.TryCreate(body.PageUrl, UriKind.Absolute, out var page) || page.Scheme is not ("http" or "https") ||
                page.UserInfo.Length > 0 || page.Fragment.Length > 0)
                return Results.Problem(statusCode: 400, detail: "Enter an absolute HTTP(S) verification-page URL without credentials or a fragment.");
            var result = await verification.BeginForAdministrationAsync(body.ApplicationId, "haley.identity", body.Request, ct).ConfigureAwait(false);
            if (!result.Status) return result.ToMinimalApiResult();
            if (result.Result.Delivery is not { } delivery) return Results.Problem(statusCode: 409,
                detail: "No challenge was issued. Check the email, account state and resend cooldown.");
            var subject = await store.FindVerificationSubjectAsync(delivery.Destination, ct).ConfigureAwait(false);
            var requiresPassword = delivery.Purpose == VerificationPurpose.PasswordReset ||
                delivery.Purpose == VerificationPurpose.Onboarding && subject?.Identity.PasswordChangeRequired == true;
            return Results.Ok(new AdminVerificationReceipt(delivery,
                IdentityVerificationLinks.Create(body.PageUrl, body.ApplicationId, "haley.identity", delivery, body.Request.Context, requiresPassword)));
        });
    }
}
