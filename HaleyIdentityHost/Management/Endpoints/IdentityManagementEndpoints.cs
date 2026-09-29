using Microsoft.AspNetCore.Mvc;
using Haley.Abstractions;
using Haley.Hosting;
using Haley.Models;
using Haley.Services;
using Haley.Utils;
using Microsoft.Extensions.Options;

namespace Haley.Extensions;

public static class IdentityManagementEndpoints
{
    public static void MapIdentityManagementEndpoints(this IEndpointRouteBuilder endpoints)
    {
        var group = endpoints.MapGroup("/admin/api").RequireAuthorization(IdentityManagementHosting.Policy)
            .AddEndpointFilter<UnsafeMethodAntiforgeryFilter>();
        group.MapGet("/users", async (string? query, IdentityStatus? status, UserActivityFilter? activity, UserSortOrder? sort,
            int? page, int? pageSize, IIdentity identity, CancellationToken ct) =>
            (await identity.ListAccountsAsync(new(query, status, page ?? 1, pageSize ?? 20, activity ?? UserActivityFilter.All, sort ?? UserSortOrder.CreatedNewest), ct)).ToMinimalApiResult());
        group.MapPost("/users", async (CreateLocalUserRequest request, IdentityAdministrationService administration, CancellationToken ct) =>
            (await administration.CreateAsync(request, ct)).ToMinimalApiResult());
        group.MapPut("/users/{userId:guid}/status", async (Guid userId, AdminStatusChange request, IIdentity identity, CancellationToken ct) =>
            (await identity.SetAccountStatusAsync(userId, new(request.Status, request.ReasonCode), ct)).ToMinimalApiResult());
        group.MapPost("/users/{userId:guid}/restore", async (Guid userId, AdminLifecycleAction request, IdentityAdministrationService administration, CancellationToken ct) =>
            (await administration.RestoreAsync(userId, request, ct)).ToMinimalApiResult());
        group.MapDelete("/users/{userId:guid}/permanent", async (Guid userId, [FromBody] AdminPermanentDelete request, IdentityAdministrationService administration, CancellationToken ct) =>
            (await administration.DeleteAsync(userId, request, ct)).ToMinimalApiResult());
        group.MapPost("/users/password/reset-bulk", async (BulkPasswordResetRequest request, IdentityAdministrationService administration, CancellationToken ct) =>
            (await administration.ResetPasswordsAsync(request, ct)).ToMinimalApiResult());
        group.MapGet("/users/{userId:guid}/profile", async (Guid userId, IIdentity identity, CancellationToken ct) =>
            (await identity.GetProfileAsync(userId, ct)).ToMinimalApiResult());
        group.MapPut("/users/{userId:guid}/profile/display-name", async (Guid userId, AdminUpdateUserDisplayNameRequest request, IdentityAdministrationService administration, CancellationToken ct) =>
            (await administration.UpdateDisplayNameAsync(userId, request.DisplayName, ct)).ToMinimalApiResult());
        group.MapGet("/users/{userId:guid}/sessions", async (Guid userId, string? view, int? page, IdentityAdministrationService administration, CancellationToken ct) =>
            await administration.SessionsAsync(userId, view != "all", page ?? 1, ct));
        group.MapDelete("/sessions/{sessionId:guid}", async (Guid sessionId, IdentityAdministrationService administration, CancellationToken ct) =>
            (await administration.RevokeSessionAsync(sessionId, ct)).ToMinimalApiResult());
        group.MapGet("/users/{userId:guid}/login-attempts", async (Guid userId, int? page, int? pageSize, IIdentity identity, CancellationToken ct) =>
            (await identity.ListLoginAttemptsAsync(new(userId, page ?? 1, pageSize ?? 10), ct)).ToMinimalApiResult());
        group.MapGet("/identity/login-protection", (IOptions<IdentityServerOptions> settings) =>
            new { maxFailedAttempts = settings.Value.MaximumFailedAttempts, lockoutSeconds = settings.Value.LockoutSeconds });
        group.MapPost("/users/{userId:guid}/login-protection/release", async (Guid userId, IIdentity identity, CancellationToken ct) =>
            (await identity.ReleaseAccountLockAsync(userId, ct)).ToMinimalApiResult());
        group.MapGet("/users/{userId:guid}/mfa", async (Guid userId, IIdentity identity, CancellationToken ct) =>
            (await identity.ListMfaMethodsAsync(userId, ct)).ToMinimalApiResult());
        group.MapPost("/users/{userId:guid}/mfa/totp", async (Guid userId, AdminBeginTotpEnrollment request, IdentityAdministrationService administration, CancellationToken ct) =>
            (await administration.BeginTotpAsync(userId, request, ct)).ToMinimalApiResult());
        group.MapPost("/users/{userId:guid}/mfa/totp/confirm", async (Guid userId, AdminConfirmTotpEnrollment request, IdentityAdministrationService administration, CancellationToken ct) =>
            (await administration.ConfirmTotpAsync(userId, request, ct)).ToMinimalApiResult());
        group.MapPost("/users/{userId:guid}/mfa/{methodId:guid}/test", async (Guid userId, Guid methodId, AdminTestTotpRequest request, IIdentity identity, CancellationToken ct) =>
            (await identity.VerifyMfaAsync(new(userId, methodId, MfaKind.Totp, request.Code), ct)).ToMinimalApiResult());
        group.MapDelete("/users/{userId:guid}/mfa/{methodId:guid}", async (Guid userId, Guid methodId, IIdentity identity, CancellationToken ct) =>
            (await identity.RetireMfaMethodAsync(userId, methodId, ct)).ToMinimalApiResult());
        group.MapGet("/identity/providers", (IIdentityProviderAdministrationService providers, CancellationToken ct) => providers.ListProvidersAsync(ct));
        group.MapPost("/identity/providers", async (UpsertIdentityProviderRequest request, IIdentityProviderAdministrationService providers, CancellationToken ct) =>
            (await providers.UpsertProviderAsync(null, request, ct)).ToMinimalApiResult());
        group.MapPut("/identity/providers/{providerId:guid}", async (Guid providerId, UpsertIdentityProviderRequest request, IIdentityProviderAdministrationService providers, CancellationToken ct) =>
            (await providers.UpsertProviderAsync(providerId, request, ct)).ToMinimalApiResult());
        group.MapGet("/identity/saml-certificates", (IIdentitySamlCertificateService certificates, CancellationToken ct) => certificates.ListAsync(ct));
        group.MapPost("/identity/saml-certificates", IdentityCertificateUploadEndpoint.HandleAsync);
    }
}
