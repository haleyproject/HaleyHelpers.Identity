using System.Security.Claims;
using Haley.Utils;
using Microsoft.AspNetCore.Http;

namespace Haley.Services;

/// <summary>Uses bound request data after the standalone application's credential has been checked.</summary>
public sealed class IdentityRateLimitFilter(FixedWindowRequestRateLimiter limits, IIdentity identity) : IEndpointFilter
{
    public const string Policy = "Haley.Identity";
    private static readonly object AccountKey = new();
    private static readonly object SessionKey = new();

    public async ValueTask<object?> InvokeAsync(EndpointFilterInvocationContext invocation, EndpointFilterDelegate next)
    {
        var context = invocation.HttpContext;
        if (context.GetEndpoint()?.Metadata.GetMetadata<IdentityOperationMetadata>()?.Standalone != true)
            return await next(invocation).ConfigureAwait(false);
        var settings = limits.GetOptions(Policy);
        if (!settings.Enabled) return await next(invocation).ConfigureAwait(false);
        string? subject = null;
        if (string.Equals(settings.Scope, RequestRateLimitOptions.IpUserScope, StringComparison.OrdinalIgnoreCase))
            subject = await ResolveSubjectAsync(invocation).ConfigureAwait(false);
        using var lease = limits.AttemptAcquire(context, Policy, subject);
        return lease.IsAcquired ? await next(invocation).ConfigureAwait(false) : FixedWindowRequestRateLimiter.Rejection(context, lease);
    }

    private async ValueTask<string?> ResolveSubjectAsync(EndpointFilterInvocationContext invocation)
    {
        var context = invocation.HttpContext;
        if (context.User.Identity?.IsAuthenticated == true &&
            Guid.TryParse(context.User.FindFirstValue(ClaimTypes.NameIdentifier) ?? context.User.FindFirstValue("sub"), out var actor))
            return Account(actor);
        if (context.Request.TryGetGuidRouteValue("userId", out var userId)) return Account(userId);
        foreach (var argument in invocation.Arguments)
        {
            if (argument is SessionTokenRequest session)
            {
                var resolved = await identity.ResolveSessionAsync(session.Token, context.RequestAborted).ConfigureAwait(false);
                context.Items[SessionKey] = resolved;
                return resolved.Status && resolved.Result is not null ? Account(resolved.Result.UserId) : null;
            }
            var id = argument switch
            {
                BeginTotpEnrollmentRequest request => request.UserId,
                VerifyMfaRequest request => request.UserId,
                ReplaceRecoveryCodesRequest request => request.UserId,
                UserLoginAttemptSearchRequest request => request.UserId,
                _ => Guid.Empty
            };
            if (id != Guid.Empty) return Account(id);
            var proof = IdentityProofRateLimitSubject.FromBoundArgument(argument);
            if (proof is not null) return proof;
            var username = argument switch
            {
                AccountEmailRequest request => request.Email,
                EnsureAccountRequest request => request.Email,
                PasswordAuthenticationRequest request => request.Username,
                TotpAuthenticationRequest request => request.Email,
                ChangePasswordRequest request => request.Username,
                ApplicationSessionRequest request => request.Email,
                BeginIdentityVerificationRequest request => request.Email,
                BeginPasswordResetRequest request => request.Destination,
                BeginFederationRequest request when request.EmailOrDomain?.Contains('@') == true => request.EmailOrDomain,
                ProviderDiscoveryRequest request when request.EmailOrDomain?.Contains('@') == true => request.EmailOrDomain,
                _ => null
            };
            if (!string.IsNullOrWhiteSpace(username))
            {
                var account = await identity.FindAccountAsync(username, context.RequestAborted).ConfigureAwait(false);
                context.Items[AccountKey] = account;
                return account.Status && account.Result is not null ? Account(account.Result.UserId) : "username:" + username.Trim().ToLowerInvariant();
            }
        }
        // No caller or account can be established for a collection-wide or anonymous operation.
        return null;
    }

    private static string Account(Guid userId) => "account:" + userId.ToString("D");

    internal static ValueTask<IFeedback<UserIdentity>> FindAccountAsync(HttpContext context, IIdentity identity, string email, CancellationToken ct) =>
        context.Items.TryGetValue(AccountKey, out var cached) && cached is IFeedback<UserIdentity> account
            ? ValueTask.FromResult(account) : identity.FindAccountAsync(email, ct);

    internal static ValueTask<IFeedback<ResolvedIdentitySession>> ResolveSessionAsync(HttpContext context, IIdentity identity, string token, CancellationToken ct) =>
        context.Items.TryGetValue(SessionKey, out var cached) && cached is IFeedback<ResolvedIdentitySession> session
            ? ValueTask.FromResult(session) : identity.ResolveSessionAsync(token, ct);

    internal static ValueTask<IFeedback<SessionValidation>> ValidateSessionAsync(HttpContext context, IIdentity identity, string token, CancellationToken ct)
    {
        if (!context.Items.TryGetValue(SessionKey, out var cached) || cached is not IFeedback<ResolvedIdentitySession> resolved)
            return identity.ValidateSessionAsync(token, ct);
        return ValueTask.FromResult<IFeedback<SessionValidation>>(new Feedback<SessionValidation>(resolved.Status, resolved.Message,
            resolved.Result is null ? null! : new SessionValidation(resolved.Result.SessionId, resolved.Result.ExpiresAt))
            { Code = resolved.Code, Key = resolved.Key, Source = resolved.Source, Trace = resolved.Trace });
    }
}
