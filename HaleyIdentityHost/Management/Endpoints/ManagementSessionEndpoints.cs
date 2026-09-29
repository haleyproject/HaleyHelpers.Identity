using System.Security.Claims;
using Haley.Hosting;
using Haley.Models;
using Haley.Services;
using Haley.Utils;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;

namespace Haley.Extensions;

public static class ManagementSessionEndpoints
{
    public static void MapIdentityManagementSessions(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapGet("/admin/api/session", (HttpContext context, IAntiforgery antiforgery, ManagementSessionService sessions) =>
        {
            var tokens = antiforgery.GetAndStoreTokens(context);
            return new AdminSessionResponse(context.User.Identity?.IsAuthenticated == true &&
                sessions.IsActive(context.User.FindFirstValue(IdentityManagementHosting.SessionClaim)), sessions.Configured,
                tokens.RequestToken ?? throw new InvalidOperationException("Antiforgery token generation failed."));
        }).AllowAnonymous();
        endpoints.MapPost("/admin/api/login", async (AdminLoginRequest request, HttpContext context,
            ManagementSessionService sessions, IOptions<IdentityManagementOptions> options, CancellationToken ct) =>
        {
            var result = await sessions.LoginAsync(request.Password, ct);
            if (result.Session is null) return Results.Problem(statusCode: result.Locked ? 429 : 401,
                detail: result.Locked ? "Management login is temporarily locked." : "The management password was rejected.");
            sessions.Revoke(context.User.FindFirstValue(IdentityManagementHosting.SessionClaim));
            await context.SignInAsync(IdentityManagementHosting.Scheme, new ClaimsPrincipal(new ClaimsIdentity(
                [new Claim(ClaimTypes.Name, "Identity administrator"), new Claim(IdentityManagementHosting.SessionClaim, result.Session)], IdentityManagementHosting.Scheme)),
                new AuthenticationProperties { IsPersistent = false, AllowRefresh = false, ExpiresUtc = DateTimeOffset.UtcNow.AddMinutes(options.Value.SessionMinutes) });
            return Results.Ok(new { authenticated = true });
        }).AllowAnonymous().RequireRateLimiting(IdentityManagementHosting.Policy).AddEndpointFilter<UnsafeMethodAntiforgeryFilter>();
        endpoints.MapPost("/admin/api/logout", async (HttpContext context, ManagementSessionService sessions) =>
        {
            sessions.Revoke(context.User.FindFirstValue(IdentityManagementHosting.SessionClaim));
            await context.SignOutAsync(IdentityManagementHosting.Scheme);
            return Results.NoContent();
        }).RequireAuthorization(IdentityManagementHosting.Policy).AddEndpointFilter<UnsafeMethodAntiforgeryFilter>();
    }
}
