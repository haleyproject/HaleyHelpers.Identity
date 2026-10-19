using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;
using Haley.Utils;
using Haley.Services;

namespace Haley.Extensions;

public static class IdentityFederationBrowserEndpoints
{
    /// <summary>Anonymous provider callbacks accept only signed, attempt-bound proofs. Session issuance remains a backend operation.</summary>
    public static void MapIdentityFederationBrowserEndpoints(this IEndpointRouteBuilder endpoints,
        string prefix = "/identity/federation", string codeField = "identity_code") =>
        MapIdentityFederationBrowserEndpoints(endpoints, null, prefix, codeField);

    public static void MapIdentityFederationBrowserEndpoints(this IEndpointRouteBuilder endpoints,
        Action<RouteHandlerBuilder>? configureRateLimit, string prefix = "/identity/federation", string codeField = "identity_code")
    {
        var group = endpoints.MapGroup(prefix).AllowAnonymous()
            .WithMetadata(new RequestSizeLimitAttribute(512000));
        var saml = group.MapPost("/saml/acs", async (HttpContext context, IFederationAuthenticationService federation, CancellationToken ct) =>
        {
            context.Response.Headers.CacheControl = "no-store";
            if (!context.Request.HasFormContentType) return Results.Problem(statusCode: 400, detail: "A SAML form response is required.");
            var form = await context.Request.ReadFormAsync(ct).ConfigureAwait(false);
            var result = await federation.CompleteAsync(new(form["SAMLResponse"].ToString(), form["RelayState"].ToString()), ct).ConfigureAwait(false);
            return Handoff(context, result, codeField);
        });
        var external = group.MapPost("/external/callback", async (HttpContext context, IFederationAuthenticationService federation, CancellationToken ct) =>
        {
            context.Response.Headers.CacheControl = "no-store";
            if (!context.Request.HasFormContentType) return Results.Problem(statusCode: 400, detail: "A signed authentication form response is required.");
            var form = await context.Request.ReadFormAsync(ct).ConfigureAwait(false);
            var result = await federation.CompleteExternalAsync(new(form["attempt"].ToString(), form["assertion"].ToString()), ct).ConfigureAwait(false);
            return Handoff(context, result, codeField);
        });
        if (configureRateLimit is null)
        {
            saml.RequireRateLimiting("Haley.Identity");
            external.RequireRateLimiting("Haley.Identity");
        }
        else
        {
            configureRateLimit(saml);
            configureRateLimit(external);
        }
    }

    private static IResult Handoff(HttpContext context, IFeedback<FederationHandoff> result, string codeField)
    {
        if (!result.Status || result.Result is not { } handoff)
            return Results.Problem(statusCode: 401, detail: "The provider authentication proof was rejected.",
                extensions: new Dictionary<string, object?> { ["code"] = result.Key ?? "identity.federation_rejected" });
        var page = FederationHandoffPage.Create(handoff.ReturnUri, handoff.Code, handoff.State, codeField);
        context.Response.Headers.ContentSecurityPolicy = page.ContentSecurityPolicy;
        context.Response.Headers["Referrer-Policy"] = "no-referrer";
        context.Response.Headers.XContentTypeOptions = "nosniff";
        return Results.Content(page.Html, "text/html; charset=utf-8");
    }
}
