using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.Mvc;
using Haley.Services;
using Haley.Utils;

namespace Haley.Extensions;

/// <summary>Public recipient assets and proof completion; never exposes challenge issuance or management.</summary>
public static class IdentityVerificationBrowserEndpoints
{
    public static void MapIdentityVerificationBrowserEndpoints(this IEndpointRouteBuilder endpoints,
        string prefix = "/identity/verify", string rateLimitPolicy = "Haley.Identity") =>
        MapIdentityVerificationBrowserEndpoints(endpoints, null, prefix, rateLimitPolicy);

    public static void MapIdentityVerificationBrowserEndpoints(this IEndpointRouteBuilder endpoints,
        Action<RouteHandlerBuilder>? configureRateLimit, string prefix = "/identity/verify", string rateLimitPolicy = "Haley.Identity")
    {
        var group = Pages(endpoints, prefix);
        var completion = group.MapPost("/{applicationId:guid}/{resource}/completion", async (Guid applicationId, string resource,
            CompleteIdentityVerificationRequest request, HttpContext context, IdentityVerificationService verification, CancellationToken ct) =>
        {
            context.Response.Headers.CacheControl = "no-store";
            context.Response.Headers.Pragma = "no-cache";
            return (await verification.CompleteForApplicationAsync(applicationId, resource, request, ct).ConfigureAwait(false)).ToMinimalApiResult();
        });
        if (configureRateLimit is null) completion.RequireRateLimiting(rateLimitPolicy);
        else configureRateLimit(completion);
    }

    internal static void MapIdentityRecipientCompletion(this IEndpointRouteBuilder endpoints, string apiPrefix) =>
        endpoints.MapPost(apiPrefix.TrimEnd('/') + "/verification/recipient/{applicationId:guid}/{resource}/completion",
            async (Guid applicationId, string resource, CompleteIdentityVerificationRequest request, HttpContext context,
                [FromServices] IdentityVerificationService verification, CancellationToken ct) =>
            {
                context.Response.Headers.CacheControl = "no-store";
                return (await verification.CompleteForApplicationAsync(applicationId, resource, request, ct).ConfigureAwait(false)).ToMinimalApiResult();
            }).AllowAnonymous().WithTags("Identity Verification")
                .WithConfiguredFixedWindowRateLimit(IdentityRateLimitFilter.Policy, IdentityProofRateLimitSubject.ResolveAsync);

    /// <summary>Hosts the same page in an application BFF using its registered embedded or remote IIdentity client.</summary>
    public static void MapIdentityVerificationProxyEndpoints(this IEndpointRouteBuilder endpoints, Guid applicationId,
        string resource, string rateLimitPolicy, string prefix = "/identity/verify")
    {
        if (applicationId == Guid.Empty || string.IsNullOrWhiteSpace(resource) || resource.Length > 200 || resource.Any(char.IsControl))
            throw new ArgumentException("Configure the application's fixed identity GUID and resource.");
        Pages(endpoints, prefix).MapPost("/{claimedApplicationId:guid}/{claimedResource}/completion",
            async (Guid claimedApplicationId, string claimedResource, CompleteIdentityVerificationRequest request,
                HttpContext context, IIdentity identity, IEnumerable<IdentityRemoteTransport> remoteClients, CancellationToken ct) =>
            {
                context.Response.Headers.CacheControl = "no-store";
                if (claimedApplicationId != applicationId || !string.Equals(claimedResource, resource, StringComparison.Ordinal))
                    return Results.Problem(statusCode: 403, detail: "This verification link belongs to another application.");
                var remote = remoteClients.SingleOrDefault();
                var result = remote is null
                    ? await identity.CompleteVerificationAsync(request, ct).ConfigureAwait(false)
                    : await remote.CompleteRecipientAsync(applicationId, resource, request, ct).ConfigureAwait(false);
                return result.ToMinimalApiResult();
            }).RequireRateLimiting(rateLimitPolicy);
    }

    private static RouteGroupBuilder Pages(IEndpointRouteBuilder endpoints, string prefix)
    {
        var group = endpoints.MapGroup(prefix).AllowAnonymous().WithTags("Identity Verification");
        group.MapGet("/", (HttpContext context) => context.Request.Path.Value?.EndsWith("/", StringComparison.Ordinal) == true
            ? Asset("index.html") : Results.Redirect(prefix.TrimEnd('/').Split('/').Last() + "/" + context.Request.QueryString));
        group.MapGet("/verification.js", () => Asset("verification.js"));
        group.MapGet("/verification.css", () => Asset("verification.css"));
        return group;
    }

    private static IResult Asset(string name)
    {
        using var stream = typeof(IdentityVerificationBrowserEndpoints).Assembly.GetManifestResourceStream("Haley.Identity.Verification." + name)
            ?? throw new InvalidOperationException("The shared verification page resource is missing.");
        using var reader = new StreamReader(stream);
        var contentType = name.EndsWith(".js", StringComparison.Ordinal) ? "text/javascript" :
            name.EndsWith(".css", StringComparison.Ordinal) ? "text/css" : "text/html";
        return Results.Content(reader.ReadToEnd(), contentType);
    }
}
