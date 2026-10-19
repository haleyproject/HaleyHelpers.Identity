using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;

namespace Haley.Services;

public sealed class IdentityBoundaryFilter(IOptions<IdentityServerOptions> options, IdentityApplicationRegistry? registry = null,
    FixedWindowRequestRateLimiter? rateLimits = null) : IEndpointFilter
{
    private readonly IdentityApplicationRegistry _applications = registry ?? new(options.Value.SessionBindingKeys,
        initialApplications: options.Value.Applications);
    public async ValueTask<object?> InvokeAsync(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
    {
        context.HttpContext.Response.Headers.CacheControl = "no-store";
        var metadata = context.HttpContext.GetEndpoint()?.Metadata.GetMetadata<IdentityOperationMetadata>();
        if (metadata?.Standalone != true) return await next(context).ConfigureAwait(false);
        if (!options.Value.TrustedNetwork)
            return Results.Problem("Standalone Identity endpoints require explicit TrustedNetwork configuration.", statusCode: 503,
                extensions: new Dictionary<string, object?> { ["code"] = "identity_boundary_unconfigured" });
        if (!Guid.TryParse(context.HttpContext.Request.Headers["X-Haley-Application-Id"], out var applicationId) || applicationId == Guid.Empty)
            return Reject(context.HttpContext, Results.Problem("A valid application identifier is required.", statusCode: 400,
                extensions: new Dictionary<string, object?> { ["code"] = "application_required" }));
        var keyId = context.HttpContext.Request.Headers["X-Haley-Session-Key-Id"].ToString();
        var provided = context.HttpContext.Request.Headers["X-Haley-Session-Key"].ToString();
        if (!_applications.Authenticate(applicationId, keyId, provided))
            return Reject(context.HttpContext, Results.Problem("The application credential was rejected.", statusCode: 401,
                extensions: new Dictionary<string, object?> { ["code"] = "invalid_session_binding" }));
        return await next(context).ConfigureAwait(false);
    }

    private IResult Reject(HttpContext context, IResult failure)
    {
        if (rateLimits is null) return failure;
        using var lease = rateLimits.AttemptAcquire(context, IdentityRateLimitFilter.Policy);
        return lease.IsAcquired ? failure : FixedWindowRequestRateLimiter.Rejection(context, lease);
    }
}
