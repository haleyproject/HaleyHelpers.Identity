using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;

namespace Haley.Services;

public sealed class IdentityBoundaryFilter(IOptions<IdentityServerOptions> options) : IEndpointFilter
{
    public async ValueTask<object?> InvokeAsync(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
    {
        var metadata = context.HttpContext.GetEndpoint()?.Metadata.GetMetadata<IdentityOperationMetadata>();
        if (metadata?.Standalone != true) return await next(context).ConfigureAwait(false);
        if (!options.Value.TrustedNetwork)
            return Results.Problem("Standalone Identity endpoints require explicit TrustedNetwork configuration.", statusCode: 503,
                extensions: new Dictionary<string, object?> { ["code"] = "identity_boundary_unconfigured" });
        if (!Guid.TryParse(context.HttpContext.Request.Headers["X-Haley-Application-Id"], out var applicationId) || applicationId == Guid.Empty)
            return Results.Problem("A valid application identifier is required.", statusCode: 400,
                extensions: new Dictionary<string, object?> { ["code"] = "application_required" });
        if (metadata.Operation is "AuthenticatePassword" or "CreateApplicationSession" or "ValidateSession" or "RevokeSession")
        {
            var keyId = context.HttpContext.Request.Headers["X-Haley-Session-Key-Id"].ToString();
            var provided = context.HttpContext.Request.Headers["X-Haley-Session-Key"].ToString();
            if (string.IsNullOrEmpty(keyId) || string.IsNullOrEmpty(provided) || provided.Length > 512 ||
                !options.Value.SessionBindingKeys.TryGetValue(applicationId.ToString("D"), out var keys) ||
                !keys.TryGetValue(keyId, out var expected) || string.IsNullOrWhiteSpace(expected) ||
                !CryptographicOperations.FixedTimeEquals(SHA256.HashData(Encoding.UTF8.GetBytes(provided)), SHA256.HashData(Encoding.UTF8.GetBytes(expected))))
                return Results.Problem("The application session binding was rejected.", statusCode: 401,
                    extensions: new Dictionary<string, object?> { ["code"] = "invalid_session_binding" });
        }
        return await next(context).ConfigureAwait(false);
    }
}
