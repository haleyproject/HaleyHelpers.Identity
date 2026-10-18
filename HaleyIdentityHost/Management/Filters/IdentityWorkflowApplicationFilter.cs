using Haley.Models;
using Haley.Services;

namespace Haley.Hosting;

internal sealed class IdentityWorkflowApplicationFilter : IEndpointFilter
{
    public async ValueTask<object?> InvokeAsync(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
    {
        var http = context.HttpContext;
        if (!Guid.TryParse(http.Request.RouteValues["applicationId"]?.ToString(), out var applicationId) ||
            !string.Equals(http.Request.RouteValues["resource"]?.ToString(), "haley.identity", StringComparison.Ordinal) ||
            !http.RequestServices.GetRequiredService<IdentityApplicationRegistry>().List().Any(application =>
                application.ApplicationId == applicationId && application.Status == IdentityRecordStatus.Active && application.KeyIds.Count > 0))
            return Results.Problem(statusCode: 403, detail: "Select an active registered application with an available key.",
                extensions: new Dictionary<string, object?> { ["code"] = "invalid_application" });

        // The cookie authorization boundary protects this selection. The normal
        // application context reads this header without changing the operator principal.
        http.Request.Headers["X-Haley-Application-Id"] = applicationId.ToString("D");
        return await next(context).ConfigureAwait(false);
    }
}
