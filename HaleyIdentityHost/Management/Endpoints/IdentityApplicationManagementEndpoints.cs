using Haley.Hosting;
using Haley.Models;
using Haley.Services;
using Haley.Utils;

namespace Haley.Extensions;

public static class IdentityApplicationManagementEndpoints
{
    public static void MapIdentityApplicationManagement(this IEndpointRouteBuilder endpoints)
    {
        var group = endpoints.MapGroup("/admin/api/applications")
            .RequireAuthorization(IdentityManagementHosting.Policy)
            .AddEndpointFilter<UnsafeMethodAntiforgeryFilter>()
            .AddEndpointFilter(async (context, next) =>
            {
                context.HttpContext.Response.Headers.CacheControl = "no-store";
                return await next(context);
            });
        group.MapGet("/", (IdentityApplicationRegistry registry) => registry.List());
        group.MapPost("/", async (RegisterIdentityApplicationRequest request, IdentityApplicationRegistry registry, CancellationToken ct) =>
            (await registry.RegisterAsync(request, ct)).ToMinimalApiResult());
        group.MapPost("/{applicationId:guid}/keys", async (Guid applicationId, IdentityApplicationRegistry registry, CancellationToken ct) =>
            (await registry.RotateAsync(applicationId, ct)).ToMinimalApiResult());
        group.MapDelete("/{applicationId:guid}/keys/{keyId}", async (Guid applicationId, string keyId, IdentityApplicationRegistry registry, CancellationToken ct) =>
            (await registry.RevokeKeyAsync(applicationId, keyId, ct)).ToMinimalApiResult());
        group.MapDelete("/{applicationId:guid}", async (Guid applicationId, IdentityApplicationRegistry registry, CancellationToken ct) =>
            (await registry.RevokeAsync(applicationId, ct)).ToMinimalApiResult());
    }
}
