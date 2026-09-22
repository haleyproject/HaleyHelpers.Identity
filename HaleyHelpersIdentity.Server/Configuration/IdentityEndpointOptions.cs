using Microsoft.AspNetCore.Builder;

namespace Haley.Models;

public sealed class IdentityEndpointOptions
{
    public bool Standalone { get; set; } = true;
    public Action<RouteHandlerBuilder, string>? ConfigureEndpoint { get; set; }
}
