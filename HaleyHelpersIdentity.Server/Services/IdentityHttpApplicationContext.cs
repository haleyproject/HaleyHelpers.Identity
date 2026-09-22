using Microsoft.AspNetCore.Http;

namespace Haley.Services;

public sealed class IdentityHttpApplicationContext(IHttpContextAccessor accessor) : IIdentityApplicationContext
{
    public Guid ApplicationId => Guid.TryParse(accessor.HttpContext?.Request.Headers["X-Haley-Application-Id"].ToString(), out var value)
        ? value : Guid.Empty;
}
