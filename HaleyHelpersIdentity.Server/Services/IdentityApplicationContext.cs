using Microsoft.Extensions.Options;

namespace Haley.Services;

public sealed class IdentityApplicationContext(IOptions<IdentityOptions> options) : IIdentityApplicationContext
{
    public Guid ApplicationId => options.Value.ApplicationId;
}
