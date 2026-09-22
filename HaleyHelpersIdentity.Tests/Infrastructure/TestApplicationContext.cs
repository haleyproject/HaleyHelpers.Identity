using Haley.Abstractions;
namespace Haley.Identity.Tests;
public sealed class TestApplicationContext : IIdentityApplicationContext
{
    public Guid ApplicationId { get; set; }
}
