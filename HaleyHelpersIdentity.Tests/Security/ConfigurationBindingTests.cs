using Haley.Models;
using Microsoft.Extensions.Configuration;
using Xunit;
namespace Haley.Identity.Tests;
public sealed class ConfigurationBindingTests
{
    [Fact]
    public void ConfigurationBindsApplicationKeyRingsAndReturnUriAllowLists()
    {
        var applicationId = Guid.NewGuid().ToString("D");
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            [$"SessionBindingKeys:{applicationId}:current"] = "a-test-secret-of-at-least-32-characters",
            [$"AllowedReturnUris:{applicationId}:0"] = "https://application.test/complete"
        }).Build();
        var options = configuration.Get<IdentityServerOptions>(); Assert.NotNull(options);
        Assert.Equal("a-test-secret-of-at-least-32-characters", options.SessionBindingKeys[applicationId]["current"]);
        Assert.Contains("https://application.test/complete", options.AllowedReturnUris[applicationId]);
    }
}
