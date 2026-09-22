using Xunit;
namespace Haley.Identity.Tests;
public sealed class MariaDbFactAttribute : FactAttribute
{
    public MariaDbFactAttribute()
    {
        if (string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("HALEY_IDENTITY_TEST_CONNECTION")))
            Skip = "Set HALEY_IDENTITY_TEST_CONNECTION to an isolated disposable MariaDB server.";
    }
}
