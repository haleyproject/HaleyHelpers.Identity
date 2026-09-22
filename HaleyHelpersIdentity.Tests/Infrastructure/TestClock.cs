using Haley.Abstractions;
namespace Haley.Identity.Tests;
public sealed class TestClock : IIdentityClock
{
    public DateTimeOffset UtcNow { get; set; } = new(2026, 9, 22, 12, 0, 0, TimeSpan.Zero);
}
