namespace Haley.Abstractions;

public interface IIdentityClock
{
    DateTimeOffset UtcNow { get; }
}
