using Microsoft.Extensions.DependencyInjection;

namespace Haley.Models;

/// <summary>Chooses exactly one implementation without loading server dependencies into clients.</summary>
public sealed class IdentityBuilder(IServiceCollection services)
{
    public IServiceCollection Services { get; } = services;
    public string? Backend { get; private set; }

    public void SelectBackend(string backend)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(backend);
        if (Backend is not null)
            throw new InvalidOperationException($"Identity backend '{Backend}' is already selected; cannot also select '{backend}'.");
        Backend = backend;
    }
}
