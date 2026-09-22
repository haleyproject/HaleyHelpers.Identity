using Haley.Services;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Haley.Extensions;

public static class IdentityRemoteRegistration
{
    public static IdentityBuilder UseRemote(this IdentityBuilder builder, Action<IdentityOptions>? configure = null)
    {
        builder.SelectBackend("remote");
        RegisterRemote(builder.Services, configure);
        return builder;
    }

    /// <summary>Registers the shared remote implementation for an explicitly selected host adapter.</summary>
    public static void RegisterRemote(IServiceCollection services, Action<IdentityOptions>? configure = null)
    {
        var options = services.AddOptions<IdentityOptions>();
        if (configure is not null) options.Configure(configure);
        options.Validate(value => value.ApplicationId != Guid.Empty && !string.IsNullOrWhiteSpace(value.Url) &&
            !string.IsNullOrWhiteSpace(value.ApiPath) && value.TimeoutSeconds is >= 1 and <= 300,
            "Remote Identity requires ApplicationId, Url, ApiPath and a timeout between 1 and 300 seconds.").ValidateOnStart();
        services.TryAddSingleton<IIdentityRemoteAuthentication, IdentityRemoteAuthentication>();
        services.TryAddSingleton<IdentityRemoteTransport>();
        services.TryAddScoped<IIdentity, IdentityRemoteClient>();
    }
}
