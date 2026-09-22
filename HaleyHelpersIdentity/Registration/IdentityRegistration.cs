using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Haley.Extensions;

public static class IdentityRegistration
{
    public static IServiceCollection AddHaleyIdentity(this IServiceCollection services,
        IConfiguration configuration, Action<IdentityBuilder> configure,
        string sectionName = IdentityOptions.SectionName)
    {
        ArgumentNullException.ThrowIfNull(configure);
        if (services.Any(item => item.ServiceType == typeof(IdentityBuilder)))
            throw new InvalidOperationException("AddHaleyIdentity has already been called for this service collection.");
        services.AddOptions<IdentityOptions>().Bind(configuration.GetSection(sectionName));
        var builder = new IdentityBuilder(services);
        configure(builder);
        if (builder.Backend is null)
            throw new InvalidOperationException("Select UseEmbedded, UseRemote or UseKida when registering Haley Identity.");
        services.AddSingleton(builder);
        return services;
    }
}
