using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.RateLimiting;
using System.Threading.RateLimiting;
using Haley.Security;
using Haley.Services;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace Haley.Extensions;

public static class IdentityServerRegistration
{
    public static IdentityBuilder UseEmbedded(this IdentityBuilder builder, IConfiguration configuration,
        Action<IdentityServerOptions>? configure = null)
    {
        builder.SelectBackend("embedded");
        builder.Services.AddHaleyIdentityEngine(configuration, configure);
        return builder;
    }

    /// <summary>Composition entry point used by an owning server such as Kida.</summary>
    public static IServiceCollection AddHaleyIdentityEngine(this IServiceCollection services, IConfiguration configuration,
        Action<IdentityServerOptions>? configure = null, bool registerInitializer = true)
    {
        var options = services.AddOptions<IdentityServerOptions>().Bind(configuration.GetSection(IdentityServerOptions.SectionName));
        if (configure is not null) options.Configure(configure);
        options.Validate(value => !string.IsNullOrWhiteSpace(value.Adapter) && value.SessionSeconds is >= 60 and <= 86400 &&
            value.PasswordHashIterations >= 100000 && value.PasswordHistoryCount is >= 0 and <= 100 &&
            value.MaximumFailedAttempts is >= 1 and <= 100 && value.LockoutSeconds is >= 60 and <= 86400,
            "Identity database, session, password and account-lock configuration is invalid.")
            .Validate(value => value.SessionBindingKeys.All(app => Guid.TryParseExact(app.Key, "D", out var id) && id != Guid.Empty &&
                app.Value.All(key => !string.IsNullOrWhiteSpace(key.Key) && key.Value.Length is >= 32 and <= 512)),
                "Session binding keys require canonical application GUIDs, key identifiers and secrets of 32 to 512 characters.").ValidateOnStart();
        services.AddOptions<IdentityOptions>();
        services.AddRateLimiter(limits =>
        {
            limits.RejectionStatusCode = 429;
            limits.AddPolicy("Haley.Identity", context => RateLimitPartition.GetFixedWindowLimiter(
                context.Connection.RemoteIpAddress?.ToString() ?? "embedded", _ => new FixedWindowRateLimiterOptions
                { PermitLimit = 120, Window = TimeSpan.FromMinutes(1), QueueLimit = 0, AutoReplenishment = true }));
        });
        services.TryAddSingleton<IIdentityClock, SystemClock>();
        services.TryAddSingleton<IIdentityUuidGenerator, Uuid7Generator>();
        services.TryAddSingleton<IPasswordHasher, Pbkdf2PasswordHasher>();
        services.TryAddSingleton<ISecretTokenGenerator, SecretTokenGenerator>();
        services.TryAddSingleton<ISecretEnvelopeProtector>(provider =>
        {
            var protection = provider.GetRequiredService<IOptions<IdentityServerOptions>>().Value.SecretProtection;
            var keys = protection.Keys.Select(key => SecretProtectionKey.FromFile(key.KeyId,
                System.IO.Path.IsPathFullyQualified(key.Path) ? key.Path : System.IO.Path.GetFullPath(key.Path, AppContext.BaseDirectory),
                key.KeyId == protection.ActiveKeyId)).ToArray();
            return keys.Length == 0 ? new IdentityUnconfiguredSecretProtector() : new AesGcmSecretProtector(keys, protection.ActiveKeyId);
        });
        services.TryAddSingleton<IdentityStore>();
        services.TryAddSingleton<IIdentityMfaStore>(provider => provider.GetRequiredService<IdentityStore>());
        services.TryAddSingleton<IIdentityCredentialStore>(provider => provider.GetRequiredService<IdentityStore>());
        services.TryAddSingleton<IMfaService, MfaService>();
        services.TryAddSingleton<IdentityCredentialVerifier>();
        services.TryAddSingleton<IIdentityRecoveryStore>(provider => provider.GetRequiredService<IdentityStore>());
        services.TryAddSingleton<IIdentityRecoveryAuthorization, IdentityRecoveryAuthorization>();
        services.TryAddSingleton<IPasswordRecoveryService, PasswordRecoveryService>();
        services.TryAddScoped<IIdentityApplicationContext, IdentityApplicationContext>();
        services.TryAddScoped<IdentityService>();
        services.TryAddScoped<IIdentity>(provider => provider.GetRequiredService<IdentityService>());
        services.TryAddSingleton<IdentityDatabaseInstaller>();
        if (registerInitializer) services.TryAddEnumerable(ServiceDescriptor.Singleton<IHostedService, IdentityDatabaseHostedService>());
        return services;
    }
}
