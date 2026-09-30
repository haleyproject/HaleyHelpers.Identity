using Haley.Abstractions;
using Haley.Extensions;
using Haley.Models;
using Haley.Security;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Haley.Tests;

internal static class FederationTestServices
{
    internal static ServiceProvider Create(TestFederationDal store, IIdentityClock? clock = null, string? certificateRoot = null)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<IIdentityFederationStore>(store);
        services.AddSingleton<IIdentityRecoveryAuthorization>(store);
        services.AddSingleton<IIdentityVerificationMfaPolicy>(store);
        services.AddSingleton<IIdentityFederationPolicy>(store);
        services.AddSingleton<IIdentityClock>(clock ?? new SamlFixedClock());
        services.AddSingleton<IIdentityUuidGenerator, SamlFixedUuidGenerator>();
        services.AddSingleton<ISecretEnvelopeProtector>(new AesGcmSecretProtector([new SecretProtectionKey("test", new byte[32], true)]));
        services.AddHaleyIdentityEngine(new ConfigurationBuilder().Build(), options =>
        {
            options.Adapter = "unused";
            options.Initialize = false;
            if (certificateRoot is not null) options.Federation.CertificateRootPath = certificateRoot;
        }, registerInitializer: false);
        return services.BuildServiceProvider();
    }
}
