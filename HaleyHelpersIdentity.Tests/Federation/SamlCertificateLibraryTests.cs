using Haley.Constants;
using Microsoft.Extensions.DependencyInjection;
using Haley.Models;
using Haley.Abstractions;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Options;
using Xunit;

namespace Haley.Tests;

public sealed class SamlCertificateLibraryTests : IDisposable
{
    private readonly string root = Path.Combine(Path.GetTempPath(), $"kida-saml-tests-{Guid.NewGuid():N}");

    [Fact]
    public async Task UploadListsAndLoadsManagedPublicCertificate()
    {
        var service = CreateService();
        var content = CreateCertificate("CN=Corporate Identity");

        var upload = await service.UploadAsync(new("corporate-2026.cer", content));
        var listed = await service.ListAsync();
        var loaded = service.LoadCertificates(["corporate-2026.cer"]);

        Assert.True(upload.Status);
        var certificate = Assert.Single(listed);
        Assert.Equal("corporate-2026.cer", certificate.Name);
        Assert.Equal(CertificateStatus.Valid, certificate.Status);
        Assert.Equal("CN=Corporate Identity", certificate.Subject);
        Assert.Single(loaded).Dispose();
    }

    [Fact]
    public async Task ExistingNameRequiresExactReplacementConfirmation()
    {
        var service = CreateService();
        Assert.True((await service.UploadAsync(new("corporate.cer", CreateCertificate("CN=First")))).Status);

        var conflict = await service.UploadAsync(new("corporate.cer", CreateCertificate("CN=Second")));
        var wrongConfirmation = await service.UploadAsync(new("corporate.cer", CreateCertificate("CN=Second"), true, "replace"));
        var replaced = await service.UploadAsync(new("corporate.cer", CreateCertificate("CN=Second"), true, "corporate.cer"));

        Assert.False(conflict.Status);
        Assert.Equal(IdentityErrorCodes.SamlCertificateConflict, conflict.Key);
        Assert.False(wrongConfirmation.Status);
        Assert.Equal(IdentityErrorCodes.SamlCertificateConflict, wrongConfirmation.Key);
        Assert.True(replaced.Status);
        Assert.Equal("CN=Second", replaced.Result.Subject);
    }

    [Fact]
    public async Task RejectsPathsAndPrivateKeyMaterial()
    {
        var service = CreateService();
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest("CN=Private", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var certificate = request.CreateSelfSigned(Now.AddDays(-1), Now.AddDays(30));
        var privatePem = certificate.ExportCertificatePem() + rsa.ExportPkcs8PrivateKeyPem();

        var path = await service.UploadAsync(new("../outside.cer", CreateCertificate("CN=Outside")));
        var privateKey = await service.UploadAsync(new("private.pem", System.Text.Encoding.UTF8.GetBytes(privatePem)));

        Assert.False(path.Status);
        Assert.Equal(IdentityErrorCodes.SamlCertificateInvalid, path.Key);
        Assert.False(privateKey.Status);
        Assert.Equal(IdentityErrorCodes.SamlCertificateInvalid, privateKey.Key);
    }

    public void Dispose()
    {
        if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
    }

    private IIdentitySamlCertificateService CreateService() =>
        FederationTestServices.Create(new TestFederationDal(), new CertificateClock(), root).GetRequiredService<IIdentitySamlCertificateService>();

    private static byte[] CreateCertificate(string subject)
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest(subject, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var certificate = request.CreateSelfSigned(Now.AddDays(-1), Now.AddDays(30));
        return certificate.Export(X509ContentType.Cert);
    }

    private static readonly DateTimeOffset Now = new(2026, 9, 6, 12, 0, 0, TimeSpan.Zero);

    private sealed class CertificateClock : IIdentityClock
    {
        public DateTimeOffset UtcNow => Now;
    }
}
