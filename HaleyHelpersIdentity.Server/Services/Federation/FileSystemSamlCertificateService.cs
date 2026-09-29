using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Haley.Abstractions;
using Haley.Models;
using Microsoft.Extensions.Options;
using Haley.Security;

namespace Haley.Services;

internal sealed class FileSystemSamlCertificateService(
    IIdentityFederationStore federation,
    IIdentityClock clock,
    IOptions<IdentityServerOptions> options) : IIdentitySamlCertificateService
{
    private const string Source = "Haley.Identity.SamlCertificates";
    private readonly SemaphoreSlim mutationGate = new(1, 1);

    public async ValueTask<IReadOnlyCollection<SamlCertificateInfo>> ListAsync(
        CancellationToken cancellationToken = default)
    {
        var references = (await federation.ListProvidersAsync(cancellationToken).ConfigureAwait(false))
            .SelectMany(provider => (provider.SigningCertificates ?? [])
                .Select(name => new { Name = NormalizeStoredName(name), provider.Code }))
            .Where(reference => reference.Name.Length > 0)
            .GroupBy(reference => reference.Name, StringComparer.Ordinal)
            .ToDictionary(
                group => group.Key,
                group => (IReadOnlyCollection<string>)group.Select(reference => reference.Code)
                    .Distinct(StringComparer.Ordinal)
                    .Order(StringComparer.Ordinal)
                    .ToArray(),
                StringComparer.Ordinal);
        var root = EnsureRoot();
        var result = new List<SamlCertificateInfo>();
        foreach (var path in Directory.EnumerateFiles(root, "*", SearchOption.TopDirectoryOnly)
                     .Where(path => SamlCertificateNames.TryNormalize(Path.GetFileName(path), out _))
                     .Order(StringComparer.Ordinal))
        {
            cancellationToken.ThrowIfCancellationRequested();
            var name = Path.GetFileName(path).ToLowerInvariant();
            references.TryGetValue(name, out var providers);
            try
            {
                using var certificate = ReadCertificate(await File.ReadAllBytesAsync(path, cancellationToken).ConfigureAwait(false));
                result.Add(ToInfo(name, path, certificate, providers ?? []));
            }
            catch (Exception exception) when (exception is CryptographicException or InvalidDataException or FormatException)
            {
                var file = new FileInfo(path);
                result.Add(new(
                    name,
                    string.Empty,
                    string.Empty,
                    string.Empty,
                    default,
                    default,
                    string.Empty,
                    file.Length,
                    CertificateStatus.Invalid,
                    new DateTimeOffset(file.LastWriteTimeUtc, TimeSpan.Zero),
                    providers ?? []));
            }
        }

        return result;
    }

    public async ValueTask<IFeedback<SamlCertificateInfo>> UploadAsync(
        UploadSamlCertificateRequest request,
        CancellationToken cancellationToken = default)
    {
        if (!SamlCertificateNames.TryNormalize(request.Name, out var name) ||
            request.Content is not { Length: > 0 } ||
            request.Content.Length > MaximumBytes())
        {
            return Failure(IdentityErrorCodes.SamlCertificateInvalid);
        }

        X509Certificate2 certificate;
        try
        {
            certificate = ReadCertificate(request.Content);
        }
        catch (Exception exception) when (exception is CryptographicException or InvalidDataException or FormatException)
        {
            return Failure(IdentityErrorCodes.SamlCertificateInvalid);
        }

        using (certificate)
        {
            await mutationGate.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                var root = EnsureRoot();
                var destination = ResolvePath(root, name);
                if (File.Exists(destination))
                {
                    var existing = await File.ReadAllBytesAsync(destination, cancellationToken).ConfigureAwait(false);
                    if (CryptographicOperations.FixedTimeEquals(SHA256.HashData(existing), SHA256.HashData(request.Content)))
                    {
                        return Success(ToInfo(name, destination, certificate, await ReferencingProvidersAsync(name, cancellationToken).ConfigureAwait(false)));
                    }

                    if (!request.Replace || !string.Equals(request.Confirmation?.Trim().ToLowerInvariant(), name, StringComparison.Ordinal))
                    {
                        return Failure(IdentityErrorCodes.SamlCertificateConflict);
                    }
                }

                var temporary = Path.Combine(root, $".{Guid.NewGuid():N}.upload");
                try
                {
                    await File.WriteAllBytesAsync(temporary, request.Content, cancellationToken).ConfigureAwait(false);
                    File.Move(temporary, destination, overwrite: true);
                }
                finally
                {
                    if (File.Exists(temporary)) File.Delete(temporary);
                }

                return Success(ToInfo(name, destination, certificate, await ReferencingProvidersAsync(name, cancellationToken).ConfigureAwait(false)));
            }
            finally
            {
                mutationGate.Release();
            }
        }
    }

    public bool Exists(string name)
    {
        if (!SamlCertificateNames.TryNormalize(name, out var normalized)) return false;
        var path = ResolvePath(EnsureRoot(), normalized);
        if (!File.Exists(path)) return false;
        try
        {
            using var certificate = ReadCertificate(File.ReadAllBytes(path));
            return true;
        }
        catch (Exception exception) when (exception is CryptographicException or InvalidDataException or FormatException)
        {
            return false;
        }
    }

    public IReadOnlyCollection<X509Certificate2> LoadCertificates(IReadOnlyCollection<string> names)
    {
        if (names.Count == 0) throw new InvalidOperationException("A SAML provider requires at least one managed signing certificate.");
        var root = EnsureRoot();
        var result = new List<X509Certificate2>(names.Count);
        try
        {
            foreach (var value in names.Distinct(StringComparer.Ordinal))
            {
                if (!SamlCertificateNames.TryNormalize(value, out var name))
                    throw new InvalidDataException("A SAML provider contains an invalid managed certificate name.");
                var path = ResolvePath(root, name);
                if (!File.Exists(path))
                    throw new FileNotFoundException($"Managed SAML certificate '{name}' was not found.", path);
                result.Add(ReadCertificate(File.ReadAllBytes(path)));
            }
            return result;
        }
        catch
        {
            result.ForEach(certificate => certificate.Dispose());
            throw;
        }
    }

    private async ValueTask<IReadOnlyCollection<string>> ReferencingProvidersAsync(
        string name,
        CancellationToken cancellationToken) =>
        (await federation.ListProvidersAsync(cancellationToken).ConfigureAwait(false))
        .Where(provider => (provider.SigningCertificates ?? []).Any(value =>
            string.Equals(NormalizeStoredName(value), name, StringComparison.Ordinal)))
        .Select(provider => provider.Code)
        .Distinct(StringComparer.Ordinal)
        .Order(StringComparer.Ordinal)
        .ToArray();

    private SamlCertificateInfo ToInfo(
        string name,
        string path,
        X509Certificate2 certificate,
        IReadOnlyCollection<string> references)
    {
        var now = clock.UtcNow;
        var validFrom = new DateTimeOffset(certificate.NotBefore.ToUniversalTime(), TimeSpan.Zero);
        var validTo = new DateTimeOffset(certificate.NotAfter.ToUniversalTime(), TimeSpan.Zero);
        var status = now < validFrom ? CertificateStatus.NotYetValid : now >= validTo ? CertificateStatus.Expired : CertificateStatus.Valid;
        var file = new FileInfo(path);
        return new(
            name,
            certificate.Subject,
            certificate.Issuer,
            certificate.SerialNumber,
            validFrom,
            validTo,
            Convert.ToHexString(certificate.GetCertHash(HashAlgorithmName.SHA256)),
            file.Length,
            status,
            new DateTimeOffset(file.LastWriteTimeUtc, TimeSpan.Zero),
            references);
    }

    private static X509Certificate2 ReadCertificate(byte[] content)
    {
        var text = Encoding.UTF8.GetString(content);
        if (text.Contains("PRIVATE KEY", StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Private key material is not accepted.");
        X509Certificate2 certificate;
        if (text.Contains("-----BEGIN CERTIFICATE-----", StringComparison.Ordinal))
        {
            if (Count(text, "-----BEGIN CERTIFICATE-----") != 1 ||
                Count(text, "-----END CERTIFICATE-----") != 1)
                throw new InvalidDataException("Upload exactly one PEM certificate per file.");
            certificate = X509Certificate2.CreateFromPem(text);
        }
        else
        {
            certificate = new X509Certificate2(content);
        }

        if (certificate.HasPrivateKey)
        {
            certificate.Dispose();
            throw new InvalidDataException("Private key material is not accepted.");
        }
        return certificate;
    }

    private string EnsureRoot()
    {
        var configured = options.Value.Federation.CertificateRootPath?.Trim();
        var root = Path.GetFullPath(
            string.IsNullOrWhiteSpace(configured) ? "SamlCerts" : configured,
            AppContext.BaseDirectory);
        Directory.CreateDirectory(root);
        return root;
    }

    private static string ResolvePath(string root, string name)
    {
        var path = Path.GetFullPath(name, root);
        var prefix = root.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar) + Path.DirectorySeparatorChar;
        if (!path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("The certificate name resolves outside the managed root.");
        return path;
    }

    private int MaximumBytes() => Math.Clamp(options.Value.Federation.MaximumCertificateBytes, 1_024, 2 * 1_024 * 1_024);
    private static int Count(string value, string marker) => value.Split(marker, StringSplitOptions.None).Length - 1;
    private static string NormalizeStoredName(string value) => SamlCertificateNames.TryNormalize(value, out var name) ? name : string.Empty;

    private static IFeedback<SamlCertificateInfo> Success(SamlCertificateInfo certificate) =>
        new Feedback<SamlCertificateInfo>(true, "SAML certificate saved.", certificate)
        {
            Source = Source
        };

    private static IFeedback<SamlCertificateInfo> Failure(string key) =>
        new Feedback<SamlCertificateInfo>(false, "SAML certificate request was rejected.", default!)
        {
            Source = Source,
            Key = key
        };
}
