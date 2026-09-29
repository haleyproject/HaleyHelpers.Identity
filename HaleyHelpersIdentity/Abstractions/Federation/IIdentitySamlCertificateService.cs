using System.Security.Cryptography.X509Certificates;
using Haley.Abstractions;

namespace Haley.Abstractions;

public interface IIdentitySamlCertificateService
{
    ValueTask<IReadOnlyCollection<SamlCertificateInfo>> ListAsync(CancellationToken cancellationToken = default);
    ValueTask<IFeedback<SamlCertificateInfo>> UploadAsync(UploadSamlCertificateRequest request, CancellationToken cancellationToken = default);
    bool Exists(string name);
    IReadOnlyCollection<X509Certificate2> LoadCertificates(IReadOnlyCollection<string> names);
}
