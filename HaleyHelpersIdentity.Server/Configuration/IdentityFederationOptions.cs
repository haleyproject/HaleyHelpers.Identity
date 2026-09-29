namespace Haley.Models;
public sealed class IdentityFederationOptions
{
    public int RequestValiditySeconds { get; set; } = 300;
    public int HandoffValiditySeconds { get; set; } = 60;
    public string CertificateRootPath { get; set; } = "SamlCerts";
    public int MaximumCertificateBytes { get; set; } = 262_144;
}
