namespace Haley.Models;

public sealed record UploadSamlCertificateRequest(
    string Name,
    byte[] Content,
    bool Replace = false,
    string? Confirmation = null);
