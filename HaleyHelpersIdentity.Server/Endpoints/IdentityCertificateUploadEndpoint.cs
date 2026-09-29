using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;

namespace Haley.Extensions;

/// <summary>Common certificate upload transport for trusted identity management hosts.</summary>
public static class IdentityCertificateUploadEndpoint
{
    public static async Task<IResult> HandleAsync(
        HttpRequest request,
        IIdentitySamlCertificateService certificates,
        IOptions<IdentityServerOptions> options,
        CancellationToken cancellationToken)
    {
        var maximumBytes = Math.Clamp(options.Value.Federation.MaximumCertificateBytes, 1_024, 2 * 1_024 * 1_024);
        UploadSamlCertificateRequest? upload;
        if (request.HasFormContentType)
        {
            var form = await request.ReadFormAsync(cancellationToken).ConfigureAwait(false);
            var file = form.Files.GetFile("file");
            if (file is null || file.Length == 0 || file.Length > maximumBytes)
                return Problem(StatusCodes.Status400BadRequest, IdentityErrorCodes.SamlCertificateInvalid, $"Choose a non-empty CER or PEM file no larger than {maximumBytes} bytes.");
            await using var stream = file.OpenReadStream();
            using var buffer = new MemoryStream((int)file.Length);
            await stream.CopyToAsync(buffer, cancellationToken).ConfigureAwait(false);
            var name = form["name"].ToString();
            if (string.IsNullOrWhiteSpace(name)) name = file.FileName;
            upload = new(
                name,
                buffer.ToArray(),
                bool.TryParse(form["replace"].ToString(), out var replacing) && replacing,
                form["confirmation"].ToString());
        }
        else if (request.ContentType?.StartsWith("application/json", StringComparison.OrdinalIgnoreCase) == true)
        {
            upload = await request.ReadFromJsonAsync<UploadSamlCertificateRequest>(cancellationToken).ConfigureAwait(false);
            if (upload?.Content is not { Length: > 0 } || upload.Content.Length > maximumBytes)
                return Problem(StatusCodes.Status400BadRequest, IdentityErrorCodes.SamlCertificateInvalid, $"Choose a non-empty CER or PEM file no larger than {maximumBytes} bytes.");
        }
        else
        {
            return Problem(StatusCodes.Status400BadRequest, IdentityErrorCodes.SamlCertificateInvalid, "Upload a SAML certificate as multipart form data or JSON.");
        }

        var result = await certificates.UploadAsync(upload, cancellationToken).ConfigureAwait(false);
        if (result.Status && result.Result is not null) return Results.Ok(result.Result);
        return Problem(
            result.Key == IdentityErrorCodes.SamlCertificateConflict
                ? StatusCodes.Status409Conflict
                : StatusCodes.Status400BadRequest,
            result.Key ?? IdentityErrorCodes.SamlCertificateInvalid,
            "The SAML certificate was not saved.");
    }

    private static IResult Problem(int status, string code, string message) =>
        Results.Problem(statusCode: status, detail: message, extensions: new Dictionary<string, object?> { ["code"] = code });
}
