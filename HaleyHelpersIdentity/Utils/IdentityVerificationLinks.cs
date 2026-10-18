using System.Text.Json;
using System.Text.Json.Serialization;

namespace Haley.Utils;

/// <summary>Builds a recipient URL without putting verification secrets in requests or referrers.</summary>
public static class IdentityVerificationLinks
{
    public static string Create(string pageUrl, Guid applicationId, string resource,
        IdentityVerificationDelivery delivery, string? context = null, bool requiresPassword = false)
    {
        if (!Uri.TryCreate(pageUrl, UriKind.Absolute, out var page) || page.Scheme is not ("https" or "http") ||
            !string.IsNullOrEmpty(page.UserInfo) || !string.IsNullOrEmpty(page.Fragment))
            throw new ArgumentException("The verification page must be an absolute HTTP(S) URL without credentials or a fragment.", nameof(pageUrl));
        if (applicationId == Guid.Empty || string.IsNullOrWhiteSpace(resource) || resource.Length > 200 ||
            resource.Any(char.IsControl) || context?.Length > 1000)
            throw new ArgumentException("An application and bounded identity context are required.");
        var data = JsonSerializer.Serialize(new
        {
            applicationId, resource, delivery.ChallengeId, delivery.Purpose, delivery.ProofKind, context,
            email = delivery.Destination, delivery.ExpiresAt, requiresPassword,
            verifier = delivery.ProofKind == VerificationProofKind.OpaqueToken ? delivery.Verifier : null
        }, new JsonSerializerOptions(JsonSerializerDefaults.Web) { DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull });
        return new UriBuilder(page) { Fragment = "proof=" + Uri.EscapeDataString(data) }.Uri.AbsoluteUri;
    }
}
