using Microsoft.AspNetCore.Http;

namespace Haley.Services;

/// <summary>Proof identifiers distinguish pending ceremonies without treating them as authentication.</summary>
public static class IdentityProofRateLimitSubject
{
    public static async ValueTask<string?> ResolveAsync(EndpointFilterInvocationContext invocation)
    {
        foreach (var argument in invocation.Arguments)
        {
            var subject = FromBoundArgument(argument);
            if (subject is not null) return subject;
        }
        var requestBody = invocation.HttpContext.Request;
        if (!requestBody.HasFormContentType) return null;
        var form = await requestBody.ReadFormAsync(invocation.HttpContext.RequestAborted).ConfigureAwait(false);
        var attempt = form["RelayState"].ToString();
        if (string.IsNullOrWhiteSpace(attempt)) attempt = form["attempt"].ToString();
        return string.IsNullOrWhiteSpace(attempt) ? null : "federation-attempt:" + attempt;
    }

    public static string? FromBoundArgument(object? argument) => argument switch
    {
        CompleteIdentityVerificationRequest request => "challenge:" + request.ChallengeId.ToString("D"),
        InspectIdentityVerificationRequest request => "challenge:" + request.ChallengeId.ToString("D"),
        VerifyPasswordResetCodeRequest request => "challenge:" + request.ChallengeId.ToString("D"),
        CompletePasswordResetRequest request => "grant:" + request.GrantId.ToString("D"),
        MfaTicketRequest request when !string.IsNullOrWhiteSpace(request.Ticket) => "mfa-ticket:" + request.Ticket,
        ConfirmTotpTicketRequest request when !string.IsNullOrWhiteSpace(request.Ticket) => "mfa-ticket:" + request.Ticket,
        CompleteSamlAuthenticationRequest request when !string.IsNullOrWhiteSpace(request.RelayState) => "federation-attempt:" + request.RelayState,
        CompleteExternalAuthenticationRequest request when !string.IsNullOrWhiteSpace(request.Attempt) => "federation-attempt:" + request.Attempt,
        RedeemFederationHandoffRequest request when !string.IsNullOrWhiteSpace(request.Code) => "handoff:" + request.Code,
        _ => null
    };
}
