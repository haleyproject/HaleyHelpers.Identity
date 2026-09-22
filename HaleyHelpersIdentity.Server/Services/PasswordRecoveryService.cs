using System.Security.Cryptography;
using System.Text;
using Haley.Abstractions;
using Haley.Models;
using Haley.Abstractions;
using Haley.Models;
using Haley.Constants;
using Haley.Utils;
using Microsoft.Extensions.Options;

namespace Haley.Services;

public sealed class PasswordRecoveryService(
    IIdentityRecoveryStore store,
    IIdentityRecoveryAuthorization clients,
    IPasswordHasher passwordHasher,
    IIdentityUuidGenerator uuids,
    IIdentityClock clock,
    IOptions<IdentityServerOptions> options) : IPasswordRecoveryService
{
    private const string Source = "Haley.Identity.PasswordRecovery";

    public async ValueTask<IFeedback<PasswordResetInitiationResult>> BeginResetAsync(
        BeginPasswordResetRequest request,
        CancellationToken cancellationToken = default)
    {
        if (request.ApplicationId == Guid.Empty ||
            !clients.TryNormalizeContext(request.Context, out var resource) ||
            !TryNormalizeChannelAndDestination(request.Channel, request.Destination, out var channel, out var destination) ||
            !TryNormalizeState(request.State, out var state) ||
            !TryNormalizeReturnUri(request.ReturnUri, out var returnUri))
        {
            return Fail<PasswordResetInitiationResult>(IdentityErrorCodes.InvalidRequest);
        }

        if (state is not null && returnUri is null)
        {
            return Fail<PasswordResetInitiationResult>(IdentityErrorCodes.InvalidRequest);
        }

        if (!await clients.HasActiveResourceAuthorityAsync(request.ApplicationId, resource, cancellationToken).ConfigureAwait(false))
        {
            return Fail<PasswordResetInitiationResult>(IdentityErrorCodes.InvalidClientResource);
        }

        if (returnUri is not null &&
            !await clients.IsReturnUriAllowedAsync(request.ApplicationId, resource, returnUri, cancellationToken).ConfigureAwait(false))
        {
            return Fail<PasswordResetInitiationResult>(IdentityErrorCodes.InvalidClientResource);
        }

        var subject = await store.FindPasswordResetSubjectAsync(channel, destination, cancellationToken).ConfigureAwait(false);
        if (subject is null || subject.Status != IdentityStatus.Active)
        {
            return Ok(new PasswordResetInitiationResult(true));
        }

        var now = clock.UtcNow;
        var codeLength = Math.Clamp(options.Value.Verification.CodeLength, 4, 12);
        var code = GenerateNumericCode(codeLength);
        var codeHash = passwordHasher.Hash(code);
        var challengeId = uuids.NewUuid7();
        var codeExpiry = now.AddSeconds(Math.Clamp(options.Value.Verification.CodeValiditySeconds, 60, 3_600));
        var resendAllowedAt = now.AddSeconds(Math.Clamp(options.Value.Verification.ResendDelaySeconds, 30, 86_400));
        var contextHash = Hash(BuildContext(request.ApplicationId, resource, returnUri, state));
        var policyCode = string.Equals(channel, "sms", StringComparison.Ordinal)
            ? "standard-sms-6"
            : "standard-email-6";
        var challenge = new CreateVerificationChallengeCommand(
            challengeId,
            request.ApplicationId,
            null,
            subject.UserId,
            policyCode,
            IdentityPurposes.PasswordReset,
            Hash(subject.DestinationNormalized),
            contextHash,
            codeHash.Value,
            codeHash.Algorithm,
            codeHash.ParametersPayload,
            codeExpiry,
            null,
            Math.Clamp(options.Value.Verification.ExhaustedCooldownSeconds, 60, 86_400),
            now,
            now,
            codeExpiry);
        var created = await store.CreateVerificationChallengeAsync(challenge, cancellationToken).ConfigureAwait(false);
        if (!created)
        {
            // A resend cooldown or exhausted challenge is deliberately indistinguishable
            // from an unknown destination to callers outside the trusted backend.
            return Ok(new PasswordResetInitiationResult(true));
        }

        var resetPath = BuildResetPath(challengeId, request.ApplicationId, resource, returnUri, state);
        return Ok(new PasswordResetInitiationResult(
            true,
            new PasswordResetDeliveryReceipt(
                challengeId,
                channel,
                subject.DestinationDisplay,
                code,
                codeExpiry,
                resendAllowedAt,
                resetPath)));
    }

    public async ValueTask<IFeedback<PasswordResetGrantReceipt>> VerifyResetCodeAsync(
        VerifyPasswordResetCodeRequest request,
        CancellationToken cancellationToken = default)
    {
        if (request.ChallengeId == Guid.Empty || request.ApplicationId == Guid.Empty ||
            !clients.TryNormalizeContext(request.Context, out var resource) ||
            !TryNormalizeState(request.State, out var state) ||
            !TryNormalizeReturnUri(request.ReturnUri, out var returnUri) ||
            string.IsNullOrWhiteSpace(request.Code) || request.Code.Trim().Length is < 4 or > 12 ||
            request.Code.Trim().Any(character => !char.IsAsciiDigit(character)))
        {
            return Fail<PasswordResetGrantReceipt>(IdentityErrorCodes.InvalidRequest);
        }

        if (state is not null && returnUri is null)
        {
            return Fail<PasswordResetGrantReceipt>(IdentityErrorCodes.InvalidRequest);
        }

        var challenge = await store.FindVerificationChallengeAsync(request.ChallengeId, cancellationToken).ConfigureAwait(false);
        var now = clock.UtcNow;
        if (challenge is null || challenge.ApplicationId != request.ApplicationId || challenge.SubjectId is null ||
            !await clients.HasActiveResourceAuthorityAsync(request.ApplicationId, resource, cancellationToken).ConfigureAwait(false) ||
            !string.Equals(challenge.Purpose, IdentityPurposes.PasswordReset, StringComparison.Ordinal) ||
            !CryptographicOperations.FixedTimeEquals(
                challenge.ContextHash,
                Hash(BuildContext(request.ApplicationId, resource, returnUri, state))) ||
            !(challenge.Status == IdentityRecordStatus.Pending) ||
            now < challenge.NotBefore || now >= challenge.ExpiresAt)
        {
            return Fail<PasswordResetGrantReceipt>(IdentityErrorCodes.VerificationInvalid);
        }

        var valid = now < challenge.CodeExpiresAt && passwordHasher.Verify(
            request.Code.Trim(),
            challenge.CodeHash,
            challenge.CodeAlgorithm,
            challenge.CodeParameters);
        var grantId = uuids.NewUuid7();
        var grantExpiry = now.AddSeconds(Math.Clamp(options.Value.Verification.PasswordResetSeconds, 300, 86_400));
        var completed = await store.CompleteVerificationAsync(
            new(
                challenge.LocalChallengeId,
                grantId,
                valid,
                challenge.Attempts,
                null,
                null,
                now,
                grantExpiry),
            cancellationToken).ConfigureAwait(false);
        if (!valid || !completed)
        {
            return Fail<PasswordResetGrantReceipt>(
                !valid && challenge.Attempts + 1 >= challenge.MaximumAttempts
                    ? IdentityErrorCodes.VerificationExhausted
                    : IdentityErrorCodes.VerificationInvalid);
        }

        return Ok(new PasswordResetGrantReceipt(grantId, grantExpiry));
    }

    public async ValueTask<IFeedback<PasswordResetCompletionReceipt>> CompleteResetAsync(
        CompletePasswordResetRequest request,
        CancellationToken cancellationToken = default)
    {
        if (request.GrantId == Guid.Empty || request.ApplicationId == Guid.Empty ||
            !clients.TryNormalizeContext(request.Context, out var resource) ||
            !TryNormalizeState(request.State, out var state) ||
            !TryNormalizeReturnUri(request.ReturnUri, out var returnUri))
        {
            return Fail<PasswordResetCompletionReceipt>(IdentityErrorCodes.InvalidRequest);
        }

        if (state is not null && returnUri is null)
        {
            return Fail<PasswordResetCompletionReceipt>(IdentityErrorCodes.InvalidRequest);
        }

        try
        {
            IdentityPolicy.ValidateNewPassword(request.NewPassword);
        }
        catch (ArgumentException)
        {
            return Fail<PasswordResetCompletionReceipt>(IdentityErrorCodes.InvalidRequest);
        }

        if (!await clients.HasActiveResourceAuthorityAsync(request.ApplicationId, resource, cancellationToken).ConfigureAwait(false))
        {
            return Fail<PasswordResetCompletionReceipt>(IdentityErrorCodes.InvalidClientResource);
        }

        var now = clock.UtcNow;
        var currentCredential = await store.FindPasswordResetGrantCredentialAsync(
            request.GrantId,
            request.ApplicationId,
            now,
            cancellationToken).ConfigureAwait(false);
        if (currentCredential is null)
        {
            return Fail<PasswordResetCompletionReceipt>(IdentityErrorCodes.VerificationInvalid);
        }

        if (passwordHasher.Verify(
            request.NewPassword,
            currentCredential.SecretHash,
            currentCredential.Algorithm,
            currentCredential.ParametersPayload))
        {
            return Fail<PasswordResetCompletionReceipt>(IdentityErrorCodes.PasswordReuse);
        }

        var returnAllowed = returnUri is not null &&
            await clients.IsReturnUriAllowedAsync(request.ApplicationId, resource, returnUri, cancellationToken).ConfigureAwait(false);
        var replacement = passwordHasher.Hash(request.NewPassword);
        var completed = await store.ConsumePasswordResetGrantAsync(
            new(
                request.GrantId,
                request.ApplicationId,
                Hash(BuildContext(request.ApplicationId, resource, returnUri, state)),
                currentCredential.CredentialId,
                uuids.NewUuid7(),
                replacement.Value,
                replacement.Algorithm,
                replacement.ParametersPayload,
                now),
            cancellationToken).ConfigureAwait(false);
        if (!completed)
        {
            return Fail<PasswordResetCompletionReceipt>(IdentityErrorCodes.VerificationInvalid);
        }

        return Ok(new PasswordResetCompletionReceipt(
            returnAllowed ? returnUri : null,
            returnAllowed ? state : null));
    }

    private static bool TryNormalizeChannelAndDestination(
        string? requestedChannel,
        string? requestedDestination,
        out string channel,
        out string destination)
    {
        channel = requestedChannel?.Trim().ToLowerInvariant() ?? string.Empty;
        destination = string.Empty;
        if (channel == "email")
        {
            var email = requestedDestination?.Trim().Normalize().ToLowerInvariant() ?? string.Empty;
            var at = email.LastIndexOf('@');
            if (email.Length is >= 3 and <= 320 && at > 0 && at < email.Length - 1 &&
                !email.Any(character => char.IsWhiteSpace(character) || char.IsControl(character)))
            {
                destination = email;
                return true;
            }

            return false;
        }

        if (channel != "sms" || string.IsNullOrWhiteSpace(requestedDestination))
        {
            return false;
        }

        var source = requestedDestination.Trim();
        var normalized = new StringBuilder(source.Length);
        foreach (var character in source)
        {
            if (character == '+' && normalized.Length == 0)
            {
                normalized.Append(character);
            }
            else if (char.IsAsciiDigit(character))
            {
                normalized.Append(character);
            }
            else if (!char.IsWhiteSpace(character) && character is not ('-' or '(' or ')' or '.'))
            {
                return false;
            }
        }

        if (normalized.Length == 0)
        {
            return false;
        }

        var digitCount = normalized[0] == '+' ? normalized.Length - 1 : normalized.Length;
        if (digitCount is < 7 or > 20)
        {
            return false;
        }

        destination = normalized.ToString();
        return true;
    }

    private static bool TryNormalizeReturnUri(string? value, out string? normalized)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            normalized = null;
            return true;
        }

        var text = value.Trim();
        if (text.Length <= 1_000 && Uri.TryCreate(text, UriKind.Absolute, out var uri) &&
            string.IsNullOrEmpty(uri.Fragment) && string.IsNullOrEmpty(uri.UserInfo) &&
            (string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase) ||
             (string.Equals(uri.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase) && uri.IsLoopback)))
        {
            normalized = uri.AbsoluteUri;
            return true;
        }

        normalized = null;
        return false;
    }

    private static bool TryNormalizeState(string? value, out string? normalized)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            normalized = null;
            return true;
        }

        normalized = value.Trim();
        return normalized.Length <= 200 && !normalized.Any(char.IsControl);
    }

    private static string BuildContext(
        Guid clientId,
        string resource,
        string? returnUri,
        string? state) =>
        $"{IdentityPurposes.PasswordReset}\n{clientId:N}\n{resource}\n{returnUri ?? string.Empty}\n{state ?? string.Empty}";

    private string BuildResetPath(
        Guid challengeId,
        Guid clientId,
        string resource,
        string? returnUri,
        string? state)
    {
        var query = new StringBuilder(options.Value.PasswordResetPath + "?challenge=")
            .Append(Uri.EscapeDataString(challengeId.ToString("D")))
            .Append("&client=").Append(Uri.EscapeDataString(clientId.ToString("D")))
            .Append("&resource=").Append(Uri.EscapeDataString(resource));
        if (returnUri is not null)
        {
            query.Append("&return_uri=").Append(Uri.EscapeDataString(returnUri));
        }

        if (state is not null)
        {
            query.Append("&state=").Append(Uri.EscapeDataString(state));
        }

        return query.ToString();
    }

    private static byte[] Hash(string value) => SHA256.HashData(Encoding.UTF8.GetBytes(value));

    private static string GenerateNumericCode(int length)
    {
        var code = new char[length];
        for (var index = 0; index < code.Length; index++)
        {
            code[index] = (char)('0' + RandomNumberGenerator.GetInt32(10));
        }

        return new string(code);
    }

    private static IFeedback<T> Ok<T>(T value) => new Feedback<T>(true, "Identity operation completed.", value)
    {
        Source = Source
    };

    private static IFeedback<T> Fail<T>(string code) => new Feedback<T>(false, "Identity operation failed.", default!)
    {
        Source = Source,
        Key = code
    };
}
