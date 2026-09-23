using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;

namespace Haley.Services;

/// <summary>Generates and checks email/SMS proof material. Only hashes enter persistence.</summary>
public sealed class VerificationProofService(IPasswordHasher hasher, ISecretTokenGenerator tokens,
    IIdentityUuidGenerator uuids, IIdentityClock clock, IOptions<IdentityServerOptions> options)
{
    public PreparedVerificationProof Create(VerificationProofRequest request)
    {
        var now = clock.UtcNow;
        var digits = new char[Math.Clamp(options.Value.Verification.CodeLength, 4, 12)];
        for (var i = 0; i < digits.Length; i++) digits[i] = (char)('0' + RandomNumberGenerator.GetInt32(10));
        var code = new string(digits);
        var hash = hasher.Hash(code);
        var token = request.TokenValiditySeconds is null ? null : tokens.Generate();
        var codeExpiry = now.AddSeconds(request.CodeValiditySeconds);
        var tokenExpiry = token is null ? codeExpiry : now.AddSeconds(request.TokenValiditySeconds!.Value);
        var challenge = new CreateVerificationChallengeCommand(uuids.NewUuid7(), request.ApplicationId, request.TenantId,
            request.UserId, request.PolicyCode, request.Purpose, Hash(request.Destination), request.ContextHash,
            hash.Value, hash.Algorithm, hash.ParametersPayload, codeExpiry, token?.Hash,
            Math.Clamp(options.Value.Verification.ExhaustedCooldownSeconds, 60, 86400), now, now,
            tokenExpiry > codeExpiry ? tokenExpiry : codeExpiry);
        return new(challenge, code, token?.Value, now.AddSeconds(Math.Clamp(options.Value.Verification.ResendDelaySeconds, 30, 86400)));
    }

    public bool Verify(StoredVerificationChallenge challenge, string? code, string? token, DateTimeOffset at,
        bool permitCode = true, bool permitToken = true)
    {
        if (!IsPending(challenge, at) || string.IsNullOrWhiteSpace(code) == string.IsNullOrWhiteSpace(token)) return false;
        if (!string.IsNullOrWhiteSpace(code))
        {
            code = code.Trim();
            return permitCode && at < challenge.CodeExpiresAt && code.Length is >= 4 and <= 12 && code.All(char.IsAsciiDigit) &&
                hasher.Verify(code, challenge.CodeHash, challenge.CodeAlgorithm, challenge.CodeParameters);
        }
        token = token!.Trim();
        return permitToken && challenge.LinkHash is not null && token.Length is >= 32 and <= 1000 &&
            CryptographicOperations.FixedTimeEquals(challenge.LinkHash, Hash(token));
    }

    public static bool IsPending(StoredVerificationChallenge challenge, DateTimeOffset at) =>
        challenge.Status == IdentityRecordStatus.Pending && challenge.Attempts < challenge.MaximumAttempts &&
        at >= challenge.NotBefore && at < challenge.ExpiresAt;

    public static bool Matches(StoredVerificationChallenge challenge, Guid applicationId, string purpose,
        byte[] contextHash, DateTimeOffset at) => IsPending(challenge, at) && challenge.ApplicationId == applicationId &&
        challenge.SubjectId is not null && string.Equals(challenge.Purpose, purpose, StringComparison.Ordinal) &&
        CryptographicOperations.FixedTimeEquals(challenge.ContextHash, contextHash);

    public static byte[] Hash(string value) => SHA256.HashData(Encoding.UTF8.GetBytes(value));
}
