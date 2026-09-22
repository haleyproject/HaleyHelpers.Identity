using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Haley.Abstractions;
using Haley.Models;
using Haley.Security;
using Microsoft.Extensions.Options;

namespace Haley.Services;
public sealed class MfaService(
    IIdentityMfaStore store,
    ISecretEnvelopeProtector protector,
    ISecretTokenGenerator tokens,
    IIdentityUuidGenerator uuids,
    IIdentityClock clock,
    IOptions<IdentityServerOptions> options) : IMfaService
{
    public ValueTask<IReadOnlyCollection<MfaMethodInfo>> ListMethodsAsync(Guid userId, CancellationToken cancellationToken = default) => store.ListMfaMethodsAsync(userId, cancellationToken);
    public async ValueTask<IFeedback<TotpEnrollmentReceipt>> BeginTotpEnrollmentAsync(BeginTotpEnrollmentRequest request, CancellationToken cancellationToken = default)
    {
        if (request.UserId == Guid.Empty || string.IsNullOrWhiteSpace(request.AccountLabel))
            return Fail<TotpEnrollmentReceipt>();

        var methodId = uuids.NewUuid7();
        var ticket = tokens.Generate();
        var now = clock.UtcNow;
        var expiresAt = now.AddSeconds(Math.Clamp(options.Value.Mfa.EnrollmentSeconds, 60, 3600));
        var secret = RandomNumberGenerator.GetBytes(20);
        byte[] encrypted;
        try
        {
            encrypted = protector.Protect(secret, Purpose(methodId));
        }
        catch (InvalidOperationException)
        {
            return Fail<TotpEnrollmentReceipt>(IdentityErrorCodes.SecretProtectionUnavailable);
        }

        var stored = await store.CreateMfaEnrollmentAsync(new(
            methodId,
            request.UserId,
            request.AccountLabel.Trim(),
            encrypted,
            "{\"digits\":6,\"period\":30,\"algorithm\":\"SHA1\"}",
            ticket.Hash,
            request.ApplicationId,
            request.Audience,
            request.ReturnUri,
            request.ReplaceMethodId,
            Math.Clamp(options.Value.Mfa.MaximumEnrollmentAttempts, 1, 20),
            now,
            expiresAt), cancellationToken).ConfigureAwait(false);
        CryptographicOperations.ZeroMemory(secret);
        if (!stored)
            return Fail<TotpEnrollmentReceipt>();
        return Ok(new TotpEnrollmentReceipt(
            methodId,
            ticket.Value,
            $"{options.Value.MfaEnrollmentPath}?ticket={Uri.EscapeDataString(ticket.Value)}",
            expiresAt));
    }

    public async ValueTask<IFeedback<TotpEnrollmentDetails>> InspectTotpEnrollmentAsync(
        string ticket,
        CancellationToken cancellationToken = default)
    {
        if (!TryHashTicket(ticket, out var ticketHash)) return Fail<TotpEnrollmentDetails>();
        var enrollment = await store.FindMfaEnrollmentAsync(ticketHash, cancellationToken).ConfigureAwait(false);
        if (!CanUse(enrollment, clock.UtcNow) || enrollment!.Method.SecretEncrypted is null)
            return Fail<TotpEnrollmentDetails>(IdentityErrorCodes.MfaInvalid);
        byte[] secret;
        try
        {
            secret = protector.Unprotect(
                enrollment.Method.SecretEncrypted,
                Purpose(enrollment.Method.Method.MethodId));
        }
        catch (InvalidOperationException)
        {
            return Fail<TotpEnrollmentDetails>(IdentityErrorCodes.SecretProtectionUnavailable);
        }
        try
        {
            var encoded = Base32.Encode(secret);
            var label = enrollment.Method.Method.Label ?? "Identity account";
            var uri = $"otpauth://totp/{Uri.EscapeDataString(label)}?secret={encoded}&issuer={Uri.EscapeDataString(options.Value.IssuerLabel)}&digits=6&period=30";
            return Ok(new TotpEnrollmentDetails(
                enrollment.Method.Method.MethodId,
                enrollment.Method.Method.UserId,
                label,
                uri,
                enrollment.ExpiresAt,
                Math.Max(0, enrollment.MaximumAttempts - enrollment.Attempts),
                enrollment.ReturnUri));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(secret);
        }
    }

    public async ValueTask<IFeedback<TotpEnrollmentCompletion>> ConfirmTotpEnrollmentAsync(
        ConfirmTotpTicketRequest request,
        CancellationToken cancellationToken = default)
    {
        if (!TryHashTicket(request.Ticket, out var ticketHash) || string.IsNullOrWhiteSpace(request.Code))
            return Fail<TotpEnrollmentCompletion>(IdentityErrorCodes.MfaInvalid);
        var now = clock.UtcNow;
        var enrollment = await store.FindMfaEnrollmentAsync(ticketHash, cancellationToken).ConfigureAwait(false);
        if (!CanUse(enrollment, now) || enrollment!.Method.SecretEncrypted is null)
            return Fail<TotpEnrollmentCompletion>(IdentityErrorCodes.MfaInvalid);
        if (MatchTotpCounter(
                enrollment.Method.SecretEncrypted,
                enrollment.Method.Method.MethodId,
                request.Code.Trim(),
                now) is null)
        {
            await store.FailMfaEnrollmentAsync(ticketHash, now, cancellationToken).ConfigureAwait(false);
            return Fail<TotpEnrollmentCompletion>(IdentityErrorCodes.MfaInvalid);
        }
        if (!await store.CompleteMfaEnrollmentAsync(ticketHash, now, cancellationToken).ConfigureAwait(false))
            return Fail<TotpEnrollmentCompletion>(IdentityErrorCodes.MfaInvalid);

        var recoveryCodes = CreateRecoveryCodes(Math.Clamp(options.Value.Mfa.RecoveryCodeCount, 5, 20));
        if (!await store.ReplaceRecoveryCodesAsync(
                enrollment.Method.Method.UserId,
                recoveryCodes.Select(HashRecovery).ToArray(),
                now,
                cancellationToken).ConfigureAwait(false))
            return Fail<TotpEnrollmentCompletion>(IdentityErrorCodes.IdentityUnavailable);
        return Ok(new TotpEnrollmentCompletion(
            enrollment.Method.Method.MethodId,
            recoveryCodes,
            enrollment.ReturnUri));
    }

    public async ValueTask<IFeedback> RetireMethodAsync(
        Guid userId,
        Guid methodId,
        CancellationToken cancellationToken = default)
    {
        if (userId == Guid.Empty || methodId == Guid.Empty) return Fail();
        return await store.RetireMfaMethodAsync(userId, methodId, clock.UtcNow, cancellationToken).ConfigureAwait(false)
            ? Ok()
            : Fail(IdentityErrorCodes.MfaInvalid);
    }

    public async ValueTask<IFeedback<RecoveryCodesReceipt>> ReplaceRecoveryCodesAsync(ReplaceRecoveryCodesRequest request, CancellationToken cancellationToken = default)
    {
        if (request.UserId == Guid.Empty || request.Count is < 5 or > 20)
            return Fail<RecoveryCodesReceipt>();
        var values = CreateRecoveryCodes(request.Count);
        var hashes = values.Select(HashRecovery).ToArray();
        return await store.ReplaceRecoveryCodesAsync(request.UserId, hashes, clock.UtcNow, cancellationToken).ConfigureAwait(false) ? Ok(new RecoveryCodesReceipt(values)) : Fail<RecoveryCodesReceipt>();
    }

    public async ValueTask<IFeedback> VerifyAsync(VerifyMfaRequest request, CancellationToken cancellationToken = default)
    {
        if (request.UserId == Guid.Empty || string.IsNullOrWhiteSpace(request.Code))
            return Fail(IdentityErrorCodes.MfaInvalid);
        if (request.Kind == MfaKind.RecoveryCode)
            return await store.ConsumeRecoveryCodeAsync(request.UserId, HashRecovery(request.Code.Trim()), clock.UtcNow, cancellationToken).ConfigureAwait(false) ? Ok() : Fail(IdentityErrorCodes.MfaInvalid);
        if (request.Kind != MfaKind.Totp || request.MethodId is null)
            return Fail(IdentityErrorCodes.MfaInvalid);
        var method = await store.FindMfaMethodAsync(request.MethodId.Value, cancellationToken).ConfigureAwait(false);
        if (method is null || method.Method.UserId != request.UserId || method.Method.Status != IdentityRecordStatus.Active || method.SecretEncrypted is null)
            return Fail(IdentityErrorCodes.MfaInvalid);
        var counter = MatchTotpCounter(method.SecretEncrypted, request.MethodId.Value, request.Code, clock.UtcNow);
        if (counter is null)
            return Fail(IdentityErrorCodes.MfaInvalid);
        var counterStartedAt = DateTimeOffset.FromUnixTimeSeconds(counter.Value * 30);
        return await store.TouchMfaMethodAsync(request.MethodId.Value, counterStartedAt, cancellationToken).ConfigureAwait(false) ? Ok() : Fail(IdentityErrorCodes.MfaInvalid);
    }

    private long? MatchTotpCounter(byte[] encrypted, Guid methodId, string code, DateTimeOffset now)
    {
        if (code.Length != 6 || !code.All(char.IsAsciiDigit))
            return null;
        var secret = protector.Unprotect(encrypted, Purpose(methodId));
        try
        {
            var counter = now.ToUnixTimeSeconds() / 30;
            for (var offset = -1; offset <= 1; offset++)
                if (CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(code), Encoding.ASCII.GetBytes(Totp(secret, counter + offset))))
                    return counter + offset;
            return null;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(secret);
        }
    }

    private static string Totp(byte[] key, long counter)
    {
        Span<byte> input = stackalloc byte[8];
        System.Buffers.Binary.BinaryPrimitives.WriteInt64BigEndian(input, counter);
        using var hmac = new HMACSHA1(key);
        var hash = hmac.ComputeHash(input.ToArray());
        var offset = hash[^1] & 0x0f;
        var binary = ((hash[offset] & 0x7f) << 24) | (hash[offset + 1] << 16) | (hash[offset + 2] << 8) | hash[offset + 3];
        return (binary % 1_000_000).ToString("D6", CultureInfo.InvariantCulture);
    }

    private static byte[] HashRecovery(string value) => SHA256.HashData(Encoding.UTF8.GetBytes(value.Trim().ToUpperInvariant()));
    private static string[] CreateRecoveryCodes(int count) =>
        Enumerable.Range(0, count)
            .Select(_ => Convert.ToHexString(RandomNumberGenerator.GetBytes(8)))
            .ToArray();
    private static bool CanUse(StoredMfaEnrollment? enrollment, DateTimeOffset now) =>
        enrollment is not null && enrollment.ConsumedAt is null && enrollment.ExpiresAt > now &&
        enrollment.Attempts < enrollment.MaximumAttempts && enrollment.Method.Method.Status == IdentityRecordStatus.Pending;
    private static bool TryHashTicket(string? value, out byte[] hash)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > 512)
        {
            hash = [];
            return false;
        }
        hash = SHA256.HashData(Encoding.UTF8.GetBytes(value));
        return true;
    }
    private string Purpose(Guid methodId) => $"{options.Value.MfaProtectionPurpose}:{methodId:N}";
    private static IFeedback Ok() => new Feedback(true, "MFA operation completed.")
    {
        Source = "Haley.Identity.Mfa"
    };
    private static IFeedback<T> Ok<T>(T value) => new Feedback<T>(true, "MFA operation completed.", value)
    {
        Source = "Haley.Identity.Mfa"
    };
    private static IFeedback Fail(string code = IdentityErrorCodes.InvalidRequest) => new Feedback(false, "MFA operation failed.")
    {
        Source = "Haley.Identity.Mfa",
        Key = code
    };
    private static IFeedback<T> Fail<T>(string code = IdentityErrorCodes.InvalidRequest) => new Feedback<T>(false, "MFA operation failed.", default!)
    {
        Source = "Haley.Identity.Mfa",
        Key = code
    };
}
