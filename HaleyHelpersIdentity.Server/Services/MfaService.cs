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
        if (!TryHashTicket(ticket, out var ticketHash))
            return Fail<TotpEnrollmentDetails>(IdentityErrorCodes.MfaEnrollmentInvalid);
        var enrollment = await store.FindMfaEnrollmentAsync(ticketHash, cancellationToken).ConfigureAwait(false);
        var failure = EnrollmentFailure(enrollment, clock.UtcNow);
        if (failure is not null) return Fail<TotpEnrollmentDetails>(failure);
        var current = enrollment!;
        byte[] secret;
        try
        {
            secret = UnprotectSecret(current.Method.SecretEncrypted, current.Method.Method.MethodId);
        }
        catch (Exception ex) when (ex is InvalidOperationException or CryptographicException)
        {
            return Fail<TotpEnrollmentDetails>(IdentityErrorCodes.SecretProtectionUnavailable);
        }
        try
        {
            var encoded = Base32.Encode(secret);
            var label = current.Method.Method.Label ?? "Identity account";
            var issuer = options.Value.IssuerLabel;
            var uri = $"otpauth://totp/{Uri.EscapeDataString(issuer + ":" + label)}?secret={encoded}&issuer={Uri.EscapeDataString(issuer)}&digits=6&period=30";
            return Ok(new TotpEnrollmentDetails(
                current.Method.Method.MethodId,
                current.Method.Method.UserId,
                label,
                uri,
                current.ExpiresAt,
                Math.Max(0, current.MaximumAttempts - current.Attempts),
                current.ReturnUri));
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
        if (!TryHashTicket(request.Ticket, out var ticketHash))
            return Fail<TotpEnrollmentCompletion>(IdentityErrorCodes.MfaEnrollmentInvalid);
        if (string.IsNullOrWhiteSpace(request.Code))
            return Fail<TotpEnrollmentCompletion>(IdentityErrorCodes.MfaCodeInvalid);
        var now = clock.UtcNow;
        var enrollment = await store.FindMfaEnrollmentAsync(ticketHash, cancellationToken).ConfigureAwait(false);
        var failure = EnrollmentFailure(enrollment, now);
        if (failure is not null) return Fail<TotpEnrollmentCompletion>(failure);

        long? counter;
        try
        {
            counter = MatchTotpCounter(
                enrollment!.Method.SecretEncrypted!,
                enrollment.Method.Method.MethodId,
                request.Code.Trim(),
                now);
        }
        catch (Exception ex) when (ex is InvalidOperationException or CryptographicException)
        {
            return Fail<TotpEnrollmentCompletion>(IdentityErrorCodes.SecretProtectionUnavailable);
        }
        if (counter is null)
        {
            await store.FailMfaEnrollmentAsync(ticketHash, now, cancellationToken).ConfigureAwait(false);
            return Fail<TotpEnrollmentCompletion>(IdentityErrorCodes.MfaCodeInvalid);
        }
        if (!await store.CompleteMfaEnrollmentAsync(ticketHash, now, cancellationToken).ConfigureAwait(false))
        {
            var current = await store.FindMfaEnrollmentAsync(ticketHash, cancellationToken).ConfigureAwait(false);
            return Fail<TotpEnrollmentCompletion>(
                EnrollmentFailure(current, clock.UtcNow) ?? IdentityErrorCodes.MfaEnrollmentInvalid);
        }

        var recoveryCodes = CreateRecoveryCodes(Math.Clamp(options.Value.Mfa.RecoveryCodeCount, 5, 20));
        if (!await store.ReplaceRecoveryCodesAsync(
                enrollment!.Method.Method.UserId,
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

    public async ValueTask<IFeedback<int>> PruneUnusedMethodsAsync(Guid userId, CancellationToken cancellationToken = default)
    {
        if (userId == Guid.Empty) return Fail<int>();
        return Ok(await store.PruneUnusedMfaMethodsAsync(userId, cancellationToken).ConfigureAwait(false));
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
            return Fail(IdentityErrorCodes.InvalidRequest, "An account and verification code are required.");
        if (request.Kind == MfaKind.RecoveryCode)
            return await store.ConsumeRecoveryCodeAsync(request.UserId, HashRecovery(request.Code.Trim()), clock.UtcNow, cancellationToken).ConfigureAwait(false)
                ? Ok() : Fail(IdentityErrorCodes.MfaInvalid, "The recovery code is invalid or has already been used.", 401);
        if (request.Kind != MfaKind.Totp)
            return Fail(IdentityErrorCodes.InvalidRequest, "Choose an authenticator code or recovery code for this operation.");
        if (request.MethodId is null)
            return Fail(IdentityErrorCodes.InvalidRequest, "Select the enrolled authenticator to verify this code.");
        var method = await store.FindMfaMethodAsync(request.MethodId.Value, cancellationToken).ConfigureAwait(false);
        if (method is null || method.Method.UserId != request.UserId || method.Method.Status != IdentityRecordStatus.Active || method.Method.Kind != MfaKind.Totp)
            return Fail(IdentityErrorCodes.MfaInvalid, "The authenticator method is unavailable for this account or is not active.", 401);
        if (method.SecretEncrypted is null)
            return Fail(IdentityErrorCodes.SecretProtectionUnavailable);
        long? counter;
        try { counter = MatchTotpCounter(method.SecretEncrypted, request.MethodId.Value, request.Code, clock.UtcNow); }
        catch (Exception error) when (error is InvalidOperationException or CryptographicException)
        { return Fail(IdentityErrorCodes.SecretProtectionUnavailable); }
        if (counter is null)
            return Fail(IdentityErrorCodes.MfaInvalid, "The authenticator code is invalid or outside the accepted time window.", 401);
        var counterStartedAt = DateTimeOffset.FromUnixTimeSeconds(counter.Value * 30);
        if (await store.TouchMfaMethodAsync(request.MethodId.Value, counterStartedAt, cancellationToken).ConfigureAwait(false))
            return Ok();
        var current = await store.FindMfaMethodAsync(request.MethodId.Value, cancellationToken).ConfigureAwait(false);
        if (current?.Method.UserId == request.UserId && current.Method.Status == IdentityRecordStatus.Active
            && current.Method.LastUsedAt >= counterStartedAt)
            return Fail(IdentityErrorCodes.MfaCodeReused,
                "This authenticator code has already been used. Wait for the next code, then try again.", 401);
        return Fail(IdentityErrorCodes.MfaInvalid, "The authenticator method is no longer available for this account.", 401);
    }

    private long? MatchTotpCounter(byte[] encrypted, Guid methodId, string code, DateTimeOffset now)
    {
        if (code.Length != 6 || !code.All(char.IsAsciiDigit))
            return null;
        var secret = UnprotectSecret(encrypted, methodId);
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
    private static string? EnrollmentFailure(StoredMfaEnrollment? enrollment, DateTimeOffset now)
    {
        if (enrollment is null) return IdentityErrorCodes.MfaEnrollmentInvalid;
        if (enrollment.Method.Method.Status is not (IdentityRecordStatus.Pending or IdentityRecordStatus.Active))
            return IdentityErrorCodes.MfaEnrollmentInvalid;
        if (enrollment.Attempts >= enrollment.MaximumAttempts) return IdentityErrorCodes.MfaEnrollmentLocked;
        if (enrollment.ConsumedAt is not null)
            return enrollment.Method.Method.Status == IdentityRecordStatus.Active
                ? IdentityErrorCodes.MfaEnrollmentConsumed
                : enrollment.Attempts > 0 ? IdentityErrorCodes.MfaEnrollmentLocked : IdentityErrorCodes.MfaEnrollmentInvalid;
        if (enrollment.ExpiresAt <= now) return IdentityErrorCodes.MfaEnrollmentExpired;
        if (enrollment.Method.Method.Status != IdentityRecordStatus.Pending)
            return IdentityErrorCodes.MfaEnrollmentInvalid;
        if (enrollment.Method.SecretEncrypted is null) return IdentityErrorCodes.SecretProtectionUnavailable;
        return null;
    }
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
    private byte[] UnprotectSecret(byte[] encrypted, Guid methodId)
    {
        try
        {
            return protector.Unprotect(encrypted, Purpose(methodId));
        }
        catch (CryptographicException)
        {
            foreach (var previous in options.Value.PreviousMfaProtectionPurposes)
            {
                if (string.Equals(previous, options.Value.MfaProtectionPurpose, StringComparison.Ordinal)) continue;
                try { return protector.Unprotect(encrypted, $"{previous}:{methodId:N}"); }
                catch (CryptographicException) { /* Try only the explicitly configured previous contexts. */ }
            }
            throw;
        }
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
    private static IFeedback Fail(string code = IdentityErrorCodes.InvalidRequest, string? message = null, int? status = null) => new Feedback(false, message ?? FailureMessage(code))
    {
        Source = "Haley.Identity.Mfa",
        Key = code,
        Code = status ?? FailureStatus(code)
    };
    private static IFeedback<T> Fail<T>(string code = IdentityErrorCodes.InvalidRequest) => new Feedback<T>(false, FailureMessage(code), default!)
    {
        Source = "Haley.Identity.Mfa",
        Key = code,
        Code = FailureStatus(code)
    };
    private static int FailureStatus(string code) => code is IdentityErrorCodes.SecretProtectionUnavailable or IdentityErrorCodes.IdentityUnavailable ? 503 : 400;
    private static string FailureMessage(string code) => code switch
    {
        IdentityErrorCodes.SecretProtectionUnavailable => "The server cannot access the authenticator secret. Check the server's SecretProtection key configuration.",
        IdentityErrorCodes.IdentityUnavailable => "The identity service could not complete the MFA storage operation.",
        IdentityErrorCodes.MfaInvalid => "The MFA method or verification proof is invalid or no longer available.",
        IdentityErrorCodes.MfaEnrollmentInvalid => "This authenticator enrollment is invalid or was replaced. Start a new setup and scan its QR code.",
        IdentityErrorCodes.MfaEnrollmentExpired => "This authenticator enrollment has expired. Start a new setup and scan its QR code.",
        IdentityErrorCodes.MfaEnrollmentConsumed => "This authenticator enrollment has already been used. Reload your authenticator settings.",
        IdentityErrorCodes.MfaEnrollmentLocked => "This authenticator enrollment has reached its failed-attempt limit. Start a new setup and scan its QR code.",
        IdentityErrorCodes.MfaCodeInvalid => "The code did not match this authenticator. Use the current code from the latest QR setup and check that your device time is automatic.",
        IdentityErrorCodes.InvalidRequest => "The MFA request is invalid. Check its account, method and required fields.",
        _ => "The MFA operation could not be completed."
    };
}
