namespace Haley.Services;

internal sealed class IdentityVerificationMfaPolicy(IMfaService mfa) : IIdentityVerificationMfaPolicy
{
    public async ValueTask<IFeedback<IReadOnlyCollection<string>>> VerifyAsync(VerificationMfaRequest request, CancellationToken cancellationToken)
    {
        var methods = (await mfa.ListMethodsAsync(request.UserId, cancellationToken).ConfigureAwait(false))
            .Where(method => method.Status == IdentityRecordStatus.Active && method.Kind is MfaKind.Totp or MfaKind.RecoveryCode).ToArray();
        if (methods.Length == 0) return new Feedback<IReadOnlyCollection<string>>(true, "No enrolled second factor.", []);
        if (request.Kind is not (MfaKind.Totp or MfaKind.RecoveryCode) || string.IsNullOrWhiteSpace(request.Code)) return Fail("mfa_required");
        var candidates = request.Kind == MfaKind.Totp && request.MethodId is null
            ? methods.Where(method => method.Kind == MfaKind.Totp).Select(method => (Guid?)method.MethodId).ToArray()
            : new Guid?[] { request.MethodId };
        foreach (var methodId in candidates)
        {
            var verified = await mfa.VerifyAsync(new(request.UserId, methodId, request.Kind.Value, request.Code), cancellationToken).ConfigureAwait(false);
            if (verified.Status) return new Feedback<IReadOnlyCollection<string>>(true, "Second factor verified.",
                [request.Kind == MfaKind.Totp ? "totp" : "recovery"]);
        }
        return Fail("mfa_invalid");
    }
    private static IFeedback<IReadOnlyCollection<string>> Fail(string key) =>
        new Feedback<IReadOnlyCollection<string>>(false, key == "mfa_required" ? "This account requires a second factor." : "The second factor was rejected.")
        { Key = key, Code = 401, Source = "Haley.Identity" };
}
