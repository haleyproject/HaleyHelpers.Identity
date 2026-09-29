namespace Haley.Services;

public static class LocalAccountRegistration
{
    public static async ValueTask<IFeedback<UserIdentity>> CreateAsync(
        CreateLocalUserRequest request,
        IPasswordHasher passwordHasher, IIdentityUuidGenerator uuidGenerator, IIdentityClock clock,
        Func<CreateLocalUserCommand, CancellationToken, ValueTask<bool>> persist, CancellationToken cancellationToken = default)
    {
        string username;
        string displayName;
        try
        {
            username = global::Haley.Utils.IdentityPolicy.NormalizeUsername(request.Username);
            displayName = global::Haley.Utils.IdentityPolicy.NormalizeDisplayName(request.DisplayName);
            global::Haley.Utils.IdentityPolicy.ValidateNewPassword(request.Password);
        }
        catch (ArgumentException)
        {
            return new Feedback<UserIdentity>(false, "The account request was rejected.") { Key = IdentityErrorCodes.InvalidRequest, Code = 400 };
        }

        var createdAt = clock.UtcNow;
        var userId = uuidGenerator.NewUuid7();
        var passwordHash = passwordHasher.Hash(request.Password);
        var status = request.ActivateImmediately ? IdentityStatus.Active : IdentityStatus.Pending;
        var emailContactId = global::Haley.Utils.IdentityPolicy.TryNormalizeEmail(username, out _)
            ? uuidGenerator.NewUuid7()
            : (Guid?)null;
        var created = await persist(
            new(
                userId,
                uuidGenerator.NewUuid7(),
                username,
                displayName,
                status,
                passwordHash.Value,
                passwordHash.Algorithm,
                passwordHash.ParametersPayload,
                request.RequirePasswordChange,
                createdAt,
                emailContactId),
            cancellationToken).ConfigureAwait(false);
        if (!created)
        {
            return new Feedback<UserIdentity>(false, "The account already exists.") { Key = IdentityErrorCodes.DuplicateIdentity, Code = 409 };
        }

        return new Feedback<UserIdentity>(true, "Account created.", new UserIdentity(
            userId,
            displayName,
            status,
            username,
            createdAt,
            null,
            request.RequirePasswordChange));
    }

}
