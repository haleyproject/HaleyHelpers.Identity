using Haley.Models;
using Haley.DAL;
using System.Text.Json;
using System.Text.Json.Nodes;
using Haley.Internal;
using static Haley.Internal.IdentityFields;
namespace Haley.Services;
public sealed partial class IdentityStore
{
    public async ValueTask<StoredIdentityProvider?> FindProviderAsync(string code, CancellationToken cancellationToken)
    {
        var row = await RowAsync(IdentityFederationQueries.FIND_PROVIDER, Load(cancellationToken), (CODE, code)).ConfigureAwait(false);
        return row is null ? null : await ToStoredProviderAsync(row, Load(cancellationToken)).ConfigureAwait(false);
    }

    public async ValueTask<IReadOnlyCollection<IdentityProviderInfo>> ListProvidersAsync(CancellationToken cancellationToken)
    {
        var load = Load(cancellationToken);
        var rows = await RowsAsync(IdentityFederationQueries.LIST_PROVIDERS, load).ConfigureAwait(false);
        var result = new List<IdentityProviderInfo>(rows.Count);
        foreach (var row in rows)
        {
            var provider = await ToStoredProviderAsync(row, load).ConfigureAwait(false);
            result.Add(new(provider.ProviderId, provider.Code, provider.Protocol, provider.Issuer, provider.DisplayName,
                provider.Status, provider.Configuration, provider.AuthoritativeDomains, provider.ModifiedAt,
                provider.SigningCertificates, provider.DiscoveryDomains));
        }
        return result;
    }

    public async ValueTask<IdentityProviderInfo?> UpsertProviderAsync(
        Guid providerId,
        UpsertIdentityProviderRequest request,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        using var transaction = CreateNewTransaction();
        var load = Load(cancellationToken, transaction);
        using (transaction.Begin())
        {
            try
            {
                var existing = await RowAsync(IdentityFederationQueries.FIND_PROVIDER_BY_UID, load,
                    (PROVIDER_UID, IdentityDatabase.ToBinary(providerId))).ConfigureAwait(false);
                var byCode = await RowAsync(IdentityFederationQueries.FIND_PROVIDER, load,
                    (CODE, request.Code)).ConfigureAwait(false);
                if (byCode is not null &&
                    (existing is null || Required<long>(byCode, "local_provider_id") != Required<long>(existing, "local_provider_id")))
                {
                    transaction.Rollback();
                    return null;
                }
                var localProviderId = existing is null
                    ? await ScalarAsync<long>(IdentityFederationQueries.INSERT_PROVIDER, load,
                        (PROVIDER_UID, IdentityDatabase.ToBinary(providerId)), 
                        (CODE, request.Code), (PROTOCOL, FormatProtocol(request.Protocol)), (ISSUER, request.Issuer),
                        (STATUS, (int?)(request.Status)), (CREATED_AT, now.UtcDateTime)).ConfigureAwait(false)
                    : Required<long>(existing, "local_provider_id");
                if (existing is not null)
                {
                    await ExecAsync(IdentityFederationQueries.UPDATE_PROVIDER, load,
                        (CODE, request.Code),
                        (PROTOCOL, FormatProtocol(request.Protocol)), (ISSUER, request.Issuer),
                        (STATUS, (int?)(request.Status)), (MODIFIED_AT, now.UtcDateTime), (PROVIDER_ID, localProviderId)).ConfigureAwait(false);
                }
                var config = JsonNode.Parse(request.Configuration) as JsonObject ?? new JsonObject();
                config["displayName"] = request.DisplayName;
                await ExecAsync(IdentityFederationQueries.UPSERT_PROVIDER_INFO, load,
                    (PROVIDER_ID, localProviderId), (CONFIG, config.ToJsonString())).ConfigureAwait(false);
                await ExecAsync(IdentityFederationQueries.DELETE_PROVIDER_DOMAINS, load, (PROVIDER_ID, localProviderId)).ConfigureAwait(false);
                foreach (var domain in (request.AuthoritativeDomains ?? []).Concat(request.DiscoveryDomains ?? []).Distinct(StringComparer.Ordinal))
                {
                    await ExecAsync(IdentityFederationQueries.INSERT_PROVIDER_DOMAIN, load,
                        (PROVIDER_ID, localProviderId), (DOMAIN, domain), (FLAGS, ((request.AuthoritativeDomains ?? []).Contains(domain) ? 1 : 0) | ((request.DiscoveryDomains ?? []).Contains(domain) ? 2 : 0)), (CREATED_AT, now.UtcDateTime)).ConfigureAwait(false);
                }
                transaction.Commit();
                return new(providerId, request.Code, request.Protocol, request.Issuer, request.DisplayName,
                    request.Status, config.ToJsonString(), request.AuthoritativeDomains ?? [], now,
                    request.SigningCertificates ?? [], request.DiscoveryDomains ?? []);
            }
            catch { transaction.Rollback(); throw; }
        }
    }

    public async ValueTask<FederatedIdentityLinkResult?> FindOrLinkFederatedIdentityAsync(
        LinkFederatedIdentityCommand command,
        CancellationToken cancellationToken)
    {
        using var transaction = CreateNewTransaction();
        var load = Load(cancellationToken, transaction);
        using (transaction.Begin())
        {
            try
            {
                var provider = await RowAsync(IdentityFederationQueries.FIND_PROVIDER_BY_UID, load,
                    (PROVIDER_UID, IdentityDatabase.ToBinary(command.ProviderId))).ConfigureAwait(false);
                if (provider is null || !((IdentityRecordStatus)Required<int>(provider, "status") == IdentityRecordStatus.Active))
                { transaction.Rollback(); return null; }

                var existingExternal = await RowAsync(IdentityFederationQueries.FIND_EXTERNAL_IDENTITY, load,
                    (PROVIDER_UID, IdentityDatabase.ToBinary(command.ProviderId)), (SUBJECT, command.Subject)).ConfigureAwait(false);
                if (existingExternal is not null)
                {
                    var localUserId = Required<long>(existingExternal, "local_user_id");
                    if (ToUser(existingExternal).Status != IdentityStatus.Active) { transaction.Rollback(); return new(localUserId, ToUser(existingExternal), false, false); }
                    await ExecAsync(IdentityFederationQueries.TOUCH_EXTERNAL_IDENTITY, load,
                        (CREATED_AT, command.AuthenticatedAt.UtcDateTime),
                        (PROVIDER_UID, IdentityDatabase.ToBinary(command.ProviderId)), (SUBJECT, command.Subject)).ConfigureAwait(false);
                    await ExecAsync(IdentityFederationQueries.TOUCH_EXTERNAL_USER, load,
                        (CREATED_AT, command.AuthenticatedAt.UtcDateTime), (USER_ID, localUserId)).ConfigureAwait(false);
                    transaction.Commit();
                    return new(localUserId, ToUser(existingExternal) with { LastAuthenticatedAt = command.AuthenticatedAt }, false, false);
                }

                Haley.Models.DbRow? emailUser = null;
                if (!string.IsNullOrWhiteSpace(command.EmailNormalized))
                {
                    emailUser = await RowAsync(IdentityFederationQueries.FIND_USER_BY_EMAIL, load,
                        (EMAIL, command.EmailNormalized)).ConfigureAwait(false);
                    if (emailUser is not null && (!command.AutoLink || ToUser(emailUser).Status != IdentityStatus.Active)) { transaction.Rollback(); return null; }
                }

                var created = false;
                long localId;
                UserIdentity identity;
                if (emailUser is not null)
                {
                    localId = Required<long>(emailUser, "local_user_id");
                    identity = ToUser(emailUser);
                }
                else
                {
                    if (!command.CreateUser) { transaction.Rollback(); return null; }
                    localId = await ScalarAsync<long?>(IdentityFederationQueries.INSERT_EXTERNAL_USER, load,
                        (UID, IdentityDatabase.ToBinary(command.UserId)), (USERNAME, null),
                        (DISPLAY_NAME, command.DisplayName), (CREATED_AT, command.AuthenticatedAt.UtcDateTime)).ConfigureAwait(false)
                        ?? throw new InvalidOperationException("Unable to create the federated account.");
                    if (!string.IsNullOrWhiteSpace(command.EmailNormalized))
                    {
                        if (await ExecAsync(IdentityFederationQueries.INSERT_EXTERNAL_EMAIL, load,
                            (CONTACT_UID, IdentityDatabase.ToBinary(_uuidGenerator.NewUuid7())), (USER_ID, localId),
                            (EMAIL, command.EmailNormalized), (DISPLAY_NAME, command.EmailDisplay),
                            (VERIFIED_AT, command.EmailVerified ? (DateTime?)command.AuthenticatedAt.UtcDateTime : null),
                            (CREATED_AT, command.AuthenticatedAt.UtcDateTime)).ConfigureAwait(false) != 1)
                        { transaction.Rollback(); return null; }
                    }
                    created = true;
                    identity = new(command.UserId, command.DisplayName, IdentityStatus.Active, null,
                        command.AuthenticatedAt, command.AuthenticatedAt, false);
                }

                var externalId = await ScalarAsync<long?>(IdentityFederationQueries.INSERT_EXTERNAL_IDENTITY, load,
                    (USER_ID, localId), (SUBJECT, command.Subject), (CREATED_AT, command.AuthenticatedAt.UtcDateTime),
                    (PROVIDER_UID, IdentityDatabase.ToBinary(command.ProviderId))).ConfigureAwait(false);
                if (externalId is null) { transaction.Rollback(); return null; }
                await ExecAsync(IdentityFederationQueries.INSERT_EXTERNAL_INFO, load,
                    (ID, externalId.Value), (CLAIMS, command.ClaimsPayload)).ConfigureAwait(false);
                await ExecAsync(IdentityFederationQueries.TOUCH_EXTERNAL_USER, load,
                    (CREATED_AT, command.AuthenticatedAt.UtcDateTime), (USER_ID, localId)).ConfigureAwait(false);
                transaction.Commit();
                return new(localId, identity with { LastAuthenticatedAt = command.AuthenticatedAt }, created, true);
            }
            catch { transaction.Rollback(); throw; }
        }
    }

    public async ValueTask<bool> CreateFederationAttemptAsync(
        CreateFederationAttemptCommand command,
        CancellationToken cancellationToken) =>
        await ExecAsync(IdentityFederationQueries.INSERT_FEDERATION_ATTEMPT, Load(cancellationToken),
            (REQUEST_UID, IdentityDatabase.ToBinary(command.RequestId)), (PROVIDER_ID, command.LocalProviderId),
            (APPLICATION_UID, IdentityDatabase.ToBinary(command.ApplicationId)), (AUDIENCE, command.Context),
            (REQUEST_ID, command.ProtocolRequestId), (RETURN_URI, command.ReturnUri),
            (STATE, command.State), (CODE_CHALLENGE, command.CodeChallenge),
            (CREATED_AT, command.CreatedAt.UtcDateTime), (EXPIRES_AT, command.ExpiresAt.UtcDateTime)).ConfigureAwait(false) == 1;

    public async ValueTask<StoredFederationAttempt?> FindFederationAttemptAsync(
        Guid requestId,
        DateTimeOffset evaluatedAt,
        CancellationToken cancellationToken)
    {
        var row = await RowAsync(IdentityFederationQueries.FIND_FEDERATION_ATTEMPT, Load(cancellationToken),
            (REQUEST_UID, IdentityDatabase.ToBinary(requestId)), (CREATED_AT, evaluatedAt.UtcDateTime)).ConfigureAwait(false);
        return row is null ? null : new(
            Required<long>(row, "local_request_id"), ToGuid(row, "request_uid"), Required<long>(row, "provider_id"),
            ToGuid(row, "provider_uid"), Required<string>(row, "provider_code"), Required<string>(row, "provider_issuer"),
            Required<string>(row, "provider_config"), ToGuid(row, "application_uid"), Required<string>(row, "context"),
            Required<string>(row, "request_id"), Required<string>(row, "return_uri"), Required<string>(row, "state"),
            Required<byte[]>(row, "code_challenge"),
            AsUtc(Required<DateTime>(row, "expires_at")), ParseProtocol(Required<string>(row, "provider_protocol")));
    }

    public async ValueTask<bool> TryConsumeFederationReplayAsync(
        long localProviderId,
        byte[] responseHash,
        byte[] assertionHash,
        DateTimeOffset expiresAt,
        DateTimeOffset createdAt,
        CancellationToken cancellationToken) =>
        await ExecAsync(IdentityFederationQueries.INSERT_FEDERATION_REPLAY, Load(cancellationToken),
            (PROVIDER_ID, localProviderId), (ASSERTION_HASH, assertionHash), (RESPONSE_HASH, responseHash),
            (EXPIRES_AT, expiresAt.UtcDateTime), (CREATED_AT, createdAt.UtcDateTime)).ConfigureAwait(false) == 1;

    public async ValueTask<bool> CompleteFederationAttemptAsync(
        CompleteFederationAttemptCommand command,
        CancellationToken cancellationToken)
    {
        using var transaction = CreateNewTransaction();
        var load = Load(cancellationToken, transaction);
        using (transaction.Begin())
        {
            try
            {
                if (await ExecAsync(IdentityFederationQueries.CONSUME_FEDERATION_ATTEMPT, load,
                        (MODIFIED_AT, command.CompletedAt.UtcDateTime), (AUTH_REQ_ID, command.LocalRequestId)).ConfigureAwait(false) != 1)
                { transaction.Rollback(); return false; }
                if (await ExecAsync(IdentityFederationQueries.INSERT_FEDERATION_HANDOFF, load,
                        (HANDOFF_UID, IdentityDatabase.ToBinary(command.HandoffId)), (CODE_HASH, command.CodeHash),
                        (PAYLOAD_ENC, command.PayloadEncrypted), (CREATED_AT, command.CompletedAt.UtcDateTime),
                        (EXPIRES_AT, command.ExpiresAt.UtcDateTime), (AUTH_REQ_ID, command.LocalRequestId)).ConfigureAwait(false) != 1)
                { transaction.Rollback(); return false; }
                transaction.Commit();
                return true;
            }
            catch { transaction.Rollback(); throw; }
        }
    }

    public async ValueTask<StoredFederationHandoff?> FindFederationHandoffAsync(Guid applicationId,
        byte[] codeHash, byte[] codeChallenge, DateTimeOffset now, CancellationToken cancellationToken)
    {
        var row = await RowAsync(IdentityFederationQueries.FIND_HANDOFF_FOR_INSPECTION, Load(cancellationToken),
            (APPLICATION_UID, IdentityDatabase.ToBinary(applicationId)), (CODE_HASH, codeHash),
            (CODE_CHALLENGE, codeChallenge), (MODIFIED_AT, now.UtcDateTime)).ConfigureAwait(false);
        return row is null ? null : new(ToGuid(row, "handoff_uid"), ToGuid(row, "application_uid"), Required<string>(row, "context"),
            Required<byte[]>(row, "payload_enc"), Required<byte[]>(row, "code_challenge"), AsUtc(Required<DateTime>(row, "expires_at")));
    }

    public async ValueTask<StoredFederationHandoff?> ConsumeFederationHandoffAsync(
        Guid clientId,
        byte[] codeHash,
        byte[] codeChallenge,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        using var transaction = CreateNewTransaction();
        var load = Load(cancellationToken, transaction);
        using (transaction.Begin())
        {
            try
            {
                var row = await RowAsync(IdentityFederationQueries.FIND_FEDERATION_HANDOFF, load,
                    (APPLICATION_UID, IdentityDatabase.ToBinary(clientId)), (CODE_HASH, codeHash),
                    (CODE_CHALLENGE, codeChallenge),
                    (MODIFIED_AT, now.UtcDateTime)).ConfigureAwait(false);
                if (row is null) { transaction.Rollback(); return null; }
                var localId = Required<long>(row, "local_handoff_id");
                if (await ExecAsync(IdentityFederationQueries.CONSUME_FEDERATION_HANDOFF, load,
                        (MODIFIED_AT, now.UtcDateTime), (ID, localId)).ConfigureAwait(false) != 1)
                { transaction.Rollback(); return null; }
                transaction.Commit();
                return new(ToGuid(row, "handoff_uid"), ToGuid(row, "application_uid"), Required<string>(row, "context"),
                    Required<byte[]>(row, "payload_enc"), Required<byte[]>(row, "code_challenge"),
                    AsUtc(Required<DateTime>(row, "expires_at")));
            }
            catch { transaction.Rollback(); throw; }
        }
    }

    private async ValueTask<StoredIdentityProvider> ToStoredProviderAsync(Haley.Models.DbRow row, Haley.Models.DbExecutionLoad load)
    {
        var localId = Required<long>(row, "local_provider_id");
        var domains = await RowsAsync(IdentityFederationQueries.LIST_PROVIDER_DOMAINS, load, (PROVIDER_ID, localId)).ConfigureAwait(false);
        return new(localId, ToGuid(row, "provider_uid"), Required<string>(row, "code"),
            ParseProtocol(Required<string>(row, "protocol")), Required<string>(row, "issuer"), Required<string>(row, "display_name"),
            (IdentityRecordStatus)Required<int>(row, "status"), Required<string>(row, "config"),
            domains.Where(item => (Required<int>(item, "flags") & 1) != 0).Select(item => Required<string>(item, "domain")).ToArray(), AsUtc(Required<DateTime>(row, "modified_at")),
            ParseCertificateNames(Required<string>(row, "config")),
            domains.Where(item => (Required<int>(item, "flags") & 2) != 0).Select(item => Required<string>(item, "domain")).ToArray());
    }

    private static IReadOnlyCollection<string> ParseCertificateNames(string configuration)
    {
        using var document = JsonDocument.Parse(configuration);
        return document.RootElement.TryGetProperty("signingCertificates", out var values) &&
               values.ValueKind == JsonValueKind.Array
            ? values.EnumerateArray()
                .Where(value => value.ValueKind == JsonValueKind.String)
                .Select(value => value.GetString() ?? string.Empty)
                .Where(value => value.Length > 0)
                .ToArray()
            : [];
    }


    private static string FormatProtocol(FederationProtocol protocol) => protocol.ToString().ToLowerInvariant();
    private static FederationProtocol ParseProtocol(string protocol) => protocol switch { "saml" => FederationProtocol.Saml, "oidc" => FederationProtocol.Oidc, "signedcallback" => FederationProtocol.SignedCallback, _ => throw new InvalidDataException($"Unknown federation protocol '{protocol}'.") };


}
