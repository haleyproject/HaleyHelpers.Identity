using System.Text.Json;
using Haley.Abstractions;
using Haley.Models;
using Haley.Services;
using Xunit;

namespace Haley.Tests.Security;

public sealed class ApplicationMfaRequirementTests {
    [Fact]
    public async Task AnExplicitOptOutDoesNotRequireOrConsumeAnEnrolledFactor() {
        var userId = Guid.NewGuid();
        var mfa = new EnrolledMfaService(userId);
        var result = await Policy(mfa).VerifyAsync(
            new(userId, "user@example.test", Guid.NewGuid(), "learndesk", null, null, null, RequireMfa: false), CancellationToken.None);
        Assert.True(result.Status);
        Assert.Empty(result.Result);
        Assert.Equal(0, mfa.ListCalls);
    }

    [Fact]
    public async Task ExistingApplicationsKeepTheirEnrolledFactorRequirementByDefault() {
        var userId = Guid.NewGuid();
        var mfa = new EnrolledMfaService(userId);
        var result = await Policy(mfa).VerifyAsync(
            new(userId, "user@example.test", Guid.NewGuid(), "other.application", null, null, null), CancellationToken.None);
        Assert.False(result.Status);
        Assert.Equal("mfa_required", result.Key);
        Assert.Equal(1, mfa.ListCalls);
    }

    [Fact]
    public void OlderPasswordRequestJsonRetainsTheDefaultRequirement() {
        var result = JsonSerializer.Deserialize<PasswordAuthenticationRequest>(
            """{"username":"user@example.test","password":"test-password"}""", new JsonSerializerOptions(JsonSerializerDefaults.Web));
        Assert.True(result!.RequireMfa);
    }

    [Fact]
    public void ExplicitPasswordOptOutSurvivesTransportSerialization() {
        var options = new JsonSerializerOptions(JsonSerializerDefaults.Web);
        var request = new PasswordAuthenticationRequest("user@example.test", "test-password", RequireMfa: false);
        var copy = JsonSerializer.Deserialize<PasswordAuthenticationRequest>(JsonSerializer.Serialize(request, options), options);
        Assert.False(copy!.RequireMfa);
    }

    private static IIdentityVerificationMfaPolicy Policy(IMfaService mfa) {
        var implementation = typeof(IdentityService).Assembly.GetType("Haley.Services.IdentityVerificationMfaPolicy", throwOnError: true)!;
        return (IIdentityVerificationMfaPolicy)Activator.CreateInstance(implementation, mfa)!;
    }

    private sealed class EnrolledMfaService(Guid userId) : IMfaService {
        public int ListCalls { get; private set; }
        public ValueTask<IReadOnlyCollection<MfaMethodInfo>> ListMethodsAsync(Guid id, CancellationToken ct = default) {
            Assert.Equal(userId, id);
            ListCalls++;
            IReadOnlyCollection<MfaMethodInfo> methods = [new(Guid.NewGuid(), userId, MfaKind.Totp, "Authenticator", IdentityRecordStatus.Active, DateTimeOffset.UtcNow, DateTimeOffset.UtcNow, null)];
            return ValueTask.FromResult(methods);
        }
        public ValueTask<IFeedback<TotpEnrollmentReceipt>> BeginTotpEnrollmentAsync(BeginTotpEnrollmentRequest request, CancellationToken ct = default) => throw new NotSupportedException();
        public ValueTask<IFeedback<TotpEnrollmentDetails>> InspectTotpEnrollmentAsync(string ticket, CancellationToken ct = default) => throw new NotSupportedException();
        public ValueTask<IFeedback<TotpEnrollmentCompletion>> ConfirmTotpEnrollmentAsync(ConfirmTotpTicketRequest request, CancellationToken ct = default) => throw new NotSupportedException();
        public ValueTask<IFeedback> RetireMethodAsync(Guid id, Guid methodId, CancellationToken ct = default) => throw new NotSupportedException();
        public ValueTask<IFeedback<int>> PruneUnusedMethodsAsync(Guid id, CancellationToken ct = default) => throw new NotSupportedException();
        public ValueTask<IFeedback<RecoveryCodesReceipt>> ReplaceRecoveryCodesAsync(ReplaceRecoveryCodesRequest request, CancellationToken ct = default) => throw new NotSupportedException();
        public ValueTask<IFeedback> VerifyAsync(VerifyMfaRequest request, CancellationToken ct = default) => throw new NotSupportedException();
    }
}

