using Haley.Models;
using System.Text.Json;
using System.Text.Json.Serialization;
using Xunit;
namespace Haley.Identity.Tests;
public sealed class StatusWireContractTests
{
    [Fact]
    public void VerificationContractsKeepNumericValuesUnderTheHostsStringEnumConfiguration()
    {
        var options = new JsonSerializerOptions(JsonSerializerDefaults.Web); options.Converters.Add(new JsonStringEnumConverter());
        var delivery = new IdentityVerificationDelivery(Guid.NewGuid(), VerificationPurpose.EmailVerification,
            VerificationProofKind.NumericCode, "recipient@example.test", "123456", DateTimeOffset.UtcNow, DateTimeOffset.UtcNow);
        using var json = JsonDocument.Parse(JsonSerializer.Serialize(delivery, options));
        Assert.Equal(1, json.RootElement.GetProperty("purpose").GetInt32());
        Assert.Equal(2, json.RootElement.GetProperty("proofKind").GetInt32());
        using var completed = JsonDocument.Parse(JsonSerializer.Serialize(new IdentityVerificationCompletion(Guid.NewGuid(),
            VerificationPurpose.Onboarding, true, IdentityStatus.Active), options));
        Assert.Equal(2, completed.RootElement.GetProperty("purpose").GetInt32());
        Assert.Equal(2, completed.RootElement.GetProperty("accountStatus").GetInt32());
    }

    [Theory]
    [InlineData(IdentityRecordStatus.Active, 2)]
    [InlineData(IdentityRecordStatus.Revoked, 64)]
    public void ApplicationStatusUsesNumericWireFormatEvenWhenTheHostUsesStringEnums(IdentityRecordStatus status, int expected)
    {
        var options = new JsonSerializerOptions(JsonSerializerDefaults.Web);
        options.Converters.Add(new JsonStringEnumConverter());
        var application = new RegisteredIdentityApplication(Guid.NewGuid(), "Test application", status, []);
        using var json = JsonDocument.Parse(JsonSerializer.Serialize(application, options));
        Assert.Equal(JsonValueKind.Number, json.RootElement.GetProperty("status").ValueKind);
        Assert.Equal(expected, json.RootElement.GetProperty("status").GetInt32());
    }

    [Fact]
    public void AccountStatusUsesNumericWireFormatEvenWhenTheHostUsesStringEnums()
    {
        var options = new JsonSerializerOptions(JsonSerializerDefaults.Web); options.Converters.Add(new JsonStringEnumConverter());
        using var json = JsonDocument.Parse(JsonSerializer.Serialize(new AccountStatusRequest(IdentityStatus.Active, "test"), options));
        Assert.Equal(2, json.RootElement.GetProperty("status").GetInt32());
        Assert.Throws<JsonException>(() => JsonSerializer.Deserialize<AccountStatusRequest>("{\"status\":\"Active\",\"reason\":\"test\"}", options));
    }
}
