using Haley.Models;
using System.Text.Json;
using System.Text.Json.Serialization;
using Xunit;
namespace Haley.Identity.Tests;
public sealed class StatusWireContractTests
{
    [Fact]
    public void AccountStatusUsesNumericWireFormatEvenWhenTheHostUsesStringEnums()
    {
        var options = new JsonSerializerOptions(JsonSerializerDefaults.Web); options.Converters.Add(new JsonStringEnumConverter());
        using var json = JsonDocument.Parse(JsonSerializer.Serialize(new AccountStatusRequest(IdentityStatus.Active, "test"), options));
        Assert.Equal(2, json.RootElement.GetProperty("status").GetInt32());
        Assert.Throws<JsonException>(() => JsonSerializer.Deserialize<AccountStatusRequest>("{\"status\":\"Active\",\"reason\":\"test\"}", options));
    }
}
