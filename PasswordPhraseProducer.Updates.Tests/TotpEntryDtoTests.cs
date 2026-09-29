using System.Text.Json;
using Password_Phrase_Producer.Services.Security;
using Xunit;

namespace PasswordPhraseProducer.Updates.Tests;

public class TotpEntryDtoTests
{
    [Fact]
    public void LegacyBase64SecretRemainsWireCompatibleWithoutASecretStringProperty()
    {
        var options = new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };
        const string legacyJson = """{"secret":"AQIDBA==","algorithm":"Sha1","digits":6,"period":30}""";

        var dto = JsonSerializer.Deserialize<TotpEntryDto>(legacyJson, options)!;

        Assert.Equal(new byte[] { 1, 2, 3, 4 }, dto.Secret);
        Assert.Equal(dto.Secret, dto.ToModel().Secret);
        Assert.Equal("AQIDBA==", JsonDocument.Parse(JsonSerializer.Serialize(dto, options))
            .RootElement.GetProperty("secret").GetString());
    }
}
