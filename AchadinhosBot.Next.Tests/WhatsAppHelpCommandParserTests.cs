using AchadinhosBot.Next.Infrastructure.WhatsApp;

namespace AchadinhosBot.Next.Tests;

public sealed class WhatsAppHelpCommandParserTests
{
    [Theory]
    [InlineData("/help", "general")]
    [InlineData("\\help 1", "instagram")]
    [InlineData("/ajuda comentarios", "cta")]
    [InlineData("/help bio", "links")]
    [InlineData("/help anuncios", "ads")]
    [InlineData("/help rapido", "quick")]
    [InlineData("/help desconhecido", "general")]
    public void TryParse_RecognizedHelpSyntax_NormalizesScope(string text, string expectedScope)
    {
        var parsed = WhatsAppHelpCommandParser.TryParse(text, out var scope);

        Assert.True(parsed);
        Assert.Equal(expectedScope, scope);
    }

    [Fact]
    public void TryParse_NonHelpText_ReturnsFalse()
    {
        Assert.False(WhatsAppHelpCommandParser.TryParse("/ig criar oferta", out var scope));
        Assert.Equal("general", scope);
    }
}
