using AchadinhosBot.Next.Infrastructure.WhatsApp;

namespace AchadinhosBot.Next.Tests;

public sealed class InstagramWhatsAppCommandParserTests
{
    [Theory]
    [InlineData("/ig criar oferta", "create", "oferta")]
    [InlineData("ig turbo link", "create_fast", "link")]
    [InlineData("/ig imagens ultimo", "manage_images", "ultimo")]
    [InlineData("/ig publicar ultimo", "confirm", "ultimo")]
    [InlineData("/ig", "help", null)]
    [InlineData("/ig algo", "unknown", "algo")]
    public void TryParse_NormalizesSupportedCommand(string text, string action, string? argument)
    {
        Assert.True(InstagramWhatsAppCommandParser.TryParse(text, out var command));
        Assert.Equal(action, command.Action);
        Assert.Equal(argument, command.Argument);
    }

    [Theory]
    [InlineData("/leg 2 draft", 2, "draft")]
    [InlineData("\\leg 1", 1, "ultimo")]
    public void TryParseCaptionChoice_ParsesValidSelection(string text, int option, string draftRef)
    {
        Assert.True(InstagramWhatsAppCommandParser.TryParseCaptionChoice(text, out var command));
        Assert.Equal(option, command.OptionNumber);
        Assert.Equal(draftRef, command.DraftRef);
    }

    [Fact]
    public void Parsers_RejectUnrelatedOrInvalidInput()
    {
        Assert.False(InstagramWhatsAppCommandParser.TryParse("/help", out _));
        Assert.False(InstagramWhatsAppCommandParser.TryParseCaptionChoice("/leg zero", out _));
    }
}
