using AchadinhosBot.Next.Infrastructure.WhatsApp;

namespace AchadinhosBot.Next.Tests;

public sealed class WhatsAppHelpCatalogTests
{
    [Theory]
    [InlineData("instagram", "GUIA /ig")]
    [InlineData("cta", "HELP 2")]
    [InlineData("links", "HELP 3")]
    [InlineData("ads", "HELP 4")]
    [InlineData("quick", "HELP 5")]
    [InlineData("unknown", "HELP - Menu Principal")]
    public void ForScope_ReturnsExpectedHelpSection(string scope, string expectedHeading)
    {
        Assert.StartsWith(expectedHeading, WhatsAppHelpCatalog.ForScope(scope));
    }

    [Fact]
    public void InstagramMenu_PreservesNumberedSelectionContract()
    {
        var menu = WhatsAppHelpCatalog.InstagramMenu();

        Assert.Contains("1) Revisar ultimo rascunho", menu);
        Assert.Contains("8) Ver ajuda do Instagram", menu);
    }
}
