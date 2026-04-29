using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Application.Services;

namespace AchadinhosBot.Next.Tests;

public class TelegramReelDraftSelectionHelperTests
{
    [Fact]
    public void SelectLatestEligibleOffer_ReturnsLatestVideoWithLink()
    {
        var offers = new[]
        {
            new TelegramUserbotOfferMessage(2425105459, "AE-IA 3000 - VÃDEOS VIRAIS", "1", DateTimeOffset.UtcNow.AddMinutes(-3), "Texto sem link", "video", "https://example.com/video-1"),
            new TelegramUserbotOfferMessage(2425105459, "AE-IA 3000 - VÃDEOS VIRAIS", "2", DateTimeOffset.UtcNow.AddMinutes(-2), "Nicho: Cozinha https://s.shopee.com.br/abc", "image", "https://example.com/image-1"),
            new TelegramUserbotOfferMessage(2425105459, "AE-IA 3000 - VÃDEOS VIRAIS", "3", DateTimeOffset.UtcNow.AddMinutes(-1), "Nicho: Cozinha https://s.shopee.com.br/16dX6wzWu", "video", "https://example.com/video-2")
        };

        var selected = TelegramReelDraftSelectionHelper.SelectLatestEligibleOffer(offers);

        Assert.NotNull(selected);
        Assert.Equal("3", selected!.MessageId);
        Assert.Equal("video", selected.MediaKind);
        Assert.Equal("https://example.com/video-2", selected.MediaUrl);
    }

    [Fact]
    public void SelectLatestEligibleOffer_IgnoresVideoWithoutLink()
    {
        var offers = new[]
        {
            new TelegramUserbotOfferMessage(2425105459, "AE-IA 3000 - VÃDEOS VIRAIS", "1", DateTimeOffset.UtcNow.AddMinutes(-1), "Nicho: Cozinha", "video", "https://example.com/video-1")
        };

        var selected = TelegramReelDraftSelectionHelper.SelectLatestEligibleOffer(offers);

        Assert.Null(selected);
    }

    [Fact]
    public void SelectLatestEligibleOffer_SkipsCupomRadarPromoMessage()
    {
        var offers = new[]
        {
            new TelegramUserbotOfferMessage(
                2425105459,
                "AE-IA 3000 - VÃDEOS VIRAIS",
                "99",
                DateTimeOffset.UtcNow.AddMinutes(-1),
                "O Cupom Radar é o Aplicativo dos Top Afiliados! https://cupomradaroficial.com/",
                "video",
                "https://example.com/promo-video"),
            new TelegramUserbotOfferMessage(
                2425105459,
                "AE-IA 3000 - VÃDEOS VIRAIS",
                "100",
                DateTimeOffset.UtcNow.AddMinutes(-2),
                "Nicho: Cozinha https://s.shopee.com.br/abc",
                "video",
                "https://example.com/video-2")
        };

        var selected = TelegramReelDraftSelectionHelper.SelectLatestEligibleOffer(offers);

        Assert.NotNull(selected);
        Assert.Equal("100", selected!.MessageId);
        Assert.Equal("https://example.com/video-2", selected.MediaUrl);
    }

    [Fact]
    public void TryGetBlockedReason_DetectsCupomRadarPromo()
    {
        var message = """
                     Automatize 100% dos seus grupos de WhatsApp e Telegram.
                     E agora também disponível o Modo Fila para (Shopee), selecione os nichos,
                     e o cupom radar converte e envia automaticamente em seus grupos.
                     Utilize até 10 postagens por dia gratuitamente, faça seu cadastro agora mesmo.
                     https://cupomradaroficial.com/
                     """;

        var blocked = TelegramReelDraftSelectionHelper.TryGetBlockedReason(message, out var reason);

        Assert.True(blocked);
        Assert.Equal("manual_blocked_cupom_radar", reason);
    }
}
