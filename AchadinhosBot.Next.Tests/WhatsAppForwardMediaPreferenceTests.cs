using AchadinhosBot.Next.Application.Services;
using Xunit;

namespace AchadinhosBot.Next.Tests;

public class WhatsAppForwardMediaPreferenceTests
{
    [Theory]
    [InlineData(false, true, true)]
    [InlineData(true, true, false)]
    [InlineData(false, false, false)]
    public void ShouldPreferLinkPreviewWithoutMedia_ShouldOnlyPreferTextWhenNoMediaCandidate(
        bool hasMediaCandidate,
        bool preferLinkPreviewWhenNoMedia,
        bool expected)
    {
        var actual = WhatsAppForwardMediaHelper.ShouldPreferLinkPreviewWithoutMedia(
            hasMediaCandidate,
            preferLinkPreviewWhenNoMedia);

        Assert.Equal(expected, actual);
    }

    [Fact]
    public void BuildOutboundMediaMessage_ShouldPromoteFallbackImageWhenOriginalHasNoMedia()
    {
        var original = new TestMessage(false, null, null, null, null, "{\"key\":\"value\"}");

        var promoted = WhatsAppForwardMediaHelper.BuildOutboundMediaMessage(
            original,
            "https://cdn.exemplo.com/oferta.jpg",
            static message => message.HasMedia,
            static (message, fallbackImageUrl) => message with
            {
                HasMedia = true,
                MediaUrl = fallbackImageUrl,
                MediaBase64 = null,
                MediaMimeType = "image/jpeg",
                MediaFileName = "offer.jpg",
                RawPayloadJson = null
            });

        Assert.True(promoted.HasMedia);
        Assert.Equal("https://cdn.exemplo.com/oferta.jpg", promoted.MediaUrl);
        Assert.Equal("image/jpeg", promoted.MediaMimeType);
        Assert.Equal("offer.jpg", promoted.MediaFileName);
        Assert.Null(promoted.RawPayloadJson);
    }

    private sealed record TestMessage(
        bool HasMedia,
        string? MediaUrl,
        string? MediaBase64,
        string? MediaMimeType,
        string? MediaFileName,
        string? RawPayloadJson);
}
