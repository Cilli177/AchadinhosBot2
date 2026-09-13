using AchadinhosBot.Next.Infrastructure.WhatsApp;

namespace AchadinhosBot.Next.Tests;

public sealed class EvolutionIncomingMessageExtractorTests
{
    [Fact]
    public void Extract_SingleTextMessage_MapsMessageIdentityAndText()
    {
        const string payload = """{"instance":"zap","data":{"key":{"remoteJid":"120@g.us","participant":"5511@s.whatsapp.net","id":"abc","fromMe":false},"message":{"conversation":"oferta https://exemplo.test"}}}""";

        var message = Assert.Single(EvolutionIncomingMessageExtractor.Extract(payload));

        Assert.Equal("zap", message.InstanceName);
        Assert.Equal("120@g.us", message.ChatId);
        Assert.Equal("5511@s.whatsapp.net", message.SenderId);
        Assert.Equal("abc", message.MessageId);
        Assert.Equal("oferta https://exemplo.test", message.Text);
        Assert.False(message.HasMedia);
    }

    [Fact]
    public void Extract_ViewOnceImageWithDataUrl_MapsCaptionAndDecodedMediaFields()
    {
        const string payload = """{"data":{"key":{"remoteJid":"5511@s.whatsapp.net","id":"media"},"message":{"viewOnceMessageV2":{"message":{"imageMessage":{"caption":"veja essa oferta","url":"data:image/png;base64,aGVsbG8="}}}}}}""";

        var message = Assert.Single(EvolutionIncomingMessageExtractor.Extract(payload));

        Assert.Equal("veja essa oferta", message.Text);
        Assert.True(message.HasMedia);
        Assert.Null(message.MediaUrl);
        Assert.Equal("aGVsbG8=", message.MediaBase64);
        Assert.Equal("image/png", message.MediaMimeType);
    }

    [Fact]
    public void Extract_ArrayAndMalformedPayload_ReturnsSupportedMessagesOrEmptyList()
    {
        const string payload = """{"instance":"zap","data":[{"key":{"remoteJid":"1@s.whatsapp.net","id":"a"},"message":{"conversation":"a"}},{"key":{"remoteJid":"2@s.whatsapp.net","id":"b"},"message":{"extendedTextMessage":{"text":"b"}}}]}""";

        var messages = EvolutionIncomingMessageExtractor.Extract(payload);

        Assert.Equal(new[] { "a", "b" }, messages.Select(message => message.Text));
        Assert.Empty(EvolutionIncomingMessageExtractor.Extract("not-json"));
    }
}
