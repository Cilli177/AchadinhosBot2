using AchadinhosBot.Next.Domain.Models;

namespace AchadinhosBot.Next.Tests;

public sealed class WhatsAppIncomingMessageTests
{
    [Fact]
    public void DomainContract_PreservesAllInboundMessageFields()
    {
        var message = new WhatsAppIncomingMessage("chat", "sender", "text", false, "instance", "message", true, "url", "base64", "image/png", "offer.png", "{}");

        Assert.Equal("chat", message.ChatId);
        Assert.Equal("sender", message.SenderId);
        Assert.True(message.HasMedia);
        Assert.Equal("image/png", message.MediaMimeType);
        Assert.Equal("{}", message.RawPayloadJson);
    }
}
