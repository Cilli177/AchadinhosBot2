using AchadinhosBot.Next.Infrastructure.WhatsApp;

namespace AchadinhosBot.Next.Tests;

public sealed class BotConversorWebhookPayloadExtractorTests
{
    [Fact]
    public void Extract_TextMessage_ExposesNormalizedMessageAndNoMembershipEvent()
    {
        const string payload = """{"data":{"key":{"remoteJid":"5511@s.whatsapp.net","id":"message-1"},"message":{"conversation":"oferta"}}}""";

        var result = BotConversorWebhookPayloadExtractor.Extract(payload);

        Assert.Equal("oferta", Assert.Single(result.Messages).Text);
        Assert.Empty(result.MembershipEvents);
    }

    [Fact]
    public void Extract_MembershipEvent_ExposesMembershipAndNoMessage()
    {
        const string payload = """{"event":"group-participants.update","data":{"id":"123@g.us","action":"add","participants":["5511@s.whatsapp.net"]}}""";

        var result = BotConversorWebhookPayloadExtractor.Extract(payload);

        var membership = Assert.Single(result.MembershipEvents);
        Assert.Equal("123@g.us", membership.GroupId);
        Assert.Equal("5511@s.whatsapp.net", membership.ParticipantId);
        Assert.Empty(result.Messages);
    }
}
