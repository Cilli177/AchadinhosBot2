using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Infrastructure.WhatsApp;

namespace AchadinhosBot.Next.Tests;

public sealed class WhatsAppWebhookIdempotencyTests
{
    [Fact]
    public void MessageId_UsesSixHourMessageKey()
    {
        var store = new Store();
        Assert.True(WhatsAppWebhookIdempotency.TryBegin(store, "instance", "chat", "sender", "message", false, null, "text"));
        Assert.Equal("wa-msg:instance:chat:message", store.Key);
        Assert.Equal(TimeSpan.FromHours(6), store.Ttl);
    }

    [Fact]
    public void MissingMessageId_UsesStableFallbackKey()
    {
        var store = new Store();
        Assert.True(WhatsAppWebhookIdempotency.TryBegin(store, null, "chat", null, null, true, "{\"same\":true}", "ignored"));
        Assert.StartsWith("wa-msg-fallback:default:chat:unknown:True:", store.Key);
        Assert.Equal(TimeSpan.FromSeconds(45), store.Ttl);
    }

    private sealed class Store : IIdempotencyStore
    {
        internal string Key { get; private set; } = string.Empty;
        internal TimeSpan Ttl { get; private set; }
        public bool TryBegin(string key, TimeSpan ttl) { Key = key; Ttl = ttl; return true; }
        public void RemoveByPrefix(string prefix) { }
    }
}
