using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Application.Consumers;
using AchadinhosBot.Next.Configuration;
using AchadinhosBot.Next.Infrastructure.Idempotency;
using AchadinhosBot.Next.Infrastructure.Resilience;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace AchadinhosBot.Next.Tests;

public sealed class AsyncMessagingFoundationTests
{
    [Fact]
    public void FileIdempotencyStore_PersistsKeysAcrossRestart()
    {
        var dir = CreateTempDir();
        try
        {
            var options = Options.Create(new MessagingOptions { DataDirectory = dir });
            var store = new FileIdempotencyStore(options, NullLogger<FileIdempotencyStore>.Instance);

            var first = store.TryBegin("wa-msg:test-1", TimeSpan.FromMinutes(5));

            var restarted = new FileIdempotencyStore(options, NullLogger<FileIdempotencyStore>.Instance);
            var second = restarted.TryBegin("wa-msg:test-1", TimeSpan.FromMinutes(5));

            Assert.True(first);
            Assert.False(second);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public async Task Orchestrator_PersistsToLocalOutbox_WhenPublishFails()
    {
        var dir = CreateTempDir();
        try
        {
            var options = Options.Create(new MessagingOptions { DataDirectory = dir });
            var outbox = new FileBotConversorOutboxStore(options, NullLogger<FileBotConversorOutboxStore>.Instance);
            var publisher = new ThrowingPublisher();
            var orchestrator = new BotConversorMessageOrchestrator(
                publisher,
                outbox,
                NullLogger<BotConversorMessageOrchestrator>.Instance);

            var result = await orchestrator.EnqueueBotConversorAsync(
                "{\"event\":\"messages.upsert\"}",
                new Dictionary<string, string> { ["x-api-key"] = "test" },
                CancellationToken.None);

            var pending = await outbox.ListPendingAsync(CancellationToken.None);

            Assert.True(result.Accepted);
            Assert.True(result.PersistedLocally);
            Assert.Equal("local-outbox", result.Mode);
            Assert.Single(pending);
            Assert.Equal(result.MessageId, pending[0].MessageId);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public async Task FileBotConversorOutboxStore_SaveAndDelete_RoundTripsMessage()
    {
        var dir = CreateTempDir();
        try
        {
            var options = Options.Create(new MessagingOptions { DataDirectory = dir });
            var store = new FileBotConversorOutboxStore(options, NullLogger<FileBotConversorOutboxStore>.Instance);
            var command = new ProcessBotConversorWebhookCommand
            {
                MessageId = Guid.NewGuid().ToString("N"),
                Body = "{\"body\":true}",
                Headers = new Dictionary<string, string> { ["x-source"] = "test" },
                Source = "test-suite"
            };

            await store.SaveAsync(command, CancellationToken.None);
            var pending = await store.ListPendingAsync(CancellationToken.None);
            await store.DeleteAsync(command.MessageId, CancellationToken.None);
            var afterDelete = await store.ListPendingAsync(CancellationToken.None);

            Assert.Single(pending);
            Assert.Equal(command.MessageId, pending[0].MessageId);
            Assert.Empty(afterDelete);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public async Task QueuedWhatsAppGateway_PersistsToLocalOutbox_WhenPublishFails()
    {
        var dir = CreateTempDir();
        try
        {
            var options = Options.Create(new MessagingOptions { DataDirectory = dir });
            var outbox = new FileWhatsAppOutboundOutboxStore(options);
            var gateway = new QueuedWhatsAppGateway(
                new FakeWhatsAppTransport(),
                new ThrowingWhatsAppPublisher(),
                outbox,
                NullLogger<QueuedWhatsAppGateway>.Instance);

            var result = await gateway.SendTextAsync("inst", "5511999999999", "oferta teste", CancellationToken.None);
            var pending = await outbox.ListPendingAsync(CancellationToken.None);

            Assert.True(result.Success);
            Assert.Single(pending);
            Assert.Equal("5511999999999", pending[0].To);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public async Task QueuedTelegramGateway_PersistsToLocalOutbox_WhenPublishFails()
    {
        var dir = CreateTempDir();
        try
        {
            var options = Options.Create(new MessagingOptions { DataDirectory = dir });
            var outbox = new FileTelegramOutboundOutboxStore(options);
            var gateway = new QueuedTelegramGateway(
                new FakeTelegramTransport(),
                new ThrowingTelegramPublisher(),
                outbox,
                NullLogger<QueuedTelegramGateway>.Instance);

            var result = await gateway.SendPhotoAsync("123:abc", -5296643037, "https://example.com/img.jpg", "oferta teste", CancellationToken.None);
            var pending = await outbox.ListPendingAsync(CancellationToken.None);

            Assert.True(result.Success);
            Assert.Single(pending);
            Assert.Equal(-5296643037, pending[0].ChatId);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    private static string CreateTempDir()
    {
        var dir = Path.Combine(Path.GetTempPath(), "achadinhos-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        return dir;
    }

    private sealed class ThrowingPublisher : IBotConversorQueuePublisher
    {
        public Task PublishAsync(ProcessBotConversorWebhookCommand command, CancellationToken cancellationToken)
        {
            throw new InvalidOperationException("rabbitmq offline");
        }
    }

    private sealed class ThrowingWhatsAppPublisher : IWhatsAppOutboundPublisher
    {
        public Task PublishAsync(SendWhatsAppMessageCommand command, CancellationToken cancellationToken)
        {
            throw new InvalidOperationException("rabbitmq offline");
        }
    }

    private sealed class ThrowingTelegramPublisher : ITelegramOutboundPublisher
    {
        public Task PublishAsync(SendTelegramMessageCommand command, CancellationToken cancellationToken)
        {
            throw new InvalidOperationException("rabbitmq offline");
        }
    }

    private sealed class FakeWhatsAppTransport : IWhatsAppTransport
    {
        public Task<WhatsAppConnectResult> ConnectAsync(string? instanceName, CancellationToken cancellationToken) => Task.FromResult(new WhatsAppConnectResult(true, null, null));
        public Task<WhatsAppInstanceResult> CreateInstanceAsync(string instanceName, CancellationToken cancellationToken) => Task.FromResult(new WhatsAppInstanceResult(true, null, null));
        public Task<IReadOnlyList<WhatsAppGroupInfo>> GetGroupsAsync(string? instanceName, CancellationToken cancellationToken) => Task.FromResult<IReadOnlyList<WhatsAppGroupInfo>>(Array.Empty<WhatsAppGroupInfo>());
        public Task<WhatsAppSendResult> SendTextAsync(string? instanceName, string to, string text, CancellationToken cancellationToken) => Task.FromResult(new WhatsAppSendResult(true, null));
        public Task<WhatsAppSendResult> SendImageAsync(string? instanceName, string to, byte[] imageBytes, string? caption, string? mimeType, CancellationToken cancellationToken) => Task.FromResult(new WhatsAppSendResult(true, null));
        public Task<WhatsAppSendResult> SendImageUrlAsync(string? instanceName, string to, string mediaUrl, string? caption, string? mimeType, string? fileName, CancellationToken cancellationToken) => Task.FromResult(new WhatsAppSendResult(true, null));
        public Task<WhatsAppSendResult> DeleteMessageAsync(string? instanceName, string chatId, string messageId, bool isGroup, CancellationToken cancellationToken) => Task.FromResult(new WhatsAppSendResult(true, null));
    }

    private sealed class FakeTelegramTransport : ITelegramTransport
    {
        public Task<TelegramConnectResult> ConnectAsync(string? botToken, CancellationToken cancellationToken) => Task.FromResult(new TelegramConnectResult(true, "bot", null));
        public Task<TelegramSendResult> SendTextAsync(string? botToken, long chatId, string text, CancellationToken cancellationToken) => Task.FromResult(new TelegramSendResult(true, null));
        public Task<TelegramSendResult> SendPhotoAsync(string? botToken, long chatId, string photoUrl, string? caption, CancellationToken cancellationToken) => Task.FromResult(new TelegramSendResult(true, null));
    }
}
