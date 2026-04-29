using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Application.Consumers;
using AchadinhosBot.Next.Configuration;
using AchadinhosBot.Next.Domain.Logs;
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
                Options.Create(new DeliverySafetyOptions()),
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
    public async Task QueuedWhatsAppGateway_DisablesTextFallback_ForOfficialImageUrl()
    {
        var dir = CreateTempDir();
        try
        {
            var publisher = new CapturingWhatsAppPublisher();
            var gateway = new QueuedWhatsAppGateway(
                new FakeWhatsAppTransport(),
                publisher,
                new FileWhatsAppOutboundOutboxStore(Options.Create(new MessagingOptions { DataDirectory = dir })),
                Options.Create(new DeliverySafetyOptions
                {
                    OfficialWhatsAppGroupIds = new List<string> { "120363405661434395@g.us" }
                }),
                NullLogger<QueuedWhatsAppGateway>.Instance);

            await gateway.SendImageUrlAsync(
                "inst",
                "120363405661434395@g.us",
                "https://example.com/image.jpg",
                "oferta oficial",
                "image/jpeg",
                "oferta.jpg",
                CancellationToken.None);

            Assert.NotNull(publisher.LastCommand);
            Assert.False(publisher.LastCommand.TextFallbackAllowed);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public async Task QueuedWhatsAppGateway_BlocksText_ForOfficialGroup()
    {
        var dir = CreateTempDir();
        try
        {
            var publisher = new CapturingWhatsAppPublisher();
            var gateway = new QueuedWhatsAppGateway(
                new FakeWhatsAppTransport(),
                publisher,
                new FileWhatsAppOutboundOutboxStore(Options.Create(new MessagingOptions { DataDirectory = dir })),
                Options.Create(new DeliverySafetyOptions
                {
                    OfficialWhatsAppGroupIds = new List<string> { "120363405661434395@g.us" }
                }),
                NullLogger<QueuedWhatsAppGateway>.Instance);

            var result = await gateway.SendTextAsync(
                "inst",
                "120363405661434395@g.us",
                "oferta oficial sem imagem",
                CancellationToken.None);

            Assert.False(result.Success);
            Assert.Null(publisher.LastCommand);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public async Task QueuedWhatsAppGateway_BlocksEmptyImageUrl_ForOfficialGroup()
    {
        var dir = CreateTempDir();
        try
        {
            var publisher = new CapturingWhatsAppPublisher();
            var gateway = new QueuedWhatsAppGateway(
                new FakeWhatsAppTransport(),
                publisher,
                new FileWhatsAppOutboundOutboxStore(Options.Create(new MessagingOptions { DataDirectory = dir })),
                Options.Create(new DeliverySafetyOptions
                {
                    OfficialWhatsAppGroupIds = new List<string> { "120363405661434395@g.us" }
                }),
                NullLogger<QueuedWhatsAppGateway>.Instance);

            var result = await gateway.SendImageUrlAsync(
                "inst",
                "120363405661434395@g.us",
                "",
                "oferta oficial sem foto",
                "image/jpeg",
                "oferta.jpg",
                CancellationToken.None);

            Assert.False(result.Success);
            Assert.Null(publisher.LastCommand);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public async Task QueuedWhatsAppGateway_BlocksEmptyImageBytes_ForOfficialGroup()
    {
        var dir = CreateTempDir();
        try
        {
            var publisher = new CapturingWhatsAppPublisher();
            var gateway = new QueuedWhatsAppGateway(
                new FakeWhatsAppTransport(),
                publisher,
                new FileWhatsAppOutboundOutboxStore(Options.Create(new MessagingOptions { DataDirectory = dir })),
                Options.Create(new DeliverySafetyOptions
                {
                    OfficialWhatsAppGroupIds = new List<string> { "120363405661434395@g.us" }
                }),
                NullLogger<QueuedWhatsAppGateway>.Instance);

            var result = await gateway.SendImageAsync(
                "inst",
                "120363405661434395@g.us",
                Array.Empty<byte>(),
                "oferta oficial sem foto",
                "image/jpeg",
                CancellationToken.None);

            Assert.False(result.Success);
            Assert.Null(publisher.LastCommand);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public async Task WhatsAppOutboundConsumer_BlocksQueuedText_ForOfficialGroup()
    {
        var transport = new RecordingWhatsAppTransport();
        var consumer = CreateWhatsAppOutboundConsumer(
            transport,
            new DeliverySafetyOptions
            {
                OfficialWhatsAppGroupIds = new List<string> { "120363405661434395@g.us" }
            });

        var result = await consumer.SendWithInstanceAsync(new SendWhatsAppMessageCommand
        {
            Kind = "text",
            InstanceName = "inst",
            To = "120363405661434395@g.us",
            Text = "oferta oficial sem imagem"
        }, "inst", CancellationToken.None);

        Assert.False(result.Success);
        Assert.Equal(0, transport.SendTextCalls);
    }

    [Fact]
    public async Task WhatsAppOutboundConsumer_BlocksQueuedImageUrlWithoutMedia_ForOfficialGroup()
    {
        var transport = new RecordingWhatsAppTransport();
        var consumer = CreateWhatsAppOutboundConsumer(
            transport,
            new DeliverySafetyOptions
            {
                OfficialWhatsAppGroupIds = new List<string> { "120363405661434395@g.us" }
            });

        var result = await consumer.SendWithInstanceAsync(new SendWhatsAppMessageCommand
        {
            Kind = "image-url",
            InstanceName = "inst",
            To = "120363405661434395@g.us",
            Text = "oferta oficial sem foto",
            MediaUrl = ""
        }, "inst", CancellationToken.None);

        Assert.False(result.Success);
        Assert.Equal(0, transport.SendImageUrlCalls);
        Assert.Equal(0, transport.SendTextCalls);
    }

    [Fact]
    public async Task WhatsAppOutboundConsumer_BlocksQueuedImageBytesWithoutMedia_ForOfficialGroup()
    {
        var transport = new RecordingWhatsAppTransport();
        var consumer = CreateWhatsAppOutboundConsumer(
            transport,
            new DeliverySafetyOptions
            {
                OfficialWhatsAppGroupIds = new List<string> { "120363405661434395@g.us" }
            });

        var result = await consumer.SendWithInstanceAsync(new SendWhatsAppMessageCommand
        {
            Kind = "image-bytes",
            InstanceName = "inst",
            To = "120363405661434395@g.us",
            Text = "oferta oficial sem foto",
            MediaBase64 = ""
        }, "inst", CancellationToken.None);

        Assert.False(result.Success);
        Assert.Equal(0, transport.SendImageCalls);
        Assert.Equal(0, transport.SendTextCalls);
    }

    [Fact]
    public async Task WhatsAppOutboundConsumer_DoesNotFallbackToText_WhenOfficialImageUrlFails()
    {
        var transport = new RecordingWhatsAppTransport(imageUrlResult: new WhatsAppSendResult(false, "media failed"));
        var consumer = CreateWhatsAppOutboundConsumer(transport);

        var result = await consumer.SendWithInstanceAsync(new SendWhatsAppMessageCommand
        {
            Kind = "image-url",
            InstanceName = "inst",
            To = "120363405661434395@g.us",
            Text = "oferta oficial",
            MediaUrl = "https://example.com/image.jpg",
            TextFallbackAllowed = false
        }, "inst", CancellationToken.None);

        Assert.False(result.Success);
        Assert.Equal(1, transport.SendImageUrlCalls);
        Assert.Equal(0, transport.SendTextCalls);
    }

    [Fact]
    public async Task WhatsAppOutboundConsumer_DoesNotFallbackToText_WhenOfficialImageBytesFails()
    {
        var transport = new RecordingWhatsAppTransport(imageBytesResult: new WhatsAppSendResult(false, "media failed"));
        var consumer = CreateWhatsAppOutboundConsumer(transport);

        var result = await consumer.SendWithInstanceAsync(new SendWhatsAppMessageCommand
        {
            Kind = "image-bytes",
            InstanceName = "inst",
            To = "120363405661434395@g.us",
            Text = "oferta oficial",
            MediaBase64 = Convert.ToBase64String(new byte[] { 1, 2, 3 }),
            TextFallbackAllowed = false
        }, "inst", CancellationToken.None);

        Assert.False(result.Success);
        Assert.Equal(1, transport.SendImageCalls);
        Assert.Equal(0, transport.SendTextCalls);
    }

    [Fact]
    public async Task WhatsAppOutboundConsumer_FallsBackToText_WhenNonOfficialImageFails()
    {
        var transport = new RecordingWhatsAppTransport(
            imageUrlResult: new WhatsAppSendResult(false, "media failed"),
            textResult: new WhatsAppSendResult(true, "text sent"));
        var consumer = CreateWhatsAppOutboundConsumer(transport);

        var result = await consumer.SendWithInstanceAsync(new SendWhatsAppMessageCommand
        {
            Kind = "image-url",
            InstanceName = "inst",
            To = "5511999999999-123@g.us",
            Text = "oferta comum",
            MediaUrl = "https://example.com/image.jpg",
            TextFallbackAllowed = true
        }, "inst", CancellationToken.None);

        Assert.True(result.Success);
        Assert.Equal(1, transport.SendImageUrlCalls);
        Assert.Equal(1, transport.SendTextCalls);
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

    private sealed class CapturingWhatsAppPublisher : IWhatsAppOutboundPublisher
    {
        public SendWhatsAppMessageCommand? LastCommand { get; private set; }

        public Task PublishAsync(SendWhatsAppMessageCommand command, CancellationToken cancellationToken)
        {
            LastCommand = command;
            return Task.CompletedTask;
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

    private sealed class RecordingWhatsAppTransport : IWhatsAppTransport
    {
        private readonly WhatsAppSendResult _textResult;
        private readonly WhatsAppSendResult _imageBytesResult;
        private readonly WhatsAppSendResult _imageUrlResult;

        public int SendTextCalls { get; private set; }
        public int SendImageCalls { get; private set; }
        public int SendImageUrlCalls { get; private set; }

        public RecordingWhatsAppTransport(
            WhatsAppSendResult? textResult = null,
            WhatsAppSendResult? imageBytesResult = null,
            WhatsAppSendResult? imageUrlResult = null)
        {
            _textResult = textResult ?? new WhatsAppSendResult(true, "text sent");
            _imageBytesResult = imageBytesResult ?? new WhatsAppSendResult(true, "image sent");
            _imageUrlResult = imageUrlResult ?? new WhatsAppSendResult(true, "image sent");
        }

        public Task<WhatsAppConnectResult> ConnectAsync(string? instanceName, CancellationToken cancellationToken) => Task.FromResult(new WhatsAppConnectResult(true, null, null));
        public Task<WhatsAppInstanceResult> CreateInstanceAsync(string instanceName, CancellationToken cancellationToken) => Task.FromResult(new WhatsAppInstanceResult(true, null, null));
        public Task<IReadOnlyList<WhatsAppGroupInfo>> GetGroupsAsync(string? instanceName, CancellationToken cancellationToken) => Task.FromResult<IReadOnlyList<WhatsAppGroupInfo>>(Array.Empty<WhatsAppGroupInfo>());
        public Task<WhatsAppSendResult> SendTextAsync(string? instanceName, string to, string text, CancellationToken cancellationToken)
        {
            SendTextCalls++;
            return Task.FromResult(_textResult);
        }

        public Task<WhatsAppSendResult> SendImageAsync(string? instanceName, string to, byte[] imageBytes, string? caption, string? mimeType, CancellationToken cancellationToken)
        {
            SendImageCalls++;
            return Task.FromResult(_imageBytesResult);
        }

        public Task<WhatsAppSendResult> SendImageUrlAsync(string? instanceName, string to, string mediaUrl, string? caption, string? mimeType, string? fileName, CancellationToken cancellationToken)
        {
            SendImageUrlCalls++;
            return Task.FromResult(_imageUrlResult);
        }

        public Task<WhatsAppSendResult> DeleteMessageAsync(string? instanceName, string chatId, string messageId, bool isGroup, CancellationToken cancellationToken) => Task.FromResult(new WhatsAppSendResult(true, null));
    }

    private static WhatsAppOutboundConsumer CreateWhatsAppOutboundConsumer(
        IWhatsAppTransport transport,
        DeliverySafetyOptions? deliverySafetyOptions = null)
        => new(
            transport,
            new MemoryIdempotencyStore(),
            new InMemoryWhatsAppOutboundLogStore(),
            Options.Create(new MessagingOptions()),
            Options.Create(deliverySafetyOptions ?? new DeliverySafetyOptions()),
            NullLogger<WhatsAppOutboundConsumer>.Instance);

    private sealed class MemoryIdempotencyStore : IIdempotencyStore
    {
        public bool TryBegin(string key, TimeSpan ttl) => true;
        public void RemoveByPrefix(string prefix) { }
    }

    private sealed class InMemoryWhatsAppOutboundLogStore : IWhatsAppOutboundLogStore
    {
        private readonly List<WhatsAppOutboundLogEntry> _entries = new();

        public Task AppendAsync(WhatsAppOutboundLogEntry entry, CancellationToken cancellationToken)
        {
            _entries.Add(entry);
            return Task.CompletedTask;
        }

        public Task<IReadOnlyList<WhatsAppOutboundLogEntry>> ListRecentAsync(int limit, CancellationToken cancellationToken)
            => Task.FromResult<IReadOnlyList<WhatsAppOutboundLogEntry>>(_entries.TakeLast(limit).ToList());

        public Task<WhatsAppOutboundLogEntry?> GetAsync(string messageId, CancellationToken cancellationToken)
            => Task.FromResult(_entries.FirstOrDefault(x => x.MessageId == messageId));
    }

    private sealed class FakeTelegramTransport : ITelegramTransport
    {
        public Task<TelegramConnectResult> ConnectAsync(string? botToken, CancellationToken cancellationToken) => Task.FromResult(new TelegramConnectResult(true, "bot", null));
        public Task<TelegramSendResult> SendTextAsync(string? botToken, long chatId, string text, CancellationToken cancellationToken) => Task.FromResult(new TelegramSendResult(true, null));
        public Task<TelegramSendResult> SendPhotoAsync(string? botToken, long chatId, string photoUrl, string? caption, CancellationToken cancellationToken) => Task.FromResult(new TelegramSendResult(true, null));
    }
}
