using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Application.Services;
using AchadinhosBot.Next.Configuration;
using AchadinhosBot.Next.Domain.Logs;
using AchadinhosBot.Next.Domain.Models;
using AchadinhosBot.Next.Domain.Settings;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace AchadinhosBot.Next.Tests;

public sealed class WhatsAppAdminAutomationServiceTests
{
    [Fact]
    public async Task GetBlastConversionAsync_ShouldAggregateJoinEventsFromSentParticipants()
    {
        var settingsStore = new InMemorySettingsStore(new AutomationSettings
        {
            WhatsAppAdminAutomation = new WhatsAppAdminAutomationSettings
            {
                ParticipantBlastSchedules =
                [
                    new WhatsAppParticipantBlastSchedule
                    {
                        Id = "blast-1",
                        Name = "Disparo teste",
                        CreatedAt = new DateTimeOffset(2026, 4, 10, 12, 0, 0, TimeSpan.Zero),
                        SentParticipantIds = new List<string> { "5511999990001@s.whatsapp.net", "5511999990002@s.whatsapp.net" }
                    }
                ]
            }
        });
        var membershipStore = new InMemoryMembershipStore(
        [
            new WhatsAppGroupMembershipEvent
            {
                ParticipantId = "5511999990001@s.whatsapp.net",
                GroupId = "120@g.us",
                GroupName = "Grupo VIP",
                Action = "join",
                Timestamp = new DateTimeOffset(2026, 4, 10, 12, 10, 0, TimeSpan.Zero)
            },
            new WhatsAppGroupMembershipEvent
            {
                ParticipantId = "5511999990001@s.whatsapp.net",
                GroupId = "120@g.us",
                GroupName = "Grupo VIP",
                Action = "join",
                Timestamp = new DateTimeOffset(2026, 4, 10, 12, 11, 0, TimeSpan.Zero)
            },
            new WhatsAppGroupMembershipEvent
            {
                ParticipantId = "5511999990002@s.whatsapp.net",
                GroupId = "120@g.us",
                GroupName = "Grupo VIP",
                Action = "add",
                Timestamp = new DateTimeOffset(2026, 4, 10, 12, 12, 0, TimeSpan.Zero)
            }
        ]);
        var service = CreateService(settingsStore, membershipStore, new NoopBlastProgressStore(), new FakeWhatsAppTransport());

        var snapshot = await service.GetBlastConversionAsync("blast-1", "120@g.us", CancellationToken.None);

        Assert.NotNull(snapshot);
        Assert.Equal(2, snapshot!.TotalSent);
        Assert.Equal(2, snapshot.Converted);
        Assert.Equal(3, snapshot.TotalJoinEvents);
        Assert.Equal(100m, snapshot.ConversionRate);
        Assert.Equal(2, snapshot.Converters.Count);
    }

    [Fact]
    public async Task RunBlastScheduleNowAsync_ShouldSendMessagesAndLogProgress()
    {
        var settings = new AutomationSettings
        {
            WhatsAppAdminAutomation = new WhatsAppAdminAutomationSettings
            {
                ParticipantBlastSchedules =
                [
                    new WhatsAppParticipantBlastSchedule
                    {
                        Id = "blast-run",
                        Name = "Disparo imediato",
                        InstanceName = "ZapOfertas2",
                        LinkUrl = "https://chat.whatsapp.com/FhkbgV9fnUjKnOM4KGDCPX",
                        SecurityPitch = "Grupo oficial com ofertas validadas.",
                        PendingParticipantIds = new List<string>
                        {
                            "5511999990003@s.whatsapp.net",
                            "5511999990004@s.whatsapp.net"
                        },
                        TotalParticipants = 2,
                        BatchSize = 5,
                        MinUserIntervalMs = 1,
                        MaxUserIntervalMs = 1,
                        BatchPauseSeconds = 0,
                        QueuedAt = DateTimeOffset.UtcNow
                    }
                ]
            }
        };
        var settingsStore = new InMemorySettingsStore(settings);
        var progressStore = new RecordingBlastProgressStore();
        var transport = new FakeWhatsAppTransport();
        var service = CreateService(settingsStore, new InMemoryMembershipStore([]), progressStore, transport);

        var result = await service.RunBlastScheduleNowAsync("blast-run", CancellationToken.None);

        Assert.True(result.Success);
        Assert.Equal(2, transport.SentMessages.Count);
        Assert.All(transport.SentMessages, msg => Assert.Contains("Link oficial do grupo", msg.Text));
        var schedule = settings.WhatsAppAdminAutomation.ParticipantBlastSchedules.Single();
        Assert.Equal("completed", schedule.Status);
        Assert.False(schedule.Enabled);
        Assert.Equal(2, schedule.SuccessParticipants);
        Assert.Contains(progressStore.Items, x => x.Stage == "schedule-completed");
    }

    private static WhatsAppAdminAutomationService CreateService(
        InMemorySettingsStore settingsStore,
        InMemoryMembershipStore membershipStore,
        IWhatsAppParticipantBlastProgressStore progressStore,
        FakeWhatsAppTransport transport)
        => new(
            settingsStore,
            transport,
            CreateTrackingService(),
            progressStore,
            membershipStore,
            NullLogger<WhatsAppAdminAutomationService>.Instance);

    private static TrackingLinkShortenerService CreateTrackingService()
        => new(
            new FakeLinkTrackingStore(),
            new FakeHttpClientFactory(),
            new InMemorySettingsStore(new AutomationSettings
            {
                BioHub = new BioHubSettings { PublicBaseUrl = "https://reidasofertas.ia.br" }
            }),
            Microsoft.Extensions.Options.Options.Create(new WebhookOptions { PublicBaseUrl = "https://reidasofertas.ia.br" }),
            new Microsoft.Extensions.Caching.Memory.MemoryCache(new Microsoft.Extensions.Caching.Memory.MemoryCacheOptions()),
            NullLogger<TrackingLinkShortenerService>.Instance);

    private sealed class InMemorySettingsStore : ISettingsStore
    {
        private readonly AutomationSettings _settings;

        public InMemorySettingsStore(AutomationSettings settings) => _settings = settings;

        public Task<AutomationSettings> GetAsync(CancellationToken cancellationToken) => Task.FromResult(_settings);

        public Task SaveAsync(AutomationSettings settings, CancellationToken cancellationToken) => Task.CompletedTask;
    }

    private sealed class InMemoryMembershipStore : IWhatsAppGroupMembershipStore
    {
        private readonly IReadOnlyList<WhatsAppGroupMembershipEvent> _events;

        public InMemoryMembershipStore(IReadOnlyList<WhatsAppGroupMembershipEvent> events) => _events = events;

        public Task AppendAsync(WhatsAppGroupMembershipEvent @event, CancellationToken cancellationToken) => Task.CompletedTask;
        public Task<IReadOnlyList<string>> GetParticipantsAsync(string groupId, CancellationToken cancellationToken) => Task.FromResult<IReadOnlyList<string>>(Array.Empty<string>());
        public Task<IReadOnlyList<string>> GetParticipantsAsync(string groupId, string? instanceName, CancellationToken cancellationToken) => Task.FromResult<IReadOnlyList<string>>(Array.Empty<string>());
        public Task<IReadOnlyList<WhatsAppGroupMembershipEvent>> ListAsync(CancellationToken cancellationToken) => Task.FromResult(_events);
        public Task SetParticipantsAsync(string groupId, IEnumerable<string> participants, CancellationToken cancellationToken) => Task.CompletedTask;
        public Task SetParticipantsAsync(string groupId, string? instanceName, IEnumerable<string> participants, CancellationToken cancellationToken) => Task.CompletedTask;
    }

    private sealed class RecordingBlastProgressStore : IWhatsAppParticipantBlastProgressStore
    {
        public List<WhatsAppParticipantBlastProgressEntry> Items { get; } = new();
        public Task AppendAsync(WhatsAppParticipantBlastProgressEntry entry, CancellationToken cancellationToken)
        {
            Items.Add(entry);
            return Task.CompletedTask;
        }
        public Task ClearAsync(CancellationToken cancellationToken)
        {
            Items.Clear();
            return Task.CompletedTask;
        }
        public Task<IReadOnlyList<WhatsAppParticipantBlastProgressEntry>> ListAsync(string? operationId, int limit, CancellationToken cancellationToken)
            => Task.FromResult<IReadOnlyList<WhatsAppParticipantBlastProgressEntry>>(Items.ToArray());
    }

    private sealed class NoopBlastProgressStore : IWhatsAppParticipantBlastProgressStore
    {
        public Task AppendAsync(WhatsAppParticipantBlastProgressEntry entry, CancellationToken cancellationToken) => Task.CompletedTask;
        public Task ClearAsync(CancellationToken cancellationToken) => Task.CompletedTask;
        public Task<IReadOnlyList<WhatsAppParticipantBlastProgressEntry>> ListAsync(string? operationId, int limit, CancellationToken cancellationToken)
            => Task.FromResult<IReadOnlyList<WhatsAppParticipantBlastProgressEntry>>(Array.Empty<WhatsAppParticipantBlastProgressEntry>());
    }

    private sealed class FakeWhatsAppTransport : IWhatsAppTransport
    {
        public List<(string? InstanceName, string ChatId, string Text)> SentMessages { get; } = new();

        public Task<WhatsAppConnectResult> ConnectAsync(string? instanceName, CancellationToken cancellationToken)
            => Task.FromResult(new WhatsAppConnectResult(true, null, "ok"));

        public Task<WhatsAppInstanceResult> CreateInstanceAsync(string instanceName, CancellationToken cancellationToken)
            => Task.FromResult(new WhatsAppInstanceResult(true, "ok", instanceName));

        public Task<IReadOnlyList<WhatsAppGroupInfo>> GetGroupsAsync(string? instanceName, CancellationToken cancellationToken)
            => Task.FromResult<IReadOnlyList<WhatsAppGroupInfo>>(Array.Empty<WhatsAppGroupInfo>());

        public Task<WhatsAppSendResult> AddParticipantsAsync(string? instanceName, string groupId, IReadOnlyList<string> participantIds, CancellationToken cancellationToken)
            => Task.FromResult(new WhatsAppSendResult(true, "ok"));

        public Task<IReadOnlyList<string>> GetGroupParticipantsAsync(string? instanceName, string groupId, CancellationToken cancellationToken)
            => Task.FromResult<IReadOnlyList<string>>(Array.Empty<string>());

        public Task<WhatsAppSendResult> SendImageAsync(string? instanceName, string chatId, byte[] imageBytes, string? caption, string? mimeType, CancellationToken cancellationToken)
            => Task.FromResult(new WhatsAppSendResult(true, "ok"));

        public Task<WhatsAppSendResult> SendImageUrlAsync(string? instanceName, string chatId, string imageUrl, string? caption, string? mimeType, string? fileName, CancellationToken cancellationToken)
            => Task.FromResult(new WhatsAppSendResult(true, "ok"));

        public Task<WhatsAppSendResult> SendTextAsync(string? instanceName, string chatId, string text, CancellationToken cancellationToken)
        {
            SentMessages.Add((instanceName, chatId, text));
            return Task.FromResult(new WhatsAppSendResult(true, "ok"));
        }

        public Task<WhatsAppSendResult> DeleteMessageAsync(string? instanceName, string chatId, string messageId, bool isGroup, CancellationToken cancellationToken)
            => Task.FromResult(new WhatsAppSendResult(true, "ok"));
    }

    private sealed class FakeLinkTrackingStore : ILinkTrackingStore
    {
        public Task<LinkTrackingEntry> CreateAsync(LinkTrackingCreateRequest request, CancellationToken cancellationToken) => throw new NotSupportedException();
        public Task<LinkTrackingEntry> CreateAsync(string targetUrl, CancellationToken cancellationToken) => throw new NotSupportedException();
        public Task<LinkTrackingEntry> GetOrCreateAsync(LinkTrackingCreateRequest request, CancellationToken cancellationToken) => throw new NotSupportedException();
        public Task<LinkTrackingEntry> GetOrCreateAsync(string targetUrl, CancellationToken cancellationToken) => throw new NotSupportedException();
        public Task<IReadOnlyList<LinkTrackingEntry>> ListAsync(CancellationToken cancellationToken) => Task.FromResult<IReadOnlyList<LinkTrackingEntry>>(Array.Empty<LinkTrackingEntry>());
        public Task<LinkTrackingEntry?> RegisterClickAsync(string trackingId, CancellationToken cancellationToken) => Task.FromResult<LinkTrackingEntry?>(null);
        public Task<LinkTrackingEntry?> GetLinkAsync(string id, CancellationToken cancellationToken) => Task.FromResult<LinkTrackingEntry?>(null);
    }

    private sealed class FakeHttpClientFactory : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => new();
    }
}
