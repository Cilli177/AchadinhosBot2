using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Configuration;
using AchadinhosBot.Next.Domain.Logs;
using AchadinhosBot.Next.Domain.Settings;
using AchadinhosBot.Next.Infrastructure.Instagram;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace AchadinhosBot.Next.Tests;

public sealed class TelegramViralReelsAutoPilotServiceTests
{
    private const long ViralChatId = 2425105459;

    [Fact]
    public async Task RunOnce_CreatesReelDraftWithoutPublishing_WhenApprovalGroupIsMissing()
    {
        var settings = CreateEnabledSettings();
        var telegram = new FakeTelegramUserbotService
        {
            Offers =
            [
                new TelegramUserbotOfferMessage(ViralChatId, "Videos virais", "101", DateTimeOffset.UtcNow, "Oferta boa https://example.com/p", "video", "https://cdn.example.com/reel.mp4")
            ],
            DraftResult = CreateDraftResult("101")
        };
        var logs = new FakeInstagramPublishLogStore();
        var whatsApp = new RecordingWhatsAppGateway();
        var service = CreateService(settings, telegram, logs, whatsApp);

        var result = await service.RunOnceAsync(CancellationToken.None);

        Assert.True(result.Success);
        Assert.Equal("draft-101", result.DraftId);
        Assert.False(result.ApprovalSent);
        Assert.Empty(whatsApp.TextMessages);
        Assert.Contains(logs.Items, x => x.Action == "viral_reel_draft_created" && x.DraftId == "draft-101");
        Assert.Contains(logs.Items, x => x.Action == "viral_reel_approval_target_missing" && x.DraftId == "draft-101");
    }

    [Fact]
    public async Task RunOnce_SendsWhatsAppApproval_WhenGroupIsConfigured()
    {
        var settings = CreateEnabledSettings();
        settings.InstagramPublish.ViralReelsApprovalWhatsAppGroupId = "120363approval@g.us";
        var telegram = new FakeTelegramUserbotService
        {
            Offers =
            [
                new TelegramUserbotOfferMessage(ViralChatId, "Videos virais", "102", DateTimeOffset.UtcNow, "Oferta boa https://example.com/p", "video", "https://cdn.example.com/reel.mp4")
            ],
            DraftResult = CreateDraftResult("102")
        };
        var logs = new FakeInstagramPublishLogStore();
        var whatsApp = new RecordingWhatsAppGateway();
        var service = CreateService(settings, telegram, logs, whatsApp);

        var result = await service.RunOnceAsync(CancellationToken.None);

        Assert.True(result.Success);
        Assert.True(result.ApprovalSent);
        Assert.Single(whatsApp.TextMessages);
        Assert.Equal(2, whatsApp.ImageUrlMessages.Count);
        Assert.Equal("ZapOfertas", whatsApp.TextMessages[0].InstanceName);
        Assert.Equal("120363approval@g.us", whatsApp.TextMessages[0].To);
        Assert.Equal("https://cdn.example.com/reel.mp4", whatsApp.ImageUrlMessages[0].MediaUrl);
        Assert.Equal("video/mp4", whatsApp.ImageUrlMessages[0].MimeType);
        Assert.Equal("https://cdn.example.com/oferta.jpg", whatsApp.ImageUrlMessages[1].MediaUrl);
        Assert.Contains("LEGENDA DO INSTAGRAM", whatsApp.TextMessages[0].Text, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("sim: aprova, publica o Reel", whatsApp.ImageUrlMessages[1].Caption, StringComparison.OrdinalIgnoreCase);
        Assert.Contains(logs.Items, x => x.Action == "viral_reel_approval_sent" && x.Success);
    }

    [Fact]
    public void CalculateNextRunAt_UsesFixedBrazilSchedule()
    {
        var settings = CreateEnabledSettings().InstagramPublish;
        settings.ViralReelsScheduleTimes = new List<string> { "07:30", "17:30" };

        var beforeMorning = new DateTimeOffset(2026, 4, 28, 10, 0, 0, TimeSpan.Zero);
        var afterMorning = new DateTimeOffset(2026, 4, 28, 12, 0, 0, TimeSpan.Zero);
        var afterEvening = new DateTimeOffset(2026, 4, 28, 22, 0, 0, TimeSpan.Zero);

        Assert.Equal(new DateTimeOffset(2026, 4, 28, 10, 30, 0, TimeSpan.Zero), TelegramViralReelsAutoPilotWorker.CalculateNextRunAt(beforeMorning, settings));
        Assert.Equal(new DateTimeOffset(2026, 4, 28, 20, 30, 0, TimeSpan.Zero), TelegramViralReelsAutoPilotWorker.CalculateNextRunAt(afterMorning, settings));
        Assert.Equal(new DateTimeOffset(2026, 4, 29, 10, 30, 0, TimeSpan.Zero), TelegramViralReelsAutoPilotWorker.CalculateNextRunAt(afterEvening, settings));
    }

    [Fact]
    public async Task RunOnce_SkipsOnlyWhenAllEligibleCandidatesWereAlreadyUsed()
    {
        var settings = CreateEnabledSettings();
        var sourceKey = $"{ViralChatId}:103";
        var telegram = new FakeTelegramUserbotService
        {
            Offers =
            [
                new TelegramUserbotOfferMessage(ViralChatId, "Videos virais", "103", DateTimeOffset.UtcNow, "Oferta boa https://example.com/p", "video", "https://cdn.example.com/reel.mp4")
            ],
            DraftResult = CreateDraftResult("103")
        };
        var logs = new FakeInstagramPublishLogStore();
        logs.Items.Add(new InstagramPublishLogEntry
        {
            Action = "viral_reel_draft_created",
            Success = true,
            Timestamp = DateTimeOffset.UtcNow.AddHours(-1),
            DraftId = "draft-existing",
            Details = $"SourceKey={sourceKey};ProductName=Oferta"
        });
        var service = CreateService(settings, telegram, logs, new RecordingWhatsAppGateway());

        var result = await service.RunOnceAsync(CancellationToken.None);

        Assert.True(result.Success);
        Assert.Equal("all_candidates_already_used", result.Message);
        Assert.Equal(0, telegram.CreateDraftCalls);
        Assert.Contains(logs.Items, x => x.Action == "viral_reel_skipped" && x.Details?.Contains("all_candidates_already_used", StringComparison.OrdinalIgnoreCase) == true);
    }

    [Fact]
    public async Task RunOnce_FallsBackToNextUnusedVideoLink_WhenNewestWasAlreadyDrafted()
    {
        var settings = CreateEnabledSettings();
        var duplicateSourceKey = $"{ViralChatId}:103";
        var telegram = new FakeTelegramUserbotService
        {
            Offers =
            [
                new TelegramUserbotOfferMessage(ViralChatId, "Videos virais", "103", DateTimeOffset.UtcNow, "Oferta repetida https://example.com/p1", "video", "https://cdn.example.com/reel-103.mp4"),
                new TelegramUserbotOfferMessage(ViralChatId, "Videos virais", "102", DateTimeOffset.UtcNow.AddMinutes(-5), "Oferta nova https://example.com/p2", "video", "https://cdn.example.com/reel-102.mp4")
            ],
            DraftResult = CreateDraftResult("102")
        };
        var logs = new FakeInstagramPublishLogStore();
        logs.Items.Add(new InstagramPublishLogEntry
        {
            Action = "viral_reel_draft_created",
            Success = true,
            Timestamp = DateTimeOffset.UtcNow.AddDays(-10),
            DraftId = "draft-existing",
            Details = $"SourceKey={duplicateSourceKey};OriginalOfferUrl=https://example.com/p1;ProductName=Oferta"
        });
        var service = CreateService(settings, telegram, logs, new RecordingWhatsAppGateway());

        var result = await service.RunOnceAsync(CancellationToken.None);

        Assert.True(result.Success);
        Assert.Equal("viral_reel_draft_created", result.Message);
        Assert.Equal("draft-102", result.DraftId);
        Assert.Equal("102", telegram.LastCreateDraftRequest?.SourceMessageId);
        Assert.Contains(logs.Items, x => x.Action == "viral_reel_duplicate_skipped" && x.Details?.Contains("SkippedCandidates=1", StringComparison.OrdinalIgnoreCase) == true);
        Assert.Contains(logs.Items, x => x.Action == "viral_reel_draft_created" && x.Details?.Contains("OriginalOfferUrl=https://example.com/p2", StringComparison.OrdinalIgnoreCase) == true);
    }

    [Fact]
    public async Task RunOnce_IgnoresNonVideoAndVideoWithoutLink()
    {
        var settings = CreateEnabledSettings();
        var telegram = new FakeTelegramUserbotService
        {
            Offers =
            [
                new TelegramUserbotOfferMessage(ViralChatId, "Videos virais", "201", DateTimeOffset.UtcNow, "Imagem https://example.com/p", "image", "https://cdn.example.com/img.jpg"),
                new TelegramUserbotOfferMessage(ViralChatId, "Videos virais", "202", DateTimeOffset.UtcNow, "Video sem link", "video", "https://cdn.example.com/reel.mp4")
            ],
            DraftResult = CreateDraftResult("202")
        };
        var logs = new FakeInstagramPublishLogStore();
        var service = CreateService(settings, telegram, logs, new RecordingWhatsAppGateway());

        var result = await service.RunOnceAsync(CancellationToken.None);

        Assert.True(result.Success);
        Assert.Equal("no_eligible_video_link", result.Message);
        Assert.Equal(0, telegram.CreateDraftCalls);
        Assert.Contains(logs.Items, x => x.Action == "viral_reel_skipped" && x.Details?.Contains("no_eligible_video_link", StringComparison.OrdinalIgnoreCase) == true);
    }

    private static TelegramViralReelsAutoPilotService CreateService(
        AutomationSettings settings,
        FakeTelegramUserbotService telegram,
        FakeInstagramPublishLogStore logs,
        RecordingWhatsAppGateway whatsApp)
        => new(
            new FakeSettingsStore(settings),
            telegram,
            logs,
            whatsApp,
            Options.Create(new EvolutionOptions { InstanceName = "ZapOfertas" }),
            NullLogger<TelegramViralReelsAutoPilotService>.Instance);

    private static AutomationSettings CreateEnabledSettings()
        => new()
        {
            InstagramPublish = new InstagramPublishSettings
            {
                ViralReelsAutoPilotEnabled = true,
                ViralReelsSourceTelegramChatId = ViralChatId,
                ViralReelsIntervalHours = 12,
                ViralReelsScheduleTimes = new List<string> { "07:30", "17:30" },
                ViralReelsLookbackHours = 24,
                ViralReelsRepeatWindowHours = 72,
                ViralReelsSendForApproval = true,
                ViralReelsApprovalChannel = "whatsapp",
                ViralReelsApprovalWhatsAppInstanceName = "ZapOfertas",
                ViralReelsAutoPublishEnabled = false
            }
        };

    private static TelegramUserbotReelDraftResult CreateDraftResult(string messageId)
        => new(
            true,
            "ok",
            ViralChatId,
            "Videos virais",
            messageId,
            "video",
            "https://cdn.example.com/reel.mp4",
            "https://reidasofertas.ia.br/r/ML-000001",
            "Oferta viral",
            $"draft-{messageId}",
            $"/conversor-admin?draftId=draft-{messageId}",
            "Legenda",
            "Comente QUERO",
            "telegram",
            "https://cdn.example.com/oferta.jpg",
            "Preview do reel");

    private sealed class FakeSettingsStore : ISettingsStore
    {
        private readonly AutomationSettings _settings;

        public FakeSettingsStore(AutomationSettings settings)
        {
            _settings = settings;
        }

        public Task<AutomationSettings> GetAsync(CancellationToken cancellationToken) => Task.FromResult(_settings);
        public Task SaveAsync(AutomationSettings settings, CancellationToken cancellationToken) => Task.CompletedTask;
    }

    private sealed class FakeInstagramPublishLogStore : IInstagramPublishLogStore
    {
        public List<InstagramPublishLogEntry> Items { get; } = new();

        public Task AppendAsync(InstagramPublishLogEntry entry, CancellationToken ct)
        {
            Items.Add(entry);
            return Task.CompletedTask;
        }

        public Task<IReadOnlyList<InstagramPublishLogEntry>> ListAsync(int take, CancellationToken ct)
            => Task.FromResult<IReadOnlyList<InstagramPublishLogEntry>>(Items.OrderByDescending(x => x.Timestamp).Take(take).ToList());

        public Task ClearAsync(CancellationToken ct)
        {
            Items.Clear();
            return Task.CompletedTask;
        }
    }

    private sealed class FakeTelegramUserbotService : ITelegramUserbotService
    {
        public IReadOnlyList<TelegramUserbotOfferMessage> Offers { get; set; } = Array.Empty<TelegramUserbotOfferMessage>();
        public TelegramUserbotReelDraftResult DraftResult { get; set; } = CreateDraftResult("1");
        public int CreateDraftCalls { get; private set; }
        public TelegramUserbotCreateReelDraftRequest? LastCreateDraftRequest { get; private set; }
        public bool IsReady { get; set; } = true;

        public Task<IReadOnlyList<TelegramUserbotChat>> GetDialogsAsync(CancellationToken cancellationToken)
            => Task.FromResult<IReadOnlyList<TelegramUserbotChat>>(Array.Empty<TelegramUserbotChat>());

        public Task<bool> RefreshDialogsAsync(CancellationToken cancellationToken) => Task.FromResult(true);

        public Task<IReadOnlyList<TelegramUserbotOfferMessage>> ListRecentOffersAsync(
            IReadOnlyCollection<long> sourceChatIds,
            int perChatLimit,
            CancellationToken cancellationToken,
            bool includeMedia = true,
            string? mediaMessageId = null)
            => Task.FromResult(Offers);

        public Task<TelegramUserbotReplayResult> ReplayRecentOffersToWhatsAppAsync(long sourceChatId, int count, bool allowOfficialDestination, CancellationToken cancellationToken)
            => Task.FromResult(new TelegramUserbotReplayResult(true, "ok", sourceChatId, count, 0, 0, 0));

        public Task<TelegramUserbotReelDraftResult> CreateLatestReelDraftAsync(TelegramUserbotCreateReelDraftRequest request, CancellationToken cancellationToken)
        {
            CreateDraftCalls++;
            LastCreateDraftRequest = request;
            return Task.FromResult(DraftResult);
        }

        public Task<TelegramUserbotAuthUpdateResult> UpdateRuntimeAuthAsync(TelegramUserbotAuthUpdateRequest request, CancellationToken cancellationToken)
            => Task.FromResult(new TelegramUserbotAuthUpdateResult(true, false, false, false, false, "ok"));
    }

    private sealed class RecordingWhatsAppGateway : IWhatsAppTransport
    {
        public List<(string? InstanceName, string To, string Text)> TextMessages { get; } = new();
        public List<(string? InstanceName, string To, string MediaUrl, string? Caption, string? MimeType, string? FileName)> ImageUrlMessages { get; } = new();

        public Task<WhatsAppConnectResult> ConnectAsync(string? instanceName, CancellationToken cancellationToken)
            => Task.FromResult(new WhatsAppConnectResult(true, null, "ok"));

        public Task<WhatsAppConnectResult> TestConnectionAsync(string? instanceName, CancellationToken cancellationToken)
            => Task.FromResult(new WhatsAppConnectResult(true, null, "ok"));

        public Task<WhatsAppInstanceResult> CreateInstanceAsync(string instanceName, CancellationToken cancellationToken)
            => Task.FromResult(new WhatsAppInstanceResult(true, null, "ok"));

        public Task<WhatsAppConnectionSnapshot> GetConnectionSnapshotAsync(string? instanceName, CancellationToken cancellationToken)
            => Task.FromResult(new WhatsAppConnectionSnapshot(true, "connected", null, "ok"));

        public Task<IReadOnlyList<WhatsAppGroupInfo>> GetGroupsAsync(string? instanceName, CancellationToken cancellationToken)
            => Task.FromResult<IReadOnlyList<WhatsAppGroupInfo>>(Array.Empty<WhatsAppGroupInfo>());

        public Task<IReadOnlyList<WhatsAppInstanceInfo>> FetchInstancesAsync(CancellationToken cancellationToken)
            => Task.FromResult<IReadOnlyList<WhatsAppInstanceInfo>>(Array.Empty<WhatsAppInstanceInfo>());

        public Task<WhatsAppSendResult> SendTextAsync(string? instanceName, string to, string text, CancellationToken cancellationToken)
        {
            TextMessages.Add((instanceName, to, text));
            return Task.FromResult(new WhatsAppSendResult(true, "ok"));
        }

        public Task<WhatsAppSendResult> SendImageAsync(string? instanceName, string to, byte[] imageBytes, string? caption, string? mimeType, CancellationToken cancellationToken)
            => Task.FromResult(new WhatsAppSendResult(true, "ok"));

        public Task<WhatsAppSendResult> SendImageUrlAsync(string? instanceName, string to, string mediaUrl, string? caption, string? mimeType, string? fileName, CancellationToken cancellationToken)
        {
            ImageUrlMessages.Add((instanceName, to, mediaUrl, caption, mimeType, fileName));
            return Task.FromResult(new WhatsAppSendResult(true, "ok"));
        }

        public Task<WhatsAppSendResult> UpdateProfilePictureAsync(string? instanceName, string picture, CancellationToken cancellationToken)
            => Task.FromResult(new WhatsAppSendResult(true, "ok"));

        public Task<WhatsAppSendResult> DeleteMessageAsync(string? instanceName, string chatId, string messageId, bool isGroup, CancellationToken cancellationToken)
            => Task.FromResult(new WhatsAppSendResult(true, "ok"));

        public Task<IReadOnlyList<string>> GetGroupParticipantsAsync(string? instanceName, string groupId, CancellationToken cancellationToken)
            => Task.FromResult<IReadOnlyList<string>>(Array.Empty<string>());

        public Task<WhatsAppSendResult> AddParticipantsAsync(string? instanceName, string groupId, IReadOnlyList<string> participantJids, CancellationToken cancellationToken)
            => Task.FromResult(new WhatsAppSendResult(true, "ok"));
    }
}
