using System.Runtime.Serialization;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Application.Consumers;
using AchadinhosBot.Next.Application.Services;
using AchadinhosBot.Next.Configuration;
using AchadinhosBot.Next.Domain.Agents;
using AchadinhosBot.Next.Domain.Instagram;
using AchadinhosBot.Next.Domain.Logs;
using AchadinhosBot.Next.Domain.Models;
using AchadinhosBot.Next.Domain.Settings;
using AchadinhosBot.Next.Infrastructure.Amazon;
using AchadinhosBot.Next.Infrastructure.Instagram;
using AchadinhosBot.Next.Infrastructure.MercadoLivre;
using AchadinhosBot.Next.Infrastructure.Media;
using AchadinhosBot.Next.Infrastructure.Telegram;
using AchadinhosBot.Next.Infrastructure.ProductData;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace AchadinhosBot.Next.Tests;

public sealed class TelegramReelDraftFlowTests
{
    [Fact]
    public void TelegramUserbotService_AllowsAEIAVideosChannel_ForConversorAdminDraft()
    {
        const long aeIaChannelId = 2425105459;

        var settings = new InstagramPostSettings
        {
            Enabled = true,
            AllowTelegramUserbot = true,
            TelegramAllowGroups = true,
            TelegramAllowPrivate = false,
            TelegramChatIds = new List<long> { aeIaChannelId }
        };

        Assert.True(TelegramUserbotService.ShouldCreateConversorAdminDraft(settings, aeIaChannelId, isGroupPeer: true));
        Assert.False(TelegramUserbotService.ShouldCreateConversorAdminDraft(settings, 5093308808, isGroupPeer: true));
        Assert.Equal("telegram:2425105459:4387", TelegramUserbotService.BuildTelegramConversorAdminMessageId(aeIaChannelId, 4387));
    }

    [Fact]
    public async Task ChannelOfferDeepAnalysisService_CreatesReelDraftAndConversorAdminUrl_ForTelegramVideoCandidate()
    {
        var candidateStore = new InMemoryCandidateStore();
        var publishStore = new InMemoryPublishStore();
        var composer = new StubComposer();
        var settingsStore = new StubSettingsStore(new AutomationSettings
        {
            InstagramPosts = new InstagramPostSettings
            {
                Enabled = true,
                AllowTelegramUserbot = true,
                TelegramAllowGroups = true,
                TelegramAllowPrivate = true,
                UseAi = false
            }
        });
        var affiliateLinkService = new StubAffiliateLinkService();
        var memoryStore = new StubWhatsAppAgentMemoryStore();
        var whatsAppOutboundLogStore = new StubWhatsAppOutboundLogStore();
        var telegramOutboundLogStore = new StubTelegramOutboundLogStore();

        using var httpClientFactory = new FakeHttpClientFactory(new StaticHtmlHandler());
        using var memoryCache = new MemoryCache(new MemoryCacheOptions());

        var affiliateOptions = Options.Create(new AffiliateOptions());
        var amazonPaApiClient = new AmazonPaApiClient(affiliateOptions, httpClientFactory, NullLogger<AmazonPaApiClient>.Instance);
        var amazonCreatorApiClient = new AmazonCreatorApiClient(affiliateOptions, httpClientFactory, NullLogger<AmazonCreatorApiClient>.Instance);
        var amazonHtmlScraper = new AmazonHtmlScraperService(httpClientFactory, memoryCache, NullLogger<AmazonHtmlScraperService>.Instance);
        var amazonPlaywrightScraper = new AmazonPlaywrightScraperClient(settingsStore, httpClientFactory, NullLogger<AmazonPlaywrightScraperClient>.Instance);
        var mercadoLivreHtmlScraper = new MercadoLivreHtmlScraperService(httpClientFactory, memoryCache, NullLogger<MercadoLivreHtmlScraperService>.Instance);
        var mercadoLivreOAuthService = new StubMercadoLivreOAuthService();
        var officialProductDataService = new OfficialProductDataService(
            amazonPaApiClient,
            amazonCreatorApiClient,
            amazonHtmlScraper,
            amazonPlaywrightScraper,
            mercadoLivreHtmlScraper,
            mercadoLivreOAuthService,
            affiliateOptions,
            httpClientFactory,
            memoryCache,
            NullLogger<OfficialProductDataService>.Instance);
        var metaService = new InstagramLinkMetaService(
            httpClientFactory,
            amazonPaApiClient,
            amazonHtmlScraper,
            NullLogger<InstagramLinkMetaService>.Instance);

        var service = new ChannelOfferDeepAnalysisService(
            candidateStore,
            memoryStore,
            whatsAppOutboundLogStore,
            telegramOutboundLogStore,
            publishStore,
            composer,
            settingsStore,
            affiliateLinkService,
            officialProductDataService,
            metaService,
            CreateUninitialized<OpenAiInstagramPostGenerator>(),
            CreateUninitialized<GeminiInstagramPostGenerator>(),
            CreateUninitialized<DeepSeekInstagramPostGenerator>(),
            CreateUninitialized<NemotronInstagramPostGenerator>(),
            CreateUninitialized<QwenInstagramPostGenerator>(),
            CreateUninitialized<VilaNvidiaGenerator>());

        var candidate = new ChannelOfferCandidate
        {
            SourceChannel = "telegram",
            MessageId = "telegram:12345:67890",
            ChatId = "12345",
            ChatTitle = "AE-IA 3000 - VÍDEOS VIRAIS",
            SourceText = "Panela de Pressão Brinox 4,2L Bege Vanilla https://www.mercadolivre.com.br/p/MLB22663071?matt_tool=98187057&matt_word=land177",
            EffectiveText = "Panela de Pressão Brinox 4,2L Bege Vanilla https://www.mercadolivre.com.br/p/MLB22663071?matt_tool=98187057&matt_word=land177",
            MediaUrl = "https://cdn.example.com/reel.mp4",
            MediaKind = "video",
            IsPrimarySourceGroup = true
        };
        await candidateStore.UpsertManyAsync(new[] { candidate }, CancellationToken.None);

        var result = await service.AnalyzeAsync(
            new ChannelOfferDeepAnalysisRequest
            {
                MessageId = candidate.MessageId,
                SourceChannel = "telegram",
                CreateDraft = true,
                UseAiReasoning = false
            },
            CancellationToken.None);

        Assert.Equal("telegram", result.SourceChannel);
        Assert.Equal(candidate.MessageId, result.MessageId);
        Assert.Equal("reel", result.SuggestedPostType);
        Assert.True(result.OfferUrlWasConverted);
        Assert.Equal("https://reidasofertas.ia.br/r/ML-000354", result.OfferUrl);
        Assert.Equal("https://www.mercadolivre.com.br/p/MLB22663071?matt_tool=98187057&matt_word=land177", result.OriginalSelectedOfferUrl);
        Assert.NotNull(result.DraftId);
        Assert.Equal($"/studio-ofertas?draftId={result.DraftId}", result.EditorUrl);

        var draft = await publishStore.GetAsync(result.DraftId!, CancellationToken.None);
        Assert.NotNull(draft);
        Assert.Equal("reel", draft!.PostType);
        Assert.Equal("Panela de Pressão Brinox 4,2L Bege Vanilla", draft.ProductName);
        Assert.Contains("AE-IA 3000 - VÍDEOS VIRAIS", draft.SourceDataOrigin, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("telegram", draft.SourceDataOrigin, StringComparison.OrdinalIgnoreCase);
        Assert.Equal("https://cdn.example.com/reel.mp4", draft.VideoUrl);
        Assert.Contains(draft.SuggestedVideoUrls, url => string.Equals(url, "https://cdn.example.com/reel.mp4", StringComparison.OrdinalIgnoreCase));
        Assert.Contains("Panela de Pressão Brinox 4,2L Bege Vanilla", draft.Caption, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("https://reidasofertas.ia.br/r/ML-000354", draft.Caption, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Acesse a bio e entre no catalogo", draft.Caption, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Comente QUERO", draft.AutoReplyMessage, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("https://reidasofertas.ia.br/r/ML-000354", draft.AutoReplyMessage, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("#achadinhos", draft.Hashtags, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("#tecnologia", draft.Hashtags, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task TelegramVideoCandidate_CanFlowIntoReelWhatsAppAndCatalogPublish()
    {
        const long telegramChannelId = 2425105459;
        const string messageId = "telegram:2425105459:67890";

        var candidateStore = new InMemoryCandidateStore();
        var publishStore = new InMemoryPublishStore();
        var settings = new AutomationSettings
        {
            InstagramPosts = new InstagramPostSettings
            {
                Enabled = true,
                AllowTelegramUserbot = true,
                TelegramAllowGroups = true,
                TelegramAllowPrivate = true,
                UseAi = false
            },
            InstagramPublish = new InstagramPublishSettings
            {
                Enabled = true,
                AccessToken = "token-123",
                InstagramUserId = "ig-user",
                CatalogTarget = CatalogTargets.Prod,
                SendToCatalog = true
            }
        };
        var settingsStore = new StubSettingsStore(settings);
        var affiliateLinkService = new StubAffiliateLinkService();
        var memoryStore = new StubWhatsAppAgentMemoryStore();
        var whatsAppOutboundLogStore = new StubWhatsAppOutboundLogStore();
        var telegramOutboundLogStore = new StubTelegramOutboundLogStore();

        using var httpClientFactory = new FakeHttpClientFactory(new StaticHtmlHandler());
        using var memoryCache = new MemoryCache(new MemoryCacheOptions());

        var affiliateOptions = Options.Create(new AffiliateOptions());
        var amazonPaApiClient = new AmazonPaApiClient(affiliateOptions, httpClientFactory, NullLogger<AmazonPaApiClient>.Instance);
        var amazonCreatorApiClient = new AmazonCreatorApiClient(affiliateOptions, httpClientFactory, NullLogger<AmazonCreatorApiClient>.Instance);
        var amazonHtmlScraper = new AmazonHtmlScraperService(httpClientFactory, memoryCache, NullLogger<AmazonHtmlScraperService>.Instance);
        var amazonPlaywrightScraper = new AmazonPlaywrightScraperClient(settingsStore, httpClientFactory, NullLogger<AmazonPlaywrightScraperClient>.Instance);
        var mercadoLivreHtmlScraper = new MercadoLivreHtmlScraperService(httpClientFactory, memoryCache, NullLogger<MercadoLivreHtmlScraperService>.Instance);
        var mercadoLivreOAuthService = new StubMercadoLivreOAuthService();
        var officialProductDataService = new OfficialProductDataService(
            amazonPaApiClient,
            amazonCreatorApiClient,
            amazonHtmlScraper,
            amazonPlaywrightScraper,
            mercadoLivreHtmlScraper,
            mercadoLivreOAuthService,
            affiliateOptions,
            httpClientFactory,
            memoryCache,
            NullLogger<OfficialProductDataService>.Instance);
        var metaService = new InstagramLinkMetaService(
            httpClientFactory,
            amazonPaApiClient,
            amazonHtmlScraper,
            NullLogger<InstagramLinkMetaService>.Instance);

        var analysisService = new ChannelOfferDeepAnalysisService(
            candidateStore,
            memoryStore,
            whatsAppOutboundLogStore,
            telegramOutboundLogStore,
            publishStore,
            new StubComposer(),
            settingsStore,
            affiliateLinkService,
            officialProductDataService,
            metaService,
            CreateUninitialized<OpenAiInstagramPostGenerator>(),
            CreateUninitialized<GeminiInstagramPostGenerator>(),
            CreateUninitialized<DeepSeekInstagramPostGenerator>(),
            CreateUninitialized<NemotronInstagramPostGenerator>(),
            CreateUninitialized<QwenInstagramPostGenerator>(),
            CreateUninitialized<VilaNvidiaGenerator>());

        var candidate = new ChannelOfferCandidate
        {
            SourceChannel = "telegram",
            MessageId = messageId,
            ChatId = telegramChannelId.ToString(),
            ChatTitle = "AE-IA 3000 - VÃDEOS VIRAIS",
            SourceText = "Panela de PressÃ£o Brinox 4,2L Bege Vanilla https://www.mercadolivre.com.br/p/MLB22663071?matt_tool=98187057&matt_word=land177",
            EffectiveText = "Panela de PressÃ£o Brinox 4,2L Bege Vanilla https://www.mercadolivre.com.br/p/MLB22663071?matt_tool=98187057&matt_word=land177",
            MediaUrl = "https://cdn.example.com/reel.mp4",
            MediaKind = "video",
            IsPrimarySourceGroup = true
        };
        await candidateStore.UpsertManyAsync(new[] { candidate }, CancellationToken.None);

        var analysisResult = await analysisService.AnalyzeAsync(
            new ChannelOfferDeepAnalysisRequest
            {
                MessageId = messageId,
                SourceChannel = "telegram",
                CreateDraft = true,
                UseAiReasoning = false
            },
            CancellationToken.None);

        Assert.Equal("reel", analysisResult.SuggestedPostType);
        Assert.True(analysisResult.OfferUrlWasConverted);
        Assert.Equal("https://reidasofertas.ia.br/r/ML-000354", analysisResult.OfferUrl);

        var draft = await publishStore.GetAsync(analysisResult.DraftId!, CancellationToken.None);
        Assert.NotNull(draft);
        Assert.Equal("reel", draft!.PostType);
        Assert.Equal("https://cdn.example.com/reel.mp4", draft.VideoUrl);
        Assert.True(draft.SendToCatalog);
        Assert.Equal(CatalogTargets.Prod, draft.CatalogTarget);
        Assert.Contains("Acesse a bio e entre no catalogo", draft.Caption, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("https://reidasofertas.ia.br/r/ML-000354", draft.AutoReplyMessage, StringComparison.OrdinalIgnoreCase);

        var metaGraphClient = new RecordingMetaGraphClient();
        var catalogStore = new RecordingCatalogOfferStore();
        var instagramService = new InstagramPublishService(
            settingsStore,
            publishStore,
            new StubPublishLogStore(),
            httpClientFactory,
            new InMemoryMediaStore(),
            metaGraphClient,
            new StubVideoProcessingService(),
            new NoopInstagramOutboundPublisher(),
            new InMemoryInstagramOutboxStore(),
            catalogStore,
            new StubIdempotencyStore(),
            Options.Create(new WebhookOptions { PublicBaseUrl = "https://bot.example.com" }),
            NullLogger<InstagramPublishService>.Instance);

        var whatsappGateway = new RecordingWhatsAppGateway();
        var whatsappResult = await whatsappGateway.SendTextAsync(
            "ZapOfertas",
            "120363405661434395@g.us",
            draft.AutoReplyMessage ?? draft.Caption,
            CancellationToken.None);

        var instagramResult = await instagramService.ExecutePublishAsync(draft.Id, CancellationToken.None);

        Assert.True(whatsappResult.Success);
        Assert.Single(whatsappGateway.TextMessages);
        Assert.Contains("https://reidasofertas.ia.br/r/ML-000354", whatsappGateway.TextMessages[0].Text, StringComparison.OrdinalIgnoreCase);
        Assert.True(instagramResult.Success);
        Assert.Equal("reel", metaGraphClient.LastPostType);
        Assert.Contains("Acesse a bio e entre no catalogo", metaGraphClient.LastCaption ?? string.Empty, StringComparison.OrdinalIgnoreCase);
        Assert.Single(metaGraphClient.LastMediaUrls);
        Assert.Equal("https://cdn.example.com/reel.mp4", metaGraphClient.LastMediaUrls[0]);
        Assert.Single(catalogStore.SyncedDraftIds);
        Assert.Equal(draft.Id, catalogStore.SyncedDraftIds[0]);
        Assert.Equal("published", (await publishStore.GetAsync(draft.Id, CancellationToken.None))?.Status);
    }

    [Fact]
    public void ParseInstagramTypeCommandInput_AllowsReel()
    {
        var result = InstagramCommandParser.ParseInstagramTypeCommandInput("ultimo reel");

        Assert.Equal("ultimo", result.DraftRef);
        Assert.Equal("reel", result.PostType);
        Assert.Null(result.Error);
    }

    private static T CreateUninitialized<T>() where T : class
        => (T)FormatterServices.GetUninitializedObject(typeof(T));

    private sealed class InMemoryCandidateStore : IChannelOfferCandidateStore
    {
        private readonly Dictionary<string, ChannelOfferCandidate> _items = new(StringComparer.OrdinalIgnoreCase);

        public Task UpsertManyAsync(IEnumerable<ChannelOfferCandidate> candidates, CancellationToken cancellationToken)
        {
            foreach (var candidate in candidates)
            {
                if (string.IsNullOrWhiteSpace(candidate.SourceChannel) || string.IsNullOrWhiteSpace(candidate.MessageId))
                {
                    continue;
                }

                _items[$"{candidate.SourceChannel}:{candidate.MessageId}"] = candidate;
            }

            return Task.CompletedTask;
        }

        public Task<ChannelOfferCandidate?> GetAsync(string sourceChannel, string messageId, CancellationToken cancellationToken)
        {
            _items.TryGetValue($"{sourceChannel}:{messageId}", out var candidate);
            return Task.FromResult(candidate);
        }
    }

    private sealed class InMemoryPublishStore : IInstagramPublishStore
    {
        private readonly Dictionary<string, InstagramPublishDraft> _items = new(StringComparer.OrdinalIgnoreCase);

        public Task<IReadOnlyList<InstagramPublishDraft>> ListAsync(CancellationToken ct)
            => Task.FromResult<IReadOnlyList<InstagramPublishDraft>>(_items.Values.OrderByDescending(x => x.CreatedAt).ToList());

        public Task<InstagramPublishDraft?> GetAsync(string id, CancellationToken ct)
        {
            _items.TryGetValue(id, out var draft);
            return Task.FromResult(draft);
        }

        public Task SaveAsync(InstagramPublishDraft draft, CancellationToken ct)
        {
            _items[draft.Id] = draft;
            return Task.CompletedTask;
        }

        public Task UpdateAsync(InstagramPublishDraft draft, CancellationToken ct)
        {
            _items[draft.Id] = draft;
            return Task.CompletedTask;
        }

        public Task ClearAsync(CancellationToken ct)
        {
            _items.Clear();
            return Task.CompletedTask;
        }
    }

    private sealed class StubComposer : IInstagramPostComposer
    {
        public Task<string> BuildAsync(string productInput, string? offerContext, InstagramPostSettings settings, CancellationToken cancellationToken)
        {
            var linkLine = string.IsNullOrWhiteSpace(offerContext)
                ? "Abra o link convertido para ver o preço atualizado."
                : $"Abra o link convertido para ver o preço atualizado: {offerContext}";

            var caption = $"""
            Legenda 1: {productInput} entrega um upgrade real, com cara de achado forte e utilidade imediata para o dia a dia.

            Legenda 2: Se você queria uma oferta bonita, prática e com potencial de clique, esse é o tipo de vídeo que vale salvar agora.

            CTA: Comente QUERO e {linkLine}

            Hashtags sugeridas: #achadinhos #ofertas #promocao #compras #tecnologia
            """;

            return Task.FromResult(caption);
        }

        public Task<string> SuggestHashtagsAsync(string productName, InstagramPostSettings settings, CancellationToken cancellationToken)
            => Task.FromResult("#achadinhos #ofertas #promocao #compras #tecnologia");
    }

    private sealed class StubSettingsStore : ISettingsStore
    {
        private readonly AutomationSettings _settings;

        public StubSettingsStore(AutomationSettings settings)
        {
            _settings = settings;
        }

        public Task<AutomationSettings> GetAsync(CancellationToken cancellationToken)
            => Task.FromResult(_settings);

        public Task SaveAsync(AutomationSettings settings, CancellationToken cancellationToken)
            => Task.CompletedTask;
    }

    private sealed class StubAffiliateLinkService : IAffiliateLinkService
    {
        public Task<AffiliateLinkResult> ConvertAsync(string rawUrl, CancellationToken cancellationToken, string? source = null, bool forceResolution = false)
        {
            if (rawUrl.Contains("MLB22663071", StringComparison.OrdinalIgnoreCase))
            {
                return Task.FromResult(new AffiliateLinkResult(true, "https://reidasofertas.ia.br/r/ML-000354", "Mercado Livre", true, null, null, true, "URL convertida para afiliado oficial."));
            }

            return Task.FromResult(new AffiliateLinkResult(true, "https://afiliado.example/oferta", "link", true, null, null, true, "URL convertida para afiliado oficial."));
        }
    }

    private sealed class StubWhatsAppAgentMemoryStore : IWhatsAppAgentMemoryStore
    {
        public Task AppendAsync(WhatsAppAgentMemoryEntry entry, CancellationToken cancellationToken) => Task.CompletedTask;

        public Task<IReadOnlyDictionary<string, WhatsAppAgentMemoryEntry>> GetLatestByMessageIdsAsync(IEnumerable<string> messageIds, CancellationToken cancellationToken)
            => Task.FromResult<IReadOnlyDictionary<string, WhatsAppAgentMemoryEntry>>(new Dictionary<string, WhatsAppAgentMemoryEntry>());
    }

    private sealed class StubWhatsAppOutboundLogStore : IWhatsAppOutboundLogStore
    {
        public Task AppendAsync(WhatsAppOutboundLogEntry entry, CancellationToken cancellationToken) => Task.CompletedTask;

        public Task<IReadOnlyList<WhatsAppOutboundLogEntry>> ListRecentAsync(int limit, CancellationToken cancellationToken)
            => Task.FromResult<IReadOnlyList<WhatsAppOutboundLogEntry>>(Array.Empty<WhatsAppOutboundLogEntry>());

        public Task<WhatsAppOutboundLogEntry?> GetAsync(string messageId, CancellationToken cancellationToken)
            => Task.FromResult<WhatsAppOutboundLogEntry?>(null);
    }

    private sealed class StubTelegramOutboundLogStore : ITelegramOutboundLogStore
    {
        public Task AppendAsync(TelegramOutboundLogEntry entry, CancellationToken cancellationToken) => Task.CompletedTask;

        public Task<IReadOnlyList<TelegramOutboundLogEntry>> ListRecentAsync(int limit, CancellationToken cancellationToken)
            => Task.FromResult<IReadOnlyList<TelegramOutboundLogEntry>>(Array.Empty<TelegramOutboundLogEntry>());

        public Task<TelegramOutboundLogEntry?> GetAsync(string messageId, CancellationToken cancellationToken)
            => Task.FromResult<TelegramOutboundLogEntry?>(null);
    }

    private sealed class StubMercadoLivreOAuthService : IMercadoLivreOAuthService
    {
        public Task<string?> GetAccessTokenAsync(CancellationToken cancellationToken) => Task.FromResult<string?>(null);

        public Task<MercadoLivreOAuthStatus> GetStatusAsync(CancellationToken cancellationToken)
            => Task.FromResult(new MercadoLivreOAuthStatus(false, false, "stub", null, null, null, null, false));

        public Task<MercadoLivreOAuthStatus> RefreshAndCheckAsync(CancellationToken cancellationToken)
            => Task.FromResult(new MercadoLivreOAuthStatus(false, false, "stub", null, null, null, null, false));
    }

    private sealed class StubPublishLogStore : IInstagramPublishLogStore
    {
        public Task AppendAsync(AchadinhosBot.Next.Domain.Logs.InstagramPublishLogEntry entry, CancellationToken ct) => Task.CompletedTask;
        public Task<IReadOnlyList<AchadinhosBot.Next.Domain.Logs.InstagramPublishLogEntry>> ListAsync(int take, CancellationToken ct)
            => Task.FromResult<IReadOnlyList<AchadinhosBot.Next.Domain.Logs.InstagramPublishLogEntry>>(Array.Empty<AchadinhosBot.Next.Domain.Logs.InstagramPublishLogEntry>());
        public Task ClearAsync(CancellationToken ct) => Task.CompletedTask;
    }

    private sealed class NoopInstagramOutboundPublisher : IInstagramOutboundPublisher
    {
        public Task PublishAsync(PublishInstagramPostCommand command, CancellationToken cancellationToken) => Task.CompletedTask;
        public Task PublishAsync(ReplyInstagramCommentCommand command, CancellationToken cancellationToken) => Task.CompletedTask;
        public Task PublishAsync(SendInstagramDirectMessageCommand command, CancellationToken cancellationToken) => Task.CompletedTask;
    }

    private sealed class StubIdempotencyStore : IIdempotencyStore
    {
        private readonly HashSet<string> _keys = new(StringComparer.OrdinalIgnoreCase);
        public bool TryBegin(string key, TimeSpan ttl) => _keys.Add(key);
        public void RemoveByPrefix(string prefix) { }
    }

    private sealed class InMemoryInstagramOutboxStore : IInstagramOutboundOutboxStore
    {
        private readonly List<InstagramOutboundEnvelope> _items = new();

        public Task SaveAsync(InstagramOutboundEnvelope envelope, CancellationToken cancellationToken)
        {
            _items.Add(envelope);
            return Task.CompletedTask;
        }

        public Task<IReadOnlyList<InstagramOutboundEnvelope>> ListPendingAsync(CancellationToken cancellationToken)
            => Task.FromResult<IReadOnlyList<InstagramOutboundEnvelope>>(_items.ToList());

        public Task DeleteAsync(string messageId, CancellationToken cancellationToken)
        {
            _items.RemoveAll(x => string.Equals(x.MessageId, messageId, StringComparison.OrdinalIgnoreCase));
            return Task.CompletedTask;
        }
    }

    private sealed class RecordingMetaGraphClient : IMetaGraphClient
    {
        public string? LastPostType { get; private set; }
        public string? LastCaption { get; private set; }
        public IReadOnlyList<string> LastMediaUrls { get; private set; } = Array.Empty<string>();

        public Task<MetaGraphOperationResult> ValidateConfigurationAsync(InstagramPublishSettings settings, CancellationToken cancellationToken)
            => Task.FromResult(new MetaGraphOperationResult(true));

        public Task<MetaGraphOperationResult> GetMediaStatusAsync(InstagramPublishSettings settings, string mediaId, CancellationToken cancellationToken)
            => Task.FromResult(new MetaGraphOperationResult(true, RawResponse: "{}"));

        public Task<MetaGraphPublishResult> PublishAsync(InstagramPublishSettings settings, string postType, IReadOnlyList<string> mediaUrls, string caption, CancellationToken cancellationToken)
        {
            LastPostType = postType;
            LastCaption = caption;
            LastMediaUrls = mediaUrls.ToList();
            return Task.FromResult(new MetaGraphPublishResult(true, "media-1"));
        }

        public Task<MetaGraphOperationResult> ReplyToCommentAsync(InstagramPublishSettings settings, string commentId, string message, CancellationToken cancellationToken)
            => Task.FromResult(new MetaGraphOperationResult(true));

        public Task<MetaGraphOperationResult> SendDirectMessageAsync(InstagramPublishSettings settings, string recipientId, string message, CancellationToken cancellationToken)
            => Task.FromResult(new MetaGraphOperationResult(true));
    }

    private sealed class StubVideoProcessingService : IVideoProcessingService
    {
        public Task<VideoProcessingResult> PrepareForInstagramPublicationAsync(
            InstagramPublishDraft draft,
            string? publicBaseUrl,
            CancellationToken cancellationToken)
            => Task.FromResult(new VideoProcessingResult(true, draft.VideoUrl, draft.VideoCoverUrl, false, null));
    }

    private sealed class RecordingCatalogOfferStore : ICatalogOfferStore
    {
        public List<string> SyncedDraftIds { get; } = new();

        public Task<CatalogSyncResult> SyncFromPublishedDraftsAsync(IReadOnlyList<InstagramPublishDraft> drafts, CancellationToken cancellationToken)
        {
            SyncedDraftIds.AddRange(drafts.Select(x => x.Id));
            return Task.FromResult(new CatalogSyncResult
            {
                Created = drafts.Count,
                TotalActive = drafts.Count,
                HighestItemNumber = drafts.Count
            });
        }

        public Task<IReadOnlyList<CatalogOfferItem>> ListAsync(string? search, int limit, CancellationToken cancellationToken, string? catalogTarget = null)
            => Task.FromResult<IReadOnlyList<CatalogOfferItem>>(Array.Empty<CatalogOfferItem>());

        public Task<CatalogOfferItem?> FindByCodeAsync(string query, CancellationToken cancellationToken, string? catalogTarget = null)
            => Task.FromResult<CatalogOfferItem?>(null);

        public Task<IReadOnlyDictionary<string, CatalogOfferItem>> GetByDraftIdAsync(CancellationToken cancellationToken, string? catalogTarget = null)
            => Task.FromResult<IReadOnlyDictionary<string, CatalogOfferItem>>(new Dictionary<string, CatalogOfferItem>());
    }

    private sealed class RecordingWhatsAppGateway : IWhatsAppGateway
    {
        public List<(string? InstanceName, string To, string Text)> TextMessages { get; } = new();

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
            => Task.FromResult(new WhatsAppSendResult(true, "ok"));

        public Task<WhatsAppSendResult> UpdateProfilePictureAsync(string? instanceName, string picture, CancellationToken cancellationToken)
            => Task.FromResult(new WhatsAppSendResult(true, "ok"));

        public Task<WhatsAppSendResult> DeleteMessageAsync(string? instanceName, string chatId, string messageId, bool isGroup, CancellationToken cancellationToken)
            => Task.FromResult(new WhatsAppSendResult(true, "ok"));

        public Task<IReadOnlyList<string>> GetGroupParticipantsAsync(string? instanceName, string groupId, CancellationToken cancellationToken)
            => Task.FromResult<IReadOnlyList<string>>(Array.Empty<string>());

        public Task<WhatsAppSendResult> AddParticipantsAsync(string? instanceName, string groupId, IReadOnlyList<string> participantJids, CancellationToken cancellationToken)
            => Task.FromResult(new WhatsAppSendResult(true, "ok"));
    }

    private sealed class StaticHtmlHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var response = new HttpResponseMessage(System.Net.HttpStatusCode.OK)
            {
                Content = new StringContent("<html><head><title>Panela de Pressão Brinox 4,2L Bege Vanilla</title><meta name=\"description\" content=\"Panela de Pressão Brinox 4,2L Bege Vanilla com link convertido e vídeo para reel\"></head><body>ok</body></html>")
            };
            return Task.FromResult(response);
        }
    }

    private sealed class FakeHttpClientFactory : IHttpClientFactory, IDisposable
    {
        private readonly HttpClient _client;

        public FakeHttpClientFactory(HttpMessageHandler handler)
        {
            _client = new HttpClient(handler, disposeHandler: false);
        }

        public HttpClient CreateClient(string name) => _client;

        public void Dispose() => _client.Dispose();
    }
}
