using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Application.Consumers;
using AchadinhosBot.Next.Application.Services;
using AchadinhosBot.Next.Configuration;
using AchadinhosBot.Next.Infrastructure.Amazon;
using AchadinhosBot.Next.Infrastructure.Audit;
using AchadinhosBot.Next.Infrastructure.Catalog;
using AchadinhosBot.Next.Infrastructure.Content;
using AchadinhosBot.Next.Infrastructure.Coupons;
using AchadinhosBot.Next.Infrastructure.Idempotency;
using AchadinhosBot.Next.Infrastructure.Instagram;
using AchadinhosBot.Next.Infrastructure.Media;
using AchadinhosBot.Next.Infrastructure.MercadoLivre;
using AchadinhosBot.Next.Infrastructure.Monitoring;
using AchadinhosBot.Next.Infrastructure.ProductData;
using AchadinhosBot.Next.Infrastructure.Resilience;
using AchadinhosBot.Next.Infrastructure.Safety;
using AchadinhosBot.Next.Infrastructure.Security;
using AchadinhosBot.Next.Infrastructure.Storage;
using AchadinhosBot.Next.Infrastructure.Telegram;
using AchadinhosBot.Next.Infrastructure.WhatsApp;
using MassTransit;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.Options;

namespace AchadinhosBot.Next;

public static class StartupServiceRegistrationExtensions
{
    public static void AddAchadinhosRuntimeComposition(
        this WebApplicationBuilder builder,
        bool startTelegramBotWorker,
        bool startTelegramUserbotWorker)
    {
        builder.Services.AddMemoryCache();
        builder.Services.AddHttpContextAccessor();
        builder.Services
            .AddOptions<OperationalReadinessOptions>()
            .Bind(builder.Configuration.GetSection("OperationalReadiness"));

        builder.Services.AddRateLimiter(options =>
        {
            options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
            options.AddFixedWindowLimiter("login", l =>
            {
                l.PermitLimit = 10;
                l.Window = TimeSpan.FromMinutes(1);
                l.QueueLimit = 0;
            });
            options.AddFixedWindowLimiter("converter", l =>
            {
                l.PermitLimit = 100;
                l.Window = TimeSpan.FromMinutes(1);
                l.QueueLimit = 0;
            });
        });

        builder.Services.AddHttpClient("default", c =>
        {
            c.Timeout = TimeSpan.FromSeconds(60);
            c.DefaultRequestHeaders.UserAgent.ParseAdd("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36");
            c.DefaultRequestHeaders.Accept.ParseAdd("text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8");
        }).ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler
        {
            AllowAutoRedirect = true,
            UseCookies = true,
            CookieContainer = new System.Net.CookieContainer()
        }).AddPolicyHandler(ResiliencyPolicies.GetRetryPolicy());

        builder.Services.AddHttpClient("evolution", c => c.Timeout = TimeSpan.FromSeconds(30)).AddPolicyHandler(ResiliencyPolicies.GetRetryPolicy());
        builder.Services.AddHttpClient("evolution-groups", c => c.Timeout = TimeSpan.FromSeconds(120)).AddPolicyHandler(ResiliencyPolicies.GetRetryPolicy());
        builder.Services.AddHttpClient("openai", c => c.Timeout = TimeSpan.FromSeconds(60)).AddPolicyHandler(ResiliencyPolicies.GetRetryPolicy());
        builder.Services.AddHttpClient("gemini", c => c.Timeout = TimeSpan.FromSeconds(60)).AddPolicyHandler(ResiliencyPolicies.GetRetryPolicy());
        builder.Services.AddHttpClient("deepseek", c => c.Timeout = TimeSpan.FromSeconds(60)).AddPolicyHandler(ResiliencyPolicies.GetRetryPolicy());
        builder.Services.AddHttpClient("nemotron", c => c.Timeout = TimeSpan.FromSeconds(60)).AddPolicyHandler(ResiliencyPolicies.GetRetryPolicy());
        builder.Services.AddHttpClient("qwen", c => c.Timeout = TimeSpan.FromSeconds(60)).AddPolicyHandler(ResiliencyPolicies.GetRetryPolicy());

        builder.Services.AddSingleton<IAffiliateLinkService, AffiliateLinkService>();
        builder.Services.AddSingleton<AmazonCreatorApiClient>();
        builder.Services.AddSingleton<AmazonPaApiClient>();
        builder.Services.AddSingleton<AmazonHtmlScraperService>();
        builder.Services.AddSingleton<AmazonPlaywrightScraperClient>();
        builder.Services.AddSingleton<AmazonStoreImageScraper>();
        builder.Services.AddSingleton<MercadoLivreHtmlScraperService>();
        builder.Services.AddSingleton<MercadoLivreStoreImageScraper>();
        builder.Services.AddSingleton<IAffiliateCouponSyncService, AffiliateCouponSyncService>();
        builder.Services.AddSingleton<IAffiliateCouponProvider, AmazonOfficialCouponProvider>();
        builder.Services.AddSingleton<IAffiliateCouponProvider, ShopeeOfficialCouponProvider>();
        builder.Services.AddSingleton<IAffiliateCouponProvider, SheinOfficialCouponProvider>();
        builder.Services.AddSingleton<IAffiliateCouponProvider, MercadoLivreOfficialCouponProvider>();
        builder.Services.AddSingleton<IMercadoLivreOAuthService, MercadoLivreOAuthService>();
        builder.Services.AddSingleton<IConversionLogStore, ConversionLogStore>();
        builder.Services.AddSingleton<ICouponSelector, CouponSelector>();
        builder.Services.AddSingleton<ILinkTrackingStore, LinkTrackingStore>();
        builder.Services.AddSingleton<ICatalogOfferStore, CatalogOfferStore>();
        builder.Services.AddSingleton<IContentCalendarStore, CsvContentCalendarStore>();
        builder.Services.AddSingleton<IClickLogStore, ClickLogStore>();
        builder.Services.AddSingleton<IInstagramAiLogStore, InstagramAiLogStore>();
        builder.Services.AddSingleton<IInstagramPublishLogStore, InstagramPublishLogStore>();
        builder.Services.AddSingleton<InstagramLinkMetaService>();
        builder.Services.AddSingleton<OfficialProductDataService>();
        builder.Services.AddSingleton<ShopeeStoreImageScraper>();
        builder.Services.AddSingleton<ICatalogOfferEnrichmentService, CatalogOfferEnrichmentService>();
        builder.Services.AddSingleton<InstagramImageDownloadService>();
        builder.Services.AddSingleton<IMetaGraphClient, MetaGraphClient>();
        builder.Services.AddSingleton<IInstagramPublishService, InstagramPublishService>();
        builder.Services.AddSingleton<IVideoProcessingService, FfmpegVideoProcessingService>();
        builder.Services.AddSingleton<IMessageProcessor, MessageProcessor>();
        builder.Services.AddSingleton<IOperationalAnalyticsService, OperationalAnalyticsService>();
        builder.Services.AddSingleton<IOfferCurationAgentService, OfferCurationAgentService>();
        builder.Services.AddSingleton<IWhatsAppOfferScoutAgentService, WhatsAppOfferScoutAgentService>();
        builder.Services.AddSingleton<OfferNormalizationService>();
        builder.Services.AddSingleton<OfferNormalizationRoutingService>();
        builder.Services.AddSingleton<IChannelOfferDeepAnalysisService, ChannelOfferDeepAnalysisService>();
        builder.Services.AddSingleton<IWhatsAppOfferReasoner, WhatsAppOfferReasoner>();
        builder.Services.AddSingleton<OpenAiInstagramPostGenerator>();
        builder.Services.AddSingleton<GeminiInstagramPostGenerator>();
        builder.Services.AddSingleton<WhatsAppAiAgentService>();
        builder.Services.AddSingleton<DeepSeekInstagramPostGenerator>();
        builder.Services.AddSingleton<NemotronInstagramPostGenerator>();
        builder.Services.AddSingleton<QwenInstagramPostGenerator>();
        builder.Services.AddSingleton<VilaNvidiaGenerator>();
        builder.Services.AddSingleton<IInstagramPostComposer, InstagramPostComposer>();
        builder.Services.AddSingleton<IInstagramAutoPilotService, InstagramAutoPilotService>();
        builder.Services.AddSingleton<ContentCalendarAutomationService>();
        builder.Services.AddSingleton<IInstagramPublishStore, InstagramPublishStore>();
        builder.Services.AddSingleton<IInstagramCommentStore, InstagramCommentStore>();
        builder.Services.AddSingleton<IWhatsAppOutboundLogStore, WhatsAppOutboundLogStore>();
        builder.Services.AddSingleton<ITelegramOutboundLogStore, TelegramOutboundLogStore>();
        builder.Services.AddSingleton<IWhatsAppAgentMemoryStore, WhatsAppAgentMemoryStore>();
        builder.Services.AddSingleton<IChannelMonitorSelectionStore, ChannelMonitorSelectionStore>();
        builder.Services.AddSingleton<IChannelMonitorUiStateStore, ChannelMonitorUiStateStore>();
        builder.Services.AddSingleton<IChannelOfferCandidateStore, ChannelOfferCandidateStore>();
        builder.Services.AddSingleton<IOfferNormalizationRunStore, OfferNormalizationRunStore>();
        builder.Services.AddSingleton<IOfferAutomationIntentStore, OfferAutomationIntentStore>();
        builder.Services.AddSingleton<IMercadoLivreApprovalStore, MercadoLivreApprovalStore>();
        builder.Services.AddSingleton<JsonSettingsStore>();
        builder.Services.AddSingleton<ISettingsStore>(provider => provider.GetRequiredService<JsonSettingsStore>());
        builder.Services.AddSingleton<ISettingsVersionStore>(provider => provider.GetRequiredService<JsonSettingsStore>());
        builder.Services.AddSingleton<TrackingLinkShortenerService>();
        builder.Services.AddSingleton<IOfferImageResolver, OfferImageResolver>();
        builder.Services.AddSingleton<IStoreImageScraper>(provider => provider.GetRequiredService<ShopeeStoreImageScraper>());
        builder.Services.AddSingleton<IStoreImageScraper>(provider => provider.GetRequiredService<AmazonStoreImageScraper>());
        builder.Services.AddSingleton<IStoreImageScraper>(provider => provider.GetRequiredService<MercadoLivreStoreImageScraper>());
        builder.Services.AddSingleton<AffiliateTrackedContentService>();
        builder.Services.AddSingleton<WhatsAppPublishContentService>();
        builder.Services.AddSingleton<EvolutionWhatsAppGateway>();
        builder.Services.AddSingleton<IWhatsAppTransport>(provider => provider.GetRequiredService<EvolutionWhatsAppGateway>());
        builder.Services.AddSingleton<IWhatsAppGateway, QueuedWhatsAppGateway>();
        builder.Services.AddSingleton<IMediaStore, FileMediaStore>();
        builder.Services.AddSingleton<IMediaFailureLogStore, MediaFailureLogStore>();
        builder.Services.AddSingleton<IOfficialWhatsAppBlockedOfferStore, OfficialWhatsAppBlockedOfferStore>();
        builder.Services.AddSingleton<IWhatsAppParticipantBlastProgressStore, WhatsAppParticipantBlastProgressStore>();
        builder.Services.AddSingleton<IPromotionalCardGenerator, PromotionalCardGenerator>();
        builder.Services.AddSingleton<InstagramConversationStore>();
        builder.Services.AddSingleton<InstagramCommandMenuStore>();
        builder.Services.AddSingleton<WhatsAppHelpMenuStore>();
        builder.Services.AddSingleton<TelegramBotApiGateway>();
        builder.Services.AddSingleton<ITelegramTransport>(provider => provider.GetRequiredService<TelegramBotApiGateway>());
        builder.Services.AddSingleton<ITelegramGateway, QueuedTelegramGateway>();
        builder.Services.AddSingleton<IBotConversorQueuePublisher, RabbitMqBotConversorQueuePublisher>();
        builder.Services.AddSingleton<IBotConversorOutboxStore, FileBotConversorOutboxStore>();
        builder.Services.AddSingleton<IMessageOrchestrator, BotConversorMessageOrchestrator>();
        builder.Services.AddSingleton<IWhatsAppOutboundPublisher, RabbitMqWhatsAppOutboundPublisher>();
        builder.Services.AddSingleton<WhatsAppAutomationQueueService>();
        builder.Services.AddSingleton<IWhatsAppOutboundOutboxStore, FileWhatsAppOutboundOutboxStore>();
        builder.Services.AddSingleton<ITelegramOutboundPublisher, RabbitMqTelegramOutboundPublisher>();
        builder.Services.AddSingleton<ITelegramOutboundOutboxStore, FileTelegramOutboundOutboxStore>();
        builder.Services.AddSingleton<IInstagramOutboundPublisher, RabbitMqInstagramOutboundPublisher>();
        builder.Services.AddSingleton<IInstagramOutboundOutboxStore, FileInstagramOutboundOutboxStore>();
        builder.Services.AddSingleton<IIdempotencyStore, FileIdempotencyStore>();
        builder.Services.AddSingleton<TelegramAlertSender>();
        builder.Services.AddSingleton<WorkerActivityTracker>();
        builder.Services.AddSingleton<OperationalReadinessService>();
        builder.Services.AddSingleton<OperationalStatusService>();
        builder.Services.AddSingleton<IAuditTrail, FileAuditTrail>();
        builder.Services.AddSingleton<DeliverySafetyPolicy>();
        builder.Services.AddSingleton<LoginAttemptStore>();
        builder.Services.AddSingleton<IWhatsAppGroupMembershipStore, WhatsAppGroupMembershipStore>();
        builder.Services.AddSingleton<WhatsAppWelcomeJourneyStore>();
        builder.Services.AddSingleton<WhatsAppMembershipSyncService>();
        builder.Services.AddSingleton<WhatsAppAdminAutomationService>();

        if (startTelegramBotWorker)
        {
            builder.Services.AddHostedService<TelegramBotPollingService>();
        }

        builder.Services.AddSingleton<ITelegramUserbotService, TelegramUserbotService>();
        if (startTelegramUserbotWorker)
        {
            builder.Services.AddHostedService(provider => (TelegramUserbotService)provider.GetRequiredService<ITelegramUserbotService>());
        }

        builder.Services.AddHostedService<InstagramOutboundReplayService>();
        builder.Services.AddHostedService<BotConversorOutboxReplayWorker>();
        builder.Services.AddHostedService<WhatsAppOutboundReplayWorker>();
        builder.Services.AddHostedService<TelegramOutboundReplayWorker>();
        builder.Services.AddHostedService<InstagramScheduledPublishWorker>();
        builder.Services.AddHostedService<CatalogPriceRefreshWorker>();
        builder.Services.AddHostedService<UptimeHeartbeatService>();
        builder.Services.AddHostedService(provider => provider.GetRequiredService<WhatsAppMembershipSyncService>());
        builder.Services.AddHostedService<WhatsAppAdminAutomationWorker>();

        builder.Services.AddMassTransit(x =>
        {
            x.AddConsumer<BotConversorWebhookConsumer>();
            x.AddConsumer<EvolutionWebhookConsumer>();
            x.AddConsumer<WhatsAppOutboundConsumer>();
            x.AddConsumer<TelegramOutboundConsumer>();
            x.AddConsumer<InstagramPublishConsumer>();
            x.AddConsumer<InstagramCommentReplyConsumer>();
            x.AddConsumer<InstagramDirectMessageConsumer>();
            x.UsingRabbitMq((context, cfg) =>
            {
                var rabbitHost = builder.Configuration["RabbitMq:Host"] ?? "localhost";
                var rabbitVirtualHost = builder.Configuration["RabbitMq:VirtualHost"] ?? "/";
                var rabbitUser = builder.Configuration["RabbitMq:Username"] ?? "guest";
                var rabbitPass = builder.Configuration["RabbitMq:Password"] ?? "guest";
                cfg.Host(rabbitHost, rabbitVirtualHost, h =>
                {
                    h.Username(rabbitUser);
                    h.Password(rabbitPass);
                });
                cfg.ConfigureEndpoints(context);
            });
        });

        builder.Services.AddHttpClient("evolution-webhook-internal", (sp, client) =>
        {
            var opts = sp.GetRequiredService<IOptions<WebhookOptions>>().Value;
            client.BaseAddress = new Uri($"http://localhost:{opts.Port}");
        });
    }
}
