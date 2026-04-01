using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using System.Globalization;
using System.Runtime.Versioning;
using System.Net;
using System.Net.Http.Headers;
using System.IO;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Application.Services;
using AchadinhosBot.Next.Configuration;
using AchadinhosBot.Next.Endpoints;
using AchadinhosBot.Next.Domain.Agents;
using AchadinhosBot.Next.Domain.Logs;
using AchadinhosBot.Next.Domain.Instagram;
using AchadinhosBot.Next.Domain.Content;
using AchadinhosBot.Next.Domain.Compliance;
using AchadinhosBot.Next.Domain.Models;
using AchadinhosBot.Next.Domain.Offers;
using AchadinhosBot.Next.Domain.Requests;
using AchadinhosBot.Next.Domain.Settings;
using AchadinhosBot.Next.Infrastructure.Audit;
using AchadinhosBot.Next.Infrastructure.Coupons;
using AchadinhosBot.Next.Infrastructure.Amazon;
using AchadinhosBot.Next.Infrastructure.Idempotency;
using AchadinhosBot.Next.Infrastructure.Instagram;
using AchadinhosBot.Next.Infrastructure.Content;
using AchadinhosBot.Next.Infrastructure.Logs;
using AchadinhosBot.Next.Infrastructure.MercadoLivre;
using AchadinhosBot.Next.Infrastructure.Media;
using AchadinhosBot.Next.Infrastructure.Monitoring;
using AchadinhosBot.Next.Infrastructure.Security;
using AchadinhosBot.Next.Infrastructure.Storage;
using AchadinhosBot.Next.Infrastructure.Telegram;
using AchadinhosBot.Next.Infrastructure.ProductData;
using AchadinhosBot.Next.Infrastructure.WhatsApp;
using AchadinhosBot.Next.Infrastructure.Resilience;
using AchadinhosBot.Next.Infrastructure.Safety;
using Serilog;
using ILogger = Microsoft.Extensions.Logging.ILogger;

using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using MassTransit;
using AchadinhosBot.Next.Application.Consumers;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.Extensions.Options;

LoadDotEnvIfPresent();

var builder = WebApplication.CreateBuilder(args);
builder.WebHost.ConfigureKestrel(options =>
{
    options.Limits.MaxRequestBodySize = 256L * 1024L * 1024L;
});

builder.Services.Configure<FormOptions>(options =>
{
    options.MultipartBodyLengthLimit = 256L * 1024L * 1024L;
});

builder.Host.UseSerilog((context, services, configuration) => configuration
    .ReadFrom.Configuration(context.Configuration)
    .ReadFrom.Services(services)
    .Enrich.FromLogContext());

// Evita falha de permissao no EventLog em ambientes sem privilegio administrativo.
builder.Logging.ClearProviders();

// Persistir chaves de DataProtection em pasta local acessível ao sandbox
var dpKeysPath = Path.Combine(AppContext.BaseDirectory, ".runtime", "localappdata", "DataProtection-Keys");
Directory.CreateDirectory(dpKeysPath);
builder.Services.AddDataProtection()
    .PersistKeysToFileSystem(new DirectoryInfo(dpKeysPath));

// Mantem a API de pe mesmo que algum worker opcional (ex: Telegram) falhe.
builder.Services.Configure<HostOptions>(options =>
{
    options.BackgroundServiceExceptionBehavior = BackgroundServiceExceptionBehavior.Ignore;
});

builder.Services
    .AddOptions<WebhookOptions>()
    .Bind(builder.Configuration.GetSection("Webhook"))
    .ValidateDataAnnotations()
    .ValidateOnStart();

builder.Services
    .AddOptions<AffiliateOptions>()
    .Bind(builder.Configuration.GetSection("Affiliate"))
    .ValidateDataAnnotations()
    .ValidateOnStart();

builder.Services
    .AddOptions<TelegramOptions>()
    .Bind(builder.Configuration.GetSection("Telegram"))
    .ValidateDataAnnotations();

builder.Services
    .AddOptions<MessagingOptions>()
    .Bind(builder.Configuration.GetSection("Messaging"))
    .ValidateDataAnnotations()
    .ValidateOnStart();

var telegramStartupOptions = builder.Configuration.GetSection("Telegram").Get<TelegramOptions>() ?? new TelegramOptions();
var persistedTelegramBotTokenPath =
    Environment.GetEnvironmentVariable("TELEGRAM__BOTTOKEN_FILE")?.Trim()
    ?? Path.Combine(AppContext.BaseDirectory, "data", "telegram-bot-token.txt");
var hasPersistedTelegramBotToken = false;
try
{
    hasPersistedTelegramBotToken = File.Exists(persistedTelegramBotTokenPath)
        && !string.IsNullOrWhiteSpace(File.ReadAllText(persistedTelegramBotTokenPath).Trim());
}
catch
{
    hasPersistedTelegramBotToken = false;
}
var startTelegramBotWorker = !string.IsNullOrWhiteSpace(telegramStartupOptions.BotToken) || hasPersistedTelegramBotToken;
var startTelegramUserbotWorker = telegramStartupOptions.ApiId > 0 && !string.IsNullOrWhiteSpace(telegramStartupOptions.ApiHash);

builder.Services
    .AddOptions<AuthOptions>()
    .Bind(builder.Configuration.GetSection("Auth"))
    .ValidateDataAnnotations()
    .ValidateOnStart();

builder.Services
    .AddOptions<EvolutionOptions>()
    .Bind(builder.Configuration.GetSection("Evolution"))
    .ValidateDataAnnotations();

builder.Services
    .AddOptions<HeartbeatOptions>()
    .Bind(builder.Configuration.GetSection("Heartbeat"));

builder.Services
    .AddOptions<DeliverySafetyOptions>()
    .Bind(builder.Configuration.GetSection("DeliverySafety"));

builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.Cookie.Name = "achadinhos.next.auth";
        options.Cookie.HttpOnly = true;
        options.Cookie.SameSite = SameSiteMode.Strict;
        options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
        options.LoginPath = "/";
        options.ExpireTimeSpan = TimeSpan.FromHours(8);
        options.SlidingExpiration = true;
        options.Events.OnRedirectToLogin = ctx =>
        {
            ctx.Response.StatusCode = StatusCodes.Status401Unauthorized;
            return Task.CompletedTask;
        };
    });

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("AdminOnly", p => p.RequireRole("admin"));
    options.AddPolicy("ReadAccess", p => p.RequireRole("admin", "operator"));
});

builder.Services.AddMemoryCache();

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
builder.Services.AddSingleton<MercadoLivreHtmlScraperService>();
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
builder.Services.AddSingleton<ICatalogOfferEnrichmentService, CatalogOfferEnrichmentService>();
builder.Services.AddSingleton<InstagramImageDownloadService>();
builder.Services.AddSingleton<IMetaGraphClient, MetaGraphClient>();
builder.Services.AddSingleton<IInstagramPublishService, InstagramPublishService>();
builder.Services.AddSingleton<IVideoProcessingService, FfmpegVideoProcessingService>();
builder.Services.AddSingleton<IMessageProcessor, MessageProcessor>();
builder.Services.AddSingleton<IOperationalAnalyticsService, OperationalAnalyticsService>();
builder.Services.AddSingleton<IOfferCurationAgentService, OfferCurationAgentService>();
builder.Services.AddSingleton<IWhatsAppOfferScoutAgentService, WhatsAppOfferScoutAgentService>();
builder.Services.AddSingleton<IChannelOfferDeepAnalysisService, ChannelOfferDeepAnalysisService>();
builder.Services.AddSingleton<IWhatsAppOfferReasoner, WhatsAppOfferReasoner>();
builder.Services.AddSingleton<OpenAiInstagramPostGenerator>();
builder.Services.AddSingleton<GeminiInstagramPostGenerator>();
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
builder.Services.AddSingleton<OfferNormalizationService>();
builder.Services.AddSingleton<OfferNormalizationRoutingService>();
builder.Services.AddSingleton<IOfferNormalizationRunStore, OfferNormalizationRunStore>();
builder.Services.AddSingleton<IOfferAutomationIntentStore, OfferAutomationIntentStore>();
builder.Services.AddSingleton<IMercadoLivreApprovalStore, MercadoLivreApprovalStore>();
builder.Services.AddSingleton<ISettingsStore, JsonSettingsStore>();
builder.Services.AddSingleton<EvolutionWhatsAppGateway>();
builder.Services.AddSingleton<IWhatsAppTransport>(provider => provider.GetRequiredService<EvolutionWhatsAppGateway>());
builder.Services.AddSingleton<IWhatsAppGateway, QueuedWhatsAppGateway>();
builder.Services.AddSingleton<IMediaStore, FileMediaStore>();
builder.Services.AddSingleton<IMediaFailureLogStore, MediaFailureLogStore>();
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
builder.Services.AddSingleton<IWhatsAppOutboundOutboxStore, FileWhatsAppOutboundOutboxStore>();
builder.Services.AddSingleton<ITelegramOutboundPublisher, RabbitMqTelegramOutboundPublisher>();
builder.Services.AddSingleton<ITelegramOutboundOutboxStore, FileTelegramOutboundOutboxStore>();
builder.Services.AddSingleton<IInstagramOutboundPublisher, RabbitMqInstagramOutboundPublisher>();
builder.Services.AddSingleton<IInstagramOutboundOutboxStore, FileInstagramOutboundOutboxStore>();
builder.Services.AddSingleton<IIdempotencyStore, FileIdempotencyStore>();
builder.Services.AddSingleton<TelegramAlertSender>();

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
builder.Services.AddHostedService<InstagramScheduledPublishWorker>();

builder.Services.AddSingleton<IAuditTrail, FileAuditTrail>();
builder.Services.AddSingleton<DeliverySafetyPolicy>();
builder.Services.AddSingleton<LoginAttemptStore>();


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

builder.Services.AddHttpClient("evolution-webhook-internal", (sp, client) => {
    var opts = sp.GetRequiredService<IOptions<WebhookOptions>>().Value;
    client.BaseAddress = new Uri($"http://localhost:{opts.Port}");
});

var app = builder.Build();

var webhookOptions = app.Services.GetRequiredService<IOptions<WebhookOptions>>().Value;
app.Urls.Clear();
app.Urls.Add($"http://0.0.0.0:{webhookOptions.Port}");

// Ajuste para abrir dashboard.html quando acessar "/"
var defaultFilesOptions = new DefaultFilesOptions();
defaultFilesOptions.DefaultFileNames.Clear();
defaultFilesOptions.DefaultFileNames.Add("dashboard.html");

app.UseDefaultFiles(defaultFilesOptions);
app.UseStaticFiles(new StaticFileOptions
{
    OnPrepareResponse = ctx =>
    {
        var contentType = ctx.Context.Response.ContentType;
        if (string.IsNullOrWhiteSpace(contentType))
        {
            return;
        }

        if (contentType.StartsWith("text/html", StringComparison.OrdinalIgnoreCase) ||
            contentType.StartsWith("text/css", StringComparison.OrdinalIgnoreCase) ||
            contentType.StartsWith("application/javascript", StringComparison.OrdinalIgnoreCase) ||
            contentType.StartsWith("application/json", StringComparison.OrdinalIgnoreCase))
        {
            if (!contentType.Contains("charset=", StringComparison.OrdinalIgnoreCase))
            {
                ctx.Context.Response.ContentType = contentType + "; charset=utf-8";
            }
        }
    }
});
app.UseSerilogRequestLogging();
app.UseRateLimiter();
app.UseAuthentication();
app.UseAuthorization();

app.MapPost("/auth/login", async (
    LoginRequest request,
    IOptions<AuthOptions> authOptions,
    LoginAttemptStore attempts,
    IAuditTrail audit,
    HttpContext httpContext,
    CancellationToken ct) =>
{
    var ip = httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
    var key = $"{request.Username}:{ip}";

    if (attempts.IsLocked(key, DateTimeOffset.UtcNow))
    {
        await audit.WriteAsync("auth.login.locked", request.Username, new { ip }, ct);
        return Results.Json(new { success = false, error = "Conta temporariamente bloqueada" }, statusCode: StatusCodes.Status423Locked);
    }

    var user = authOptions.Value.Users.FirstOrDefault(x => x.Enabled && x.Username.Equals(request.Username, StringComparison.OrdinalIgnoreCase));
    Console.WriteLine($"[AUTH-DEBUG] Login attempt for user '{request.Username}'. Password length: {request.Password?.Length}. RememberMe: {request.RememberMe}");
    Console.WriteLine($"[AUTH-DEBUG] Loaded {authOptions.Value.Users?.Count ?? 0} users from configuration.");
    if (authOptions.Value.Users != null) {
        foreach (var u in authOptions.Value.Users) {
            Console.WriteLine($"[AUTH-DEBUG] Registered user: {u.Username}, Enabled: {u.Enabled}");
        }
    }
    Console.WriteLine($"[AUTH-DEBUG] Found matching user config: {user != null}");
    var valid = user is not null
        && !string.IsNullOrEmpty(request.Password)
        && PasswordHasher.Verify(request.Password, user.PasswordHash);
    Console.WriteLine($"[AUTH-DEBUG] Password valid: {valid}");

    if (!valid)
    {
        attempts.RegisterFailure(key, DateTimeOffset.UtcNow, 5, TimeSpan.FromMinutes(15));
        await audit.WriteAsync("auth.login.failed", request.Username, new { ip }, ct);
        return Results.Unauthorized();
    }

    attempts.RegisterSuccess(key);

    var claims = new[]
    {
        new Claim(ClaimTypes.Name, user!.Username),
        new Claim(ClaimTypes.Role, user.Role)
    };

    var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
    var authProps = new AuthenticationProperties();
    if (request.RememberMe) {
        authProps.IsPersistent = true;
        authProps.ExpiresUtc = DateTimeOffset.UtcNow.AddDays(30);
    }
    await httpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(identity), authProps);
    await audit.WriteAsync("auth.login.success", user.Username, new { ip, role = user.Role }, ct);
    return Results.Ok(new { success = true, username = user.Username, role = user.Role });
}).RequireRateLimiting("login");

app.MapPost("/auth/logout", async (HttpContext context, IAuditTrail audit, CancellationToken ct) =>
{
    var actor = context.User.Identity?.Name ?? "anonymous";
    await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    await audit.WriteAsync("auth.logout", actor, new { }, ct);
    return Results.Ok(new { success = true });
});

app.MapGet("/auth/me", (HttpContext context) =>
{
    if (context.User.Identity?.IsAuthenticated != true)
    {
        return Results.Unauthorized();
    }

    return Results.Ok(new
    {
        authenticated = true,
        username = context.User.Identity.Name,
        role = context.User.FindFirst(ClaimTypes.Role)?.Value
    });
});

app.MapConverterEndpoint();
app.MapAdminEndpoints();
app.MapChannelAgentAdminEndpoints();
app.MapHealthEndpoints(startTelegramBotWorker, startTelegramUserbotWorker);

app.MapGet("/", (HttpContext context, IWebHostEnvironment env) =>
{
    var host = context.Request.Host.Host;
    if (host.StartsWith("bio.", StringComparison.OrdinalIgnoreCase))
    {
        var query = context.Request.QueryString.HasValue ? context.Request.QueryString.Value : string.Empty;
        return Results.Redirect($"/bio{query}", permanent: false);
    }
    
    // Fallback normal: dashboard.html
    var dashboardPath = Path.Combine(env.WebRootPath, "dashboard.html");
    return File.Exists(dashboardPath) ? Results.File(dashboardPath, "text/html") : Results.NotFound();
});

app.MapGet("/links", (HttpContext context) =>
{
    var query = context.Request.QueryString.HasValue ? context.Request.QueryString.Value : string.Empty;
    return Results.Redirect($"/bio{query}", permanent: false);
});


app.MapGet("/conversor", (IWebHostEnvironment env) =>
{
    var path = Path.Combine(env.WebRootPath, "conversor.html");
    return File.Exists(path) ? Results.File(path, "text/html") : Results.NotFound();
});

app.MapGet("/dashboard", (IWebHostEnvironment env) =>
{
    var path = Path.Combine(env.WebRootPath, "dashboard.html");
    return File.Exists(path) ? Results.File(path, "text/html") : Results.NotFound();
});

app.MapPost("/api/conversor", async (
    [FromBody] ConversorWebRequest webRequest,
    HttpContext context,
    IAffiliateLinkService affiliateLinkService,
    InstagramLinkMetaService instagramMeta,
    IHttpClientFactory httpClientFactory,
    OfficialProductDataService officialProductDataService,
    ILinkTrackingStore trackingStore,
    ICouponSelector couponSelector,
    ISettingsStore settingsStore,
    IOptions<WebhookOptions> webhookOptions,
    CancellationToken ct) =>
{
    try
    {
        var request = context.Request;
        var input = webRequest.Url;
        var viewModel = new PublicLinkConverterViewModel
        {
            Input = input?.Trim() ?? string.Empty
        };

    if (!string.IsNullOrWhiteSpace(viewModel.Input))
    {
        var normalizedInputUrl = NormalizeConverterInputToUrl(viewModel.Input);

        // Strip third-party Amazon affiliate tags before enrichment so our pipeline
        // always works with a clean canonical product URL.
        if (!string.IsNullOrWhiteSpace(normalizedInputUrl) &&
            Uri.TryCreate(normalizedInputUrl, UriKind.Absolute, out var inputUri) &&
            (inputUri.Host.EndsWith("amazon.com.br", StringComparison.OrdinalIgnoreCase) ||
             inputUri.Host.EndsWith("amazon.com", StringComparison.OrdinalIgnoreCase)))
        {
            var q = System.Web.HttpUtility.ParseQueryString(inputUri.Query);
            q.Remove("tag");   // remove any existing affiliate tag
            q.Remove("linkCode");
            q.Remove("linkId");
            var builder = new UriBuilder(inputUri) { Query = q.Count > 0 ? q.ToString() : string.Empty };
            normalizedInputUrl = builder.Uri.ToString().TrimEnd('?');
        }

        if (string.IsNullOrWhiteSpace(normalizedInputUrl))
        {
            viewModel.Error = "Cole um link valido para converter.";
        }
        else
        {
            viewModel.OriginalUrl = normalizedInputUrl;
            var requestedSource = NormalizeWebConversorSource(webRequest.Source);
            var conversion = await affiliateLinkService.ConvertAsync(normalizedInputUrl, ct, requestedSource);
            if (!conversion.Success || string.IsNullOrWhiteSpace(conversion.ConvertedUrl))
            {
                viewModel.Store = string.IsNullOrWhiteSpace(conversion.Store) || string.Equals(conversion.Store, "Unknown", StringComparison.OrdinalIgnoreCase)
                    ? ResolveStoreNameFromUrl(normalizedInputUrl)
                    : conversion.Store;
                viewModel.IsAffiliated = conversion.IsAffiliated;
                viewModel.ValidationError = conversion.ValidationError;
                viewModel.CorrectionNote = conversion.CorrectionNote;

                LinkMetaResult fallbackOriginalMeta;
                try
                {
                    fallbackOriginalMeta = await instagramMeta.GetMetaAsync(normalizedInputUrl, ct);
                }
                catch
                {
                    fallbackOriginalMeta = new LinkMetaResult();
                }

                string? fallbackResolvedUrl = null;
                try
                {
                    fallbackResolvedUrl = await TryResolveFinalUrlForMetaAsync(normalizedInputUrl, httpClientFactory, ct);
                }
                catch
                {
                    fallbackResolvedUrl = null;
                }

                LinkMetaResult fallbackResolvedMeta = new();
                if (!string.IsNullOrWhiteSpace(fallbackResolvedUrl) &&
                    !string.Equals(fallbackResolvedUrl, normalizedInputUrl, StringComparison.OrdinalIgnoreCase))
                {
                    try
                    {
                        fallbackResolvedMeta = await instagramMeta.GetMetaAsync(fallbackResolvedUrl, ct);
                    }
                    catch
                    {
                        fallbackResolvedMeta = new LinkMetaResult();
                    }
                }

                OfficialProductDataResult? fallbackOfficial = null;
                try
                {
                    fallbackOfficial = await officialProductDataService.TryGetBestAsync(normalizedInputUrl, fallbackResolvedUrl, ct);
                }
                catch
                {
                    fallbackOfficial = null;
                }

                var mergedFallbackMeta = MergeConverterMeta(fallbackOriginalMeta, fallbackResolvedMeta);
                var hasFallbackData = fallbackOfficial is not null
                    || !string.IsNullOrWhiteSpace(mergedFallbackMeta.Title)
                    || !string.IsNullOrWhiteSpace(mergedFallbackMeta.PriceText)
                    || !string.IsNullOrWhiteSpace(mergedFallbackMeta.Description)
                    || (mergedFallbackMeta.Images?.Count ?? 0) > 0
                    || (mergedFallbackMeta.Videos?.Count ?? 0) > 0;

                if (hasFallbackData)
                {
                    var fallbackDescription = mergedFallbackMeta.Description?.Trim() ?? string.Empty;
                    var fallbackImages = (fallbackOfficial?.Images ?? new List<string>())
                        .Concat(mergedFallbackMeta.Images ?? new List<string>())
                        .Where(x => !string.IsNullOrWhiteSpace(x))
                        .Distinct(StringComparer.OrdinalIgnoreCase)
                        .ToList();

                    viewModel.Success = true;
                    viewModel.Error = null;
                    viewModel.Title = NormalizeConverterDisplayText(FirstNonEmpty(fallbackOfficial?.Title ?? string.Empty, mergedFallbackMeta.Title, $"Oferta {viewModel.Store}") ?? $"Oferta {viewModel.Store}");
                    viewModel.Description = NormalizeConverterDisplayText(fallbackDescription);
                    viewModel.Price = FirstNonEmpty(
                        fallbackOfficial?.CurrentPrice ?? string.Empty,
                        mergedFallbackMeta.PriceText ?? string.Empty,
                        ExtractPriceFromText(fallbackDescription),
                        "Preco sob consulta") ?? "Preco sob consulta";
                    viewModel.ImageUrl = SelectBestConverterImage(fallbackImages, viewModel.Title, viewModel.Description);
                    viewModel.VideoUrl = FirstNonEmpty(mergedFallbackMeta.Videos?.FirstOrDefault(), string.Empty) ?? string.Empty;
                    viewModel.PreviousPrice = NormalizeConverterDisplayText(FirstNonEmpty(
                        fallbackOfficial?.PreviousPrice ?? string.Empty,
                        mergedFallbackMeta.PreviousPriceText ?? string.Empty) ?? string.Empty);
                    viewModel.DiscountPercent = fallbackOfficial?.DiscountPercent
                        ?? mergedFallbackMeta.DiscountPercentFromHtml
                        ?? TryComputeDiscountFromDisplayPrices(viewModel.PreviousPrice, viewModel.Price);
                    viewModel.EstimatedDelivery = NormalizeConverterDisplayText(fallbackOfficial?.EstimatedDelivery ?? string.Empty);
                    viewModel.DataSource = !string.IsNullOrWhiteSpace(fallbackOfficial?.DataSource) ? fallbackOfficial!.DataSource : "meta-fallback";
                    viewModel.ConvertedUrl = FirstNonEmpty(fallbackResolvedUrl, normalizedInputUrl) ?? normalizedInputUrl;
                    viewModel.TrackedUrl = viewModel.ConvertedUrl;
                    viewModel.IsLightningDeal = fallbackOfficial?.IsLightningDeal ?? false;
                    viewModel.LightningDealExpiry = fallbackOfficial?.LightningDealExpiry;
                    viewModel.CouponCode = fallbackOfficial?.CouponCode;
                    viewModel.CouponDescription = fallbackOfficial?.CouponDescription;
                    viewModel.ConversionHost = ExtractHostForDisplay(viewModel.ConvertedUrl);
                    viewModel.DomainHost = ExtractHostForDisplay(viewModel.TrackedUrl);
                }
                else
                {
                    viewModel.Error = string.IsNullOrWhiteSpace(conversion.Error)
                        ? "Nao foi possivel converter esse link agora."
                        : conversion.Error;
                }
            }
            else
            {
                var convertedUrl = conversion.ConvertedUrl.Trim();
                static bool IsMercadoLivreSocialOrShortUrl(string? value)
                {
                    if (string.IsNullOrWhiteSpace(value) || !Uri.TryCreate(value, UriKind.Absolute, out var uri))
                    {
                        return false;
                    }

                    var host = uri.Host.Trim().Trim('.').ToLowerInvariant();
                    if (host is "meli.la" or "meli.co")
                    {
                        return true;
                    }

                    var absolute = uri.AbsoluteUri.ToLowerInvariant();
                    return absolute.Contains("/social/")
                           || absolute.Contains("/sec/")
                           || absolute.Contains("/loja/")
                           || absolute.Contains("/perfil/");
                }

                // If ML conversion still resolves to social/short destination (including via shortened links),
                // try one more pass from the fully resolved URL to force a canonical product link.
                if (string.Equals(conversion.Store, "Mercado Livre", StringComparison.OrdinalIgnoreCase))
                {
                    var resolvedConvertedUrl = await TryResolveFinalUrlForMetaAsync(convertedUrl, httpClientFactory, ct);
                    var shouldRetryMercadoLivre = IsMercadoLivreSocialOrShortUrl(convertedUrl)
                                                  || IsMercadoLivreSocialOrShortUrl(resolvedConvertedUrl);

                    if (shouldRetryMercadoLivre)
                    {
                        var retryInput = !string.IsNullOrWhiteSpace(resolvedConvertedUrl)
                            ? resolvedConvertedUrl
                            : normalizedInputUrl;
                        var retryConversion = await affiliateLinkService.ConvertAsync(retryInput, ct, requestedSource);
                        if (retryConversion.Success && !string.IsNullOrWhiteSpace(retryConversion.ConvertedUrl))
                        {
                            var retryUrl = retryConversion.ConvertedUrl.Trim();
                            var retryResolved = await TryResolveFinalUrlForMetaAsync(retryUrl, httpClientFactory, ct);
                            if (!IsMercadoLivreSocialOrShortUrl(retryUrl) && !IsMercadoLivreSocialOrShortUrl(retryResolved))
                            {
                                convertedUrl = retryUrl;
                            }
                        }
                    }
                }

                var trackedUrl = convertedUrl;
                var enrichmentUrl = FirstNonEmpty(
                    conversion.EnrichmentUrl ?? string.Empty,
                    normalizedInputUrl,
                    convertedUrl) ?? convertedUrl;

                // =================== PARALLEL METADATA FETCH ===================
                // All metadata sources run concurrently to minimize total latency.
                // Previously sequential (~8-15s), now parallel (~3-5s).
                var productPageMetaTask = Task.Run(async () =>
                {
                    if (!string.IsNullOrWhiteSpace(enrichmentUrl) &&
                        !string.Equals(enrichmentUrl, convertedUrl, StringComparison.OrdinalIgnoreCase))
                    {
                        try { return await instagramMeta.GetMetaAsync(enrichmentUrl, ct); } catch { }
                    }

                    // Priority: fetch directly from the real ML product page URL
                    if (!string.IsNullOrWhiteSpace(convertedUrl) &&
                        !convertedUrl.Contains("mercadolivre.com.br", StringComparison.OrdinalIgnoreCase))
                    {
                        var resolvedForMeta = await TryResolveFinalUrlForMetaAsync(convertedUrl, httpClientFactory, ct);
                        if (!string.IsNullOrWhiteSpace(resolvedForMeta) &&
                            resolvedForMeta.Contains("mercadolivre.com.br", StringComparison.OrdinalIgnoreCase))
                        {
                            try { return await instagramMeta.GetMetaAsync(resolvedForMeta, ct); } catch { }
                        }
                    }
                    else if (!string.IsNullOrWhiteSpace(convertedUrl))
                    {
                        try { return await instagramMeta.GetMetaAsync(convertedUrl, ct); } catch { }
                    }
                    return new LinkMetaResult();
                }, ct);

                var convertedMetaTask = Task.Run(async () =>
                {
                    try
                    {
                        var meta = await instagramMeta.GetMetaAsync(convertedUrl, ct);
                        var resolvedConvertedUrl = await TryResolveFinalUrlForMetaAsync(convertedUrl, httpClientFactory, ct);
                        if (!string.IsNullOrWhiteSpace(resolvedConvertedUrl) &&
                            !string.Equals(resolvedConvertedUrl, convertedUrl, StringComparison.OrdinalIgnoreCase))
                        {
                            try
                            {
                                var resolvedMeta = await instagramMeta.GetMetaAsync(resolvedConvertedUrl, ct);
                                return MergeConverterMeta(meta, resolvedMeta);
                            }
                            catch { }
                        }
                        return meta;
                    }
                    catch { return new LinkMetaResult(); }
                }, ct);

                var originalMetaTask = Task.Run(async () =>
                {
                    if (string.Equals(convertedUrl, normalizedInputUrl, StringComparison.OrdinalIgnoreCase))
                        return new LinkMetaResult();
                    try
                    {
                        var meta = await instagramMeta.GetMetaAsync(normalizedInputUrl, ct);
                        var resolvedOriginalUrl = await TryResolveFinalUrlForMetaAsync(normalizedInputUrl, httpClientFactory, ct);
                        if (!string.IsNullOrWhiteSpace(resolvedOriginalUrl) &&
                            !string.Equals(resolvedOriginalUrl, normalizedInputUrl, StringComparison.OrdinalIgnoreCase))
                        {
                            try
                            {
                                var resolvedMeta = await instagramMeta.GetMetaAsync(resolvedOriginalUrl, ct);
                                return MergeConverterMeta(meta, resolvedMeta);
                            }
                            catch { }
                        }
                        return meta;
                    }
                    catch { return new LinkMetaResult(); }
                }, ct);

                var resolvedOriginalUrlTask = TryResolveFinalUrlForMetaAsync(normalizedInputUrl, httpClientFactory, ct);
                var officialDataTask = Task.Run(async () =>
                {
                    var resolvedOriginalUrl = await resolvedOriginalUrlTask;
                    var primaryOfficialInput = !string.IsNullOrWhiteSpace(conversion.EnrichmentUrl)
                        ? conversion.EnrichmentUrl
                        : !string.IsNullOrWhiteSpace(resolvedOriginalUrl)
                        ? resolvedOriginalUrl
                        : normalizedInputUrl;
                    return await officialProductDataService.TryGetBestAsync(primaryOfficialInput, convertedUrl, ct);
                }, ct);
                var couponsTask = Task.Run(async () =>
                {
                    try
                    {
                        var store = conversion.Store?.Trim() ?? string.Empty;
                        if (!string.IsNullOrWhiteSpace(store) && !string.Equals(store, "Unknown", StringComparison.OrdinalIgnoreCase))
                        {
                            return await couponSelector.GetActiveCouponsAsync(store, 1, ct);
                        }
                    }
                    catch { }
                    return Enumerable.Empty<AffiliateCoupon>();
                }, ct);

                await Task.WhenAll(productPageMetaTask, convertedMetaTask, originalMetaTask, officialDataTask, couponsTask, resolvedOriginalUrlTask);

                var productPageMeta = await productPageMetaTask;
                var convertedMeta = await convertedMetaTask;
                var originalMeta = await originalMetaTask;
                var resolvedOriginalUrl = await resolvedOriginalUrlTask;
                var officialData = await officialDataTask;
                
                // Fallback for short links (e.g. meli.la) - if Official API couldn't resolve the ID organically,
                // try again using the ResolvedUrl obtained by the metadata HTML scraper
                if (officialData is null)
                {
                    var resolvedFromMeta = FirstNonEmpty(
                        conversion.EnrichmentUrl ?? string.Empty,
                        resolvedOriginalUrl,
                        productPageMeta.ResolvedUrl,
                        originalMeta.ResolvedUrl,
                        convertedMeta.ResolvedUrl);
                    if (!string.IsNullOrWhiteSpace(resolvedFromMeta) && 
                        !string.Equals(resolvedFromMeta, normalizedInputUrl, StringComparison.OrdinalIgnoreCase) &&
                        !string.Equals(resolvedFromMeta, convertedUrl, StringComparison.OrdinalIgnoreCase))
                    {
                        officialData = await officialProductDataService.TryGetBestAsync(resolvedFromMeta, null, ct);
                    }
                }
                
                var coupons = await couponsTask;
                // ================================================================

                // Merge: productPageMeta (from real ML product) takes highest priority for title, price, image
                var mergedTitle = ChooseBestConverterTitle(
                    ChooseBestConverterTitle(productPageMeta.Title, originalMeta.Title),
                    convertedMeta.Title);
                var mergedDescription = ChooseBestConverterDescription(
                    ChooseBestConverterDescription(productPageMeta.Description, originalMeta.Description),
                    convertedMeta.Description);
                var mergedPrice = FirstNonEmpty(
                    officialData?.CurrentPrice ?? string.Empty,
                    productPageMeta.PriceText ?? string.Empty,
                    originalMeta.PriceText ?? string.Empty,
                    convertedMeta.PriceText ?? string.Empty,
                    ExtractPriceFromText(mergedDescription),
                    ExtractPriceFromText(productPageMeta.Description),
                    ExtractPriceFromText(originalMeta.Description),
                    ExtractPriceFromText(convertedMeta.Description),
                    "Preco sob consulta");
                var mergedImages = (officialData?.Images ?? new List<string>())
                    .Concat(productPageMeta.Images ?? new List<string>())
                    .Concat(originalMeta.Images ?? new List<string>())
                    .Concat(convertedMeta.Images ?? new List<string>())
                    .Where(x => !string.IsNullOrWhiteSpace(x))
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToList();

                viewModel.Success = true;
                viewModel.Store = string.IsNullOrWhiteSpace(conversion.Store) || string.Equals(conversion.Store, "Unknown", StringComparison.OrdinalIgnoreCase)
                    ? ResolveStoreNameFromUrl(convertedUrl)
                    : conversion.Store.Trim();
                viewModel.Title = NormalizeConverterDisplayText(FirstNonEmpty(officialData?.Title ?? string.Empty, mergedTitle, $"Oferta {viewModel.Store}") ?? $"Oferta {viewModel.Store}");
                viewModel.Description = NormalizeConverterDisplayText(mergedDescription?.Trim() ?? string.Empty);
                viewModel.Price = FirstNonEmpty(mergedPrice, "Preco sob consulta") ?? "Preco sob consulta";
                viewModel.ImageUrl = SelectBestConverterImage(mergedImages, viewModel.Title, viewModel.Description);
                viewModel.VideoUrl = FirstNonEmpty(
                    productPageMeta.Videos?.FirstOrDefault(),
                    originalMeta.Videos?.FirstOrDefault(),
                    convertedMeta.Videos?.FirstOrDefault(),
                    string.Empty) ?? string.Empty;

                // Previous price: cascade from official data → HTML scraping of each meta source
                viewModel.PreviousPrice = NormalizeConverterDisplayText(FirstNonEmpty(
                    officialData?.PreviousPrice ?? string.Empty,
                    productPageMeta.PreviousPriceText ?? string.Empty,
                    convertedMeta.PreviousPriceText ?? string.Empty,
                    originalMeta.PreviousPriceText ?? string.Empty) ?? string.Empty);
                viewModel.IsLightningDeal = officialData?.IsLightningDeal ?? false;
                viewModel.LightningDealExpiry = officialData?.LightningDealExpiry;
                viewModel.CouponCode = officialData?.CouponCode;
                viewModel.CouponDescription = officialData?.CouponDescription;

                // Validate previous price: must be greater than current price, otherwise discard
                if (!string.IsNullOrWhiteSpace(viewModel.PreviousPrice) && !string.IsNullOrWhiteSpace(viewModel.Price))
                {
                    var prevVal = ParseBrlPrice(viewModel.PreviousPrice);
                    var curVal = ParseBrlPrice(viewModel.Price);
                    if (prevVal.HasValue && curVal.HasValue && prevVal.Value <= curVal.Value)
                    {
                        viewModel.PreviousPrice = string.Empty; // Invalid: old price should be higher
                    }
                }

                // Discount percent: cascade official API → HTML extracted % → computed from prices
                viewModel.DiscountPercent = officialData?.DiscountPercent;
                if (!viewModel.DiscountPercent.HasValue || viewModel.DiscountPercent.Value <= 0)
                {
                    // Try HTML-extracted discount % (e.g. "25% OFF" on the page)
                    viewModel.DiscountPercent = productPageMeta.DiscountPercentFromHtml
                        ?? convertedMeta.DiscountPercentFromHtml
                        ?? originalMeta.DiscountPercentFromHtml;
                }
                if (!viewModel.DiscountPercent.HasValue || viewModel.DiscountPercent.Value <= 0)
                {
                    // Fallback: compute from display prices
                    viewModel.DiscountPercent = TryComputeDiscountFromDisplayPrices(viewModel.PreviousPrice, viewModel.Price);
                }

                // Calculate previous price from discount if we have discount % but no valid previous price
                if (string.IsNullOrWhiteSpace(viewModel.PreviousPrice) &&
                    viewModel.DiscountPercent.HasValue && viewModel.DiscountPercent.Value > 0 &&
                    !string.IsNullOrWhiteSpace(viewModel.Price))
                {
                    var curVal = ParseBrlPrice(viewModel.Price);
                    if (curVal.HasValue && curVal.Value > 0)
                    {
                        var calculatedPrev = Math.Round(curVal.Value / (1m - viewModel.DiscountPercent.Value / 100m), 2);
                        viewModel.PreviousPrice = $"R$ {calculatedPrev.ToString("N2", System.Globalization.CultureInfo.GetCultureInfo("pt-BR"))}";
                    }
                }

                viewModel.EstimatedDelivery = NormalizeConverterDisplayText(officialData?.EstimatedDelivery ?? string.Empty);
                viewModel.DataSource = !string.IsNullOrWhiteSpace(officialData?.DataSource) ? officialData!.DataSource : "meta";
                viewModel.ConvertedUrl = convertedUrl;
                viewModel.TrackedUrl = trackedUrl;
                viewModel.IsAffiliated = conversion.IsAffiliated;
                viewModel.ValidationError = conversion.ValidationError;
                viewModel.CorrectionNote = conversion.CorrectionNote;
                viewModel.ConversionHost = ExtractHostForDisplay(convertedUrl);
                viewModel.DomainHost = ExtractHostForDisplay(trackedUrl);

                try
                {
                    var coupon = coupons.FirstOrDefault();
                    if (coupon is not null)
                    {
                        viewModel.HasCoupon = true;
                        viewModel.CouponCode = coupon.Code ?? string.Empty;
                        viewModel.CouponDescription = coupon.Description ?? string.Empty;
                    }
                }
                catch
                {
                }
            }
        }
    }

        return Results.Ok(viewModel);
    }
    catch (Exception ex)
    {
        return Results.Json(new { success = false, error = ex.Message, validationError = "Erro inesperado interno do servidor." }, statusCode: 500);
    }
});

app.MapGet("/bio", async (
    HttpContext context,
    IInstagramPublishStore publishStore,
    ICatalogOfferStore catalogOfferStore,
    IConversionLogStore conversionLogStore,
    ILinkTrackingStore trackingStore,
    ISettingsStore settingsStore,
    IOptions<WebhookOptions> webhookOptions,
    CancellationToken ct) =>
{
    var settings = await settingsStore.GetAsync(ct);
    var bioSettings = settings.BioHub ?? new BioHubSettings();
    if (!bioSettings.Enabled)
    {
        return Results.Content("<!doctype html><html><body><p>Bio temporariamente desativada.</p></body></html>", "text/html; charset=utf-8");
    }

    var request = context.Request;
    var source = NormalizeTrackingToken(
        FirstNonEmpty(request.Query["src"].ToString(), bioSettings.DefaultSource, "bio"),
        "bio") ?? "bio";
    var campaign = NormalizeTrackingToken(
        FirstNonEmpty(request.Query["camp"].ToString(), bioSettings.DefaultCampaign),
        null);
    var medium = NormalizeTrackingToken(request.Query["medium"].ToString(), "instagram") ?? "instagram";
    var maxItems = Math.Clamp(bioSettings.MaxItems, 5, 80);
    var catalogTarget = ResolveCatalogTargetForRequest(request);
    var recentConversions = await conversionLogStore.QueryAsync(new ConversionLogQuery { Limit = 500 }, ct);

    var drafts = await publishStore.ListAsync(ct);
    var draftsById = drafts
        .Where(d => !string.IsNullOrWhiteSpace(d.Id))
        .ToDictionary(d => d.Id, StringComparer.OrdinalIgnoreCase);
    var catalogByDraftId = await catalogOfferStore.GetByDraftIdAsync(ct, catalogTarget);
    if (catalogByDraftId.Count == 0)
    {
        catalogByDraftId = BuildCatalogFallbackItemsFromDrafts(drafts, recentConversions, catalogTarget)
            .Where(x => !string.IsNullOrWhiteSpace(x.DraftId))
            .GroupBy(x => x.DraftId, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(
                g => g.Key,
                g => g.OrderByDescending(x => x.UpdatedAt).First(),
                StringComparer.OrdinalIgnoreCase);
    }

    var baseItems = drafts
        .Where(d => string.Equals(d.Status, "published", StringComparison.OrdinalIgnoreCase))
        .Select(d =>
        {
            catalogByDraftId.TryGetValue(d.Id, out var catalogItem);
            var effectiveOfferUrl = ResolveEffectiveCatalogOfferUrl(catalogItem, d, recentConversions);
            var title = !string.IsNullOrWhiteSpace(d.ProductName) ? d.ProductName : "Oferta";
            return new BioLinkItem
            {
                CreatedAt = d.CreatedAt,
                Title = title.Trim(),
                Link = effectiveOfferUrl,
                OriginalLink = effectiveOfferUrl,
                Store = ResolveStoreNameFromUrl(FirstNonEmpty(effectiveOfferUrl, catalogItem?.Store)),
                ItemNumber = catalogItem?.ItemNumber,
                IsHighlightedOnBio = d.IsBioHighlighted,
                BioHighlightedAt = d.BioHighlightedAt,
                Keyword = FirstNonEmpty(catalogItem?.Keyword, d.Ctas.FirstOrDefault(c => !string.IsNullOrWhiteSpace(c.Keyword))?.Keyword?.Trim()),
                IsLightningDeal = catalogItem?.IsLightningDeal ?? false,
                LightningDealExpiry = catalogItem?.LightningDealExpiry,
                CouponCode = catalogItem?.CouponCode,
                CouponDescription = catalogItem?.CouponDescription,
                ImageUrl = BuildPublicImageProxyUrl(publicBaseUrl: null, request, FirstNonEmpty(catalogItem?.ImageUrl, ResolveBioImageUrl(d)))
            };
        })
        .Where(x => !string.IsNullOrWhiteSpace(x.Link))
        .OrderByDescending(x => x.IsHighlightedOnBio)
        .ThenByDescending(x => x.BioHighlightedAt ?? DateTimeOffset.MinValue)
        .ThenByDescending(x => x.CreatedAt)
        .GroupBy(x => x.Link, StringComparer.OrdinalIgnoreCase)
        .Select(g => g.First())
        .Take(maxItems)
        .ToList();

    var publicBaseUrl = ResolvePublicBaseUrl(
        bioSettings.PublicBaseUrl,
        webhookOptions.Value.PublicBaseUrl,
        request.Scheme,
        request.Host.ToString());
    var trackedItems = new List<BioLinkItem>();
    foreach (var item in baseItems)
    {
        var targetUrl = AppendBioCampaignParameters(item.OriginalLink, source, medium, campaign, item.Title);
        var tracked = await trackingStore.GetOrCreateAsync(targetUrl, ct);
        trackedItems.Add(item with
        {
            Link = BuildTrackedRedirectUrl(publicBaseUrl, tracked.Id, source, campaign),
            OriginalLink = targetUrl
        });
    }

    var currentUrl = BuildBioCurrentUrl(publicBaseUrl, source, campaign);
    var html = BuildBioLinksPageHtml(trackedItems, currentUrl, bioSettings, source, campaign);
    return Results.Content(html, "text/html; charset=utf-8");
});

app.MapGet("/catalogo", async (
    HttpContext context,
    IInstagramPublishStore publishStore,
    ICatalogOfferStore catalogOfferStore,
    IConversionLogStore conversionLogStore,
    CancellationToken ct) =>
{
    var q = context.Request.Query["q"].ToString();
    var catalogTarget = ResolveCatalogTargetForRequest(context.Request);

    var items = await catalogOfferStore.ListAsync(q, 120, ct, catalogTarget);
    var drafts = await publishStore.ListAsync(ct);
    var draftsById = drafts
        .Where(d => !string.IsNullOrWhiteSpace(d.Id))
        .ToDictionary(d => d.Id, StringComparer.OrdinalIgnoreCase);
    var recentConversions = await conversionLogStore.QueryAsync(new ConversionLogQuery { Limit = 500 }, ct);
    if (items.Count == 0)
    {
        items = BuildCatalogFallbackItemsFromDrafts(drafts, recentConversions, catalogTarget, q)
            .Take(120)
            .ToArray();
    }
    var request = context.Request;
    var currentUrl = $"{request.Scheme}://{request.Host}/catalogo";
    if (!string.IsNullOrWhiteSpace(q))
    {
        currentUrl += $"?q={Uri.EscapeDataString(q)}";
    }

    items = items
        .Select(item =>
        {
            var draft = FindRelatedDraftForCatalogItem(item, draftsById, drafts);
            item.OfferUrl = ResolveEffectiveCatalogOfferUrl(item, draft, recentConversions);
            item.ImageUrl = BuildPublicImageProxyUrl(publicBaseUrl: null, request, FirstNonEmpty(item.ImageUrl, draft is null ? null : ResolveBioImageUrl(draft)));
            if (string.IsNullOrWhiteSpace(item.Store))
            {
                item.Store = ResolveStoreNameFromUrl(item.OfferUrl);
            }

            return item;
        })
        .ToArray();

    var html = BuildCatalogPageHtml(items, q, currentUrl);
    return Results.Content(html, "text/html; charset=utf-8");
});

app.MapGet("/item/{query}", async (
    string query,
    HttpContext context,
    IInstagramPublishStore publishStore,
    ICatalogOfferStore catalogOfferStore,
    IConversionLogStore conversionLogStore,
    CancellationToken ct) =>
{
    var catalogTarget = ResolveCatalogTargetForRequest(context.Request);
    var drafts = await publishStore.ListAsync(ct);
    var draftsById = drafts
        .Where(d => !string.IsNullOrWhiteSpace(d.Id))
        .ToDictionary(d => d.Id, StringComparer.OrdinalIgnoreCase);
    var recentConversions = await conversionLogStore.QueryAsync(new ConversionLogQuery { Limit = 500 }, ct);
    var item = await catalogOfferStore.FindByCodeAsync(query, ct, catalogTarget);
    if (item is null)
    {
        item = BuildCatalogFallbackItemsFromDrafts(drafts, recentConversions, catalogTarget)
            .FirstOrDefault(x =>
                x.ItemNumber.ToString(CultureInfo.InvariantCulture).Equals(query, StringComparison.OrdinalIgnoreCase) ||
                x.Keyword.Equals(query, StringComparison.OrdinalIgnoreCase) ||
                x.Keyword.Contains(query, StringComparison.OrdinalIgnoreCase));
        if (item is null)
        {
            return Results.NotFound($"Item '{query}' nao encontrado.");
        }
    }
    else if (!string.IsNullOrWhiteSpace(item.DraftId) && draftsById.TryGetValue(item.DraftId, out var storedDraft))
    {
        item.OfferUrl = ResolveEffectiveCatalogOfferUrl(item, storedDraft, recentConversions);
        item.ImageUrl = BuildPublicImageProxyUrl(publicBaseUrl: null, context.Request, FirstNonEmpty(item.ImageUrl, ResolveBioImageUrl(storedDraft)));
    }
    else
    {
        var relatedDraft = FindRelatedDraftForCatalogItem(item, draftsById, drafts);
        item.OfferUrl = ResolveEffectiveCatalogOfferUrl(item, relatedDraft, recentConversions);
        item.ImageUrl = BuildPublicImageProxyUrl(publicBaseUrl: null, context.Request, FirstNonEmpty(item.ImageUrl, relatedDraft is null ? null : ResolveBioImageUrl(relatedDraft)));
    }

    var baseCatalogUrl = $"{context.Request.Scheme}://{context.Request.Host}/catalogo";
    var html = BuildCatalogItemPageHtml(item, baseCatalogUrl);
    return Results.Content(html, "text/html; charset=utf-8");
});

app.MapGet("/media/remote", async (
    string url,
    IHttpClientFactory httpClientFactory,
    HttpContext context,
    CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(url) ||
        !Uri.TryCreate(url, UriKind.Absolute, out var uri) ||
        (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps))
    {
        return Results.BadRequest("URL invalida.");
    }

    using var request = new HttpRequestMessage(HttpMethod.Get, uri);
    request.Headers.UserAgent.ParseAdd("Mozilla/5.0 (compatible; ReiDasOfertasBot/1.0)");
    request.Headers.Referrer = new Uri($"{context.Request.Scheme}://{context.Request.Host}");

    var client = httpClientFactory.CreateClient();
    using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);
    if (!response.IsSuccessStatusCode)
    {
        return Results.StatusCode((int)response.StatusCode);
    }

    var contentType = response.Content.Headers.ContentType?.MediaType;
    if (string.IsNullOrWhiteSpace(contentType) || !contentType.StartsWith("image/", StringComparison.OrdinalIgnoreCase))
    {
        return Results.BadRequest("Midia remota invalida.");
    }

    var bytes = await response.Content.ReadAsByteArrayAsync(ct);
    context.Response.Headers.CacheControl = "public,max-age=1800";
    return Results.File(bytes, contentType);
});

app.MapPost("/webhooks/evolution", async (
    HttpRequest request,
    IOptions<EvolutionOptions> evolution,
    IIdempotencyStore idempotency,
    ISettingsStore settingsStore,
    IAuditTrail audit,
    CancellationToken ct) =>
{
    var body = await new StreamReader(request.Body).ReadToEndAsync(ct);

    if (!WebhookSignatureVerifier.TryValidate(request, body, evolution.Value.WebhookSecret))
    {
        return Results.Unauthorized();
    }

    using var doc = JsonDocument.Parse(body);
    var root = doc.RootElement;
    var eventName = root.TryGetProperty("event", out var e) ? e.GetString() : "unknown";
    var eventId = root.TryGetProperty("eventId", out var id) ? id.GetString() : null;

    var idempotencyKey = $"evolution:{eventName}:{eventId ?? body.GetHashCode().ToString()}";
    if (!idempotency.TryBegin(idempotencyKey, TimeSpan.FromHours(6)))
    {
        return Results.Ok(new { success = true, duplicate = true });
    }

    var settings = await settingsStore.GetAsync(ct);
    if (string.Equals(eventName, "connection.update", StringComparison.OrdinalIgnoreCase) && root.TryGetProperty("data", out var data))
    {
        var state = data.TryGetProperty("state", out var s) ? s.GetString() : null;
        if (string.Equals(state, "open", StringComparison.OrdinalIgnoreCase))
        {
            settings.Integrations.WhatsApp.Connected = true;
            settings.Integrations.WhatsApp.LastLoginAt = DateTimeOffset.UtcNow;
            settings.Integrations.WhatsApp.Notes = "Conectado via webhook Evolution";
        }
        else if (string.Equals(state, "close", StringComparison.OrdinalIgnoreCase))
        {
            settings.Integrations.WhatsApp.Connected = false;
            settings.Integrations.WhatsApp.Notes = "Desconectado via webhook Evolution";
        }

        await settingsStore.SaveAsync(settings, ct);
    }

    await audit.WriteAsync("evolution.webhook.received", "system", new { eventName, eventId }, ct);
    return Results.Ok(new { success = true });
});

app.MapPost("/webhook/bot-conversor", async (
    HttpRequest request,
    IMessageOrchestrator orchestrator,
    ILogger<Program> logger,
    IOptions<EvolutionOptions> evolutionOptions,
    IOptions<WebhookOptions> webhookOptions,
    CancellationToken ct) =>
{
    request.EnableBuffering();
    var body = await new StreamReader(request.Body).ReadToEndAsync(ct);
    request.Body.Position = 0;

    if (!IsBotConversorWebhookAuthorized(request, body, evolutionOptions.Value.WebhookSecret, webhookOptions.Value.ApiKey))
    {
        return Results.Unauthorized();
    }

    if (string.IsNullOrWhiteSpace(body))
    {
        return Results.Ok(new { success = true, ignored = true });
    }

    var headers = request.Headers.ToDictionary(
        header => header.Key,
        header => header.Value.ToString(),
        StringComparer.OrdinalIgnoreCase);

    var result = await orchestrator.EnqueueBotConversorAsync(body, headers, ct);
    if (!result.Accepted)
    {
        logger.LogWarning(
            "Webhook bot-conversor falhou ao enfileirar. MessageId={MessageId} Mode={Mode} Error={Error}",
            result.MessageId,
            result.Mode,
            result.Error);

        return Results.StatusCode(StatusCodes.Status502BadGateway);
    }

    return Results.Ok(new
    {
        success = true,
        messageId = result.MessageId,
        mode = result.Mode,
        persistedLocally = result.PersistedLocally
    });
});

app.MapPost("/internal/webhook/bot-conversor", async (
    HttpRequest request,
    IMessageProcessor processor,
    IWhatsAppGateway gateway,
    IMediaStore mediaStore,
    IMediaFailureLogStore mediaFailureLogStore,
    ISettingsStore settingsStore,
    IConversionLogStore conversionLogStore,
    ILinkTrackingStore linkTrackingStore,
    IInstagramPostComposer instagramComposer,
    IInstagramPublishStore instagramPublishStore,
    IInstagramPublishLogStore instagramPublishLogStore,
    InstagramConversationStore instagramStore,
    InstagramCommandMenuStore instagramMenuStore,
    WhatsAppHelpMenuStore helpMenuStore,
    InstagramLinkMetaService instagramMeta,
    InstagramImageDownloadService instagramImages,
    IIdempotencyStore idempotency,
    OfficialProductDataService officialProductDataService,
    IOptions<AffiliateOptions> affiliate,
    IOptions<TelegramOptions> telegramOptions,
    IOptions<EvolutionOptions> evolutionOptions,
    IOptions<WebhookOptions> webhookOptions,
    IHttpClientFactory httpClientFactory,
    ILogger<Program> logger,
    CancellationToken ct) =>
{
    var body = await new StreamReader(request.Body).ReadToEndAsync(ct);
    var remoteIp = request.HttpContext.Connection.RemoteIpAddress;
    var isLoopbackCaller = remoteIp is not null && IPAddress.IsLoopback(remoteIp);
    if (!isLoopbackCaller &&
        !IsBotConversorWebhookAuthorized(request, body, evolutionOptions.Value.WebhookSecret, webhookOptions.Value.ApiKey))
    {
        return Results.Unauthorized();
    }

    if (string.IsNullOrWhiteSpace(body))
    {
        return Results.Ok(new { success = true, ignored = true });
    }

    var messages = ExtractEvolutionMessages(body);
    if (messages.Count == 0)
    {
        return Results.Ok(new { success = true, ignored = true });
    }

    var settings = await settingsStore.GetAsync(ct);
    var waSettings = settings.WhatsAppForwarding ?? new WhatsAppForwardingSettings();
    var waRoutes = ResolveWhatsAppForwardingRoutes(settings);
    var responder = settings.LinkResponder ?? new LinkResponderSettings();

    async Task SendReplyAsync(string? instanceName, string chatId, string text)
    {
        var sendResult = await gateway.SendTextAsync(instanceName, chatId, text, ct);
        if (!sendResult.Success)
        {
            logger.LogWarning(
                "Falha ao responder WhatsApp comando/chat. Chat={ChatId} Instance={InstanceName} Error={Error}",
                chatId,
                instanceName ?? "default",
                sendResult.Message ?? "unknown");
        }
    }

    var processed = 0;
    var responderProcessed = 0;
    foreach (var msg in messages)
    {
        var mercadoLivreQueuedToBridge = false;
        if (!string.IsNullOrWhiteSpace(msg.MessageId))
        {
            var waEventKey = $"wa-msg:{msg.InstanceName ?? "default"}:{msg.ChatId}:{msg.MessageId}";
            if (!idempotency.TryBegin(waEventKey, TimeSpan.FromHours(6)))
            {
                continue;
            }
        }
        else
        {
            // Fallback idempotency for payloads sem messageId (alguns provedores reenviam o mesmo evento).
            var fallbackHash = ComputeStableHash(msg.RawPayloadJson ?? msg.Text);
            var senderKey = string.IsNullOrWhiteSpace(msg.SenderId) ? "unknown" : msg.SenderId;
            var waFallbackKey = $"wa-msg-fallback:{msg.InstanceName ?? "default"}:{msg.ChatId}:{senderKey}:{msg.FromMe}:{fallbackHash}";
            if (!idempotency.TryBegin(waFallbackKey, TimeSpan.FromSeconds(45)))
            {
                continue;
            }
        }

        var responderInstance = string.IsNullOrWhiteSpace(waSettings.InstanceName) ? msg.InstanceName : waSettings.InstanceName;
        var instaSettings = settings.InstagramPosts;
        var normalizedText = msg.Text?.Trim() ?? string.Empty;
        var isCommandLike = normalizedText.StartsWith("/help", StringComparison.OrdinalIgnoreCase)
                            || normalizedText.StartsWith(@"\help", StringComparison.OrdinalIgnoreCase)
                            || normalizedText.StartsWith("/ig", StringComparison.OrdinalIgnoreCase)
                            || normalizedText.StartsWith("ig ", StringComparison.OrdinalIgnoreCase)
                            || normalizedText.StartsWith("/leg", StringComparison.OrdinalIgnoreCase)
                            || normalizedText.StartsWith(@"\leg", StringComparison.OrdinalIgnoreCase);
        if (isCommandLike)
        {
            logger.LogInformation(
                "WA comando recebido. Chat={ChatId} Sender={SenderId} FromMe={FromMe} MessageId={MessageId} Text={Text}",
                msg.ChatId,
                msg.SenderId ?? "unknown",
                msg.FromMe,
                msg.MessageId ?? "none",
                normalizedText.Length > 140 ? normalizedText[..140] : normalizedText);
        }

        if (TryParseInstagramCaptionChoiceCommand(normalizedText, out var captionChoice))
        {
            if (!instaSettings.Enabled || !instaSettings.AllowWhatsApp || !IsInstagramAllowed(instaSettings, msg.ChatId))
            {
                await SendReplyAsync(responderInstance, msg.ChatId, "Comando /leg bloqueado neste chat.");
                continue;
            }

            var (draft, error) = await ResolveInstagramDraftAsync(instagramPublishStore, captionChoice.DraftRef, ct);
            if (draft is null)
            {
                await SendReplyAsync(responderInstance, msg.ChatId, error ?? "Rascunho nao encontrado.");
                continue;
            }

            var options = (draft.CaptionOptions ?? new List<string>())
                .Where(x => !string.IsNullOrWhiteSpace(x))
                .ToList();

            if (options.Count == 0)
            {
                options.Add(draft.Caption ?? string.Empty);
            }

            if (captionChoice.OptionNumber < 1 || captionChoice.OptionNumber > options.Count)
            {
                var max = options.Count;
                await SendReplyAsync(responderInstance, msg.ChatId, $"Legenda {captionChoice.OptionNumber} nao existe. Escolha de 1 a {max}.");
                continue;
            }

            var selected = options[captionChoice.OptionNumber - 1];
            selected = FormatInstagramCaptionForReadability(selected);
            selected = EnsureInstagramCaptionContainsCta(selected, draft.Ctas);
            if (selected.Length > 2200)
            {
                selected = selected[..2200].TrimEnd() + "...";
            }

            draft.Caption = selected;
            draft.CaptionOptions = options;
            draft.SelectedCaptionIndex = captionChoice.OptionNumber;
            await instagramPublishStore.UpdateAsync(draft, ct);
            await instagramPublishLogStore.AppendAsync(new InstagramPublishLogEntry
            {
                Action = "wa_command_draft_select_caption",
                Success = true,
                DraftId = draft.Id,
                Details = $"Option={captionChoice.OptionNumber},Total={options.Count}"
            }, ct);

            var shortId = draft.Id.Length > 8 ? draft.Id[..8] : draft.Id;
            await SendReplyAsync(
                responderInstance,
                msg.ChatId,
                $"Legenda {captionChoice.OptionNumber} selecionada para o draft {shortId}.\nUse /ig revisar {shortId} e /ig confirmar {shortId}.");
            continue;
        }

        if (TryParseWhatsAppHelpCommand(normalizedText, out var helpCommand))
        {
            var senderKey = string.IsNullOrWhiteSpace(msg.SenderId) ? "unknown" : msg.SenderId;
            var helpKey = $"wa-help:{msg.InstanceName ?? "default"}:{msg.ChatId}:{senderKey}:{msg.FromMe}:{ComputeStableHash(normalizedText)}";
            if (!idempotency.TryBegin(helpKey, TimeSpan.FromMinutes(1)))
            {
                continue;
            }

            // /help deve priorizar o menu de ajuda numerico neste chat.
            instagramMenuStore.Disarm(msg.ChatId);
            helpMenuStore.Arm(msg.ChatId);

            var helpMessage = BuildWhatsAppHelpMessageForScope(helpCommand.Scope);
            await SendReplyAsync(responderInstance, msg.ChatId, helpMessage);
            continue;
        }

        if (helpMenuStore.TryResolveScope(msg.ChatId, msg.Text, out var helpScope))
        {
            await SendReplyAsync(responderInstance, msg.ChatId, BuildWhatsAppHelpMessageForScope(helpScope));
            continue;
        }

        if (instagramMenuStore.TryResolveSelection(msg.ChatId, msg.Text, out var menuCommandText))
        {
            if (TryParseInstagramWhatsAppCommand(menuCommandText, out var menuCommand))
            {
                if (!instaSettings.Enabled || !instaSettings.AllowWhatsApp || !IsInstagramAllowed(instaSettings, msg.ChatId))
                {
                    await SendReplyAsync(responderInstance, msg.ChatId, "Comando /ig bloqueado neste chat.");
                    continue;
                }

                var commandResponses = await ExecuteInstagramWhatsAppCommandAsync(
                    menuCommand,
                    msg.ChatId,
                    settings,
                    instagramComposer,
                    instagramPublishStore,
                    instagramPublishLogStore,
                    instagramMeta,
                    httpClientFactory,
                    mediaStore,
                    webhookOptions.Value.PublicBaseUrl,
                    instagramMenuStore,
                    ct);

                foreach (var response in commandResponses)
                {
                    foreach (var chunk in SplitLongMessage(response, 3000))
                    {
                        await SendReplyAsync(responderInstance, msg.ChatId, chunk);
                    }
                }

                continue;
            }
        }

        if (TryParseInstagramWhatsAppCommand(normalizedText, out var igCommand))
        {
            if (string.Equals(igCommand.Action, "menu", StringComparison.OrdinalIgnoreCase))
            {
                helpMenuStore.Disarm(msg.ChatId);
            }

            if (!instaSettings.Enabled || !instaSettings.AllowWhatsApp || !IsInstagramAllowed(instaSettings, msg.ChatId))
            {
                await SendReplyAsync(responderInstance, msg.ChatId, "Comando /ig bloqueado neste chat.");
                continue;
            }

            if (string.Equals(igCommand.Action, "reset", StringComparison.OrdinalIgnoreCase))
            {
                var instaKey = $"wa:{msg.ChatId}";
                instagramStore.Clear(instaKey);
                instagramMenuStore.Disarm(msg.ChatId);
                helpMenuStore.Disarm(msg.ChatId);

                var instances = new[] { msg.InstanceName ?? "default", "default" }
                    .Where(x => !string.IsNullOrWhiteSpace(x))
                    .Distinct(StringComparer.OrdinalIgnoreCase);
                foreach (var inst in instances)
                {
                    idempotency.RemoveByPrefix($"wa-help:{inst}:{msg.ChatId}:");
                    idempotency.RemoveByPrefix($"wa-msg:{inst}:{msg.ChatId}:");
                    idempotency.RemoveByPrefix($"wa-msg-fallback:{inst}:{msg.ChatId}:");
                }

                var normalizedArg = igCommand.Argument?.Trim().ToLowerInvariant() ?? string.Empty;
                var fullReset = normalizedArg is "tudo" or "all" or "geral" or "total";
                if (fullReset)
                {
                    await instagramPublishStore.ClearAsync(ct);
                }

                var resetMessage = fullReset
                    ? "Reset concluido: estado do chat limpo e todos os drafts apagados.\nPode comecar de novo com /ig criar <produto ou link>."
                    : "Reset do chat concluido: menu, contexto pendente e deduplicacao limpos.\nPode comecar de novo com /ig criar <produto ou link>.\nDica: use /ig reset tudo para apagar tambem os drafts.";
                await SendReplyAsync(responderInstance, msg.ChatId, resetMessage);
                continue;
            }

            var commandResponses = await ExecuteInstagramWhatsAppCommandAsync(
                igCommand,
                msg.ChatId,
                settings,
                instagramComposer,
                instagramPublishStore,
                instagramPublishLogStore,
                instagramMeta,
                httpClientFactory,
                mediaStore,
                webhookOptions.Value.PublicBaseUrl,
                instagramMenuStore,
                ct);

            foreach (var response in commandResponses)
            {
                foreach (var chunk in SplitLongMessage(response, 3000))
                {
                    await SendReplyAsync(responderInstance, msg.ChatId, chunk);
                }
            }

            continue;
        }

        if (!msg.FromMe &&
            !IsInstagramBotResponse(normalizedText) &&
            instaSettings.Enabled &&
            instaSettings.AllowWhatsApp &&
            IsInstagramAllowed(instaSettings, msg.ChatId))
        {
            var instaKey = $"wa:{msg.ChatId}";
            if (instagramStore.TryConsume(instaKey, out var convo))
            {
                var post = await instagramComposer.BuildAsync(normalizedText, convo.Context, instaSettings, ct);
                foreach (var chunk in SplitInstagramMessages(post))
                {
                    await gateway.SendTextAsync(responderInstance, msg.ChatId, chunk, ct);
                }
                await SendInstagramImagesIfAnyAsync(instaSettings, normalizedText, convo.Context, post, responderInstance, msg.ChatId, instagramMeta, instagramImages, gateway, ct);
                continue;
            }

            if (IsInstagramTrigger(normalizedText, instaSettings.Triggers))
            {
                if (TryGetInstagramInlineProduct(normalizedText, instaSettings.Triggers, out var inlineProduct))
                {
                    var post = await instagramComposer.BuildAsync(inlineProduct, null, instaSettings, ct);
                    foreach (var chunk in SplitInstagramMessages(post))
                    {
                        await gateway.SendTextAsync(responderInstance, msg.ChatId, chunk, ct);
                    }
                    await SendInstagramImagesIfAnyAsync(instaSettings, inlineProduct, null, post, responderInstance, msg.ChatId, instagramMeta, instagramImages, gateway, ct);
                }
                else
                {
                    instagramStore.SetPending(instaKey, normalizedText);
                    await gateway.SendTextAsync(responderInstance, msg.ChatId, "Qual produto? Envie o nome ou o link.", ct);
                }
                continue;
            }
        }

        var autoReply = GetAutoReply(settings, normalizedText);
        if (!msg.FromMe && !string.IsNullOrWhiteSpace(autoReply))
        {
            var tracked = await ApplyTrackingAsync(autoReply, linkTrackingStore, webhookOptions.Value.PublicBaseUrl, responder.TrackingEnabled, ct);
            await gateway.SendTextAsync(responderInstance, msg.ChatId, tracked.Text, ct);
            _ = conversionLogStore.AppendAsync(new ConversionLogEntry
            {
                Source = "AutoReply",
                Store = "AutoReply",
                Success = true,
                OriginalUrl = normalizedText,
                ConvertedUrl = tracked.Text,
                TrackingIds = tracked.TrackingIds,
                OriginChatRef = msg.ChatId,
                DestinationChatRef = msg.ChatId
            }, ct);
            continue;
        }

        if (responder.Enabled &&
            responder.AllowWhatsApp &&
            !msg.FromMe &&
            normalizedText.Contains("http", StringComparison.OrdinalIgnoreCase) &&
            IsWhatsAppResponderAllowed(responder, msg))
        {
            var responderResult = await processor.ProcessAsync(
                normalizedText,
                "WhatsAppResponder",
                ct,
                originChatRef: msg.ChatId,
                destinationChatRef: msg.ChatId,
                sourceImageUrl: msg.HasMedia &&
                                !string.IsNullOrWhiteSpace(msg.MediaUrl) &&
                                (string.IsNullOrWhiteSpace(msg.MediaMimeType) ||
                                 msg.MediaMimeType.StartsWith("image/", StringComparison.OrdinalIgnoreCase))
                    ? msg.MediaUrl
                    : null);

            if (ForwardingSafety.TryGetStrictForwardText(responderResult, out var strictResponderText, out var strictResponderReason))
            {
                var replyText = BuildResponderMessage(responder, strictResponderText);

                // Enriquecer com metadados de produto (Amazon/Shopee/ML)
                var (enrichedReply, responderProductImageUrl, _) = await processor.EnrichTextWithProductDataAsync(
                    replyText, normalizedText, ct);
                replyText = enrichedReply;

                if (responder.AppendSheinCode &&
                    replyText.Contains("shein", StringComparison.OrdinalIgnoreCase) &&
                    !string.IsNullOrWhiteSpace(affiliate.Value.SheinCode) &&
                    !replyText.Contains(affiliate.Value.SheinCode, StringComparison.OrdinalIgnoreCase))
                {
                    replyText += $"\n\nCodigo Shein: {affiliate.Value.SheinCode}";
                }

                if (!string.IsNullOrWhiteSpace(responder.FooterText))
                {
                    replyText += $"\n\n{responder.FooterText}";
                }

                var tracked = await ApplyTrackingAsync(replyText, linkTrackingStore, webhookOptions.Value.PublicBaseUrl, responder.TrackingEnabled, ct);

                if (!string.IsNullOrWhiteSpace(responderProductImageUrl))
                {
                    var imgResult = await gateway.SendImageUrlAsync(responderInstance, msg.ChatId, responderProductImageUrl, tracked.Text, "image/jpeg", null, ct);
                    if (!imgResult.Success)
                    {
                        await gateway.SendTextAsync(responderInstance, msg.ChatId, tracked.Text, ct);
                    }
                }
                else
                {
                    await gateway.SendTextAsync(responderInstance, msg.ChatId, tracked.Text, ct);
                }
                _ = conversionLogStore.AppendAsync(new ConversionLogEntry
                {
                    Source = "WhatsAppResponder",
                    Store = "Unknown",
                    Success = true,
                    OriginalUrl = normalizedText,
                    ConvertedUrl = tracked.Text,
                    TrackingIds = tracked.TrackingIds,
                    OriginChatRef = msg.ChatId,
                    DestinationChatRef = msg.ChatId
                }, ct);
                
                // Sprint 1: Auto-Responder Inteligente (Clean Chat)
                // Remove a mensagem original do membro após postar a conversão bonita
                if (!string.IsNullOrWhiteSpace(msg.MessageId))
                {
                    var isGroup = IsWhatsAppGroupChat(msg.ChatId);
                    var delResult = await gateway.DeleteMessageAsync(responderInstance, msg.ChatId, msg.MessageId, isGroup, ct);
                    if (!delResult.Success)
                    {
                        logger.LogWarning("Não foi possível apagar a mensagem original do membro {SenderId} no chat {ChatId}: {Error}", 
                            msg.SenderId, msg.ChatId, delResult.Message);
                    }
                }

                responderProcessed++;
            }
            else if (!IsWhatsAppGroupChat(msg.ChatId) && !string.IsNullOrWhiteSpace(responder.ReplyOnFailure))
            {
                logger.LogWarning(
                    "WhatsApp responder bloqueado por conversao invalida ou nao afiliada. Chat={ChatId} Reason={Reason} ConvertedLinks={ConvertedLinks} Success={Success}",
                    msg.ChatId,
                    strictResponderReason,
                    responderResult.ConvertedLinks,
                    responderResult.Success);
                await gateway.SendTextAsync(responderInstance, msg.ChatId, responder.ReplyOnFailure, ct);
                responderProcessed++;
            }
        }

        foreach (var waRoute in waRoutes)
        {
            if (!waRoute.Enabled)
            {
                continue;
            }

            var protectedOfficialGroupIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "120363405661434395@g.us"
            };
            var configuredOfficialGroupId = Environment.GetEnvironmentVariable("OFFICIAL_WHATSAPP_GROUP_ID");
            if (!string.IsNullOrWhiteSpace(configuredOfficialGroupId))
            {
                protectedOfficialGroupIds.Add(configuredOfficialGroupId.Trim());
            }

            var isTestRoute = !string.IsNullOrWhiteSpace(waRoute.Name)
                && (waRoute.Name.Contains("teste", StringComparison.OrdinalIgnoreCase)
                    || waRoute.Name.Contains("test", StringComparison.OrdinalIgnoreCase));

            var destinations = waRoute.DestinationGroupIds
                .Where(x => !string.IsNullOrWhiteSpace(x))
                .Where(x => !(isTestRoute && protectedOfficialGroupIds.Contains(x.Trim())))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray();

            if (isTestRoute && destinations.Length == 0 && waRoute.DestinationGroupIds.Count > 0)
            {
                logger.LogWarning(
                    "Rota de teste bloqueada por protecao do grupo oficial. Route={RouteName} Destinations={Destinations}",
                    waRoute.Name,
                    string.Join(",", waRoute.DestinationGroupIds));
            }

            if (destinations.Length == 0 || waRoute.SourceChatIds.Count == 0)
            {
                continue;
            }

            if (msg.FromMe)
            {
                if (!waRoute.ProcessFromMeOnly) continue;
                if (!waRoute.SourceChatIds.Any(id => string.Equals(id, msg.ChatId, StringComparison.OrdinalIgnoreCase))) continue;
            }
            else if (waRoute.ProcessFromMeOnly)
            {
                continue;
            }

            if (waRoute.SourceChatIds.Count > 0 &&
                !waRoute.SourceChatIds.Any(id => string.Equals(id, msg.ChatId, StringComparison.OrdinalIgnoreCase)))
            {
                continue;
            }

            if (destinations.Any(id => string.Equals(id, msg.ChatId, StringComparison.OrdinalIgnoreCase)))
            {
                continue;
            }

            var result = await processor.ProcessAsync(
                normalizedText,
                "WhatsApp",
                ct,
                originChatRef: msg.ChatId,
                destinationChatRef: string.Join(",", destinations),
                sourceImageUrl: msg.HasMedia &&
                                !string.IsNullOrWhiteSpace(msg.MediaUrl) &&
                                (string.IsNullOrWhiteSpace(msg.MediaMimeType) ||
                                 msg.MediaMimeType.StartsWith("image/", StringComparison.OrdinalIgnoreCase))
                    ? msg.MediaUrl
                    : null);

            if (!ForwardingSafety.TryGetStrictForwardText(result, out var finalText, out var strictForwardReason))
            {
                logger.LogWarning(
                    "WhatsApp forwarding bloqueado por conversao invalida ou nao afiliada. Chat={ChatId} Reason={Reason} ConvertedLinks={ConvertedLinks} Success={Success}",
                    msg.ChatId,
                    strictForwardReason,
                    result.ConvertedLinks,
                    result.Success);

                if (!mercadoLivreQueuedToBridge)
                {
                    var hasMercadoLivreLink =
                        ExtractUrlsFromText(normalizedText).Any(IsMercadoLivreUrlLike)
                        || (!string.IsNullOrWhiteSpace(result.ConvertedText)
                            && ExtractUrlsFromText(result.ConvertedText).Any(IsMercadoLivreUrlLike));
                    if (hasMercadoLivreLink)
                    {
                        var bridgeChatId = ResolveMercadoLivreApprovalTelegramBridgeChatId();
                        if (bridgeChatId != 0)
                        {
                            var bridgeText = string.IsNullOrWhiteSpace(normalizedText)
                                ? "Oferta Mercado Livre pendente de aprovacao manual."
                                : normalizedText;
                            var bridgeImageUrl = msg.HasMedia ? msg.MediaUrl : null;
                            var bridgeSent = await SendTelegramManualApprovalAsync(
                                httpClientFactory,
                                telegramOptions.Value,
                                bridgeChatId,
                                bridgeText,
                                bridgeImageUrl,
                                ct);
                            if (bridgeSent)
                            {
                                mercadoLivreQueuedToBridge = true;
                            }
                            else
                            {
                                logger.LogWarning(
                                    "Falha ao enviar pendencia Mercado Livre para ponte Telegram. ChatId={ChatId}",
                                    bridgeChatId);
                            }
                        }
                    }
                }
                continue;
            }

            // Enriquecer com metadados de produto (Amazon/Shopee/ML)
            var (enrichedFinal, forwardProductImageUrl, _) = await processor.EnrichTextWithProductDataAsync(
                finalText, normalizedText, ct);
            finalText = enrichedFinal;

            var hasImageCandidate =
                (msg.HasMedia && (!string.IsNullOrWhiteSpace(msg.MediaUrl) || !string.IsNullOrWhiteSpace(msg.MediaBase64)))
                || !string.IsNullOrWhiteSpace(forwardProductImageUrl);
            var qualityGate = OfferQualityGate.ValidateForAutoForward(finalText, hasImageCandidate);
            if (!qualityGate.Allowed)
            {
                logger.LogWarning(
                    "WhatsApp forwarding bloqueado por quality gate. Chat={ChatId} Reason={Reason} Detail={Detail} HasImageCandidate={HasImageCandidate}",
                    msg.ChatId,
                    qualityGate.Reason,
                    qualityGate.Detail ?? "n/a",
                    hasImageCandidate);

                if (!mercadoLivreQueuedToBridge)
                {
                    var hasMercadoLivreLink =
                        ExtractUrlsFromText(normalizedText).Any(IsMercadoLivreUrlLike)
                        || ExtractUrlsFromText(finalText).Any(IsMercadoLivreUrlLike);
                    if (hasMercadoLivreLink)
                    {
                        var bridgeChatId = ResolveMercadoLivreApprovalTelegramBridgeChatId();
                        if (bridgeChatId != 0)
                        {
                            var bridgeText = string.IsNullOrWhiteSpace(normalizedText)
                                ? finalText
                                : normalizedText;
                            var bridgeImageUrl = msg.HasMedia ? msg.MediaUrl : null;
                            var bridgeSent = await SendTelegramManualApprovalAsync(
                                httpClientFactory,
                                telegramOptions.Value,
                                bridgeChatId,
                                bridgeText,
                                bridgeImageUrl,
                                ct);
                            if (bridgeSent)
                            {
                                mercadoLivreQueuedToBridge = true;
                            }
                            else
                            {
                                logger.LogWarning(
                                    "Falha ao enviar pendencia Mercado Livre para ponte Telegram apos quality gate. ChatId={ChatId}",
                                    bridgeChatId);
                            }
                        }
                    }
                }
                continue;
            }

            if (waRoute.AppendSheinCode &&
                finalText.Contains("shein", StringComparison.OrdinalIgnoreCase) &&
                !string.IsNullOrWhiteSpace(affiliate.Value.SheinCode) &&
                !finalText.Contains(affiliate.Value.SheinCode, StringComparison.OrdinalIgnoreCase))
            {
                finalText += $"\n\nCodigo Shein: {affiliate.Value.SheinCode}";
            }

            if (!string.IsNullOrWhiteSpace(waRoute.FooterText))
            {
                finalText += $"\n\n{waRoute.FooterText}";
            }

            var instanceToUse = FirstNonEmpty(waRoute.InstanceName, waSettings.InstanceName, msg.InstanceName);
            foreach (var destination in destinations)
            {
                WhatsAppForwardSendOutcome outcome;
                if (waRoute.SendMediaEnabled)
                {
                    // Se nao tem midia na msg original mas temos imagem do produto via API, enviar a imagem do produto
                    if (!msg.HasMedia && !string.IsNullOrWhiteSpace(forwardProductImageUrl))
                    {
                        var imgResult = await gateway.SendImageUrlAsync(
                            instanceToUse, destination, forwardProductImageUrl, finalText, "image/jpeg", null, ct);
                        outcome = imgResult.Success
                            ? new WhatsAppForwardSendOutcome(imgResult, "image_sent_product_api")
                            : new WhatsAppForwardSendOutcome(
                                await gateway.SendTextAsync(instanceToUse, destination, finalText, ct),
                                "text_fallback_product_image_failed");
                    }
                    else
                    {
                        outcome = await SendWhatsAppMessageWithMediaFallbackAsync(
                            gateway,
                            httpClientFactory,
                            evolutionOptions.Value,
                            mediaStore,
                            webhookOptions.Value.PublicBaseUrl,
                            instanceToUse,
                            destination,
                            finalText,
                            msg,
                            logger,
                            ct);
                    }
                }
                else
                {
                    var textOnly = await gateway.SendTextAsync(instanceToUse, destination, finalText, ct);
                    outcome = new WhatsAppForwardSendOutcome(textOnly, "text_only_media_disabled");
                }

                if (waRoute.SendMediaEnabled)
                {
                    await mediaFailureLogStore.AppendAsync(new MediaFailureEntry
                    {
                        Source = "WhatsAppWebhook",
                        DestinationChatRef = destination,
                        Success = outcome.Result.Success && (outcome.Mode.StartsWith("image_", StringComparison.OrdinalIgnoreCase) || !msg.HasMedia),
                        Reason = outcome.Mode,
                        Detail = msg.HasMedia
                            ? $"hasMedia=true,mime={msg.MediaMimeType ?? "n/a"},hasUrl={!string.IsNullOrWhiteSpace(msg.MediaUrl)},diag={outcome.Diagnostic ?? outcome.Result.Message ?? "n/a"}"
                            : $"hasMedia=false,diag={outcome.Diagnostic ?? outcome.Result.Message ?? "n/a"}"
                    }, ct);
                }

                var sendResult = outcome.Result;
                if (!sendResult.Success)
                {
                    logger.LogWarning("Falha ao enviar WhatsApp destino {Destination}: {Message}", destination, sendResult.Message);
                }
            }

            processed++;
        }
    }

    return Results.Ok(new { success = true, processed, responderProcessed });
});

app.MapGet("/webhook/instagram", async (HttpRequest request, ISettingsStore store, CancellationToken ct) =>
{
    var settings = await store.GetAsync(ct);
    var verifyToken = settings.InstagramPublish?.VerifyToken;
    var mode = request.Query["hub.mode"].ToString();
    var token = request.Query["hub.verify_token"].ToString();
    var challenge = request.Query["hub.challenge"].ToString();
    if (mode == "subscribe" && !string.IsNullOrWhiteSpace(verifyToken) && token == verifyToken)
    {
        return Results.Text(challenge);
    }
    return Results.BadRequest("Invalid token");
});

app.MapPost("/webhook/instagram", async (
    HttpRequest request,
    ISettingsStore store,
    IInstagramPublishStore publishStore,
    IInstagramCommentStore commentStore,
    IInstagramPublishLogStore publishLogStore,
    IHttpClientFactory httpClientFactory,
    IIdempotencyStore idempotency,
    ILogger<Program> logger,
    CancellationToken ct) =>
{
    var body = await new StreamReader(request.Body).ReadToEndAsync(ct);
    if (string.IsNullOrWhiteSpace(body)) return Results.Ok();

    var settings = await store.GetAsync(ct);
    var publishSettings = settings.InstagramPublish ?? new InstagramPublishSettings();
    var commentsProcessed = 0;
    var directMessagesProcessed = 0;

    foreach (var comment in ExtractInstagramComments(body))
    {
        if (!string.IsNullOrWhiteSpace(comment.CommentId))
        {
            var key = $"ig-comment:{comment.CommentId}";
            if (!idempotency.TryBegin(key, TimeSpan.FromDays(7)))
            {
                continue;
            }
        }

        var isOwnComment = !string.IsNullOrWhiteSpace(publishSettings.InstagramUserId) &&
                           !string.IsNullOrWhiteSpace(comment.FromId) &&
                           string.Equals(comment.FromId, publishSettings.InstagramUserId, StringComparison.OrdinalIgnoreCase);
        if (isOwnComment)
        {
            await publishLogStore.AppendAsync(new InstagramPublishLogEntry
            {
                Action = "comment_ignored_self",
                Success = true,
                MediaId = comment.MediaId,
                Details = $"CommentId={comment.CommentId}"
            }, ct);
            continue;
        }

        var draft = await FindDraftByMediaIdAsync(publishStore, comment.MediaId, ct);
        var cta = ResolveInstagramCtaReply(draft, publishSettings, comment.Text);
        comment.SuggestedReply = cta.Reply;
        comment.MatchedKeyword = cta.Keyword;
        comment.MatchedLink = cta.Link;

        var autoReplyAllowed = publishSettings.AutoReplyEnabled &&
                               !string.IsNullOrWhiteSpace(cta.Reply) &&
                               (!publishSettings.AutoReplyOnlyOnKeywordMatch || cta.HasKeywordMatch);

        if (autoReplyAllowed)
        {
            if (string.IsNullOrWhiteSpace(publishSettings.AccessToken) || publishSettings.AccessToken == "********")
            {
                comment.DmStatus = "skipped";
                comment.DmError = "Access token nao configurado para auto reply.";
                logger.LogWarning("Instagram auto-reply ignorado: access token ausente.");
            }
            else
            {
                var replied = await ReplyToInstagramCommentAsync(
                    httpClientFactory,
                    publishSettings.GraphBaseUrl,
                    comment.CommentId,
                    cta.Reply,
                    publishSettings.AccessToken!,
                    ct);

                if (replied)
                {
                    comment.Status = "approved";
                    comment.ApprovedReply = cta.Reply;
                    await publishLogStore.AppendAsync(new InstagramPublishLogEntry
                    {
                        Action = "comment_reply_auto",
                        Success = true,
                        MediaId = comment.MediaId,
                        Details = $"CommentId={comment.CommentId},Keyword={cta.Keyword}"
                    }, ct);

                    if (publishSettings.AutoDmEnabled && cta.HasKeywordMatch)
                    {
                        var dmMessage = BuildInstagramDmMessage(publishSettings, comment, cta);
                        var dmResult = await SendInstagramAutoDmAsync(httpClientFactory, publishSettings, comment, dmMessage, ct);
                        comment.DmStatus = dmResult.Success ? "sent" : "failed";
                        comment.DmError = dmResult.Error;
                        await publishLogStore.AppendAsync(new InstagramPublishLogEntry
                        {
                            Action = "comment_dm_auto",
                            Success = dmResult.Success,
                            MediaId = comment.MediaId,
                            Error = dmResult.Success ? null : dmResult.Error,
                            Details = $"CommentId={comment.CommentId},Provider={dmResult.Provider},Keyword={cta.Keyword}"
                        }, ct);
                    }
                }
                else
                {
                    await publishLogStore.AppendAsync(new InstagramPublishLogEntry
                    {
                        Action = "comment_reply_auto",
                        Success = false,
                        MediaId = comment.MediaId,
                        Error = "Falha ao responder comentario automaticamente.",
                        Details = $"CommentId={comment.CommentId},Keyword={cta.Keyword}"
                    }, ct);
                }
            }
        }

        await commentStore.AddAsync(comment, ct);
        await publishLogStore.AppendAsync(new InstagramPublishLogEntry
        {
            Action = "comment_received",
            Success = true,
            MediaId = comment.MediaId,
            Details = $"CommentId={comment.CommentId},AutoReply={autoReplyAllowed},AutoDm={publishSettings.AutoDmEnabled}"
        }, ct);
        commentsProcessed++;
    }

    foreach (var directMessage in ExtractInstagramDirectMessages(body))
    {
        if (directMessage.IsEcho)
        {
            continue;
        }

        if (string.IsNullOrWhiteSpace(directMessage.FromId))
        {
            continue;
        }

        if (!string.IsNullOrWhiteSpace(publishSettings.InstagramUserId) &&
            string.Equals(directMessage.FromId, publishSettings.InstagramUserId, StringComparison.OrdinalIgnoreCase))
        {
            continue;
        }

        var dmKeySeed = !string.IsNullOrWhiteSpace(directMessage.MessageId)
            ? directMessage.MessageId!
            : $"{directMessage.FromId}:{directMessage.Text}";
        if (!idempotency.TryBegin($"ig-dm:{dmKeySeed}", TimeSpan.FromDays(7)))
        {
            continue;
        }

        var cta = await ResolveInstagramDmKeywordReplyAsync(publishStore, publishSettings, directMessage.Text, ct);
        var shouldReply = publishSettings.AutoDmEnabled &&
                          !string.IsNullOrWhiteSpace(cta.Reply) &&
                          (!publishSettings.AutoReplyOnlyOnKeywordMatch || cta.HasKeywordMatch);

        if (shouldReply)
        {
            var dmReplyMessage = BuildInstagramInboundDmMessage(publishSettings, cta, directMessage.Text);
            var dmEnvelope = new InstagramCommentPending
            {
                From = directMessage.FromId,
                FromId = directMessage.FromId,
                Text = directMessage.Text,
                MatchedKeyword = cta.Keyword,
                MatchedLink = cta.Link
            };

            var sendResult = await SendInstagramAutoDmAsync(httpClientFactory, publishSettings, dmEnvelope, dmReplyMessage, ct);
            await publishLogStore.AppendAsync(new InstagramPublishLogEntry
            {
                Action = "dm_inbound_reply",
                Success = sendResult.Success,
                Error = sendResult.Success ? null : sendResult.Error,
                Details = $"FromId={directMessage.FromId},Provider={sendResult.Provider},Keyword={cta.Keyword}"
            }, ct);
        }

        await publishLogStore.AppendAsync(new InstagramPublishLogEntry
        {
            Action = "dm_inbound_received",
            Success = true,
            Details = $"FromId={directMessage.FromId},HasKeyword={cta.HasKeywordMatch},AutoDm={publishSettings.AutoDmEnabled}"
        }, ct);
        directMessagesProcessed++;
    }

    return Results.Ok(new { success = true, commentsProcessed, directMessagesProcessed });
});

var api = app.MapGroup("/api").RequireAuthorization("ReadAccess");

api.MapGet("/settings", async (
    ISettingsStore store,
    IOptions<WebhookOptions> webhookOptions,
    IHostEnvironment hostEnvironment,
    HttpContext context,
    CancellationToken ct) =>
{
    var settings = await store.GetAsync(ct);
    if (!string.IsNullOrWhiteSpace(settings.OpenAI?.ApiKey))
    {
        settings.OpenAI.ApiKey = "********";
    }
    if (settings.OpenAI?.ApiKeys?.Count > 0)
    {
        settings.OpenAI.ApiKeys = settings.OpenAI.ApiKeys
            .Where(key => !string.IsNullOrWhiteSpace(key))
            .Select(_ => "********")
            .ToList();
    }
    if (!string.IsNullOrWhiteSpace(settings.Gemini?.ApiKey))
    {
        settings.Gemini.ApiKey = "********";
    }
    if (settings.Gemini?.ApiKeys?.Count > 0)
    {
        settings.Gemini.ApiKeys = settings.Gemini.ApiKeys
            .Where(key => !string.IsNullOrWhiteSpace(key))
            .Select(_ => "********")
            .ToList();
    }
    if (!string.IsNullOrWhiteSpace(settings.DeepSeek?.ApiKey))
    {
        settings.DeepSeek.ApiKey = "********";
    }
    if (settings.DeepSeek?.ApiKeys?.Count > 0)
    {
        settings.DeepSeek.ApiKeys = settings.DeepSeek.ApiKeys
            .Where(key => !string.IsNullOrWhiteSpace(key))
            .Select(_ => "********")
            .ToList();
    }
    if (!string.IsNullOrWhiteSpace(settings.Nemotron?.ApiKey))
    {
        settings.Nemotron.ApiKey = "********";
    }
    if (settings.Nemotron?.ApiKeys?.Count > 0)
    {
        settings.Nemotron.ApiKeys = settings.Nemotron.ApiKeys
            .Where(key => !string.IsNullOrWhiteSpace(key))
            .Select(_ => "********")
            .ToList();
    }
    if (!string.IsNullOrWhiteSpace(settings.Qwen?.ApiKey))
    {
        settings.Qwen.ApiKey = "********";
    }
    if (settings.Qwen?.ApiKeys?.Count > 0)
    {
        settings.Qwen.ApiKeys = settings.Qwen.ApiKeys
            .Where(key => !string.IsNullOrWhiteSpace(key))
            .Select(_ => "********")
            .ToList();
    }
    if (!string.IsNullOrWhiteSpace(settings.VilaNvidia?.ApiKey))
    {
        settings.VilaNvidia.ApiKey = "********";
    }
    if (settings.VilaNvidia?.ApiKeys?.Count > 0)
    {
        settings.VilaNvidia.ApiKeys = settings.VilaNvidia.ApiKeys
            .Where(key => !string.IsNullOrWhiteSpace(key))
            .Select(_ => "********")
            .ToList();
    }
    if (!string.IsNullOrWhiteSpace(settings.InstagramPublish?.AccessToken))
    {
        settings.InstagramPublish.AccessToken = "********";
    }
    if (!string.IsNullOrWhiteSpace(settings.InstagramPublish?.ManyChatApiKey))
    {
        settings.InstagramPublish.ManyChatApiKey = "********";
    }

    var payload = JsonSerializer.SerializeToNode(
        settings,
        new JsonSerializerOptions(JsonSerializerDefaults.Web))?.AsObject() ?? new JsonObject();
    payload["publicBaseUrl"] = ResolvePublicBaseUrl(
        settings.BioHub?.PublicBaseUrl,
        webhookOptions.Value.PublicBaseUrl,
        context.Request.Scheme,
        context.Request.Host.ToString());
    payload["runtimeEnvironment"] = hostEnvironment.EnvironmentName;
    payload["isProduction"] = hostEnvironment.IsProduction();

    return Results.Json(payload);
});

api.MapPost("/agents/offers/curate", async (
    OfferCurationRequest request,
    IOfferCurationAgentService offerCurationAgent,
    IAuditTrail audit,
    HttpContext context,
    CancellationToken ct) =>
{
    var result = await offerCurationAgent.CurateAsync(request, ct);
    await audit.WriteAsync("agents.offer_curator.preview", context.User.Identity?.Name ?? "unknown", new
    {
        request.HoursWindow,
        request.MaxItems,
        request.IncludeDrafts,
        request.IncludeScheduled,
        request.IncludePublished,
        result.EvaluatedDrafts,
        result.SuggestedActions
    }, ct);
    return Results.Ok(result);
});

api.MapPost("/agents/whatsapp/offers/scout", async (
    WhatsAppOfferScoutRequest request,
    IWhatsAppOfferScoutAgentService whatsAppOfferScoutAgent,
    IAuditTrail audit,
    HttpContext context,
    CancellationToken ct) =>
{
    var result = await whatsAppOfferScoutAgent.AnalyzeAsync(request, ct);
    await audit.WriteAsync("agents.whatsapp_offer_scout.preview", context.User.Identity?.Name ?? "unknown", new
    {
        request.SourceChannel,
        request.TargetSelectionMode,
        request.TargetChatIds,
        request.HoursWindow,
        request.MaxItems,
        request.UseAiDecision,
        request.IncludeAiReasoning,
        result.EvaluatedMessages,
        result.SuggestedActions
    }, ct);
    return Results.Ok(result);
});

api.MapGet("/agents/channel-monitor-selections", async (
    string? sourceChannel,
    IChannelMonitorSelectionStore selectionStore,
    CancellationToken ct) =>
{
    var normalizedSource = string.Equals(sourceChannel, "whatsapp", StringComparison.OrdinalIgnoreCase) ? "whatsapp" : "telegram";
    var items = await selectionStore.ListBySourceAsync(normalizedSource, ct);
    return Results.Ok(new ChannelMonitorSelectionResponse
    {
        SourceChannel = normalizedSource,
        Count = items.Count,
        Items = items.ToList()
    });
});

api.MapPost("/agents/channel-monitor-selections", async (
    ChannelMonitorSelectionUpsertRequest request,
    IChannelMonitorSelectionStore selectionStore,
    IAuditTrail audit,
    HttpContext context,
    CancellationToken ct) =>
{
    var normalizedSource = string.Equals(request.SourceChannel, "whatsapp", StringComparison.OrdinalIgnoreCase) ? "whatsapp" : "telegram";
    var selections = request.Selections ?? new List<ChannelMonitorSelectionEntry>();
    var items = await selectionStore.ReplaceSelectionsAsync(normalizedSource, selections, ct);
    await audit.WriteAsync("agents.channel_monitor_selections.update", context.User.Identity?.Name ?? "unknown", new
    {
        SourceChannel = normalizedSource,
        Count = items.Count,
        ChatIds = items.Select(x => x.ChatId).ToArray()
    }, ct);

    return Results.Ok(new ChannelMonitorSelectionResponse
    {
        SourceChannel = normalizedSource,
        Count = items.Count,
        Items = items.ToList()
    });
});

api.MapPost("/agents/channel-monitor-seed-log", async (
    ChannelMonitorSeedLogRequest request,
    IWhatsAppOutboundLogStore whatsAppOutboundLogStore,
    ITelegramOutboundLogStore telegramOutboundLogStore,
    IAuditTrail audit,
    HttpContext context,
    CancellationToken ct) =>
{
    var sourceChannel = string.Equals(request.SourceChannel, "whatsapp", StringComparison.OrdinalIgnoreCase) ? "whatsapp" : "telegram";
    var rawChatId = (request.ChatId ?? string.Empty).Trim();
    if (string.IsNullOrWhiteSpace(rawChatId))
    {
        return Results.BadRequest(new { error = "ChatId obrigatorio." });
    }

    if (sourceChannel == "telegram")
    {
        var normalizedTelegramId = rawChatId.StartsWith("-100", StringComparison.Ordinal) ? rawChatId : $"-100{rawChatId.TrimStart('-')}";
        if (!long.TryParse(normalizedTelegramId, out var telegramChatId))
        {
            return Results.BadRequest(new { error = "ChatId de Telegram invalido." });
        }

        var messageId = $"seed-tg-{DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()}";
        await telegramOutboundLogStore.AppendAsync(new TelegramOutboundLogEntry
        {
            MessageId = messageId,
            CreatedAtUtc = DateTimeOffset.UtcNow,
            ChatId = telegramChatId,
            Text = $"[TESTE AGENTE] {request.Title ?? "Oferta de teste"} https://example.com/oferta/{Math.Abs(telegramChatId)}",
            ImageUrl = "https://picsum.photos/seed/achadinhos-agent/1200/1200"
        }, ct);

        await audit.WriteAsync("agents.channel_monitor.seed_log", context.User.Identity?.Name ?? "unknown", new
        {
            SourceChannel = sourceChannel,
            ChatId = telegramChatId,
            MessageId = messageId
        }, ct);

        return Results.Ok(new { success = true, sourceChannel, chatId = telegramChatId.ToString(), messageId });
    }

    var normalizedWhatsAppId = rawChatId;
    var waMessageId = $"seed-wa-{DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()}";
    await whatsAppOutboundLogStore.AppendAsync(new WhatsAppOutboundLogEntry
    {
        MessageId = waMessageId,
        CreatedAtUtc = DateTimeOffset.UtcNow,
        Kind = "image-url",
        InstanceName = "seed",
        To = normalizedWhatsAppId,
        Text = $"[TESTE AGENTE] {request.Title ?? "Oferta de teste"} https://example.com/oferta/{DateTimeOffset.UtcNow.ToUnixTimeSeconds()}",
        MediaUrl = "https://picsum.photos/seed/achadinhos-agent-wa/1200/1200",
        MimeType = "image/jpeg",
        FileName = "seed-agent.jpg"
    }, ct);

    await audit.WriteAsync("agents.channel_monitor.seed_log", context.User.Identity?.Name ?? "unknown", new
    {
        SourceChannel = sourceChannel,
        ChatId = normalizedWhatsAppId,
        MessageId = waMessageId
    }, ct);

    return Results.Ok(new { success = true, sourceChannel, chatId = normalizedWhatsAppId, messageId = waMessageId });
});

api.MapGet("/agents/channel-monitor-ui-state", async (
    IChannelMonitorUiStateStore uiStateStore,
    CancellationToken ct) =>
{
    var state = await uiStateStore.GetAsync(ct);
    return Results.Ok(state);
});

api.MapPost("/agents/channel-monitor-ui-state", async (
    ChannelMonitorUiState state,
    IChannelMonitorUiStateStore uiStateStore,
    IAuditTrail audit,
    HttpContext context,
    CancellationToken ct) =>
{
    var saved = await uiStateStore.SaveAsync(state, ct);
    await audit.WriteAsync("agents.channel_monitor_ui_state.save", context.User.Identity?.Name ?? "unknown", new
    {
        saved.SourceChannel,
        saved.SelectionMode,
        saved.HoursWindow,
        saved.MaxItems,
        saved.IncludeAiReasoning,
        saved.UseAiDecision
    }, ct);
    return Results.Ok(saved);
});

api.MapGet("/diagnostics/apis", async (
    ISettingsStore store,
    IOptions<AffiliateOptions> affiliateOptions,
    IMercadoLivreOAuthService mercadoLivreOAuthService,
    CancellationToken ct) =>
{
    var settings = await store.GetAsync(ct);
    var affiliate = affiliateOptions.Value;

    var gemini = settings.Gemini ?? new GeminiSettings();
    var geminiKeys = new List<string>();
    if (!string.IsNullOrWhiteSpace(gemini.ApiKey) && gemini.ApiKey != "********")
    {
        geminiKeys.Add(gemini.ApiKey.Trim());
    }
    if (gemini.ApiKeys is not null)
    {
        geminiKeys.AddRange(gemini.ApiKeys
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .Select(x => x.Trim())
            .Where(x => x != "********"));
    }

    var openAiConfigured = !string.IsNullOrWhiteSpace(settings.OpenAI?.ApiKey) && settings.OpenAI.ApiKey != "********";
    var openAiKeys = NormalizeSecretList(settings.OpenAI?.ApiKeys);
    if (openAiConfigured && !string.IsNullOrWhiteSpace(settings.OpenAI?.ApiKey))
    {
        openAiKeys.Add(settings.OpenAI.ApiKey.Trim());
    }
    openAiKeys = openAiKeys.Distinct(StringComparer.Ordinal).ToList();
    var deepSeekKeys = NormalizeSecretList(settings.DeepSeek?.ApiKeys);
    if (!string.IsNullOrWhiteSpace(settings.DeepSeek?.ApiKey) && settings.DeepSeek.ApiKey != "********")
    {
        deepSeekKeys.Add(settings.DeepSeek.ApiKey.Trim());
    }
    deepSeekKeys = deepSeekKeys.Distinct(StringComparer.Ordinal).ToList();
    var nemotronKeys = NormalizeSecretList(settings.Nemotron?.ApiKeys);
    if (!string.IsNullOrWhiteSpace(settings.Nemotron?.ApiKey) && settings.Nemotron.ApiKey != "********")
    {
        nemotronKeys.Add(settings.Nemotron.ApiKey.Trim());
    }
    nemotronKeys = nemotronKeys.Distinct(StringComparer.Ordinal).ToList();
    var qwenKeys = NormalizeSecretList(settings.Qwen?.ApiKeys);
    if (!string.IsNullOrWhiteSpace(settings.Qwen?.ApiKey) && settings.Qwen.ApiKey != "********")
    {
        qwenKeys.Add(settings.Qwen.ApiKey.Trim());
    }
    qwenKeys = qwenKeys.Distinct(StringComparer.Ordinal).ToList();
    var vilaKeys = NormalizeSecretList(settings.VilaNvidia?.ApiKeys);
    if (!string.IsNullOrWhiteSpace(settings.VilaNvidia?.ApiKey) && settings.VilaNvidia.ApiKey != "********")
    {
        vilaKeys.Add(settings.VilaNvidia.ApiKey.Trim());
    }
    vilaKeys = vilaKeys.Distinct(StringComparer.Ordinal).ToList();
    var amazonApi = affiliate.AmazonProductApi ?? new AmazonProductApiOptions();
    var amazonCreatorApi = affiliate.AmazonCreatorApi ?? new AmazonCreatorApiOptions();
    var amazonPaConfigured = !string.IsNullOrWhiteSpace(amazonApi.AccessKey)
        && !string.IsNullOrWhiteSpace(amazonApi.SecretKey)
        && !string.IsNullOrWhiteSpace(amazonApi.PartnerTag);
    var amazonCreatorConfigured = !string.IsNullOrWhiteSpace(amazonCreatorApi.ClientId)
        && !string.IsNullOrWhiteSpace(amazonCreatorApi.ClientSecret)
        && !string.IsNullOrWhiteSpace(amazonCreatorApi.TokenEndpoint)
        && !string.IsNullOrWhiteSpace(amazonCreatorApi.CatalogEndpoint)
        && !string.IsNullOrWhiteSpace(amazonCreatorApi.Version);
    var shopeeApi = affiliate.ShopeeProductApi ?? new ShopeeProductApiOptions();
    var shopeeConfigured = shopeeApi.PartnerId > 0
        && shopeeApi.ShopId > 0
        && !string.IsNullOrWhiteSpace(shopeeApi.PartnerKey);
    var mercadoLivreOAuthConfigured =
        !string.IsNullOrWhiteSpace(affiliate.MercadoLivreClientId) &&
        !string.IsNullOrWhiteSpace(affiliate.MercadoLivreClientSecret) &&
        !string.IsNullOrWhiteSpace(affiliate.MercadoLivreRefreshToken) &&
        !string.IsNullOrWhiteSpace(affiliate.MercadoLivreUserId);
    var mercadoLivreOAuthStatus = mercadoLivreOAuthConfigured
        ? await mercadoLivreOAuthService.GetStatusAsync(ct)
        : null;

    var publish = settings.InstagramPublish ?? new InstagramPublishSettings();
    return Results.Ok(new
    {
        app = new
        {
            instagramPublishEnabled = publish.Enabled,
            autoPilotEnabled = publish.AutoPilotEnabled,
            storyAutoPilotEnabled = publish.StoryAutoPilotEnabled,
            strictMode = new
            {
                requireOfficialProductData = publish.AutoPilotRequireOfficialProductData,
                minimumImageMatchScore = publish.AutoPilotMinimumImageMatchScore,
                requireAiCaption = publish.AutoPilotRequireAiCaption
            }
        },
        ai = new
        {
            openAiConfigured = openAiKeys.Count > 0,
            openAiKeysConfigured = openAiKeys.Count,
            geminiKeysConfigured = geminiKeys.Distinct(StringComparer.Ordinal).Count(),
            deepSeekKeysConfigured = deepSeekKeys.Count,
            nemotronKeysConfigured = nemotronKeys.Count,
            qwenKeysConfigured = qwenKeys.Count,
            vilaKeysConfigured = vilaKeys.Count
        },
        officialProductApis = new
        {
            amazon = new
            {
                enabled = amazonApi.Enabled || amazonCreatorApi.Enabled,
                configured = amazonPaConfigured || amazonCreatorConfigured,
                provider = amazonCreatorApi.Enabled
                    ? "creator-api"
                    : (amazonApi.Enabled ? "pa-api" : "fallback"),
                creatorApi = new
                {
                    enabled = amazonCreatorApi.Enabled,
                    configured = amazonCreatorConfigured
                },
                paApi = new
                {
                    enabled = amazonApi.Enabled,
                    configured = amazonPaConfigured
                }
            },
            shopee = new
            {
                enabled = shopeeApi.Enabled,
                configured = shopeeConfigured
            },
            mercadoLivre = new
            {
                oauthConfigured = mercadoLivreOAuthConfigured,
                oauthValid = mercadoLivreOAuthStatus?.Success ?? false,
                oauthMessage = mercadoLivreOAuthStatus?.Message
            }
        },
        integrations = new
        {
            whatsappConnected = settings.Integrations?.WhatsApp?.Connected ?? false,
            telegramConnected = settings.Integrations?.Telegram?.Connected ?? false,
            mercadoLivreConnected = settings.Integrations?.MercadoLivre?.Connected ?? false
        }
    });
});

api.MapPut("/settings", async (
    AutomationSettings payload,
    ISettingsStore store,
    IAuditTrail audit,
    HttpContext context,
    CancellationToken ct) =>
{
    var errors = ValidateSettings(payload).ToArray();
    if (errors.Length > 0)
    {
        return Results.BadRequest(new { success = false, errors });
    }

    var current = await store.GetAsync(ct);
    if (payload.OpenAI is null)
    {
        payload.OpenAI = current.OpenAI ?? new OpenAISettings();
    }
    else
    {
        var incomingOpenAiApiKey = payload.OpenAI.ApiKey;
        payload.OpenAI.ApiKey = ResolveSecretWithMask(incomingOpenAiApiKey, current.OpenAI?.ApiKey);
        payload.OpenAI.ApiKeys = MergeSecretListWithMask(
            current.OpenAI?.ApiKeys,
            payload.OpenAI.ApiKeys,
            incomingOpenAiApiKey,
            current.OpenAI?.ApiKey);
    }

    if (payload.Gemini is null)
    {
        payload.Gemini = current.Gemini ?? new GeminiSettings();
    }
    else
    {
        var incomingGeminiApiKey = payload.Gemini.ApiKey;
        payload.Gemini.ApiKey = ResolveSecretWithMask(incomingGeminiApiKey, current.Gemini?.ApiKey);
        payload.Gemini.ApiKeys = MergeSecretListWithMask(
            current.Gemini?.ApiKeys,
            payload.Gemini.ApiKeys,
            incomingGeminiApiKey,
            current.Gemini?.ApiKey);
    }

    if (payload.DeepSeek is null)
    {
        payload.DeepSeek = current.DeepSeek ?? new DeepSeekSettings();
    }
    else
    {
        var incomingDeepSeekApiKey = payload.DeepSeek.ApiKey;
        payload.DeepSeek.ApiKey = ResolveSecretWithMask(incomingDeepSeekApiKey, current.DeepSeek?.ApiKey);
        payload.DeepSeek.ApiKeys = MergeSecretListWithMask(
            current.DeepSeek?.ApiKeys,
            payload.DeepSeek.ApiKeys,
            incomingDeepSeekApiKey,
            current.DeepSeek?.ApiKey);
    }

    if (payload.Nemotron is null)
    {
        payload.Nemotron = current.Nemotron ?? new NemotronSettings();
    }
    else
    {
        var incomingNemotronApiKey = payload.Nemotron.ApiKey;
        payload.Nemotron.ApiKey = ResolveSecretWithMask(incomingNemotronApiKey, current.Nemotron?.ApiKey);
        payload.Nemotron.ApiKeys = MergeSecretListWithMask(
            current.Nemotron?.ApiKeys,
            payload.Nemotron.ApiKeys,
            incomingNemotronApiKey,
            current.Nemotron?.ApiKey);
    }

    if (payload.Qwen is null)
    {
        payload.Qwen = current.Qwen ?? new QwenSettings();
    }
    else
    {
        var incomingQwenApiKey = payload.Qwen.ApiKey;
        payload.Qwen.ApiKey = ResolveSecretWithMask(incomingQwenApiKey, current.Qwen?.ApiKey);
        payload.Qwen.ApiKeys = MergeSecretListWithMask(
            current.Qwen?.ApiKeys,
            payload.Qwen.ApiKeys,
            incomingQwenApiKey,
            current.Qwen?.ApiKey);
    }

    if (payload.VilaNvidia is null)
    {
        payload.VilaNvidia = current.VilaNvidia ?? new VilaNvidiaSettings();
    }
    else
    {
        var incomingVilaApiKey = payload.VilaNvidia.ApiKey;
        payload.VilaNvidia.ApiKey = ResolveSecretWithMask(incomingVilaApiKey, current.VilaNvidia?.ApiKey);
        payload.VilaNvidia.ApiKeys = MergeSecretListWithMask(
            current.VilaNvidia?.ApiKeys,
            payload.VilaNvidia.ApiKeys,
            incomingVilaApiKey,
            current.VilaNvidia?.ApiKey);
    }

    if (payload.InstagramPublish is null)
    {
        payload.InstagramPublish = current.InstagramPublish ?? new InstagramPublishSettings();
    }
    else
    {
        var key = payload.InstagramPublish.AccessToken;
        if (string.IsNullOrWhiteSpace(key) || key == "********")
        {
            payload.InstagramPublish.AccessToken = current.InstagramPublish?.AccessToken;
        }

        var manyChatKey = payload.InstagramPublish.ManyChatApiKey;
        if (string.IsNullOrWhiteSpace(manyChatKey) || manyChatKey == "********")
        {
            payload.InstagramPublish.ManyChatApiKey = current.InstagramPublish?.ManyChatApiKey;
        }
    }

    await store.SaveAsync(payload, ct);
    await audit.WriteAsync("settings.updated", context.User.Identity?.Name ?? "unknown", new { autoReplies = payload.AutoReplies.Count }, ct);
    return Results.Ok(new { success = true });
}).RequireAuthorization("AdminOnly");

api.MapPost("/catalog/sync", async (
    IInstagramPublishStore publishStore,
    ICatalogOfferStore catalogOfferStore,
    IAuditTrail audit,
    HttpContext context,
    CancellationToken ct) =>
{
    var drafts = await publishStore.ListAsync(ct);
    var result = await catalogOfferStore.SyncFromPublishedDraftsAsync(drafts, ct);
    await audit.WriteAsync("catalog.sync", context.User.Identity?.Name ?? "unknown", result, ct);
    return Results.Ok(new
    {
        success = true,
        result
    });
}).RequireAuthorization("AdminOnly");

api.MapGet("/catalog/items", async (
    [FromQuery] string? q,
    [FromQuery] int? limit,
    [FromQuery] string? target,
    HttpContext context,
    ICatalogOfferStore catalogOfferStore,
    CancellationToken ct) =>
{
    var catalogTarget = string.IsNullOrWhiteSpace(target)
        ? ResolveCatalogTargetForRequest(context.Request)
        : CatalogTargets.Normalize(target, CatalogTargets.Prod);
    var items = await catalogOfferStore.ListAsync(q, limit ?? 200, ct, catalogTarget);
    return Results.Ok(new { items });
});

api.MapGet("/catalog/items/{query}", async (
    string query,
    [FromQuery] string? target,
    HttpContext context,
    ICatalogOfferStore catalogOfferStore,
    CancellationToken ct) =>
{
    var catalogTarget = string.IsNullOrWhiteSpace(target)
        ? ResolveCatalogTargetForRequest(context.Request)
        : CatalogTargets.Normalize(target, CatalogTargets.Prod);
    var item = await catalogOfferStore.FindByCodeAsync(query, ct, catalogTarget);
    return item is null ? Results.NotFound() : Results.Ok(item);
});

api.MapPost("/integrations/whatsapp/connect", async (
    WhatsAppInstanceRequest payload,
    IWhatsAppGateway gateway,
    ISettingsStore store,
    IAuditTrail audit,
    HttpContext context,
    CancellationToken ct) =>
{
    var result = await gateway.ConnectAsync(payload.InstanceName, ct);

    var settings = await store.GetAsync(ct);
    settings.Integrations.WhatsApp.Connected = result.Success;
    settings.Integrations.WhatsApp.Identifier = "evolution-instance";
    settings.Integrations.WhatsApp.LastLoginAt = DateTimeOffset.UtcNow;
    settings.Integrations.WhatsApp.Notes = result.Message ?? "ConexÃ£o solicitada";
    await store.SaveAsync(settings, ct);

    await audit.WriteAsync("integration.whatsapp.connect", context.User.Identity?.Name ?? "unknown", new { result.Success, payload.InstanceName }, ct);
    return Results.Ok(result);
}).RequireAuthorization("AdminOnly");

api.MapPost("/integrations/whatsapp/instance", async (
    WhatsAppInstanceRequest payload,
    IWhatsAppGateway gateway,
    IAuditTrail audit,
    HttpContext context,
    CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(payload.InstanceName))
    {
        return Results.BadRequest(new { success = false, message = "InstanceName obrigatÃ³rio" });
    }

    var result = await gateway.CreateInstanceAsync(payload.InstanceName, ct);
    await audit.WriteAsync("integration.whatsapp.instance.create", context.User.Identity?.Name ?? "unknown", new { result.Success, payload.InstanceName }, ct);
    return Results.Ok(result);
}).RequireAuthorization("AdminOnly");

api.MapPost("/integrations/telegram/connect", async (
    TelegramBotConnectRequest payload,
    ITelegramGateway gateway,
    ISettingsStore store,
    IAuditTrail audit,
    HttpContext context,
    CancellationToken ct) =>
{
    var result = await gateway.ConnectAsync(payload.BotToken, ct);

    var settings = await store.GetAsync(ct);
    settings.Integrations.Telegram.Connected = result.Success;
    settings.Integrations.Telegram.Identifier = result.Username;
    settings.Integrations.Telegram.LastLoginAt = DateTimeOffset.UtcNow;
    settings.Integrations.Telegram.Notes = result.Message ?? "ConexÃ£o solicitada";
    await store.SaveAsync(settings, ct);

    await audit.WriteAsync("integration.telegram.connect", context.User.Identity?.Name ?? "unknown", new { result.Success, result.Username }, ct);
    return Results.Ok(result);
}).RequireAuthorization("AdminOnly");

api.MapPost("/integrations/telegram/test-alert", async (
    TelegramAlertSender alertSender,
    IOptions<TelegramOptions> telegramOptions,
    IOptions<HeartbeatOptions> heartbeatOptions,
    IAuditTrail audit,
    HttpContext context,
    CancellationToken ct) =>
{
    var chatId = heartbeatOptions.Value.TelegramAlertChatId != 0
        ? heartbeatOptions.Value.TelegramAlertChatId
        : telegramOptions.Value.LogsChatId;

    if (chatId == 0)
    {
        return Results.BadRequest(new
        {
            success = false,
            message = "Chat de alerta nao configurado. Defina Heartbeat:TelegramAlertChatId ou Telegram:LogsChatId."
        });
    }

    var stamp = DateTimeOffset.UtcNow.ToString("yyyy-MM-dd HH:mm:ss 'UTC'");
    var sent = await alertSender.SendAsync(chatId, $"TESTE ALERTA: monitoramento ativo. Horario: {stamp}", ct);

    await audit.WriteAsync("integration.telegram.test_alert", context.User.Identity?.Name ?? "unknown", new { sent, chatId }, ct);

    if (!sent)
    {
        return Results.Json(new { success = false, message = "Falha ao enviar teste no Telegram." }, statusCode: StatusCodes.Status502BadGateway);
    }

    return Results.Ok(new { success = true, chatId, message = "Teste enviado com sucesso no Telegram." });
}).RequireAuthorization("AdminOnly");

api.MapPost("/integrations/mercadolivre/connect", async (
    IMercadoLivreOAuthService mercadoLivreOAuthService,
    ISettingsStore store,
    IAuditTrail audit,
    HttpContext context,
    CancellationToken ct) =>
{
    var result = await mercadoLivreOAuthService.RefreshAndCheckAsync(ct);

    var settings = await store.GetAsync(ct);
    settings.Integrations.MercadoLivre.Connected = result.Success;
    settings.Integrations.MercadoLivre.Identifier = result.UserId?.ToString();
    settings.Integrations.MercadoLivre.LastLoginAt = DateTimeOffset.UtcNow;
    settings.Integrations.MercadoLivre.Notes = result.Message;
    await store.SaveAsync(settings, ct);

    await audit.WriteAsync("integration.mercadolivre.connect", context.User.Identity?.Name ?? "unknown", new
    {
        result.Configured,
        result.Success,
        result.UserId,
        result.RefreshTokenRotated
    }, ct);

    return Results.Ok(result);
}).RequireAuthorization("AdminOnly");

api.MapGet("/coupons", async (ISettingsStore store, CancellationToken ct) =>
{
    var settings = await store.GetAsync(ct);
    var hub = settings.CouponHub ?? new CouponHubSettings();
    var coupons = hub.Coupons
        .OrderByDescending(x => x.Enabled)
        .ThenByDescending(x => x.Priority)
        .ThenBy(x => x.Store)
        .ThenBy(x => x.Code)
        .ToArray();

    return Results.Ok(new
    {
        hub.Enabled,
        hub.AppendToConvertedMessages,
        hub.AppendToInstagramCaptions,
        hub.MaxCouponsPerStore,
        items = coupons
    });
});

api.MapPost("/coupons/upsert", async (
    CouponUpsertRequest payload,
    ISettingsStore store,
    IAuditTrail audit,
    HttpContext context,
    CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(payload.Store) || string.IsNullOrWhiteSpace(payload.Code))
    {
        return Results.BadRequest(new { success = false, message = "Store e Code sao obrigatorios." });
    }

    var settings = await store.GetAsync(ct);
    settings.CouponHub ??= new CouponHubSettings();
    var coupons = settings.CouponHub.Coupons;

    var id = string.IsNullOrWhiteSpace(payload.Id) ? Guid.NewGuid().ToString("N") : payload.Id.Trim();
    var existing = coupons.FirstOrDefault(x => x.Id.Equals(id, StringComparison.OrdinalIgnoreCase));
    if (existing is null)
    {
        existing = coupons.FirstOrDefault(x =>
            x.Store.Equals(payload.Store.Trim(), StringComparison.OrdinalIgnoreCase) &&
            x.Code.Equals(payload.Code.Trim(), StringComparison.OrdinalIgnoreCase));
    }

    if (existing is null)
    {
        coupons.Add(new AffiliateCoupon
        {
            Id = id,
            Enabled = payload.Enabled ?? true,
            Store = payload.Store.Trim(),
            Code = payload.Code.Trim(),
            Description = payload.Description?.Trim() ?? string.Empty,
            AffiliateLink = string.IsNullOrWhiteSpace(payload.AffiliateLink) ? null : payload.AffiliateLink.Trim(),
            StartsAt = payload.StartsAt,
            EndsAt = payload.EndsAt,
            Priority = payload.Priority ?? 100,
            Source = string.IsNullOrWhiteSpace(payload.Source) ? "manual" : payload.Source.Trim(),
            CreatedAt = DateTimeOffset.UtcNow
        });
    }
    else
    {
        existing.Enabled = payload.Enabled ?? existing.Enabled;
        existing.Store = payload.Store.Trim();
        existing.Code = payload.Code.Trim();
        existing.Description = payload.Description?.Trim() ?? existing.Description;
        existing.AffiliateLink = string.IsNullOrWhiteSpace(payload.AffiliateLink) ? existing.AffiliateLink : payload.AffiliateLink.Trim();
        existing.StartsAt = payload.StartsAt ?? existing.StartsAt;
        existing.EndsAt = payload.EndsAt ?? existing.EndsAt;
        existing.Priority = payload.Priority ?? existing.Priority;
        existing.Source = string.IsNullOrWhiteSpace(payload.Source) ? existing.Source : payload.Source.Trim();
    }

    await store.SaveAsync(settings, ct);
    await audit.WriteAsync("coupon.upsert", context.User.Identity?.Name ?? "unknown", new { id, payload.Store, payload.Code }, ct);
    return Results.Ok(new { success = true, id });
}).RequireAuthorization("AdminOnly");

api.MapDelete("/coupons/{id}", async (
    string id,
    ISettingsStore store,
    IAuditTrail audit,
    HttpContext context,
    CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(id))
    {
        return Results.BadRequest(new { success = false, message = "Id obrigatorio." });
    }

    var settings = await store.GetAsync(ct);
    settings.CouponHub ??= new CouponHubSettings();
    var removed = settings.CouponHub.Coupons.RemoveAll(x => x.Id.Equals(id.Trim(), StringComparison.OrdinalIgnoreCase));

    if (removed == 0)
    {
        return Results.NotFound(new { success = false, message = "Cupom nao encontrado." });
    }

    await store.SaveAsync(settings, ct);
    await audit.WriteAsync("coupon.delete", context.User.Identity?.Name ?? "unknown", new { id = id.Trim(), removed }, ct);
    return Results.Ok(new { success = true, removed });
}).RequireAuthorization("AdminOnly");

api.MapPost("/coupons/extract", async (
    CouponExtractRequest payload,
    ISettingsStore store,
    IAuditTrail audit,
    HttpContext context,
    CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(payload.Store) || string.IsNullOrWhiteSpace(payload.Text))
    {
        return Results.BadRequest(new { success = false, message = "Store e Text sao obrigatorios." });
    }

    var codes = ExtractCouponCodesFromText(payload.Text);
    if (codes.Count == 0)
    {
        return Results.BadRequest(new { success = false, message = "Nenhum cupom detectado no texto." });
    }

    var settings = await store.GetAsync(ct);
    settings.CouponHub ??= new CouponHubSettings();
    var inserted = 0;
    foreach (var code in codes)
    {
        var exists = settings.CouponHub.Coupons.Any(x =>
            x.Store.Equals(payload.Store.Trim(), StringComparison.OrdinalIgnoreCase) &&
            x.Code.Equals(code, StringComparison.OrdinalIgnoreCase));
        if (exists)
        {
            continue;
        }

        settings.CouponHub.Coupons.Add(new AffiliateCoupon
        {
            Id = Guid.NewGuid().ToString("N"),
            Enabled = true,
            Store = payload.Store.Trim(),
            Code = code,
            Description = payload.Description?.Trim() ?? string.Empty,
            AffiliateLink = string.IsNullOrWhiteSpace(payload.AffiliateLink) ? null : payload.AffiliateLink.Trim(),
            EndsAt = payload.EndsAt,
            Priority = payload.Priority ?? 100,
            Source = string.IsNullOrWhiteSpace(payload.Source) ? "extract" : payload.Source.Trim(),
            CreatedAt = DateTimeOffset.UtcNow
        });
        inserted++;
    }

    if (inserted > 0)
    {
        await store.SaveAsync(settings, ct);
    }

    await audit.WriteAsync("coupon.extract", context.User.Identity?.Name ?? "unknown", new { payload.Store, inserted, codes }, ct);
    return Results.Ok(new { success = true, inserted, codes });
}).RequireAuthorization("AdminOnly");

api.MapPost("/coupons/sync-official", async (
    CouponOfficialSyncRequest payload,
    IAffiliateCouponSyncService couponSyncService,
    IAuditTrail audit,
    HttpContext context,
    CancellationToken ct) =>
{
    var result = await couponSyncService.SyncAsync(new AffiliateCouponSyncRequest(payload.Store), ct);

    await audit.WriteAsync("coupon.sync.official", context.User.Identity?.Name ?? "unknown", new
    {
        payload.Store,
        result.Success,
        result.ProvidersAttempted,
        result.ProvidersSucceeded,
        result.TotalFetched,
        result.TotalInserted,
        result.TotalUpdated,
        result.TotalIgnored
    }, ct);

    return Results.Ok(result);
}).RequireAuthorization("AdminOnly");

api.MapPost("/playground/preview", async (
    PlaygroundRequest payload,
    IMessageProcessor processor,
    ISettingsStore store,
    CancellationToken ct) =>
{
    var settings = await store.GetAsync(ct);
    var matched = settings.AutoReplies.FirstOrDefault(r => r.Enabled && payload.Text.Contains(r.Trigger, StringComparison.OrdinalIgnoreCase));
    var result = await processor.ProcessAsync(payload.Text, "Playground", ct);

    return Results.Ok(new
    {
        matchedRule = matched?.Name,
        autoReply = matched?.ResponseTemplate,
        converted = result.ConvertedText,
        convertedLinks = result.ConvertedLinks
    });
});

api.MapPost("/instagram/test", async (
    InstagramTestRequest payload,
    ISettingsStore store,
    IInstagramPostComposer composer,
    OpenAiInstagramPostGenerator openAiGenerator,
    GeminiInstagramPostGenerator geminiGenerator,
    DeepSeekInstagramPostGenerator deepSeekGenerator,
    NemotronInstagramPostGenerator nemotronGenerator,
    QwenInstagramPostGenerator qwenGenerator,
    VilaNvidiaGenerator vilaGenerator,
    CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(payload.Input))
    {
        return Results.BadRequest(new { error = "Informe o texto para teste." });
    }

    var settings = await store.GetAsync(ct);
    var insta = settings.InstagramPosts ?? new InstagramPostSettings();
    if (!string.IsNullOrWhiteSpace(payload.Provider))
    {
        insta = JsonSerializer.Deserialize<InstagramPostSettings>(JsonSerializer.Serialize(insta)) ?? new InstagramPostSettings();
        insta.AiProvider = payload.Provider.Trim().ToLowerInvariant();
    }

    var mode = string.IsNullOrWhiteSpace(payload.Mode) ? "structured" : payload.Mode.Trim().ToLowerInvariant();
    string text;
    if (mode == "raw")
    {
        text = (insta.AiProvider ?? "openai") switch
        {
            "gemini" => await geminiGenerator.GenerateFreeformAsync(string.Join("\n\n", new[] { payload.Input, payload.Context }.Where(x => !string.IsNullOrWhiteSpace(x))), settings.Gemini ?? new GeminiSettings(), ct) ?? "Sem resposta.",
            "deepseek" => await deepSeekGenerator.GenerateFreeformAsync(string.Join("\n\n", new[] { payload.Input, payload.Context }.Where(x => !string.IsNullOrWhiteSpace(x))), settings.DeepSeek ?? new DeepSeekSettings(), ct) ?? "Sem resposta.",
            "nemotron" => await nemotronGenerator.GenerateFreeformAsync(string.Join("\n\n", new[] { payload.Input, payload.Context }.Where(x => !string.IsNullOrWhiteSpace(x))), settings.Nemotron ?? new NemotronSettings(), ct) ?? "Sem resposta.",
            "qwen" => await qwenGenerator.GenerateFreeformAsync(string.Join("\n\n", new[] { payload.Input, payload.Context }.Where(x => !string.IsNullOrWhiteSpace(x))), settings.Qwen ?? new QwenSettings(), ct) ?? "Sem resposta.",
            "vila" => await vilaGenerator.GenerateFreeformAsync(string.Join("\n\n", new[] { payload.Input, payload.Context }.Where(x => !string.IsNullOrWhiteSpace(x))), settings.VilaNvidia ?? new VilaNvidiaSettings(), ct) ?? "Sem resposta.",
            _ => await openAiGenerator.GenerateFreeformAsync(string.Join("\n\n", new[] { payload.Input, payload.Context }.Where(x => !string.IsNullOrWhiteSpace(x))), settings.OpenAI ?? new OpenAISettings(), ct) ?? "Sem resposta."
        };
    }
    else
    {
        text = await composer.BuildAsync(payload.Input, payload.Context, insta, ct);
    }

    return Results.Ok(new { text, provider = insta.AiProvider });
}).RequireAuthorization("AdminOnly");

api.MapPost("/ai-lab/compare", async (
    InstagramTestRequest payload,
    ISettingsStore store,
    IInstagramPostComposer composer,
    OpenAiInstagramPostGenerator openAiGenerator,
    GeminiInstagramPostGenerator geminiGenerator,
    DeepSeekInstagramPostGenerator deepSeekGenerator,
    NemotronInstagramPostGenerator nemotronGenerator,
    QwenInstagramPostGenerator qwenGenerator,
    VilaNvidiaGenerator vilaGenerator,
    CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(payload.Input))
    {
        return Results.BadRequest(new { error = "Informe o texto para teste." });
    }

    var requestedProviders = (payload.Providers ?? new List<string> { "openai", "gemini", "deepseek", "nemotron", "qwen", "vila" })
        .Where(x => !string.IsNullOrWhiteSpace(x))
        .Select(x => x.Trim().ToLowerInvariant())
        .Distinct(StringComparer.OrdinalIgnoreCase)
        .ToList();

    var allowedProviders = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "openai", "gemini", "deepseek", "nemotron", "qwen", "vila" };
    var providers = requestedProviders.Where(allowedProviders.Contains).ToList();
    if (providers.Count == 0)
    {
        return Results.BadRequest(new { error = "Selecione ao menos um provedor valido." });
    }

    var settings = await store.GetAsync(ct);
    var instaBase = settings.InstagramPosts ?? new InstagramPostSettings();
    var results = new List<object>();
    var mode = string.IsNullOrWhiteSpace(payload.Mode) ? "raw" : payload.Mode.Trim().ToLowerInvariant();
    var freeformPrompt = string.Join("\n\n", new[] { payload.Input, payload.Context }.Where(x => !string.IsNullOrWhiteSpace(x)));

    foreach (var provider in providers)
    {
        var started = DateTimeOffset.UtcNow;
        string text;
        if (mode == "structured")
        {
            var insta = JsonSerializer.Deserialize<InstagramPostSettings>(JsonSerializer.Serialize(instaBase)) ?? new InstagramPostSettings();
            insta.AiProvider = provider;
            text = await composer.BuildAsync(payload.Input, payload.Context, insta, ct);
        }
        else
        {
            text = provider switch
            {
                "gemini" => await geminiGenerator.GenerateFreeformAsync(freeformPrompt, settings.Gemini ?? new GeminiSettings(), ct) ?? "Sem resposta.",
                "deepseek" => await deepSeekGenerator.GenerateFreeformAsync(freeformPrompt, settings.DeepSeek ?? new DeepSeekSettings(), ct) ?? "Sem resposta.",
                "nemotron" => await nemotronGenerator.GenerateFreeformAsync(freeformPrompt, settings.Nemotron ?? new NemotronSettings(), ct) ?? "Sem resposta.",
                "qwen" => await qwenGenerator.GenerateFreeformAsync(freeformPrompt, settings.Qwen ?? new QwenSettings(), ct) ?? "Sem resposta.",
                "vila" => await vilaGenerator.GenerateFreeformAsync(freeformPrompt, settings.VilaNvidia ?? new VilaNvidiaSettings(), ct) ?? "Sem resposta.",
                _ => await openAiGenerator.GenerateFreeformAsync(freeformPrompt, settings.OpenAI ?? new OpenAISettings(), ct) ?? "Sem resposta."
            };
        }

        results.Add(new
        {
            provider,
            mode,
            durationMs = (long)(DateTimeOffset.UtcNow - started).TotalMilliseconds,
            text
        });
    }

    return Results.Ok(new { success = true, results });
}).RequireAuthorization("AdminOnly");

api.MapGet("/content-calendar/items", async (
    [FromQuery] int? limit,
    IContentCalendarStore store,
    CancellationToken ct) =>
{
    var max = Math.Clamp(limit ?? 300, 1, 1000);
    var items = (await store.ListAsync(ct))
        .OrderBy(x => x.ScheduledAt)
        .Take(max)
        .ToList();
    return Results.Ok(new { items });
}).RequireAuthorization("ReadAccess");

api.MapGet("/content-calendar/csv", async (
    IContentCalendarStore store,
    CancellationToken ct) =>
{
    var csv = await store.ExportCsvAsync(ct);
    var bytes = Encoding.UTF8.GetBytes(csv);
    return Results.File(bytes, "text/csv; charset=utf-8", "content-calendar.csv");
}).RequireAuthorization("AdminOnly");

api.MapPost("/content-calendar/items", async (
    ContentCalendarCreateRequest payload,
    ContentCalendarAutomationService automationService,
    CancellationToken ct) =>
{
    var item = await automationService.CreateAsync(payload, ct);
    return Results.Ok(new { success = true, item });
}).RequireAuthorization("AdminOnly");

api.MapPut("/content-calendar/items/{id}", async (
    string id,
    ContentCalendarCreateRequest payload,
    IContentCalendarStore store,
    CancellationToken ct) =>
{
    var existing = await store.GetAsync(id, ct);
    if (existing is null)
    {
        return Results.NotFound(new { error = "Item do calendario nao encontrado." });
    }

    existing.ScheduledAt = payload.ScheduledAt ?? existing.ScheduledAt;
    existing.PostType = string.IsNullOrWhiteSpace(payload.PostType) ? existing.PostType : payload.PostType.Trim();
    existing.SourceInput = payload.SourceInput ?? existing.SourceInput;
    existing.OfferContext = payload.OfferContext ?? existing.OfferContext;
    existing.MediaUrl = payload.MediaUrl ?? existing.MediaUrl;
    existing.OfferUrl = payload.OfferUrl ?? existing.OfferUrl;
    existing.Keyword = payload.Keyword ?? existing.Keyword;
    existing.Hashtags = payload.Hashtags ?? existing.Hashtags;
    existing.GeneratedCaption = payload.GeneratedCaption ?? existing.GeneratedCaption;
    existing.AutoPublish = payload.AutoPublish ?? existing.AutoPublish;
    existing.ReferenceUrl = payload.ReferenceUrl ?? existing.ReferenceUrl;
    existing.ReferenceCaption = payload.ReferenceCaption ?? existing.ReferenceCaption;
    existing.ReferenceMediaUrl = payload.ReferenceMediaUrl ?? existing.ReferenceMediaUrl;
    existing.UpdatedAt = DateTimeOffset.UtcNow;
    await store.SaveAsync(existing, ct);

    return Results.Ok(new { success = true, item = existing });
}).RequireAuthorization("AdminOnly");

api.MapDelete("/content-calendar/items/{id}", async (
    string id,
    IContentCalendarStore store,
    CancellationToken ct) =>
{
    await store.DeleteAsync(id, ct);
    return Results.Ok(new { success = true });
}).RequireAuthorization("AdminOnly");

api.MapPost("/content-calendar/import-reference", async (
    ContentReferenceImportRequest payload,
    ContentCalendarAutomationService automationService,
    CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(payload.ReferenceUrl) &&
        string.IsNullOrWhiteSpace(payload.ReferenceCaption) &&
        string.IsNullOrWhiteSpace(payload.OfferUrl))
    {
        return Results.BadRequest(new { error = "Informe ao menos referencia (url/legenda) ou link da oferta." });
    }

    var item = await automationService.ImportReferenceAsync(payload, ct);
    return Results.Ok(new { success = true, item });
}).RequireAuthorization("AdminOnly");

api.MapPost("/content-calendar/process-due", async (
    ContentCalendarAutomationService automationService,
    CancellationToken ct) =>
{
    var result = await automationService.ProcessDueAsync(ct);
    return Results.Ok(new { success = true, result });
}).RequireAuthorization("AdminOnly");

api.MapGet("/instagram/publish/drafts", async (
    IInstagramPublishStore publishStore,
    CancellationToken ct) =>
{
    var items = await publishStore.ListAsync(ct);
    return Results.Ok(new { items });
}).RequireAuthorization("AdminOnly");

api.MapPost("/instagram/publish/drafts", async (
    InstagramDraftRequest payload,
    IInstagramPublishStore publishStore,
    IInstagramPublishLogStore publishLogStore,
    CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(payload.ProductName) && string.IsNullOrWhiteSpace(payload.Caption))
    {
        return Results.BadRequest(new { error = "Informe produto ou legenda." });
    }

    var draft = new InstagramPublishDraft
    {
        PostType = NormalizeInstagramPostTypeValue(payload.PostType),
        ProductName = payload.ProductName?.Trim() ?? string.Empty,
        Caption = payload.Caption?.Trim() ?? string.Empty,
        Hashtags = payload.Hashtags?.Trim() ?? string.Empty,
        ImageUrls = payload.ImageUrls?.Where(x => !string.IsNullOrWhiteSpace(x)).ToList() ?? new List<string>(),
        Ctas = payload.Ctas ?? new List<InstagramCtaOption>()
    };
    await publishStore.SaveAsync(draft, ct);
    await publishLogStore.AppendAsync(new InstagramPublishLogEntry
    {
        Action = "draft_created",
        Success = true,
        DraftId = draft.Id,
        Details = $"Images={draft.ImageUrls.Count},Ctas={draft.Ctas.Count}"
    }, ct);
    return Results.Ok(new { success = true, id = draft.Id });
}).RequireAuthorization("AdminOnly");

api.MapPost("/instagram/autopilot/run", async (
    InstagramAutoPilotRunRequest payload,
    IInstagramAutoPilotService autoPilotService,
    CancellationToken ct) =>
{
    var result = await autoPilotService.RunNowAsync(payload, ct);
    return Results.Ok(result);
}).RequireAuthorization("AdminOnly");

api.MapPost("/instagram/autostory/run", async (
    InstagramAutoPilotRunRequest payload,
    IInstagramAutoPilotService autoPilotService,
    CancellationToken ct) =>
{
    payload.PostType = "story";
    var result = await autoPilotService.RunNowAsync(payload, ct);
    return Results.Ok(result);
}).RequireAuthorization("AdminOnly");

api.MapPost("/instagram/publish/drafts/{id}/publish", async (
    string id,
    ISettingsStore store,
    IInstagramPublishStore publishStore,
    IInstagramPublishLogStore publishLogStore,
    IHttpClientFactory httpClientFactory,
    IMediaStore mediaStore,
    IOptions<WebhookOptions> webhookOptions,
    CancellationToken ct) =>
{
    var settings = await store.GetAsync(ct);
    var publishResult = await PublishInstagramDraftAsync(
        id,
        settings.InstagramPublish ?? new InstagramPublishSettings(),
        settings.VilaNvidia ?? new VilaNvidiaSettings(),
        settings.Gemini ?? new GeminiSettings(),
        publishStore,
        publishLogStore,
        httpClientFactory,
        mediaStore,
        webhookOptions.Value.PublicBaseUrl,
        ct);

    return Results.Json(
        new { success = publishResult.Success, mediaId = publishResult.MediaId, error = publishResult.Error },
        statusCode: publishResult.StatusCode);
}).RequireAuthorization("AdminOnly");

api.MapPost("/instagram/publish/test", async (
    ISettingsStore store,
    IInstagramPublishLogStore publishLogStore,
    IHttpClientFactory httpClientFactory,
    CancellationToken ct) =>
{
    var settings = await store.GetAsync(ct);
    var publishSettings = settings.InstagramPublish ?? new InstagramPublishSettings();
    if (!publishSettings.Enabled)
    {
        await publishLogStore.AppendAsync(new InstagramPublishLogEntry
        {
            Action = "test",
            Success = false,
            Error = "Publicacao Instagram desativada."
        }, ct);
        return Results.BadRequest(new { error = "Publicacao Instagram desativada." });
    }
    if (string.IsNullOrWhiteSpace(publishSettings.AccessToken) || publishSettings.AccessToken == "********")
    {
        await publishLogStore.AppendAsync(new InstagramPublishLogEntry
        {
            Action = "test",
            Success = false,
            Error = "Access token nao configurado."
        }, ct);
        return Results.BadRequest(new { error = "Access token nao configurado." });
    }
    if (string.IsNullOrWhiteSpace(publishSettings.InstagramUserId))
    {
        await publishLogStore.AppendAsync(new InstagramPublishLogEntry
        {
            Action = "test",
            Success = false,
            Error = "Instagram user id nao configurado."
        }, ct);
        return Results.BadRequest(new { error = "Instagram user id nao configurado." });
    }

    var client = httpClientFactory.CreateClient("default");
    var baseUrl = string.IsNullOrWhiteSpace(publishSettings.GraphBaseUrl)
        ? "https://graph.facebook.com/v19.0"
        : publishSettings.GraphBaseUrl.TrimEnd('/');

    var meUrl = $"{baseUrl}/{publishSettings.InstagramUserId}?fields=id,username&access_token={Uri.EscapeDataString(publishSettings.AccessToken!)}";
    using var meResp = await client.GetAsync(meUrl, ct);
    var meBody = await meResp.Content.ReadAsStringAsync(ct);
    if (!meResp.IsSuccessStatusCode)
    {
        await publishLogStore.AppendAsync(new InstagramPublishLogEntry
        {
            Action = "test",
            Success = false,
            Error = "Falha ao validar usuario.",
            Details = meBody
        }, ct);
        return Results.BadRequest(new { error = "Falha ao validar usuario.", details = meBody });
    }

    var mediaUrl = $"{baseUrl}/{publishSettings.InstagramUserId}/media?limit=1&access_token={Uri.EscapeDataString(publishSettings.AccessToken!)}";
    using var mediaResp = await client.GetAsync(mediaUrl, ct);
    var mediaBody = await mediaResp.Content.ReadAsStringAsync(ct);
    if (!mediaResp.IsSuccessStatusCode)
    {
        await publishLogStore.AppendAsync(new InstagramPublishLogEntry
        {
            Action = "test",
            Success = false,
            Error = "Falha ao listar midias.",
            Details = mediaBody
        }, ct);
        return Results.BadRequest(new { error = "Falha ao listar midias.", details = mediaBody });
    }

    await publishLogStore.AppendAsync(new InstagramPublishLogEntry
    {
        Action = "test",
        Success = true,
        Details = "Conexao OK"
    }, ct);
    return Results.Ok(new { success = true });
}).RequireAuthorization("AdminOnly");

api.MapGet("/instagram/publish/status/{mediaId}", async (
    string mediaId,
    ISettingsStore store,
    IInstagramPublishLogStore publishLogStore,
    IHttpClientFactory httpClientFactory,
    CancellationToken ct) =>
{
    var settings = await store.GetAsync(ct);
    var publishSettings = settings.InstagramPublish ?? new InstagramPublishSettings();
    if (string.IsNullOrWhiteSpace(publishSettings.AccessToken) || publishSettings.AccessToken == "********")
    {
        return Results.BadRequest(new { error = "Access token nao configurado." });
    }

    var client = httpClientFactory.CreateClient("default");
    var baseUrl = string.IsNullOrWhiteSpace(publishSettings.GraphBaseUrl)
        ? "https://graph.facebook.com/v19.0"
        : publishSettings.GraphBaseUrl.TrimEnd('/');
    var url = $"{baseUrl}/{mediaId}?fields=id,status,permalink,media_type&access_token={Uri.EscapeDataString(publishSettings.AccessToken!)}";
    using var resp = await client.GetAsync(url, ct);
    var body = await resp.Content.ReadAsStringAsync(ct);
    if (!resp.IsSuccessStatusCode)
    {
        await publishLogStore.AppendAsync(new InstagramPublishLogEntry
        {
            Action = "status_check",
            Success = false,
            MediaId = mediaId,
            Error = "Falha ao consultar status.",
            Details = body
        }, ct);
        return Results.BadRequest(new { error = "Falha ao consultar status.", details = body });
    }

    await publishLogStore.AppendAsync(new InstagramPublishLogEntry
    {
        Action = "status_check",
        Success = true,
        MediaId = mediaId,
        Details = body
    }, ct);
    return Results.Ok(new { success = true, data = body });
}).RequireAuthorization("AdminOnly");

api.MapGet("/instagram/comments/pending", async (
    IInstagramCommentStore commentStore,
    CancellationToken ct) =>
{
    var items = await commentStore.ListPendingAsync(ct);
    return Results.Ok(new { items });
}).RequireAuthorization("AdminOnly");

api.MapPost("/instagram/comments/{id}/approve", async (
    string id,
    InstagramApproveRequest payload,
    ISettingsStore store,
    IInstagramCommentStore commentStore,
    IInstagramPublishLogStore publishLogStore,
    IHttpClientFactory httpClientFactory,
    CancellationToken ct) =>
{
    var settings = await store.GetAsync(ct);
    var publishSettings = settings.InstagramPublish ?? new InstagramPublishSettings();
    if (string.IsNullOrWhiteSpace(publishSettings.AccessToken) || publishSettings.AccessToken == "********")
    {
        return Results.BadRequest(new { error = "Access token nao configurado." });
    }

    var comment = await commentStore.GetAsync(id, ct);
    if (comment is null) return Results.NotFound();

    var reply = payload.Message?.Trim();
    if (string.IsNullOrWhiteSpace(reply)) return Results.BadRequest(new { error = "Mensagem vazia." });

    var ok = await ReplyToInstagramCommentAsync(httpClientFactory, publishSettings.GraphBaseUrl, comment.CommentId, reply!, publishSettings.AccessToken!, ct);
    if (!ok)
    {
        await publishLogStore.AppendAsync(new InstagramPublishLogEntry
        {
            Action = "comment_reply",
            Success = false,
            MediaId = comment.MediaId,
            Error = "Falha ao responder comentario."
        }, ct);
        return Results.BadRequest(new { error = "Falha ao responder comentario." });
    }

    comment.Status = "approved";
    comment.ApprovedReply = reply;
    await commentStore.UpdateAsync(comment, ct);
    await publishLogStore.AppendAsync(new InstagramPublishLogEntry
    {
        Action = "comment_reply",
        Success = true,
        MediaId = comment.MediaId,
        Details = $"CommentId={comment.CommentId}"
    }, ct);
    return Results.Ok(new { success = true });
}).RequireAuthorization("AdminOnly");

api.MapPost("/instagram/comments/{id}/reject", async (
    string id,
    IInstagramCommentStore commentStore,
    IInstagramPublishLogStore publishLogStore,
    CancellationToken ct) =>
{
    var comment = await commentStore.GetAsync(id, ct);
    if (comment is null) return Results.NotFound();
    comment.Status = "rejected";
    await commentStore.UpdateAsync(comment, ct);
    await publishLogStore.AppendAsync(new InstagramPublishLogEntry
    {
        Action = "comment_reject",
        Success = true,
        MediaId = comment.MediaId,
        Details = $"CommentId={comment.CommentId}"
    }, ct);
    return Results.Ok(new { success = true });
}).RequireAuthorization("AdminOnly");

api.MapGet("/mercadolivre/pending", async (
    [FromQuery] string? status,
    [FromQuery] int? limit,
    IMercadoLivreApprovalStore approvalStore,
    IMessageProcessor processor,
    CancellationToken ct) =>
{
    var items = await approvalStore.ListAsync(status, limit ?? 200, ct);
    var previewBudget = 50;
    var previewUsed = 0;
    var enriched = new List<object>(items.Count);

    foreach (var item in items)
    {
        var previewConvertedUrls = new List<string>();
        if (previewUsed < previewBudget
            && string.Equals(item.Status, "pending", StringComparison.OrdinalIgnoreCase)
            && !string.IsNullOrWhiteSpace(item.OriginalText))
        {
            var preview = await processor.ProcessAsync(
                item.OriginalText,
                "MercadoLivreManualApproval",
                ct,
                originChatId: item.OriginChatId,
                destinationChatId: item.DestinationChatId,
                originChatRef: item.OriginChatRef,
                destinationChatRef: item.DestinationChatRef);

            previewUsed++;
            if (!string.IsNullOrWhiteSpace(preview.ConvertedText))
            {
                previewConvertedUrls = ExtractUrlsFromText(preview.ConvertedText!)
                    .Where(IsMercadoLivreUrlLike)
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .Take(10)
                    .ToList();
            }
        }

        enriched.Add(new
        {
            item.Id,
            item.CreatedAt,
            item.Status,
            item.Source,
            item.Reason,
            item.OriginalText,
            item.ExtractedUrls,
            item.OriginChatId,
            item.DestinationChatId,
            item.OriginChatRef,
            item.DestinationChatRef,
            item.ReviewedAt,
            item.ReviewedBy,
            item.ReviewNote,
            item.ConvertedText,
            item.ConvertedLinks,
            item.OriginalImageUrl,
            previewConvertedUrls
        });
    }

    return Results.Ok(new { items = enriched });
}).RequireAuthorization("AdminOnly");

api.MapPost("/mercadolivre/pending/{id}/approve", async (
    string id,
    MercadoLivreDecisionRequest payload,
    IMercadoLivreApprovalStore approvalStore,
    IMessageProcessor processor,
    ISettingsStore settingsStore,
    IWhatsAppGateway gateway,
    IHttpClientFactory httpClientFactory,
    IOptions<TelegramOptions> telegramOptions,
    IAuditTrail audit,
    HttpContext context,
    CancellationToken ct) =>
{
    var item = await approvalStore.GetAsync(id, ct);
    if (item is null)
    {
        return Results.NotFound(new { error = "Pendencia nao encontrada." });
    }

    if (!string.Equals(item.Status, "pending", StringComparison.OrdinalIgnoreCase))
    {
        return Results.Ok(new
        {
            success = true,
            alreadyReviewed = true,
            status = item.Status,
            converted = item.ConvertedText ?? item.OriginalText,
            convertedLinks = item.ConvertedLinks,
            sendNow = false,
            sentTargets = 0,
            sendFailures = Array.Empty<string>()
        });
    }

    if (string.IsNullOrWhiteSpace(payload.OverrideUrl))
    {
        return Results.BadRequest(new
        {
            error = "Link corrigido obrigatorio para aprovar ofertas do Mercado Livre."
        });
    }

    var convertedText = ApplyMercadoLivreManualOverride(
        item.OriginalText ?? string.Empty,
        item.ExtractedUrls,
        payload.OverrideUrl);
    var convertedLinks = CountUrlsInText(convertedText);
    var convertedTextForStore = convertedText;
    var convertedLinksForStore = convertedLinks;

    if (string.IsNullOrWhiteSpace(convertedText))
    {
        return Results.BadRequest(new { error = "Pendencia sem texto para aprovar." });
    }

    // Guarda uma versao normalizada para cruzar aprovacao mesmo quando
    // o link aprovado (ex.: meli.la) for expandido depois no fluxo.
    var normalizedForStore = await processor.ProcessAsync(
        convertedText,
        "MercadoLivreManualApproval",
        ct,
        originChatId: item.OriginChatId,
        destinationChatId: item.DestinationChatId,
        originChatRef: item.OriginChatRef,
        destinationChatRef: item.DestinationChatRef,
        sourceImageUrl: item.OriginalImageUrl);
    if (!string.IsNullOrWhiteSpace(normalizedForStore.ConvertedText))
    {
        convertedTextForStore = normalizedForStore.ConvertedText!;
        convertedLinksForStore = normalizedForStore.ConvertedLinks;
    }

    // Persistir a aprovacao antes do envio evita re-bloqueio imediato quando a
    // mensagem publicada no Telegram e processada em seguida pelo userbot.
    var initialReviewNote = payload.Note;
    var initialSaveOk = await approvalStore.DecideAsync(
        id,
        "approved",
        context.User.Identity?.Name ?? "unknown",
        initialReviewNote,
        convertedTextForStore,
        convertedLinksForStore,
        ct);

    if (!initialSaveOk)
    {
        return Results.BadRequest(new { error = "Falha ao salvar aprovacao." });
    }

    var sendNow = payload.SendNow ?? true;
    var sendSuccess = 0;
    var sendFailures = new List<string>();
    var telegramTargets = new List<long>();
    var outboundText = convertedText;
    string? outboundImageUrl = item.OriginalImageUrl;

    if (sendNow)
    {
        var settings = await settingsStore.GetAsync(ct);
        var (enrichedText, productImageUrl, _) = await processor.EnrichTextWithProductDataAsync(convertedText, item.OriginalText ?? string.Empty, ct);
        if (!string.IsNullOrWhiteSpace(enrichedText))
        {
            outboundText = enrichedText;
        }
        if (string.IsNullOrWhiteSpace(outboundImageUrl))
        {
            outboundImageUrl = productImageUrl;
        }

        if (item.DestinationChatId.HasValue && item.DestinationChatId.Value != 0)
        {
            telegramTargets.Add(item.DestinationChatId.Value);
        }

        if (settings.TelegramForwarding.DestinationChatId != 0)
        {
            telegramTargets.Add(settings.TelegramForwarding.DestinationChatId);
        }

        if (telegramOptions.Value.DestinationChatId != 0)
        {
            telegramTargets.Add(telegramOptions.Value.DestinationChatId);
        }

        if (item.OriginChatId.HasValue
            && item.OriginChatId.Value != 0
            && telegramTargets.Count == 0
            && string.IsNullOrWhiteSpace(item.DestinationChatRef))
        {
            telegramTargets.Add(item.OriginChatId.Value);
        }

        var uniqueTelegramTargets = telegramTargets
            .Distinct()
            .ToArray();
        foreach (var chatId in uniqueTelegramTargets)
        {
            var sent = await SendTelegramManualApprovalAsync(httpClientFactory, telegramOptions.Value, chatId, outboundText, outboundImageUrl, ct);
            if (sent)
            {
                sendSuccess++;
            }
            else
            {
                sendFailures.Add($"{chatId}: falha no envio Telegram durante aprovacao manual.");
            }
        }
    }

    var reviewNote = payload.Note;
    if (sendNow)
    {
        var summary = $"Envio Telegram manual: sucesso={sendSuccess}, falhas={sendFailures.Count}.";
        reviewNote = string.IsNullOrWhiteSpace(reviewNote) ? summary : $"{reviewNote} | {summary}";
    }

    var ok = await approvalStore.DecideAsync(
        id,
        "approved",
        context.User.Identity?.Name ?? "unknown",
        reviewNote,
        convertedTextForStore,
        convertedLinksForStore,
        ct);

    if (!ok)
    {
        return Results.BadRequest(new { error = "Falha ao salvar aprovacao." });
    }

    await audit.WriteAsync("mercadolivre.pending.approved", context.User.Identity?.Name ?? "unknown", new
    {
        id,
        convertedLinks,
        sendNow,
        sendSuccess,
        sendFailures = sendFailures.Count
    }, ct);
    return Results.Ok(new
    {
        success = true,
        converted = outboundText,
        convertedLinks,
        sendNow,
        sentTargets = sendSuccess,
        sendFailures
    });
}).RequireAuthorization("AdminOnly");

api.MapPost("/mercadolivre/pending/{id}/reject", async (
    string id,
    MercadoLivreDecisionRequest payload,
    IMercadoLivreApprovalStore approvalStore,
    IAuditTrail audit,
    HttpContext context,
    CancellationToken ct) =>
{
    var item = await approvalStore.GetAsync(id, ct);
    if (item is null)
    {
        return Results.NotFound(new { error = "Pendencia nao encontrada." });
    }

    if (!string.Equals(item.Status, "pending", StringComparison.OrdinalIgnoreCase))
    {
        return Results.BadRequest(new { error = $"Pendencia ja foi analisada ({item.Status})." });
    }

    var ok = await approvalStore.DecideAsync(
        id,
        "rejected",
        context.User.Identity?.Name ?? "unknown",
        payload.Note,
        null,
        0,
        ct);

    if (!ok)
    {
        return Results.BadRequest(new { error = "Falha ao salvar rejeicao." });
    }

    await audit.WriteAsync("mercadolivre.pending.rejected", context.User.Identity?.Name ?? "unknown", new { id }, ct);
    return Results.Ok(new { success = true });
}).RequireAuthorization("AdminOnly");

api.MapGet("/logs/conversions", async (
    [FromQuery] string? store,
    [FromQuery] string? q,
    [FromQuery] int? limit,
    IConversionLogStore logStore,
    CancellationToken ct) =>
{
    var query = new ConversionLogQuery
    {
        Store = store,
        Search = q,
        Limit = limit ?? 200
    };
    var items = await logStore.QueryAsync(query, ct);
    return Results.Ok(new { items });
});

api.MapGet("/logs/clicks", async (
    [FromQuery] string? q,
    [FromQuery] int? limit,
    IClickLogStore clickLogStore,
    CancellationToken ct) =>
{
    var items = await clickLogStore.QueryAsync(null, q, limit ?? 200, ct);
    return Results.Ok(new { items });
});

api.MapGet("/logs/funnel", async (
    [FromQuery] int? hours,
    IConversionLogStore conversionLogStore,
    IClickLogStore clickLogStore,
    CancellationToken ct) =>
{
    var windowHours = Math.Clamp(hours ?? 168, 1, 720);
    var since = DateTimeOffset.UtcNow.AddHours(-windowHours);
    var conversions = await conversionLogStore.QueryAsync(new ConversionLogQuery { Limit = 2000 }, ct);
    var clicks = await clickLogStore.QueryAsync(null, null, 2000, ct);

    var conversionsWindow = conversions
        .Where(x => x.Timestamp >= since)
        .ToList();
    var clicksWindow = clicks
        .Where(x => x.Timestamp >= since)
        .ToList();

    var bySource = clicksWindow
        .GroupBy(x => string.IsNullOrWhiteSpace(x.Source) ? "unknown" : x.Source.Trim().ToLowerInvariant())
        .Select(g => new
        {
            source = g.Key,
            clicks = g.Count(),
            uniqueLinks = g
                .Select(x => x.TargetUrl)
                .Where(x => !string.IsNullOrWhiteSpace(x))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Count()
        })
        .OrderByDescending(x => x.clicks)
        .Take(20)
        .ToArray();

    var byCampaign = clicksWindow
        .GroupBy(x => string.IsNullOrWhiteSpace(x.Campaign) ? "(none)" : x.Campaign!.Trim().ToLowerInvariant())
        .Select(g => new
        {
            campaign = g.Key,
            clicks = g.Count(),
            uniqueLinks = g
                .Select(x => x.TargetUrl)
                .Where(x => !string.IsNullOrWhiteSpace(x))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Count()
        })
        .OrderByDescending(x => x.clicks)
        .Take(20)
        .ToArray();

    var topLinks = clicksWindow
        .GroupBy(x => x.TargetUrl, StringComparer.OrdinalIgnoreCase)
        .Select(g => new
        {
            targetUrl = g.Key,
            clicks = g.Count(),
            lastClickAt = g.Max(x => x.Timestamp),
            source = g
                .GroupBy(x => string.IsNullOrWhiteSpace(x.Source) ? "unknown" : x.Source.Trim().ToLowerInvariant())
                .OrderByDescending(x => x.Count())
                .Select(x => x.Key)
                .FirstOrDefault() ?? "unknown",
            campaign = g
                .GroupBy(x => string.IsNullOrWhiteSpace(x.Campaign) ? "(none)" : x.Campaign!.Trim().ToLowerInvariant())
                .OrderByDescending(x => x.Count())
                .Select(x => x.Key)
                .FirstOrDefault() ?? "(none)"
        })
        .OrderByDescending(x => x.clicks)
        .ThenByDescending(x => x.lastClickAt)
        .Take(30)
        .ToArray();

    return Results.Ok(new
    {
        windowHours,
        since,
        totals = new
        {
            clicks = clicksWindow.Count,
            conversions = conversionsWindow.Count,
            successfulConversions = conversionsWindow.Count(x => x.Success),
            affiliatedConversions = conversionsWindow.Count(x => x.IsAffiliated),
            trackedConversionLinks = conversionsWindow
                .SelectMany(x => x.TrackingIds ?? new List<string>())
                .Where(x => !string.IsNullOrWhiteSpace(x))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Count()
        },
        bySource,
        byCampaign,
        topLinks
    });
});

api.MapPost("/logs/clicks/clear", async (IClickLogStore clickLogStore, IAuditTrail audit, HttpContext ctx, CancellationToken ct) =>
{
    await clickLogStore.ClearAsync(null, ct);
    await audit.WriteAsync("logs.clicks.clear", ctx.User.Identity?.Name ?? "unknown", new { }, ct);
    return Results.Ok(new { success = true });
});

api.MapGet("/logs/instagram-ai", async (
    [FromQuery] string? q,
    [FromQuery] int? limit,
    IInstagramAiLogStore logStore,
    CancellationToken ct) =>
{
    var items = await logStore.ListAsync(Math.Clamp(limit ?? 200, 1, 200), ct);
    if (!string.IsNullOrWhiteSpace(q))
    {
        var term = q.Trim();
        items = items.Where(i =>
            i.Provider.Contains(term, StringComparison.OrdinalIgnoreCase) ||
            i.Model.Contains(term, StringComparison.OrdinalIgnoreCase) ||
            (i.Error?.Contains(term, StringComparison.OrdinalIgnoreCase) ?? false) ||
            i.InputSnippet.Contains(term, StringComparison.OrdinalIgnoreCase)).ToList();
    }
    return Results.Ok(new { items });
});

api.MapPost("/logs/instagram-ai/clear", async (IInstagramAiLogStore logStore, IAuditTrail audit, HttpContext ctx, CancellationToken ct) =>
{
    await logStore.ClearAsync(ct);
    await audit.WriteAsync("logs.instagram_ai.clear", ctx.User.Identity?.Name ?? "unknown", new { }, ct);
    return Results.Ok(new { success = true });
});

api.MapGet("/logs/instagram-publish", async (
    [FromQuery] string? q,
    [FromQuery] int? limit,
    IInstagramPublishLogStore logStore,
    CancellationToken ct) =>
{
    var items = await logStore.ListAsync(Math.Clamp(limit ?? 200, 1, 200), ct);
    if (!string.IsNullOrWhiteSpace(q))
    {
        var term = q.Trim();
        items = items.Where(i =>
            i.Action.Contains(term, StringComparison.OrdinalIgnoreCase) ||
            (i.Error?.Contains(term, StringComparison.OrdinalIgnoreCase) ?? false) ||
            (i.Details?.Contains(term, StringComparison.OrdinalIgnoreCase) ?? false) ||
            (i.MediaId?.Contains(term, StringComparison.OrdinalIgnoreCase) ?? false) ||
            (i.DraftId?.Contains(term, StringComparison.OrdinalIgnoreCase) ?? false)
        ).ToList();
    }
    return Results.Ok(new { items });
});

api.MapPost("/logs/instagram-publish/clear", async (IInstagramPublishLogStore logStore, IAuditTrail audit, HttpContext ctx, CancellationToken ct) =>
{
    await logStore.ClearAsync(ct);
    await audit.WriteAsync("logs.instagram_publish.clear", ctx.User.Identity?.Name ?? "unknown", new { }, ct);
    return Results.Ok(new { success = true });
}).RequireAuthorization("AdminOnly");

api.MapPost("/logs/conversions/clear", async (IConversionLogStore logStore, IAuditTrail audit, HttpContext ctx, CancellationToken ct) =>
{
    await logStore.ClearAsync(ct);
    await audit.WriteAsync("logs.conversions.clear", ctx.User.Identity?.Name ?? "unknown", new { }, ct);
    return Results.Ok(new { success = true });
});

api.MapGet("/logs/media", async (
    [FromQuery] int? limit,
    IMediaFailureLogStore logStore,
    CancellationToken ct) =>
{
    var items = await logStore.ListAsync(limit ?? 50, ct);
    return Results.Ok(new { items });
});

api.MapPost("/logs/media/clear", async (IMediaFailureLogStore logStore, IAuditTrail audit, HttpContext ctx, CancellationToken ct) =>
{
    await logStore.ClearAsync(ct);
    await audit.WriteAsync("logs.media.clear", ctx.User.Identity?.Name ?? "unknown", new { }, ct);
    return Results.Ok(new { success = true });
});

api.MapGet("/telegram/userbot/chats", async (ITelegramUserbotService userbot, CancellationToken ct) =>
{
    var chats = await userbot.GetDialogsAsync(ct);
    return Results.Ok(new { ready = userbot.IsReady, chats });
});

api.MapPost("/telegram/userbot/refresh", async (ITelegramUserbotService userbot, CancellationToken ct) =>
{
    var ok = await userbot.RefreshDialogsAsync(ct);
    var chats = await userbot.GetDialogsAsync(ct);
    return Results.Ok(new { success = ok, ready = userbot.IsReady, chats });
});

api.MapPost("/telegram/userbot/auth", async (
    TelegramUserbotAuthUpdateRequest payload,
    ITelegramUserbotService userbot,
    IAuditTrail audit,
    HttpContext context,
    CancellationToken ct) =>
{
    var result = await userbot.UpdateRuntimeAuthAsync(payload, ct);

    await audit.WriteAsync("telegram.userbot.auth.update", context.User.Identity?.Name ?? "unknown", new
    {
        HasPhone = payload.PhoneNumber is not null,
        HasCode = payload.VerificationCode is not null,
        HasPassword = payload.Password is not null,
        payload.ForceReconnect,
        result.Success,
        result.ReconnectRequested
    }, ct);

    if (!result.Success)
    {
        return Results.BadRequest(new
        {
            success = false,
            message = result.Message
        });
    }

    return Results.Ok(new
    {
        success = true,
        reconnectRequested = result.ReconnectRequested,
        hasPhoneNumber = result.HasPhoneNumber,
        hasVerificationCode = result.HasVerificationCode,
        hasPassword = result.HasPassword,
        message = result.Message
    });
}).RequireAuthorization("AdminOnly");

api.MapPost("/telegram/userbot/replay-to-whatsapp", async (
    TelegramUserbotReplayRequest payload,
    ITelegramUserbotService userbot,
    IAuditTrail audit,
    HttpContext context,
    CancellationToken ct) =>
{
    if (payload.SourceChatId == 0)
    {
        return Results.BadRequest(new { success = false, error = "SourceChatId obrigatorio." });
    }

    var count = payload.Count <= 0 ? 10 : Math.Min(payload.Count, 50);
    var result = await userbot.ReplayRecentOffersToWhatsAppAsync(payload.SourceChatId, count, payload.AllowOfficialDestination, ct);

    await audit.WriteAsync("telegram.userbot.replay_to_whatsapp", context.User.Identity?.Name ?? "unknown", new
    {
        payload.SourceChatId,
        Count = count,
        payload.AllowOfficialDestination,
        result.Success,
        result.Replayed,
        result.Failed
    }, ct);

    return Results.Ok(result);
}).RequireAuthorization("AdminOnly");

api.MapGet("/whatsapp/groups", async (
    [FromQuery] string? instanceName,
    IWhatsAppGateway gateway,
    CancellationToken ct) =>
{
    var groups = await gateway.GetGroupsAsync(instanceName, ct);
    return Results.Ok(new { groups });
});

api.MapPost("/admin/offers/normalize", async (
    NormalizeOffersRequest request,
    OfferNormalizationService normalizationService,
    IOfferNormalizationRunStore runStore,
    IAuditTrail audit,
    HttpContext context,
    CancellationToken ct) =>
{
    var actor = context.User.Identity?.Name ?? "unknown";
    var run = normalizationService.Normalize(
        request.RawInput,
        request.InputType,
        request.SelectedTarget,
        request.Notes,
        actor);

    var saved = await runStore.SaveAsync(run, ct);
    await audit.WriteAsync("offers.normalization.create", actor, new
    {
        saved.Id,
        saved.SourceType,
        saved.SelectedTarget,
        saved.Status,
        offers = saved.NormalizedOffers.Count,
        issues = saved.ValidationIssues.Count
    }, ct);

    return Results.Ok(new
    {
        runId = saved.Id,
        saved.SourceType,
        selectedTarget = saved.SelectedTarget,
        saved.Status,
        saved.Summary,
        offers = saved.NormalizedOffers,
        validationIssues = saved.ValidationIssues,
        saved.NextStepHint,
        saved.CreatedAtUtc,
        saved.UpdatedAtUtc,
        saved.Notes,
        saved.Operator
    });
});

api.MapGet("/admin/offers/normalization-runs", async (
    string? status,
    string? target,
    int? limit,
    IOfferNormalizationRunStore runStore,
    CancellationToken ct) =>
{
    var runs = await runStore.ListAsync(status, target, limit ?? 30, ct);
    return Results.Ok(new
    {
        count = runs.Count,
        items = runs
    });
});

api.MapGet("/admin/offers/normalization-runs/{id}", async (
    string id,
    IOfferNormalizationRunStore runStore,
    CancellationToken ct) =>
{
    var run = await runStore.GetAsync(id, ct);
    return run is null
        ? Results.NotFound(new { error = "Execução de normalização não encontrada." })
        : Results.Ok(run);
});

api.MapPost("/admin/offers/normalization-runs/{id}/route", async (
    string id,
    RouteOfferNormalizationRunRequest request,
    OfferNormalizationService normalizationService,
    OfferNormalizationRoutingService routingService,
    IOfferNormalizationRunStore runStore,
    IAuditTrail audit,
    HttpContext context,
    CancellationToken ct) =>
{
    var existing = await runStore.GetAsync(id, ct);
    if (existing is null)
    {
        return Results.NotFound(new { error = "Execução de normalização não encontrada." });
    }

    if (existing.NormalizedOffers.Count == 0)
    {
        return Results.BadRequest(new { error = "Esta execução não possui ofertas válidas para encaminhamento." });
    }

    var actor = context.User.Identity?.Name ?? "unknown";
    var updated = normalizationService.Route(existing, request.SelectedTarget, request.Notes);
    updated = await routingService.MaterializeAsync(updated, actor, ct);
    updated.Operator = actor;
    var saved = await runStore.SaveAsync(updated, ct);

    await audit.WriteAsync("offers.normalization.route", actor, new
    {
        saved.Id,
        saved.SelectedTarget,
        saved.Status,
        offers = saved.NormalizedOffers.Count,
        delivery = saved.AssistedDelivery is null ? null : new
        {
            saved.AssistedDelivery.Kind,
            saved.AssistedDelivery.Status,
            saved.AssistedDelivery.TargetScope,
            saved.AssistedDelivery.ReferenceIds
        }
    }, ct);

    return Results.Ok(saved);
});

app.MapGet("/media/{id}", (string id, IMediaStore store) =>
{
    if (!store.TryGet(id, out var item))
    {
        return Results.NotFound();
    }

    return Results.File(item.Bytes, item.MimeType);
});

app.MapGet("/media/{id}.{ext}", (string id, string ext, IMediaStore store) =>
{
    if (!store.TryGet(id, out var item))
    {
        return Results.NotFound();
    }

    return Results.File(item.Bytes, item.MimeType);
});

app.MapGet("/r/{id}", async (
    string id,
    HttpContext context,
    ILinkTrackingStore trackingStore,
    IClickLogStore clickLogStore,
    CancellationToken ct) =>
{
    var entry = await trackingStore.RegisterClickAsync(id, ct);
    if (entry is null)
    {
        return Results.NotFound();
    }

    var source = NormalizeTrackingToken(context.Request.Query["src"].ToString(), "LinkTracking") ?? "LinkTracking";
    var campaign = NormalizeTrackingToken(context.Request.Query["camp"].ToString(), null);
    var referrer = TruncateForLog(context.Request.Headers.Referer.ToString(), 600);
    var userAgent = TruncateForLog(context.Request.Headers.UserAgent.ToString(), 320);
    var ip = context.Connection.RemoteIpAddress?.ToString();

    await clickLogStore.AppendAsync(new ClickLogEntry
    {
        TrackingId = entry.Id,
        TargetUrl = entry.TargetUrl,
        Source = source,
        Campaign = campaign,
        Referrer = string.IsNullOrWhiteSpace(referrer) ? null : referrer,
        UserAgent = string.IsNullOrWhiteSpace(userAgent) ? null : userAgent,
        IpHash = string.IsNullOrWhiteSpace(ip) ? null : ComputeStableHash(ip)
    }, null, ct);

    return Results.Redirect(entry.TargetUrl);
});

app.Run();

static void LoadDotEnvIfPresent()
{
    var roots = new[]
    {
        Directory.GetCurrentDirectory(),
        AppContext.BaseDirectory
    };

    var candidates = roots
        .SelectMany(root => new[]
        {
            Path.Combine(root, ".env"),
            Path.Combine(root, "AchadinhosBot.Next", ".env")
        })
        .Distinct(StringComparer.OrdinalIgnoreCase)
        .Where(File.Exists)
        .ToArray();

    foreach (var file in candidates)
    {
        foreach (var raw in File.ReadAllLines(file))
        {
            var line = raw.Trim();
            if (line.Length == 0 || line.StartsWith('#'))
            {
                continue;
            }

            var idx = line.IndexOf('=');
            if (idx <= 0)
            {
                continue;
            }

            var key = line[..idx].Trim();
            if (string.IsNullOrWhiteSpace(key))
            {
                continue;
            }

            var value = line[(idx + 1)..].Trim();
            if (value.Length >= 2 &&
                ((value.StartsWith('"') && value.EndsWith('"')) ||
                 (value.StartsWith('\'') && value.EndsWith('\''))))
            {
                value = value[1..^1];
            }

            SetIfMissing(key, value);

            var normalizedAlias = BuildNormalizedAlias(key);
            if (!normalizedAlias.Equals(key, StringComparison.Ordinal))
            {
                SetIfMissing(normalizedAlias, value);
            }
        }
    }

    static void SetIfMissing(string key, string value)
    {
        if (Environment.GetEnvironmentVariable(key) is null)
        {
            Environment.SetEnvironmentVariable(key, value, EnvironmentVariableTarget.Process);
        }
    }

    static string BuildNormalizedAlias(string key)
    {
        var sections = key.Split("__", StringSplitOptions.None);
        if (sections.Length < 2)
        {
            return key;
        }

        for (var i = 0; i < sections.Length; i++)
        {
            if (sections[i].Contains('_', StringComparison.Ordinal))
            {
                sections[i] = sections[i].Replace("_", string.Empty, StringComparison.Ordinal);
            }
        }

        return string.Join("__", sections);
    }
}

static IEnumerable<string> ValidateSettings(AutomationSettings settings)
{
    var triggers = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
    foreach (var rule in settings.AutoReplies)
    {
        if (string.IsNullOrWhiteSpace(rule.Trigger) || string.IsNullOrWhiteSpace(rule.ResponseTemplate))
        {
            yield return $"Regra '{rule.Name}' invÃ¡lida (gatilho/resposta obrigatÃ³rios).";
            continue;
        }

        if (!triggers.Add(rule.Trigger.Trim()))
        {
            yield return $"Gatilho duplicado: {rule.Trigger}";
        }
    }

    var bio = settings.BioHub ?? new BioHubSettings();
    if (bio.MaxItems is < 5 or > 80)
    {
        yield return "BioHub.MaxItems deve estar entre 5 e 80.";
    }

    if (!string.IsNullOrWhiteSpace(bio.DefaultSource) &&
        NormalizeTrackingToken(bio.DefaultSource, null) is null)
    {
        yield return "BioHub.DefaultSource invalido.";
    }

    if (!string.IsNullOrWhiteSpace(bio.DefaultCampaign) &&
        NormalizeTrackingToken(bio.DefaultCampaign, null) is null)
    {
        yield return "BioHub.DefaultCampaign invalido.";
    }

    if (!string.IsNullOrWhiteSpace(bio.PublicBaseUrl) &&
        !TryNormalizePublicBaseUrl(bio.PublicBaseUrl, out _))
    {
        yield return "BioHub.PublicBaseUrl invalido. Use URL absoluta (http/https).";
    }

    var gemini = settings.Gemini ?? new GeminiSettings();
    if (gemini.MaxOutputTokens is < 200 or > 4096)
    {
        yield return "Gemini.MaxOutputTokens deve estar entre 200 e 4096.";
    }

    var deepSeek = settings.DeepSeek ?? new DeepSeekSettings();
    if (deepSeek.MaxOutputTokens is < 200 or > 4096)
    {
        yield return "DeepSeek.MaxOutputTokens deve estar entre 200 e 4096.";
    }

    var nemotron = settings.Nemotron ?? new NemotronSettings();
    if (nemotron.MaxOutputTokens is < 200 or > 16384)
    {
        yield return "Nemotron.MaxOutputTokens deve estar entre 200 e 16384.";
    }
    if (nemotron.ReasoningBudget is < 0 or > 16384)
    {
        yield return "Nemotron.ReasoningBudget deve estar entre 0 e 16384.";
    }
    if (nemotron.TopP is <= 0 or > 1.0)
    {
        yield return "Nemotron.TopP deve estar entre 0 e 1.";
    }

    var qwen = settings.Qwen ?? new QwenSettings();
    if (qwen.MaxOutputTokens is < 200 or > 8192)
    {
        yield return "Qwen.MaxOutputTokens deve estar entre 200 e 8192.";
    }

    var vila = settings.VilaNvidia ?? new VilaNvidiaSettings();
    if (vila.MaxOutputTokens is < 200 or > 16384)
    {
        yield return "VilaNvidia.MaxOutputTokens deve estar entre 200 e 16384.";
    }
    if (vila.TopP is <= 0 or > 1.0)
    {
        yield return "VilaNvidia.TopP deve estar entre 0 e 1.";
    }

    var instaPublish = settings.InstagramPublish ?? new InstagramPublishSettings();
    if (instaPublish.AutoPilotMinimumImageMatchScore is < 0 or > 100)
    {
        yield return "InstagramPublish.AutoPilotMinimumImageMatchScore deve estar entre 0 e 100.";
    }

    var contentCalendar = settings.ContentCalendar ?? new ContentCalendarSettings();
    if (contentCalendar.PollIntervalSeconds is < 15 or > 300)
    {
        yield return "ContentCalendar.PollIntervalSeconds deve estar entre 15 e 300.";
    }

    if (contentCalendar.MaxAttempts is < 1 or > 10)
    {
        yield return "ContentCalendar.MaxAttempts deve estar entre 1 e 10.";
    }
}

static string? ResolveSecretWithMask(string? incoming, string? current)
{
    if (string.IsNullOrWhiteSpace(incoming))
    {
        return current;
    }

    var trimmed = incoming.Trim();
    return trimmed == "********" ? current : trimmed;
}

static List<string> MergeSecretListWithMask(
    IEnumerable<string>? currentValues,
    IEnumerable<string>? incomingValues,
    string? incomingSingle,
    string? currentSingle)
{
    var current = NormalizeSecretList(currentValues);
    var singleCurrent = NormalizeSecret(currentSingle);
    if (!string.IsNullOrWhiteSpace(singleCurrent))
    {
        current.Add(singleCurrent);
    }

    var incoming = NormalizeSecretList(incomingValues);
    var hasMaskedValue = incomingValues?.Any(x => string.Equals(x?.Trim(), "********", StringComparison.Ordinal)) ?? false;
    var singleIncoming = NormalizeSecret(incomingSingle);

    if (incoming.Count == 0 && string.IsNullOrWhiteSpace(singleIncoming))
    {
        return current;
    }

    var merged = hasMaskedValue ? new List<string>(current) : new List<string>();
    merged.AddRange(incoming);
    if (!string.IsNullOrWhiteSpace(singleIncoming))
    {
        merged.Add(singleIncoming);
    }

    return merged
        .Where(x => !string.IsNullOrWhiteSpace(x))
        .Distinct(StringComparer.Ordinal)
        .ToList();
}

static List<string> NormalizeSecretList(IEnumerable<string>? values)
    => (values ?? Array.Empty<string>())
        .Select(NormalizeSecret)
        .Where(x => !string.IsNullOrWhiteSpace(x))
        .Cast<string>()
        .Distinct(StringComparer.Ordinal)
        .ToList();

static string? NormalizeSecret(string? value)
{
    if (string.IsNullOrWhiteSpace(value))
    {
        return null;
    }

    var trimmed = value.Trim();
    return trimmed == "********" ? null : trimmed;
}

static bool IsBotConversorWebhookAuthorized(HttpRequest request, string body, string? webhookSecret, string? fallbackApiKey)
{
    if (WebhookSignatureVerifier.TryValidate(request, body, webhookSecret))
    {
        return true;
    }

    string[] tryHeaders = { "x-api-key", "apikey", "Authorization" };
    foreach (var h in tryHeaders)
    {
        if (request.Headers.TryGetValue(h, out var providedAuth))
        {
            var val = providedAuth.ToString().Trim();
            if (val.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            {
                val = val["Bearer ".Length..].Trim();
            }

            if (SecretComparer.EqualsConstantTime(fallbackApiKey, val))
            {
                return true;
            }
        }
    }

    return false;
}

static string ComputeStableHash(string? input)
{
    var value = input ?? string.Empty;
    var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(value));
    return Convert.ToHexString(bytes).ToLowerInvariant();
}

static IEnumerable<string> ExtractUrlsFromText(string text)
{
    if (string.IsNullOrWhiteSpace(text))
    {
        return Array.Empty<string>();
    }

    return Regex.Matches(text, @"https?://[^\s]+", RegexOptions.IgnoreCase)
        .Select(m => m.Value.Trim().TrimEnd('.', ',', ';', '!', '?', ')', ']', '}'))
        .Where(x => !string.IsNullOrWhiteSpace(x));
}

static bool IsMercadoLivreUrlLike(string url)
{
    if (string.IsNullOrWhiteSpace(url))
    {
        return false;
    }

    return url.Contains("mercadolivre", StringComparison.OrdinalIgnoreCase)
           || url.Contains("mercadolibre", StringComparison.OrdinalIgnoreCase)
           || url.Contains("meli.la", StringComparison.OrdinalIgnoreCase)
           || url.Contains("compre.link", StringComparison.OrdinalIgnoreCase);
}

static int CountUrlsInText(string? text)
{
    if (string.IsNullOrWhiteSpace(text))
    {
        return 0;
    }

    return Regex.Matches(text, @"https?://[^\s]+", RegexOptions.IgnoreCase).Count;
}

static string ApplyMercadoLivreManualOverride(string text, IReadOnlyCollection<string>? extractedUrls, string? overrideUrl)
{
    if (string.IsNullOrWhiteSpace(text) || string.IsNullOrWhiteSpace(overrideUrl))
    {
        return text;
    }

    var replacement = overrideUrl.Trim();
    if (!Uri.TryCreate(replacement, UriKind.Absolute, out _))
    {
        return text;
    }

    var result = text;
    if (extractedUrls is not null)
    {
        foreach (var original in extractedUrls
                     .Where(x => !string.IsNullOrWhiteSpace(x))
                     .Select(x => x.Trim())
                     .Distinct(StringComparer.OrdinalIgnoreCase))
        {
            result = result.Replace(original, replacement, StringComparison.OrdinalIgnoreCase);
        }
    }

    result = Regex.Replace(
        result,
        @"https?://[^\s]+",
        match =>
        {
            var url = match.Value;
            var lowered = url.ToLowerInvariant();
            if (lowered.Contains("mercadolivre", StringComparison.OrdinalIgnoreCase)
                || lowered.Contains("mercadolibre", StringComparison.OrdinalIgnoreCase)
                || lowered.Contains("meli.la", StringComparison.OrdinalIgnoreCase))
            {
                return replacement;
            }

            return url;
        },
        RegexOptions.IgnoreCase);

    return result;
}

static async Task<bool> SendTelegramManualApprovalAsync(
    IHttpClientFactory httpClientFactory,
    TelegramOptions telegramOptions,
    long chatId,
    string text,
    string? imageUrl,
    CancellationToken ct)
{
    if (chatId == 0 || string.IsNullOrWhiteSpace(text) || string.IsNullOrWhiteSpace(telegramOptions.BotToken))
    {
        return false;
    }

    try
    {
        var client = httpClientFactory.CreateClient("default");
        var hasImage = !string.IsNullOrWhiteSpace(imageUrl);
        var caption = text.Length > 1000 ? text[..1000] : text;
        var remainingText = text.Length > 1000 ? text[1000..].Trim() : null;

        if (hasImage)
        {
            var photoUrl = $"https://api.telegram.org/bot{telegramOptions.BotToken}/sendPhoto";
            using var photoRequest = new HttpRequestMessage(HttpMethod.Post, photoUrl);
            var photoPayload = JsonSerializer.Serialize(new
            {
                chat_id = chatId,
                photo = imageUrl,
                caption
            });
            photoRequest.Content = new StringContent(photoPayload, Encoding.UTF8, "application/json");

            using var photoResponse = await client.SendAsync(photoRequest, ct);
            if (photoResponse.IsSuccessStatusCode)
            {
                if (!string.IsNullOrWhiteSpace(remainingText))
                {
                    var sendRemaining = await SendTelegramTextAsync(client, telegramOptions.BotToken, chatId, remainingText, ct);
                    if (!sendRemaining)
                    {
                        return false;
                    }
                }
                return true;
            }

            // Fallback: baixa a imagem e envia como arquivo multipart.
            if (Uri.TryCreate(imageUrl, UriKind.Absolute, out _))
            {
                using var imageReq = new HttpRequestMessage(HttpMethod.Get, imageUrl);
                imageReq.Headers.UserAgent.ParseAdd("Mozilla/5.0 (compatible; AchadinhosBot/1.0)");
                imageReq.Headers.Accept.ParseAdd("image/*,*/*;q=0.8");
                using var imageRes = await client.SendAsync(imageReq, ct);
                if (imageRes.IsSuccessStatusCode)
                {
                    var bytes = await imageRes.Content.ReadAsByteArrayAsync(ct);
                    if (bytes.Length > 0)
                    {
                        var multipartPhotoUrl = $"https://api.telegram.org/bot{telegramOptions.BotToken}/sendPhoto";
                        using var form = new MultipartFormDataContent();
                        form.Add(new StringContent(chatId.ToString()), "chat_id");
                        form.Add(new StringContent(caption), "caption");
                        var mime = imageRes.Content.Headers.ContentType?.MediaType
                                   ?? DetectMimeTypeFromBytes(bytes)
                                   ?? "image/jpeg";
                        var fileName = mime.Contains("png", StringComparison.OrdinalIgnoreCase)
                            ? "photo.png"
                            : "photo.jpg";
                        var file = new ByteArrayContent(bytes);
                        file.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue(mime);
                        form.Add(file, "photo", fileName);

                        using var multipartReq = new HttpRequestMessage(HttpMethod.Post, multipartPhotoUrl)
                        {
                            Content = form
                        };
                        using var multipartRes = await client.SendAsync(multipartReq, ct);
                        if (multipartRes.IsSuccessStatusCode)
                        {
                            if (!string.IsNullOrWhiteSpace(remainingText))
                            {
                                var sendRemaining = await SendTelegramTextAsync(client, telegramOptions.BotToken, chatId, remainingText, ct);
                                if (!sendRemaining)
                                {
                                    return false;
                                }
                            }
                            return true;
                        }
                    }
                }
            }
        }

        return await SendTelegramTextAsync(client, telegramOptions.BotToken, chatId, text, ct);
    }
    catch
    {
        return false;
    }
}

static async Task<bool> SendTelegramTextAsync(
    HttpClient client,
    string botToken,
    long chatId,
    string text,
    CancellationToken ct)
{
    if (string.IsNullOrWhiteSpace(text))
    {
        return false;
    }

    var messageUrl = $"https://api.telegram.org/bot{botToken}/sendMessage";
    using var messageRequest = new HttpRequestMessage(HttpMethod.Post, messageUrl);
    var messagePayload = JsonSerializer.Serialize(new
    {
        chat_id = chatId,
        text
    });
    messageRequest.Content = new StringContent(messagePayload, Encoding.UTF8, "application/json");

    using var messageResponse = await client.SendAsync(messageRequest, ct);
    return messageResponse.IsSuccessStatusCode;
}

static long ResolveMercadoLivreApprovalTelegramBridgeChatId()
{
    var fromEnv = Environment.GetEnvironmentVariable("MERCADOLIVRE_APPROVAL_TELEGRAM_BRIDGE_CHAT_ID");
    if (!string.IsNullOrWhiteSpace(fromEnv) && long.TryParse(fromEnv.Trim(), out var parsed) && parsed != 0)
    {
        return parsed;
    }

    // Fallback operacional solicitado: ponte Telegram para encaminhamento ao WhatsApp.
    return 5169049471;
}

#pragma warning disable CS8321
static async Task<WhatsAppSendResult> SendWhatsAppManualApprovalWithFallbackAsync(
    IWhatsAppGateway gateway,
    IHttpClientFactory httpClientFactory,
    string? instanceName,
    string target,
    string text,
    string? imageUrl,
    CancellationToken ct)
{
    if (string.IsNullOrWhiteSpace(imageUrl))
    {
        return await gateway.SendTextAsync(instanceName, target, text, ct);
    }

    var byUrl = await gateway.SendImageUrlAsync(instanceName, target, imageUrl, text, "image/jpeg", null, ct);
    if (byUrl.Success)
    {
        return byUrl;
    }

    try
    {
        var client = httpClientFactory.CreateClient("default");
        using var req = new HttpRequestMessage(HttpMethod.Get, imageUrl);
        req.Headers.UserAgent.ParseAdd("Mozilla/5.0 (compatible; AchadinhosBot/1.0)");
        req.Headers.Accept.ParseAdd("image/*,*/*;q=0.8");
        using var res = await client.SendAsync(req, ct);
        if (res.IsSuccessStatusCode)
        {
            var bytes = await res.Content.ReadAsByteArrayAsync(ct);
            if (bytes.Length > 0)
            {
                var mime = DetectMimeTypeFromBytes(bytes) ?? "image/jpeg";
                var byBytes = await gateway.SendImageAsync(instanceName, target, bytes, text, mime, ct);
                if (byBytes.Success)
                {
                    return byBytes;
                }
            }
        }
    }
    catch
    {
        // Fallback final para texto simples.
    }

    var textFallback = await gateway.SendTextAsync(instanceName, target, text, ct);
    if (textFallback.Success)
    {
        return new WhatsAppSendResult(true, "Imagem falhou; enviado como texto.");
    }

    return new WhatsAppSendResult(false, $"Falha imagem={byUrl.Message}; falha texto={textFallback.Message}");
}
#pragma warning restore CS8321

static IReadOnlyList<WhatsAppForwardingRouteSettings> ResolveWhatsAppForwardingRoutes(AutomationSettings settings)
{
    var explicitRoutes = (settings.WhatsAppForwardingRoutes ?? new List<WhatsAppForwardingRouteSettings>())
        .Where(route => route is not null)
        .Select(route => new WhatsAppForwardingRouteSettings
        {
            Name = string.IsNullOrWhiteSpace(route.Name) ? "Rota WhatsApp" : route.Name.Trim(),
            Enabled = route.Enabled,
            ProcessFromMeOnly = route.ProcessFromMeOnly,
            SourceChatIds = route.SourceChatIds
                .Where(x => !string.IsNullOrWhiteSpace(x))
                .Select(x => x.Trim())
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList(),
            DestinationGroupIds = route.DestinationGroupIds
                .Where(x => !string.IsNullOrWhiteSpace(x))
                .Select(x => x.Trim())
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList(),
            AppendSheinCode = route.AppendSheinCode,
            SendMediaEnabled = route.SendMediaEnabled,
            FooterText = route.FooterText ?? string.Empty,
            InstanceName = string.IsNullOrWhiteSpace(route.InstanceName) ? null : route.InstanceName.Trim()
        })
        .ToList();
    if (explicitRoutes.Count > 0)
    {
        return explicitRoutes;
    }

    var legacy = settings.WhatsAppForwarding ?? new WhatsAppForwardingSettings();
    return new List<WhatsAppForwardingRouteSettings>
    {
        new()
        {
            Name = "Rota padrao",
            Enabled = legacy.Enabled,
            ProcessFromMeOnly = legacy.ProcessFromMeOnly,
            SourceChatIds = legacy.SourceChatIds
                .Where(x => !string.IsNullOrWhiteSpace(x))
                .Select(x => x.Trim())
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList(),
            DestinationGroupIds = legacy.DestinationGroupIds
                .Where(x => !string.IsNullOrWhiteSpace(x))
                .Select(x => x.Trim())
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList(),
            AppendSheinCode = legacy.AppendSheinCode,
            SendMediaEnabled = legacy.SendMediaEnabled,
            FooterText = legacy.FooterText ?? string.Empty,
            InstanceName = string.IsNullOrWhiteSpace(legacy.InstanceName) ? null : legacy.InstanceName.Trim()
        }
    };
}

static string? FirstNonEmpty(params string?[] values)
{
    foreach (var value in values)
    {
        if (!string.IsNullOrWhiteSpace(value))
        {
            return value.Trim();
        }
    }

    return null;
}

static int? TryComputeDiscountFromDisplayPrices(string? previousDisplay, string? currentDisplay)
{
    if (string.IsNullOrWhiteSpace(previousDisplay) || string.IsNullOrWhiteSpace(currentDisplay))
        return null;

    var previous = ParseBrlPrice(previousDisplay);
    var current = ParseBrlPrice(currentDisplay);

    if (!previous.HasValue || !current.HasValue || previous.Value <= 0 || current.Value <= 0 || previous.Value <= current.Value)
        return null;

    var pct = (int)Math.Round(((previous.Value - current.Value) / previous.Value) * 100m, MidpointRounding.AwayFromZero);
    return pct > 0 && pct < 100 ? pct : null;
}

static decimal? ParseBrlPrice(string? text)
{
    if (string.IsNullOrWhiteSpace(text)) return null;
    var clean = System.Text.RegularExpressions.Regex.Replace(text, @"[^\d\.,]", "", System.Text.RegularExpressions.RegexOptions.CultureInvariant).Trim();
    if (string.IsNullOrWhiteSpace(clean)) return null;

    // BRL: 2.999,99 → dots are thousand separators, comma is decimal
    if (clean.Contains(',') && clean.Contains('.'))
    {
        if (clean.LastIndexOf(',') > clean.LastIndexOf('.'))
            clean = clean.Replace(".", "").Replace(",", ".");
        else
            clean = clean.Replace(",", "");
    }
    else if (clean.Contains(','))
    {
        clean = clean.Replace(",", ".");
    }

    return decimal.TryParse(clean, System.Globalization.NumberStyles.Number, System.Globalization.CultureInfo.InvariantCulture, out var val) ? val : null;
}



static async Task<WhatsAppForwardSendOutcome> SendWhatsAppMessageWithMediaFallbackAsync(
    IWhatsAppGateway gateway,
    IHttpClientFactory httpClientFactory,
    EvolutionOptions evolutionOptions,
    IMediaStore mediaStore,
    string? publicBaseUrl,
    string? instanceName,
    string destination,
    string text,
    WhatsAppIncomingMessage msg,
    ILogger logger,
    CancellationToken ct)
{
    if (!msg.HasMedia)
    {
        var textOnly = await gateway.SendTextAsync(instanceName, destination, text, ct);
        return new WhatsAppForwardSendOutcome(textOnly, "text_no_media_in_payload");
    }

    var diagnostics = new List<string>();
    string? effectiveMimeType = msg.MediaMimeType;
    string? effectiveFileName = msg.MediaFileName;

    // Prioriza URL original (normalmente arquivo completo); base64 do webhook pode ser apenas thumbnail.
    byte[]? imageBytes = null;
    var bytesCameFromUrl = false;
    if (!string.IsNullOrWhiteSpace(msg.MediaUrl))
    {
        imageBytes = await TryDownloadIncomingMediaAsBytesAsync(httpClientFactory, evolutionOptions, msg.MediaUrl!, logger, ct);
        diagnostics.Add(imageBytes is { Length: > 0 } ? $"downloaded_bytes={imageBytes.Length}" : "downloaded_bytes=0");
        bytesCameFromUrl = imageBytes is { Length: > 0 };
        if (imageBytes is { Length: > 0 } && string.IsNullOrWhiteSpace(DetectMimeTypeFromBytes(imageBytes)))
        {
            diagnostics.Add("download_mime_unknown");
            imageBytes = null;
            bytesCameFromUrl = false;
        }
    }

    if ((imageBytes is null || imageBytes.Length == 0) && !string.IsNullOrWhiteSpace(msg.RawPayloadJson))
    {
        imageBytes = await TryDownloadMediaViaEvolutionMessageApiAsync(httpClientFactory, evolutionOptions, msg, logger, ct);
        diagnostics.Add(imageBytes is { Length: > 0 } ? $"evolution_message_api_bytes={imageBytes.Length}" : "evolution_message_api_bytes=0");
        bytesCameFromUrl = false;
    }

    if ((imageBytes is null || imageBytes.Length == 0) && !string.IsNullOrWhiteSpace(msg.MediaBase64))
    {
        imageBytes = DecodeBase64Payload(msg.MediaBase64);
        if (imageBytes is { Length: > 0 })
        {
            diagnostics.Add($"payload_base64_bytes={imageBytes.Length}");
        }
    }

    if (imageBytes is { Length: > 0 } &&
        !bytesCameFromUrl &&
        imageBytes.Length < 1024)
    {
        diagnostics.Add($"payload_base64_suspected_thumbnail={imageBytes.Length}");
        imageBytes = null;
    }

    if (imageBytes is { Length: > 0 })
    {
        var detectedMimeType = DetectMimeTypeFromBytes(imageBytes);
        if (!string.IsNullOrWhiteSpace(detectedMimeType))
        {
            if (!string.Equals(effectiveMimeType, detectedMimeType, StringComparison.OrdinalIgnoreCase))
            {
                diagnostics.Add($"mime_override={effectiveMimeType ?? "n/a"}->{detectedMimeType}");
                effectiveMimeType = detectedMimeType;
            }
        }
        else
        {
            var transcodedPng = TryTranscodeImageToPng(imageBytes, logger);
            if (transcodedPng is { Length: > 0 })
            {
                imageBytes = transcodedPng;
                effectiveMimeType = "image/png";
                diagnostics.Add($"mime_transcoded_to_png={transcodedPng.Length}");
            }
            else
            {
                diagnostics.Add("mime_detect=unknown");
                imageBytes = null;
            }
        }

        if (imageBytes is { Length: > 0 })
        {
            effectiveFileName = ResolveMediaFileName(effectiveFileName, effectiveMimeType);
        }
    }

    if (imageBytes is { Length: > 0 })
    {
        if (!string.IsNullOrWhiteSpace(publicBaseUrl))
        {
            var mediaId = mediaStore.Add(imageBytes, string.IsNullOrWhiteSpace(effectiveMimeType) ? "image/jpeg" : effectiveMimeType);
            var hostedUrl = BuildPublicMediaUrl(publicBaseUrl, mediaId);
            var imageByHostedUrl = await gateway.SendImageUrlAsync(
                instanceName,
                destination,
                hostedUrl,
                text,
                effectiveMimeType,
                effectiveFileName,
                ct);
            if (imageByHostedUrl.Success)
            {
                diagnostics.Add("send_hosted_url=ok");
                return new WhatsAppForwardSendOutcome(imageByHostedUrl, "image_sent_hosted_url", string.Join(";", diagnostics));
            }

            diagnostics.Add($"send_hosted_url=fail:{imageByHostedUrl.Message ?? "unknown"}");
            logger.LogWarning("Falha ao enviar imagem por URL hospedada para {Destination}: {Message}", destination, imageByHostedUrl.Message);
        }

        var imageByBytes = await gateway.SendImageAsync(instanceName, destination, imageBytes, text, effectiveMimeType, ct);
        if (imageByBytes.Success)
        {
            diagnostics.Add("send_bytes=ok");
            return new WhatsAppForwardSendOutcome(imageByBytes, "image_sent_bytes", string.Join(";", diagnostics));
        }

        diagnostics.Add($"send_bytes=fail:{imageByBytes.Message ?? "unknown"}");
        logger.LogWarning("Falha ao enviar imagem em base64 para {Destination}: {Message}", destination, imageByBytes.Message);
    }

    if (!string.IsNullOrWhiteSpace(msg.MediaUrl))
    {
        var imageByUrl = await gateway.SendImageUrlAsync(
            instanceName,
            destination,
            msg.MediaUrl!,
            text,
            effectiveMimeType,
            effectiveFileName,
            ct);
        if (imageByUrl.Success)
        {
            diagnostics.Add("send_url=ok");
            return new WhatsAppForwardSendOutcome(imageByUrl, "image_sent_url", string.Join(";", diagnostics));
        }

        diagnostics.Add($"send_url=fail:{imageByUrl.Message ?? "unknown"}");
        logger.LogWarning("Falha ao enviar imagem por URL para {Destination}: {Message}", destination, imageByUrl.Message);
    }

    var fallbackText = await gateway.SendTextAsync(instanceName, destination, text, ct);
    diagnostics.Add(fallbackText.Success ? "fallback_text=ok" : $"fallback_text=fail:{fallbackText.Message ?? "unknown"}");
    return new WhatsAppForwardSendOutcome(
        fallbackText,
        fallbackText.Success ? "text_fallback_after_media_failure" : "send_failed",
        string.Join(";", diagnostics));
}

static async Task<byte[]?> TryDownloadIncomingMediaAsBytesAsync(
    IHttpClientFactory httpClientFactory,
    EvolutionOptions evolutionOptions,
    string mediaUrl,
    ILogger logger,
    CancellationToken ct)
{
    if (string.IsNullOrWhiteSpace(mediaUrl))
    {
        return null;
    }

    if (mediaUrl.StartsWith("data:", StringComparison.OrdinalIgnoreCase))
    {
        return DecodeBase64Payload(mediaUrl);
    }

    if (!Uri.TryCreate(mediaUrl, UriKind.Absolute, out var mediaUri) && !string.IsNullOrWhiteSpace(evolutionOptions.BaseUrl))
    {
        if (Uri.TryCreate(new Uri(evolutionOptions.BaseUrl), mediaUrl, out var combined))
        {
            mediaUri = combined;
        }
    }

    if (mediaUri is null)
    {
        return null;
    }

    async Task<byte[]?> DownloadAsync(bool authenticated)
    {
        try
        {
            if (authenticated && string.IsNullOrWhiteSpace(evolutionOptions.ApiKey))
            {
                return null;
            }

            var client = httpClientFactory.CreateClient("default");
            using var request = new HttpRequestMessage(HttpMethod.Get, mediaUri);
            if (authenticated)
            {
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", evolutionOptions.ApiKey);
                request.Headers.TryAddWithoutValidation("apikey", evolutionOptions.ApiKey);
                request.Headers.TryAddWithoutValidation("x-api-key", evolutionOptions.ApiKey);
            }

            using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);
            if (!response.IsSuccessStatusCode)
            {
                logger.LogWarning(
                    "Falha ao baixar midia original da mensagem ({Mode}): {StatusCode}",
                    authenticated ? "auth" : "anon",
                    response.StatusCode);
                return null;
            }

            var contentType = response.Content.Headers.ContentType?.MediaType ?? string.Empty;
            var payload = await response.Content.ReadAsByteArrayAsync(ct);
            var parsed = TryDecodeMediaBytesFromResponse(payload, contentType, logger, authenticated ? "auth" : "anon");
            if (parsed is { Length: > 0 })
            {
                return parsed;
            }

            logger.LogWarning(
                "Midia baixada ({Mode}) sem bytes validos. ContentType={ContentType}, Bytes={Length}",
                authenticated ? "auth" : "anon",
                string.IsNullOrWhiteSpace(contentType) ? "n/a" : contentType,
                payload.Length);
            return null;
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Erro ao baixar midia original da mensagem ({Mode}).", authenticated ? "auth" : "anon");
            return null;
        }
    }

    var anonBytes = await DownloadAsync(authenticated: false);
    if (anonBytes is { Length: > 0 })
    {
        return anonBytes;
    }

    var authBytes = await DownloadAsync(authenticated: true);
    if (authBytes is { Length: > 0 })
    {
        return authBytes;
    }

    return null;
}

static async Task<byte[]?> TryDownloadMediaViaEvolutionMessageApiAsync(
    IHttpClientFactory httpClientFactory,
    EvolutionOptions evolutionOptions,
    WhatsAppIncomingMessage msg,
    ILogger logger,
    CancellationToken ct)
{
    if (string.IsNullOrWhiteSpace(evolutionOptions.BaseUrl) ||
        string.IsNullOrWhiteSpace(evolutionOptions.ApiKey) ||
        string.IsNullOrWhiteSpace(msg.RawPayloadJson))
    {
        return null;
    }

    var instance = FirstNonEmpty(msg.InstanceName, evolutionOptions.InstanceName);
    if (string.IsNullOrWhiteSpace(instance))
    {
        return null;
    }

    var payloads = BuildEvolutionMediaExtractionPayloads(msg.RawPayloadJson!, logger);
    if (payloads.Count == 0)
    {
        return null;
    }

    var client = httpClientFactory.CreateClient("evolution");
    client.BaseAddress = new Uri(evolutionOptions.BaseUrl);
    client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", evolutionOptions.ApiKey);
    if (!client.DefaultRequestHeaders.Contains("apikey"))
    {
        client.DefaultRequestHeaders.Add("apikey", evolutionOptions.ApiKey);
    }
    if (!client.DefaultRequestHeaders.Contains("x-api-key"))
    {
        client.DefaultRequestHeaders.Add("x-api-key", evolutionOptions.ApiKey);
    }

    var endpoint = $"/chat/getBase64FromMediaMessage/{instance}";
    for (var i = 0; i < payloads.Count; i++)
    {
        try
        {
            using var content = new StringContent(payloads[i], Encoding.UTF8, "application/json");
            using var response = await client.PostAsync(endpoint, content, ct);
            var responseBytes = await response.Content.ReadAsByteArrayAsync(ct);
            var contentType = response.Content.Headers.ContentType?.MediaType ?? string.Empty;

            if (!response.IsSuccessStatusCode)
            {
                logger.LogDebug(
                    "Evolution media API falhou. Endpoint={Endpoint}, Tentativa={Attempt}, Status={StatusCode}",
                    endpoint,
                    i + 1,
                    response.StatusCode);
                continue;
            }

            var parsed = TryDecodeMediaBytesFromResponse(responseBytes, contentType, logger, $"evolution-media-api-{i + 1}");
            if (parsed is { Length: > 0 })
            {
                return parsed;
            }

            var responseText = Encoding.UTF8.GetString(responseBytes);
            var decoded = DecodeBase64Payload(responseText);
            if (decoded is { Length: > 0 })
            {
                return decoded;
            }
        }
        catch (Exception ex)
        {
            logger.LogDebug(ex, "Erro ao tentar extrair midia via Evolution media API. Tentativa={Attempt}", i + 1);
        }
    }

    return null;
}

static List<string> BuildEvolutionMediaExtractionPayloads(string rawPayloadJson, ILogger logger)
{
    var results = new List<string>();
    var seen = new HashSet<string>(StringComparer.Ordinal);

    void AddPayload(string payload)
    {
        if (string.IsNullOrWhiteSpace(payload))
        {
            return;
        }

        var trimmed = payload.Trim();
        if (seen.Add(trimmed))
        {
            results.Add(trimmed);
        }
    }

    void AddCore(string core)
    {
        AddPayload(core);
        AddPayload($"{{\"message\":{core}}}");
        AddPayload($"{{\"data\":{core}}}");
    }

    try
    {
        using var doc = JsonDocument.Parse(rawPayloadJson);
        var root = doc.RootElement;
        var rootRaw = root.GetRawText();
        AddCore(rootRaw);

        if (root.TryGetProperty("data", out var dataNode) &&
            (dataNode.ValueKind == JsonValueKind.Object || dataNode.ValueKind == JsonValueKind.Array))
        {
            AddCore(dataNode.GetRawText());
        }

        if (root.TryGetProperty("message", out var messageNode) &&
            (messageNode.ValueKind == JsonValueKind.Object || messageNode.ValueKind == JsonValueKind.Array))
        {
            AddCore(messageNode.GetRawText());
        }

        if (root.TryGetProperty("key", out var keyNode) &&
            root.TryGetProperty("message", out messageNode) &&
            keyNode.ValueKind == JsonValueKind.Object &&
            messageNode.ValueKind == JsonValueKind.Object)
        {
            AddPayload($"{{\"key\":{keyNode.GetRawText()},\"message\":{messageNode.GetRawText()}}}");
            AddPayload($"{{\"message\":{{\"key\":{keyNode.GetRawText()},\"message\":{messageNode.GetRawText()}}}}}");
        }
    }
    catch (Exception ex)
    {
        logger.LogDebug(ex, "Nao foi possivel montar payload para Evolution media API.");
    }

    return results;
}

static byte[]? TryDecodeMediaBytesFromResponse(byte[] payload, string contentType, ILogger logger, string mode)
{
    if (payload.Length == 0)
    {
        return null;
    }

    if (IsLikelyBinaryMediaPayload(payload, contentType))
    {
        return payload;
    }

    if (LooksLikeJsonPayload(payload, contentType))
    {
        var fromJson = TryParseJsonMediaBytes(payload, logger);
        if (fromJson is { Length: > 0 })
        {
            return fromJson;
        }
    }

    if (contentType.StartsWith("text/", StringComparison.OrdinalIgnoreCase))
    {
        logger.LogWarning("Download de midia retornou texto ({Mode}), ignorando. ContentType={ContentType}", mode, contentType);
        return null;
    }

    return null;
}

static bool IsLikelyBinaryMediaPayload(byte[] payload, string contentType)
{
    var detectedMime = DetectMimeTypeFromBytes(payload);
    if (contentType.StartsWith("image/", StringComparison.OrdinalIgnoreCase) ||
        contentType.StartsWith("video/", StringComparison.OrdinalIgnoreCase) ||
        contentType.StartsWith("audio/", StringComparison.OrdinalIgnoreCase))
    {
        if (contentType.StartsWith("image/", StringComparison.OrdinalIgnoreCase))
        {
            return !string.IsNullOrWhiteSpace(detectedMime);
        }

        return true;
    }

    if (!string.IsNullOrWhiteSpace(detectedMime))
    {
        return true;
    }

    return false;
}

static byte[]? TryTranscodeImageToPng(byte[] payload, ILogger logger)
{
    try
    {
        return ImageNormalizationSupport.TranscodeToPng(payload);
    }
    catch (Exception ex)
    {
        logger.LogDebug(ex, "Nao foi possivel transcodificar imagem para PNG.");
        return null;
    }
}

static string? DetectMimeTypeFromBytes(byte[] payload)
{
    if (payload is null || payload.Length < 4)
    {
        return null;
    }

    if (payload.Length >= 3 &&
        payload[0] == 0xFF &&
        payload[1] == 0xD8 &&
        payload[2] == 0xFF)
    {
        return "image/jpeg";
    }

    if (payload.Length >= 8 &&
        payload[0] == 0x89 &&
        payload[1] == 0x50 &&
        payload[2] == 0x4E &&
        payload[3] == 0x47 &&
        payload[4] == 0x0D &&
        payload[5] == 0x0A &&
        payload[6] == 0x1A &&
        payload[7] == 0x0A)
    {
        return "image/png";
    }

    if (payload.Length >= 6 &&
        payload[0] == 0x47 &&
        payload[1] == 0x49 &&
        payload[2] == 0x46 &&
        payload[3] == 0x38 &&
        (payload[4] == 0x37 || payload[4] == 0x39) &&
        payload[5] == 0x61)
    {
        return "image/gif";
    }

    if (payload.Length >= 12 &&
        payload[0] == 0x52 &&
        payload[1] == 0x49 &&
        payload[2] == 0x46 &&
        payload[3] == 0x46 &&
        payload[8] == 0x57 &&
        payload[9] == 0x45 &&
        payload[10] == 0x42 &&
        payload[11] == 0x50)
    {
        return "image/webp";
    }

    if (payload.Length >= 2 &&
        payload[0] == 0x42 &&
        payload[1] == 0x4D)
    {
        return "image/bmp";
    }

    if (payload.Length >= 4 &&
        ((payload[0] == 0x49 && payload[1] == 0x49 && payload[2] == 0x2A && payload[3] == 0x00) ||
         (payload[0] == 0x4D && payload[1] == 0x4D && payload[2] == 0x00 && payload[3] == 0x2A)))
    {
        return "image/tiff";
    }

    if (payload.Length >= 12 &&
        payload[4] == 0x66 &&
        payload[5] == 0x74 &&
        payload[6] == 0x79 &&
        payload[7] == 0x70)
    {
        var brand = Encoding.ASCII.GetString(payload, 8, 4).ToLowerInvariant();
        if (brand.Contains("avif", StringComparison.Ordinal))
        {
            return "image/avif";
        }

        if (brand.Contains("heic", StringComparison.Ordinal) || brand.Contains("heif", StringComparison.Ordinal))
        {
            return "image/heic";
        }
    }

    return null;
}

static string? ResolveMediaFileName(string? currentFileName, string? mimeType)
{
    if (!string.IsNullOrWhiteSpace(currentFileName))
    {
        return currentFileName;
    }

    var ext = mimeType?.ToLowerInvariant() switch
    {
        "image/jpeg" => "jpg",
        "image/png" => "png",
        "image/webp" => "webp",
        "image/gif" => "gif",
        "image/bmp" => "bmp",
        "image/tiff" => "tiff",
        "image/avif" => "avif",
        "image/heic" => "heic",
        _ => "jpg"
    };

    return $"image.{ext}";
}

static bool LooksLikeJsonPayload(byte[] payload, string contentType)
{
    if (contentType.Contains("json", StringComparison.OrdinalIgnoreCase))
    {
        return true;
    }

    foreach (var b in payload)
    {
        if (b is (byte)' ' or (byte)'\t' or (byte)'\r' or (byte)'\n')
        {
            continue;
        }

        return b is (byte)'{' or (byte)'[';
    }

    return false;
}

static byte[]? TryParseJsonMediaBytes(byte[] payload, ILogger logger)
{
    try
    {
        using var doc = JsonDocument.Parse(payload);
        if (!TryFindMediaStringCandidate(doc.RootElement, out var mediaString))
        {
            return null;
        }

        var decoded = DecodeBase64Payload(mediaString);
        if (decoded is { Length: > 0 })
        {
            return decoded;
        }
    }
    catch (Exception ex)
    {
        logger.LogDebug(ex, "Nao foi possivel interpretar payload JSON de midia.");
    }

    return null;
}

static bool TryFindMediaStringCandidate(JsonElement element, out string value)
{
    value = string.Empty;

    if (element.ValueKind == JsonValueKind.String)
    {
        var candidate = element.GetString()?.Trim() ?? string.Empty;
        if (candidate.StartsWith("data:", StringComparison.OrdinalIgnoreCase) || LooksLikeBase64Payload(candidate))
        {
            value = candidate;
            return true;
        }

        return false;
    }

    if (element.ValueKind == JsonValueKind.Object)
    {
        var preferred = new[]
        {
            "base64", "fileBase64", "data", "media", "buffer", "content", "file", "payload"
        };
        foreach (var key in preferred)
        {
            if (element.TryGetProperty(key, out var property) && TryFindMediaStringCandidate(property, out value))
            {
                return true;
            }
        }

        foreach (var property in element.EnumerateObject())
        {
            if (TryFindMediaStringCandidate(property.Value, out value))
            {
                return true;
            }
        }

        return false;
    }

    if (element.ValueKind == JsonValueKind.Array)
    {
        foreach (var item in element.EnumerateArray())
        {
            if (TryFindMediaStringCandidate(item, out value))
            {
                return true;
            }
        }
    }

    return false;
}

static bool LooksLikeBase64Payload(string value)
{
    if (string.IsNullOrWhiteSpace(value))
    {
        return false;
    }

    var candidate = value.Trim();
    if (candidate.Length < 64)
    {
        return false;
    }

    candidate = candidate.Replace("\r", string.Empty, StringComparison.Ordinal)
        .Replace("\n", string.Empty, StringComparison.Ordinal)
        .Replace(" ", string.Empty, StringComparison.Ordinal)
        .Replace("-", "+", StringComparison.Ordinal)
        .Replace("_", "/", StringComparison.Ordinal);

    foreach (var ch in candidate)
    {
        var isAlphaNum = (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9');
        if (!isAlphaNum && ch != '+' && ch != '/' && ch != '=')
        {
            return false;
        }
    }

    return true;
}

static byte[]? DecodeBase64Payload(string? payload)
{
    if (string.IsNullOrWhiteSpace(payload))
    {
        return null;
    }

    var value = payload.Trim();
    if (value.StartsWith("data:", StringComparison.OrdinalIgnoreCase))
    {
        var comma = value.IndexOf(',');
        if (comma >= 0 && comma + 1 < value.Length)
        {
            value = value[(comma + 1)..];
        }
    }

    try
    {
        return Convert.FromBase64String(value);
    }
    catch
    {
        try
        {
            var normalized = value
                .Replace("\r", string.Empty, StringComparison.Ordinal)
                .Replace("\n", string.Empty, StringComparison.Ordinal)
                .Replace(" ", string.Empty, StringComparison.Ordinal)
                .Replace("-", "+", StringComparison.Ordinal)
                .Replace("_", "/", StringComparison.Ordinal);

            var pad = normalized.Length % 4;
            if (pad > 0)
            {
                normalized = normalized.PadRight(normalized.Length + (4 - pad), '=');
            }

            return Convert.FromBase64String(normalized);
        }
        catch
        {
            return null;
        }
    }
}

static bool TryExtractIncomingMedia(
    JsonElement node,
    out string? mediaUrl,
    out string? mediaBase64,
    out string? mediaMimeType,
    out string? mediaFileName)
{
    mediaUrl = null;
    mediaBase64 = null;
    mediaMimeType = null;
    mediaFileName = null;

    var hasMedia = false;
    var messageNode = node;
    if (node.TryGetProperty("message", out var rootMessage))
    {
        messageNode = rootMessage;
    }

    while (TryUnwrapMessageEnvelope(messageNode, out var inner))
    {
        messageNode = inner;
    }

    if (TryGetIncomingMediaNode(messageNode, out var mediaNode))
    {
        hasMedia = true;
        mediaUrl = GetString(mediaNode, "url", "mediaUrl", "media_url");
        mediaBase64 = GetString(mediaNode, "base64", "fileBase64", "data");
        mediaMimeType = GetString(mediaNode, "mimetype", "mimeType");
        mediaFileName = GetString(mediaNode, "fileName", "filename");
    }

    mediaUrl ??= GetString(node, "mediaUrl", "media_url");
    mediaBase64 ??= GetString(node, "base64", "fileBase64");
    mediaMimeType ??= GetString(node, "mimetype", "mimeType");
    mediaFileName ??= GetString(node, "fileName", "filename");
    mediaUrl ??= GetString(messageNode, "mediaUrl", "media_url", "url");
    mediaBase64 ??= GetString(messageNode, "base64", "fileBase64", "data");
    mediaMimeType ??= GetString(messageNode, "mimetype", "mimeType");
    mediaFileName ??= GetString(messageNode, "fileName", "filename");

    if (string.IsNullOrWhiteSpace(mediaBase64) &&
        !string.IsNullOrWhiteSpace(mediaUrl) &&
        mediaUrl.StartsWith("data:", StringComparison.OrdinalIgnoreCase))
    {
        var value = mediaUrl;
        var comma = value.IndexOf(',');
        if (comma > 0 && comma + 1 < value.Length)
        {
            var header = value[..comma];
            if (string.IsNullOrWhiteSpace(mediaMimeType) &&
                header.StartsWith("data:", StringComparison.OrdinalIgnoreCase))
            {
                var semicolon = header.IndexOf(';');
                if (semicolon > 5)
                {
                    mediaMimeType = header[5..semicolon];
                }
            }

            mediaBase64 = value[(comma + 1)..];
            mediaUrl = null;
        }
    }

    if (!hasMedia)
    {
        var messageType = GetString(node, "messageType", "type");
        hasMedia = !string.IsNullOrWhiteSpace(messageType) &&
                   (messageType.Contains("image", StringComparison.OrdinalIgnoreCase) ||
                    messageType.Contains("media", StringComparison.OrdinalIgnoreCase));
    }

    return hasMedia || !string.IsNullOrWhiteSpace(mediaUrl) || !string.IsNullOrWhiteSpace(mediaBase64);
}

static bool TryGetIncomingMediaNode(JsonElement node, out JsonElement mediaNode)
{
    if (node.TryGetProperty("imageMessage", out mediaNode)) return true;
    if (node.TryGetProperty("videoMessage", out mediaNode)) return true;
    if (node.TryGetProperty("documentMessage", out mediaNode)) return true;
    if (node.TryGetProperty("stickerMessage", out mediaNode)) return true;

    mediaNode = default;
    return false;
}

static bool TryUnwrapMessageEnvelope(JsonElement messageNode, out JsonElement innerMessage)
{
    if (messageNode.TryGetProperty("ephemeralMessage", out var ephemeral) &&
        ephemeral.TryGetProperty("message", out innerMessage))
    {
        return true;
    }

    if (messageNode.TryGetProperty("viewOnceMessage", out var viewOnce) &&
        viewOnce.TryGetProperty("message", out innerMessage))
    {
        return true;
    }

    if (messageNode.TryGetProperty("viewOnceMessageV2", out var viewOnceV2) &&
        viewOnceV2.TryGetProperty("message", out innerMessage))
    {
        return true;
    }

    if (messageNode.TryGetProperty("viewOnceMessageV2Extension", out var viewOnceExt) &&
        viewOnceExt.TryGetProperty("message", out innerMessage))
    {
        return true;
    }

    if (messageNode.TryGetProperty("editedMessage", out var edited) &&
        edited.TryGetProperty("message", out innerMessage))
    {
        return true;
    }

    innerMessage = default;
    return false;
}

static List<WhatsAppIncomingMessage> ExtractEvolutionMessages(string body)
{
    var items = new List<WhatsAppIncomingMessage>();
    try
    {
        using var doc = JsonDocument.Parse(body);
        var root = doc.RootElement;
        var instanceName = root.TryGetProperty("instance", out var instNode) && instNode.ValueKind == JsonValueKind.String
            ? instNode.GetString()
            : null;
        var data = root.TryGetProperty("data", out var dataNode) ? dataNode : root;

        if (data.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in data.EnumerateArray())
            {
                if (TryExtractEvolutionMessage(item, instanceName, out var msg))
                {
                    items.Add(msg);
                }
            }
            return items;
        }

        if (data.TryGetProperty("messages", out var messagesNode) && messagesNode.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in messagesNode.EnumerateArray())
            {
                if (TryExtractEvolutionMessage(item, instanceName, out var msg))
                {
                    items.Add(msg);
                }
            }
            return items;
        }

        if (TryExtractEvolutionMessage(data, instanceName, out var single))
        {
            items.Add(single);
            return items;
        }

        if (TryExtractEvolutionMessage(root, instanceName, out var fallback))
        {
            items.Add(fallback);
        }
    }
    catch
    {
        // ignore malformed payload
    }

    return items;
}

static bool TryExtractEvolutionMessage(JsonElement node, string? instanceName, out WhatsAppIncomingMessage msg)
{
    msg = new WhatsAppIncomingMessage(string.Empty, null, string.Empty, false, instanceName, null, false, null, null, null, null, null);

    var chatId = string.Empty;
    var senderId = string.Empty;
    var messageId = string.Empty;
    var fromMe = false;

    if (node.TryGetProperty("key", out var key))
    {
        chatId = GetString(key, "remoteJid") ?? string.Empty;
        senderId = GetString(key, "participant", "sender", "from") ?? string.Empty;
        messageId = GetString(key, "id") ?? string.Empty;
        fromMe = GetBool(key, "fromMe");
    }

    if (string.IsNullOrWhiteSpace(chatId))
    {
        chatId = GetString(node, "remoteJid", "chatId", "from", "to") ?? string.Empty;
    }

    if (!fromMe)
    {
        fromMe = GetBool(node, "fromMe");
    }

    if (string.IsNullOrWhiteSpace(senderId))
    {
        senderId = GetString(node, "participant", "sender", "sender_id", "from") ?? string.Empty;
    }

    if (string.IsNullOrWhiteSpace(senderId) && node.TryGetProperty("sender", out var senderNode))
    {
        if (senderNode.ValueKind == JsonValueKind.String)
        {
            senderId = senderNode.GetString() ?? string.Empty;
        }
        else if (senderNode.ValueKind == JsonValueKind.Object)
        {
            senderId = GetString(senderNode, "id", "jid", "from", "user") ?? string.Empty;
        }
    }

    if (string.IsNullOrWhiteSpace(senderId) && fromMe)
    {
        senderId = "self";
    }

    var text = ExtractMessageText(node);
    var hasMedia = TryExtractIncomingMedia(node, out var mediaUrl, out var mediaBase64, out var mediaMimeType, out var mediaFileName);
    if (string.IsNullOrWhiteSpace(text) && !hasMedia)
    {
        return false;
    }

    msg = new WhatsAppIncomingMessage(
        chatId,
        string.IsNullOrWhiteSpace(senderId) ? null : senderId,
        text,
        fromMe,
        instanceName,
        string.IsNullOrWhiteSpace(messageId) ? null : messageId,
        hasMedia,
        mediaUrl,
        mediaBase64,
        mediaMimeType,
        mediaFileName,
        node.GetRawText());
    return true;
}

static bool IsWhatsAppGroupChat(string chatId)
    => chatId.EndsWith("@g.us", StringComparison.OrdinalIgnoreCase);

static bool IsWhatsAppResponderAllowed(LinkResponderSettings responder, WhatsAppIncomingMessage msg)
{
    if (!responder.Enabled || !responder.AllowWhatsApp)
    {
        return false;
    }

    var chatId = msg.ChatId ?? string.Empty;
    if (responder.WhatsAppChatIds.Count > 0)
    {
        return responder.WhatsAppChatIds.Any(id => string.Equals(id, chatId, StringComparison.OrdinalIgnoreCase));
    }

    var isGroup = IsWhatsAppGroupChat(chatId);
    return isGroup ? responder.WhatsAppAllowGroups : responder.WhatsAppAllowPrivate;
}

static string? GetAutoReply(AutomationSettings settings, string text)
{
    if (!settings.AutoRepliesSettings.Enabled) return null;
    if (string.IsNullOrWhiteSpace(text)) return null;
    var hasLink = text.Contains("http", StringComparison.OrdinalIgnoreCase);
    if (hasLink) return null;

    foreach (var rule in settings.AutoReplies)
    {
        if (!rule.Enabled) continue;
        if (string.IsNullOrWhiteSpace(rule.Trigger)) continue;
        if (text.Contains(rule.Trigger, StringComparison.OrdinalIgnoreCase))
        {
            return rule.ResponseTemplate;
        }
    }

    return null;
}

static bool IsInstagramAllowed(InstagramPostSettings settings, string chatId)
{
    if (settings.WhatsAppChatIds.Count > 0)
    {
        return settings.WhatsAppChatIds.Contains(chatId);
    }

    var isGroup = IsWhatsAppGroupChat(chatId);
    return isGroup ? settings.WhatsAppAllowGroups : settings.WhatsAppAllowPrivate;
}

static bool IsInstagramTrigger(string text, List<string> triggers)
{
    if (string.IsNullOrWhiteSpace(text)) return false;
    if (triggers is null || triggers.Count == 0) return false;
    var normalized = text.Trim();
    foreach (var trigger in triggers)
    {
        if (string.IsNullOrWhiteSpace(trigger)) continue;
        if (normalized.StartsWith(trigger.Trim(), StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }
    }
    return false;
}

static bool TryParseInstagramWhatsAppCommand(string text, out InstagramWhatsAppCommand command)
{
    command = new InstagramWhatsAppCommand("unknown", null);
    if (string.IsNullOrWhiteSpace(text))
    {
        return false;
    }

    var trimmed = text.Trim();
    string payload;
    if (trimmed.StartsWith("/ig", StringComparison.OrdinalIgnoreCase))
    {
        payload = trimmed[3..].Trim();
    }
    else if (trimmed.StartsWith("ig ", StringComparison.OrdinalIgnoreCase))
    {
        payload = trimmed[2..].Trim();
    }
    else
    {
        return false;
    }

    if (string.IsNullOrWhiteSpace(payload))
    {
        command = new InstagramWhatsAppCommand("help", null);
        return true;
    }

    var parts = payload.Split(' ', 2, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
    var action = parts[0].Trim().ToLowerInvariant();
    var argument = parts.Length > 1 ? parts[1].Trim() : null;

    command = action switch
    {
        "criar" => new InstagramWhatsAppCommand("create", argument),
        "novo" => new InstagramWhatsAppCommand("create", argument),
        "rapido" => new InstagramWhatsAppCommand("create_fast", argument),
        "fluxo" => new InstagramWhatsAppCommand("create_fast", argument),
        "turbo" => new InstagramWhatsAppCommand("create_fast", argument),
        "imagem" => new InstagramWhatsAppCommand("add_images", argument),
        "img" => new InstagramWhatsAppCommand("add_images", argument),
        "midia" => new InstagramWhatsAppCommand("add_images", argument),
        "imagens" => new InstagramWhatsAppCommand("manage_images", argument),
        "fotos" => new InstagramWhatsAppCommand("manage_images", argument),
        "galeria" => new InstagramWhatsAppCommand("manage_images", argument),
        "limpar-imagens" => new InstagramWhatsAppCommand("clear_images", argument),
        "limparimagens" => new InstagramWhatsAppCommand("clear_images", argument),
        "limpar-midias" => new InstagramWhatsAppCommand("clear_images", argument),
        "limparmidias" => new InstagramWhatsAppCommand("clear_images", argument),
        "tipo" => new InstagramWhatsAppCommand("set_type", argument),
        "modo" => new InstagramWhatsAppCommand("set_type", argument),
        "formatar" => new InstagramWhatsAppCommand("format_caption", argument),
        "format" => new InstagramWhatsAppCommand("format_caption", argument),
        "leg" => new InstagramWhatsAppCommand("pick_caption", argument),
        "cta" => new InstagramWhatsAppCommand("set_cta", argument),
        "anunciar" => new InstagramWhatsAppCommand("boost_post", argument),
        "boost" => new InstagramWhatsAppCommand("boost_post", argument),
        "promover" => new InstagramWhatsAppCommand("boost_post", argument),
        "templates" => new InstagramWhatsAppCommand("list_templates", argument),
        "template" => new InstagramWhatsAppCommand("apply_template", argument),
        "modelo" => new InstagramWhatsAppCommand("apply_template", argument),
        "menu" => new InstagramWhatsAppCommand("menu", argument),
        "opcoes" => new InstagramWhatsAppCommand("menu", argument),
        "atalhos" => new InstagramWhatsAppCommand("menu", argument),
        "legenda" => new InstagramWhatsAppCommand("set_caption", argument),
        "caption" => new InstagramWhatsAppCommand("set_caption", argument),
        "texto" => new InstagramWhatsAppCommand("set_caption", argument),
        "revisar" => new InstagramWhatsAppCommand("review", argument),
        "status" => new InstagramWhatsAppCommand("review", argument),
        "confirmar" => new InstagramWhatsAppCommand("confirm", argument),
        "publicar" => new InstagramWhatsAppCommand("confirm", argument),
        "reset" => new InstagramWhatsAppCommand("reset", argument),
        "zerar" => new InstagramWhatsAppCommand("reset", argument),
        "reiniciar" => new InstagramWhatsAppCommand("reset", argument),
        "ajuda" => new InstagramWhatsAppCommand("help", argument),
        "help" => new InstagramWhatsAppCommand("help", argument),
        _ => new InstagramWhatsAppCommand("unknown", payload)
    };

    return true;
}

static bool TryParseWhatsAppHelpCommand(string text, out WhatsAppHelpCommand command)
{
    command = new WhatsAppHelpCommand("general");
    if (string.IsNullOrWhiteSpace(text))
    {
        return false;
    }

    var normalized = text.Trim();
    var firstToken = normalized
        .Split(' ', 2, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
        .FirstOrDefault() ?? string.Empty;

    var isHelp = string.Equals(firstToken, @"\help", StringComparison.OrdinalIgnoreCase)
                 || string.Equals(firstToken, "/help", StringComparison.OrdinalIgnoreCase)
                 || string.Equals(firstToken, "/ajuda", StringComparison.OrdinalIgnoreCase)
                 || string.Equals(normalized, "help", StringComparison.OrdinalIgnoreCase)
                 || string.Equals(normalized, "ajuda", StringComparison.OrdinalIgnoreCase);
    if (!isHelp)
    {
        return false;
    }

    var scopeToken = normalized
        .Split(' ', 3, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
        .Skip(1)
        .FirstOrDefault() ?? "general";

    var scope = scopeToken.ToLowerInvariant() switch
    {
        "1" => "instagram",
        "ig" => "instagram",
        "insta" => "instagram",
        "instagram" => "instagram",
        "2" => "cta",
        "cta" => "cta",
        "comentarios" => "cta",
        "3" => "links",
        "link" => "links",
        "links" => "links",
        "bio" => "links",
        "4" => "ads",
        "ad" => "ads",
        "ads" => "ads",
        "anuncio" => "ads",
        "anuncios" => "ads",
        "5" => "quick",
        "rapido" => "quick",
        "atalhos" => "quick",
        "menu" => "general",
        _ => "general"
    };

    command = new WhatsAppHelpCommand(scope);
    return true;
}

static bool TryParseInstagramCaptionChoiceCommand(string text, out InstagramCaptionChoiceCommand command)
{
    command = new InstagramCaptionChoiceCommand(0, "ultimo");
    if (string.IsNullOrWhiteSpace(text))
    {
        return false;
    }

    var normalized = text.Trim();
    var parts = normalized.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
    if (parts.Length < 2)
    {
        return false;
    }

    var token = parts[0];
    var isLegToken = string.Equals(token, "/leg", StringComparison.OrdinalIgnoreCase)
                     || string.Equals(token, "\\leg", StringComparison.OrdinalIgnoreCase)
                     || string.Equals(token, "leg", StringComparison.OrdinalIgnoreCase);
    if (!isLegToken)
    {
        return false;
    }

    if (!int.TryParse(parts[1], out var option) || option <= 0)
    {
        return false;
    }

    var draftRef = parts.Length >= 3 ? parts[2] : "ultimo";
    command = new InstagramCaptionChoiceCommand(option, draftRef);
    return true;
}

static IEnumerable<string> SplitInstagramMessages(string text)
{
    if (string.IsNullOrWhiteSpace(text))
    {
        yield break;
    }

    var lines = text.Replace("\r", string.Empty).Split('\n');
    var blocks = new List<List<string>>();

    foreach (var raw in lines)
    {
        var line = raw?.TrimEnd() ?? string.Empty;
        if (IsInstagramSectionHeader(line) && blocks.Count > 0)
        {
            blocks.Add(new List<string>());
        }
        if (blocks.Count == 0)
        {
            blocks.Add(new List<string>());
        }
        blocks[^1].Add(line);
    }

    foreach (var block in blocks)
    {
        var chunk = string.Join('\n', block).Trim();
        if (!string.IsNullOrWhiteSpace(chunk))
        {
            yield return chunk;
        }
    }
}

static IEnumerable<string> SplitLongMessage(string text, int maxLength)
{
    if (string.IsNullOrWhiteSpace(text))
    {
        yield break;
    }

    var normalized = text.Replace("\r", string.Empty);
    if (normalized.Length <= maxLength)
    {
        yield return normalized;
        yield break;
    }

    var lines = normalized.Split('\n');
    var current = new StringBuilder();

    foreach (var raw in lines)
    {
        var line = raw ?? string.Empty;
        if (line.Length > maxLength)
        {
            if (current.Length > 0)
            {
                yield return current.ToString().TrimEnd();
                current.Clear();
            }

            for (var i = 0; i < line.Length; i += maxLength)
            {
                var size = Math.Min(maxLength, line.Length - i);
                yield return line.Substring(i, size);
            }

            continue;
        }

        if (current.Length + line.Length + 1 > maxLength)
        {
            yield return current.ToString().TrimEnd();
            current.Clear();
        }

        current.AppendLine(line);
    }

    if (current.Length > 0)
    {
        yield return current.ToString().TrimEnd();
    }
}

static async Task<IReadOnlyList<string>> ExecuteInstagramWhatsAppCommandAsync(
    InstagramWhatsAppCommand command,
    string chatId,
    AutomationSettings settings,
    IInstagramPostComposer instagramComposer,
    IInstagramPublishStore publishStore,
    IInstagramPublishLogStore publishLogStore,
    InstagramLinkMetaService instagramMeta,
    IHttpClientFactory httpClientFactory,
    IMediaStore mediaStore,
    string? publicBaseUrl,
    InstagramCommandMenuStore instagramMenuStore,
    CancellationToken ct)
{
    switch (command.Action)
    {
        case "help":
            return new[] { BuildInstagramCommandHelp() };

        case "menu":
            instagramMenuStore.Arm(chatId);
            return new[] { BuildInstagramMenuMessage() };

        case "create":
        {
            if (string.IsNullOrWhiteSpace(command.Argument))
            {
                return new[] { "Uso: /ig criar <produto ou link>" };
            }

            var instaSettings = settings.InstagramPosts ?? new InstagramPostSettings();
            var draftResult = await BuildInstagramDraftFromCreateInputAsync(command.Argument, instaSettings, instagramComposer, instagramMeta, ct);
            if (!string.IsNullOrWhiteSpace(draftResult.Error))
            {
                return new[] { draftResult.Error };
            }
            var draft = draftResult.Draft!;

            await publishStore.SaveAsync(draft, ct);
            await publishLogStore.AppendAsync(new InstagramPublishLogEntry
            {
                Action = "wa_command_draft_create",
                Success = true,
                DraftId = draft.Id,
                Details = $"Chat={chatId},Images={draft.ImageUrls.Count},Ctas={draft.Ctas.Count}"
            }, ct);

            var shortId = draft.Id.Length > 8 ? draft.Id[..8] : draft.Id;
            var responses = new List<string>
            {
                $"Rascunho criado: {draft.Id}\nTipo: {draft.PostType}\nProduto: {draft.ProductName}\nImagens: {draft.ImageUrls.Count}\nCTAs: {(draft.Ctas.Count == 0 ? "nenhum" : string.Join(", ", draft.Ctas.Select(c => c.Keyword)))}\nLegendas: {draft.CaptionOptions.Count}\nComandos: /ig revisar {shortId} | /ig confirmar {shortId}"
            };

            if (draft.CaptionOptions.Count > 1)
            {
                responses.Add($"Escolha uma legenda com /leg <numero> {shortId} (ex.: /leg 2 {shortId})");
                for (var i = 0; i < draft.CaptionOptions.Count; i++)
                {
                    responses.Add($"Legenda {i + 1}:\n{draft.CaptionOptions[i]}");
                }
            }
            else
            {
                responses.Add($"Legenda:\n{draft.Caption}");
            }
            if (!string.IsNullOrWhiteSpace(draft.Hashtags))
            {
                responses.Add($"Hashtags:\n{draft.Hashtags}");
            }
            if (draft.ImageUrls.Count == 0)
            {
                responses.Add($"Nenhuma imagem foi detectada no link.\nAdicione manualmente: /ig imagem {shortId} <url-da-imagem>\nPara story: /ig tipo {shortId} story");
            }

            return responses;
        }

        case "create_fast":
        {
            if (string.IsNullOrWhiteSpace(command.Argument))
            {
                return new[] { "Uso: /ig rapido <produto ou link> cta=BIKE img=https://... tipo=feed|story" };
            }

            var instaSettings = settings.InstagramPosts ?? new InstagramPostSettings();
            var draftResult = await BuildInstagramDraftFromCreateInputAsync(command.Argument, instaSettings, instagramComposer, instagramMeta, ct);
            if (!string.IsNullOrWhiteSpace(draftResult.Error))
            {
                return new[] { draftResult.Error };
            }
            var draft = draftResult.Draft!;
            await publishStore.SaveAsync(draft, ct);

            await publishLogStore.AppendAsync(new InstagramPublishLogEntry
            {
                Action = "wa_command_draft_create_fast",
                Success = true,
                DraftId = draft.Id,
                Details = $"Chat={chatId},Images={draft.ImageUrls.Count},Ctas={draft.Ctas.Count}"
            }, ct);

            var shortId = draft.Id.Length > 8 ? draft.Id[..8] : draft.Id;
            if (draft.ImageUrls.Count == 0)
            {
                return new[]
                {
                    $"Fluxo rapido criou o draft {shortId}, mas nao encontrei imagem para publicar.",
                    $"Adicione imagem e confirme:\n/ig imagem {shortId} <url-da-imagem>\n/ig confirmar {shortId}"
                };
            }

            var publishResult = await PublishInstagramDraftAsync(
                draft.Id,
                settings.InstagramPublish ?? new InstagramPublishSettings(),
                settings.VilaNvidia ?? new VilaNvidiaSettings(),
                settings.Gemini ?? new GeminiSettings(),
                publishStore,
                publishLogStore,
                httpClientFactory,
                mediaStore,
                publicBaseUrl,
                ct);

            if (publishResult.Success)
            {
                return new[]
                {
                    $"Fluxo rapido concluido.",
                    $"Draft: {draft.Id}\nMediaId: {publishResult.MediaId}\nCTA: {(draft.Ctas.Count == 0 ? "nao definido" : string.Join(", ", draft.Ctas.Select(c => c.Keyword)))}"
                };
            }

            return new[]
            {
                $"Fluxo rapido criou o draft {shortId}, mas falhou ao publicar.",
                $"Erro: {publishResult.Error ?? "erro desconhecido"}\nRevise com /ig revisar {shortId} e confirme com /ig confirmar {shortId}."
            };
        }

        case "list_templates":
            return new[] { BuildInstagramCaptionTemplateHelp(settings.InstagramPosts ?? new InstagramPostSettings()) };

        case "apply_template":
        {
            var parsedTemplate = ParseInstagramCaptionTemplateInput(command.Argument);
            if (!string.IsNullOrWhiteSpace(parsedTemplate.Error))
            {
                return new[] { parsedTemplate.Error };
            }

            var (draft, error) = await ResolveInstagramDraftAsync(publishStore, parsedTemplate.DraftRef, ct);
            if (draft is null)
            {
                return new[] { error ?? "Rascunho nao encontrado." };
            }

            draft.Caption = ApplyInstagramCaptionTemplate(draft, parsedTemplate.TemplateNumber, settings.InstagramPosts ?? new InstagramPostSettings());
            if (draft.CaptionOptions.Count == 0)
            {
                draft.CaptionOptions = new List<string> { draft.Caption };
                draft.SelectedCaptionIndex = 1;
            }
            else if (draft.SelectedCaptionIndex >= 1 && draft.SelectedCaptionIndex <= draft.CaptionOptions.Count)
            {
                draft.CaptionOptions[draft.SelectedCaptionIndex - 1] = draft.Caption;
            }
            else
            {
                draft.CaptionOptions[0] = draft.Caption;
                draft.SelectedCaptionIndex = 1;
            }

            await publishStore.UpdateAsync(draft, ct);
            await publishLogStore.AppendAsync(new InstagramPublishLogEntry
            {
                Action = "wa_command_draft_apply_template",
                Success = true,
                DraftId = draft.Id,
                Details = $"Template={parsedTemplate.TemplateNumber}"
            }, ct);

            var shortId = draft.Id.Length > 8 ? draft.Id[..8] : draft.Id;
            return new[]
            {
                $"Template {parsedTemplate.TemplateNumber} aplicado no draft {shortId}.",
                $"Use /ig revisar {shortId} e /ig confirmar {shortId}."
            };
        }

        case "add_images":
        {
            var parsedImageCommand = ParseInstagramImageCommandInput(command.Argument);
            if (!string.IsNullOrWhiteSpace(parsedImageCommand.Error))
            {
                return new[] { parsedImageCommand.Error };
            }

            var (draft, error) = await ResolveInstagramDraftAsync(publishStore, parsedImageCommand.DraftRef, ct);
            if (draft is null)
            {
                return new[] { error ?? "Rascunho nao encontrado." };
            }

            var current = draft.ImageUrls ?? new List<string>();
            var merged = NormalizeExternalUrls(current.Concat(parsedImageCommand.ImageUrls), 10);
            draft.ImageUrls = merged;
            draft.SelectedImageIndexes = SanitizeInstagramSelectedIndexes(draft.SelectedImageIndexes, draft.ImageUrls.Count);
            await publishStore.UpdateAsync(draft, ct);

            await publishLogStore.AppendAsync(new InstagramPublishLogEntry
            {
                Action = "wa_command_draft_add_images",
                Success = true,
                DraftId = draft.Id,
                Details = $"Images={draft.ImageUrls.Count}"
            }, ct);

            var shortId = draft.Id.Length > 8 ? draft.Id[..8] : draft.Id;
            return new[]
            {
                $"Imagens atualizadas no draft {shortId}.\nTotal de imagens: {draft.ImageUrls.Count}\nSe houver 2+ imagens, publica como carrossel.\nComando: /ig confirmar {shortId}"
            };
        }

        case "manage_images":
        {
            var parsedManage = ParseInstagramManageImagesInput(command.Argument);
            if (!string.IsNullOrWhiteSpace(parsedManage.Error))
            {
                return new[] { parsedManage.Error };
            }

            var (draft, error) = await ResolveInstagramDraftAsync(publishStore, parsedManage.DraftRef, ct);
            if (draft is null)
            {
                return new[] { error ?? "Rascunho nao encontrado." };
            }

            if (draft.ImageUrls.Count == 0)
            {
                var shortEmpty = draft.Id.Length > 8 ? draft.Id[..8] : draft.Id;
                return new[]
                {
                    $"O draft {shortEmpty} nao tem imagens ainda.",
                    $"Adicione com /ig imagem {shortEmpty} <url-da-imagem>"
                };
            }

            if (parsedManage.ListOnly)
            {
                return new[] { BuildInstagramImageSelectionMessage(draft) };
            }

            var max = draft.ImageUrls.Count;
            var invalid = parsedManage.SelectedIndexes.Where(i => i < 1 || i > max).ToList();
            if (invalid.Count > 0)
            {
                return new[] { $"Indice(s) invalido(s): {string.Join(", ", invalid)}. Use valores entre 1 e {max}." };
            }

            var selected = parsedManage.SelectedIndexes
                .Select(i => draft.ImageUrls[i - 1])
                .Where(x => !string.IsNullOrWhiteSpace(x))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();

            if (selected.Count == 0)
            {
                return new[] { "Nenhuma imagem valida selecionada." };
            }

            var selectedIndexes = parsedManage.SelectedIndexes
                .Distinct()
                .OrderBy(x => x)
                .ToList();
            draft.SelectedImageIndexes = selectedIndexes;
            await publishStore.UpdateAsync(draft, ct);
            await publishLogStore.AppendAsync(new InstagramPublishLogEntry
            {
                Action = "wa_command_draft_select_images",
                Success = true,
                DraftId = draft.Id,
                Details = $"Indexes={string.Join(",", selectedIndexes)},Total={selected.Count}"
            }, ct);

            var shortId = draft.Id.Length > 8 ? draft.Id[..8] : draft.Id;
            return new[]
            {
                $"Imagens selecionadas no draft {shortId}: {string.Join(", ", selectedIndexes)}.",
                $"Total para publicar: {selected.Count}. Use /ig confirmar {shortId}."
            };
        }

        case "clear_images":
        {
            var target = (command.Argument ?? "ultimo").Trim();
            var (draft, error) = await ResolveInstagramDraftAsync(publishStore, target, ct);
            if (draft is null)
            {
                return new[] { error ?? "Rascunho nao encontrado." };
            }

            draft.ImageUrls = new List<string>();
            draft.SelectedImageIndexes = new List<int>();
            await publishStore.UpdateAsync(draft, ct);
            await publishLogStore.AppendAsync(new InstagramPublishLogEntry
            {
                Action = "wa_command_draft_clear_images",
                Success = true,
                DraftId = draft.Id
            }, ct);

            var shortId = draft.Id.Length > 8 ? draft.Id[..8] : draft.Id;
            return new[] { $"Imagens removidas do draft {shortId}. Adicione novas com /ig imagem {shortId} <url-da-imagem>" };
        }

        case "set_type":
        {
            var parsedType = ParseInstagramTypeCommandInput(command.Argument);
            if (!string.IsNullOrWhiteSpace(parsedType.Error))
            {
                return new[] { parsedType.Error };
            }

            var (draft, error) = await ResolveInstagramDraftAsync(publishStore, parsedType.DraftRef, ct);
            if (draft is null)
            {
                return new[] { error ?? "Rascunho nao encontrado." };
            }

            draft.PostType = parsedType.PostType;
            await publishStore.UpdateAsync(draft, ct);
            await publishLogStore.AppendAsync(new InstagramPublishLogEntry
            {
                Action = "wa_command_draft_set_type",
                Success = true,
                DraftId = draft.Id,
                Details = $"PostType={draft.PostType}"
            }, ct);

            var shortId = draft.Id.Length > 8 ? draft.Id[..8] : draft.Id;
            return new[] { $"Tipo do draft {shortId} atualizado para '{draft.PostType}'." };
        }

        case "format_caption":
        {
            var target = string.IsNullOrWhiteSpace(command.Argument) ? "ultimo" : command.Argument.Trim();
            var (draft, error) = await ResolveInstagramDraftAsync(publishStore, target, ct);
            if (draft is null)
            {
                return new[] { error ?? "Rascunho nao encontrado." };
            }

            var formatted = FormatInstagramCaptionForReadability(draft.Caption);
            SyncDraftCtasFromCaptionIfPresent(draft, formatted);
            formatted = EnsureInstagramCaptionContainsCta(formatted, draft.Ctas);
            if (formatted.Length > 2200)
            {
                formatted = formatted[..2200].TrimEnd() + "...";
            }

            draft.Caption = formatted;
            if (draft.CaptionOptions.Count > 0 && draft.SelectedCaptionIndex >= 1 && draft.SelectedCaptionIndex <= draft.CaptionOptions.Count)
            {
                draft.CaptionOptions[draft.SelectedCaptionIndex - 1] = formatted;
            }

            await publishStore.UpdateAsync(draft, ct);
            await publishLogStore.AppendAsync(new InstagramPublishLogEntry
            {
                Action = "wa_command_draft_format_caption",
                Success = true,
                DraftId = draft.Id,
                Details = $"CaptionLength={draft.Caption.Length}"
            }, ct);

            var shortId = draft.Id.Length > 8 ? draft.Id[..8] : draft.Id;
            return new[] { $"Formatacao aplicada na legenda do draft {shortId}. Use /ig revisar {shortId}." };
        }

        case "pick_caption":
        {
            var parsedPick = ParseInstagramCaptionChoiceInput(command.Argument);
            if (!string.IsNullOrWhiteSpace(parsedPick.Error))
            {
                return new[] { parsedPick.Error };
            }

            var (draft, error) = await ResolveInstagramDraftAsync(publishStore, parsedPick.DraftRef, ct);
            if (draft is null)
            {
                return new[] { error ?? "Rascunho nao encontrado." };
            }

            var options = (draft.CaptionOptions ?? new List<string>())
                .Where(x => !string.IsNullOrWhiteSpace(x))
                .ToList();
            if (options.Count == 0)
            {
                return new[] { "Esse draft nao possui multiplas legendas. Use /ig legenda para editar manualmente." };
            }

            if (parsedPick.OptionNumber < 1 || parsedPick.OptionNumber > options.Count)
            {
                return new[] { $"Legenda {parsedPick.OptionNumber} nao existe. Escolha de 1 a {options.Count}." };
            }

            var selected = options[parsedPick.OptionNumber - 1];
            selected = FormatInstagramCaptionForReadability(selected);
            SyncDraftCtasFromCaptionIfPresent(draft, selected);
            selected = EnsureInstagramCaptionContainsCta(selected, draft.Ctas);
            if (selected.Length > 2200)
            {
                selected = selected[..2200].TrimEnd() + "...";
            }

            draft.Caption = selected;
            draft.CaptionOptions = options;
            draft.SelectedCaptionIndex = parsedPick.OptionNumber;
            await publishStore.UpdateAsync(draft, ct);
            await publishLogStore.AppendAsync(new InstagramPublishLogEntry
            {
                Action = "wa_command_draft_select_caption",
                Success = true,
                DraftId = draft.Id,
                Details = $"Option={parsedPick.OptionNumber},Total={options.Count}"
            }, ct);

            var shortId = draft.Id.Length > 8 ? draft.Id[..8] : draft.Id;
            return new[] { $"Legenda {parsedPick.OptionNumber} selecionada no draft {shortId}. Use /ig revisar {shortId}." };
        }

        case "set_caption":
        {
            var parsedCaption = ParseInstagramCaptionCommandInput(command.Argument);
            if (!string.IsNullOrWhiteSpace(parsedCaption.Error))
            {
                return new[] { parsedCaption.Error };
            }

            var (draft, error) = await ResolveInstagramDraftAsync(publishStore, parsedCaption.DraftRef, ct);
            if (draft is null)
            {
                return new[] { error ?? "Rascunho nao encontrado." };
            }

            var formattedCaption = FormatInstagramCaptionForReadability(parsedCaption.Caption);
            if (formattedCaption.Length > 2200)
            {
                formattedCaption = formattedCaption[..2200].TrimEnd() + "...";
            }

            SyncDraftCtasFromCaptionIfPresent(draft, formattedCaption);
            draft.Caption = EnsureInstagramCaptionContainsCta(formattedCaption, draft.Ctas);
            draft.CaptionOptions = new List<string> { draft.Caption };
            draft.SelectedCaptionIndex = 1;
            await publishStore.UpdateAsync(draft, ct);
            await publishLogStore.AppendAsync(new InstagramPublishLogEntry
            {
                Action = "wa_command_draft_set_caption",
                Success = true,
                DraftId = draft.Id,
                Details = $"CaptionLength={draft.Caption.Length}"
            }, ct);

            var shortId = draft.Id.Length > 8 ? draft.Id[..8] : draft.Id;
            return new[]
            {
                $"Legenda atualizada no draft {shortId}. Use /ig revisar {shortId} para conferir e /ig confirmar {shortId} para publicar."
            };
        }

        case "set_cta":
        {
            var parsedCta = ParseInstagramCtaCommandInput(command.Argument);
            if (!string.IsNullOrWhiteSpace(parsedCta.Error))
            {
                return new[] { parsedCta.Error };
            }

            var (draft, error) = await ResolveInstagramDraftAsync(publishStore, parsedCta.DraftRef, ct);
            if (draft is null)
            {
                return new[] { error ?? "Rascunho nao encontrado." };
            }

            var link = draft.Ctas.FirstOrDefault(c => !string.IsNullOrWhiteSpace(c.Link))?.Link
                       ?? ExtractFirstUrl(draft.Caption)
                       ?? ExtractFirstUrl(string.Join(" ", draft.CaptionOptions ?? new List<string>()));
            if (string.IsNullOrWhiteSpace(link))
            {
                return new[] { "Nao foi encontrado link para associar ao CTA. Recrie com um link ou ajuste a legenda com URL." };
            }

            draft.Ctas = parsedCta.Keywords
                .Select(keyword => new InstagramCtaOption
                {
                    Keyword = keyword,
                    Link = link
                })
                .ToList();

            draft.Caption = EnsureInstagramCaptionContainsCta(FormatInstagramCaptionForReadability(draft.Caption), draft.Ctas);
            var captionOptions = draft.CaptionOptions ??= new List<string>();
            if (captionOptions.Count > 0 && draft.SelectedCaptionIndex >= 1 && draft.SelectedCaptionIndex <= captionOptions.Count)
            {
                captionOptions[draft.SelectedCaptionIndex - 1] = draft.Caption;
            }

            await publishStore.UpdateAsync(draft, ct);
            await publishLogStore.AppendAsync(new InstagramPublishLogEntry
            {
                Action = "wa_command_draft_set_cta",
                Success = true,
                DraftId = draft.Id,
                Details = $"Keywords={string.Join(",", parsedCta.Keywords)}"
            }, ct);

            var shortId = draft.Id.Length > 8 ? draft.Id[..8] : draft.Id;
            return new[]
            {
                $"CTA atualizado no draft {shortId}: {string.Join(", ", parsedCta.Keywords)}.\nUse /ig revisar {shortId} e /ig confirmar {shortId}."
            };
        }

        case "review":
        {
            var (draft, error) = await ResolveInstagramDraftAsync(publishStore, command.Argument, ct);
            if (draft is null)
            {
                return new[] { error ?? "Rascunho nao encontrado." };
            }

            return new[] { BuildInstagramDraftReviewMessage(draft) };
        }

        case "confirm":
        {
            var (draft, error) = await ResolveInstagramDraftAsync(publishStore, command.Argument, ct);
            if (draft is null)
            {
                return new[] { error ?? "Rascunho nao encontrado." };
            }

            var publishResult = await PublishInstagramDraftAsync(
                draft.Id,
                settings.InstagramPublish ?? new InstagramPublishSettings(),
                settings.VilaNvidia ?? new VilaNvidiaSettings(),
                settings.Gemini ?? new GeminiSettings(),
                publishStore,
                publishLogStore,
                httpClientFactory,
                mediaStore,
                publicBaseUrl,
                ct);

            if (publishResult.Success)
            {
                return new[] { $"Publicado com sucesso.\nDraft: {draft.Id}\nMediaId: {publishResult.MediaId}" };
            }

            if (publishResult.StatusCode == StatusCodes.Status404NotFound)
            {
                return new[] { "Rascunho nao encontrado." };
            }

            var shortId = draft.Id.Length > 8 ? draft.Id[..8] : draft.Id;
            var isNoImageError = publishResult.Error?.Contains("Sem imagens", StringComparison.OrdinalIgnoreCase) == true;
            var isMediaTypeError = IsInstagramMediaTypeError(publishResult.Error);
            var help = isNoImageError
                ? $"\nDica: /ig imagem {shortId} <url-da-imagem>"
                : isMediaTypeError
                    ? $"\nDica: /ig imagens {shortId} (listar)\nDepois selecione JPG/PNG: /ig imagens {shortId} 1,2\nOu limpe e adicione novas: /ig limpar-imagens {shortId}"
                    : string.Empty;

            return new[] { $"Falha ao publicar.\nDraft: {draft.Id}\nErro: {publishResult.Error ?? "erro desconhecido"}{help}" };
        }

        case "boost_post":
        {
            var parsedBoost = ParseInstagramBoostCommandInput(command.Argument);
            if (!string.IsNullOrWhiteSpace(parsedBoost.Error))
            {
                return new[] { parsedBoost.Error };
            }

            var (draft, error) = await ResolveInstagramDraftAsync(publishStore, parsedBoost.DraftRef, ct);
            if (draft is null)
            {
                return new[] { error ?? "Rascunho nao encontrado." };
            }
            if (string.IsNullOrWhiteSpace(draft.MediaId))
            {
                return new[] { "Esse draft ainda nao foi publicado. Execute /ig confirmar antes de anunciar." };
            }

            var publishSettings = settings.InstagramPublish ?? new InstagramPublishSettings();
            if (string.IsNullOrWhiteSpace(publishSettings.AccessToken) || publishSettings.AccessToken == "********")
            {
                return new[] { "Access token do Instagram nao configurado para criar anuncio." };
            }
            if (string.IsNullOrWhiteSpace(publishSettings.InstagramUserId))
            {
                return new[] { "Instagram user id nao configurado." };
            }

            var url = parsedBoost.LinkUrl;
            if (string.IsNullOrWhiteSpace(url))
            {
                url = draft.Ctas.FirstOrDefault(c => !string.IsNullOrWhiteSpace(c.Link))?.Link ?? ExtractFirstUrl(draft.Caption);
            }
            if (string.IsNullOrWhiteSpace(url))
            {
                return new[] { "Nao foi encontrado link para o anuncio. Envie url=... no comando." };
            }

            var pageId = parsedBoost.PageId;
            if (string.IsNullOrWhiteSpace(pageId))
            {
                pageId = await TryResolvePageIdForInstagramUserAsync(
                    httpClientFactory,
                    publishSettings.GraphBaseUrl,
                    publishSettings.AccessToken!,
                    publishSettings.InstagramUserId!,
                    ct);
            }
            if (string.IsNullOrWhiteSpace(pageId))
            {
                return new[] { "Nao foi possivel descobrir Page ID automaticamente. Envie pagina=<PAGE_ID> no comando." };
            }

            var boostResult = await CreateInstagramBoostAdAsync(
                httpClientFactory,
                publishSettings,
                draft.MediaId!,
                parsedBoost,
                pageId!,
                url,
                ct);

            await publishLogStore.AppendAsync(new InstagramPublishLogEntry
            {
                Action = "wa_command_boost_create",
                Success = boostResult.Success,
                DraftId = draft.Id,
                MediaId = draft.MediaId,
                Error = boostResult.Success ? null : boostResult.Error,
                Details = boostResult.Success
                    ? $"AdAccount={parsedBoost.AdAccountId},Campaign={boostResult.CampaignId},AdSet={boostResult.AdSetId},Ad={boostResult.AdId},Cta={parsedBoost.CtaType}"
                    : $"AdAccount={parsedBoost.AdAccountId},Cta={parsedBoost.CtaType}"
            }, ct);

            if (!boostResult.Success)
            {
                return new[] { $"Falha ao criar anuncio no Meta Ads.\nErro: {boostResult.Error ?? "erro desconhecido"}" };
            }

            return new[]
            {
                $"Anuncio criado em status PAUSED.\nDraft: {draft.Id}\nMediaId: {draft.MediaId}\nCampaignId: {boostResult.CampaignId}\nAdSetId: {boostResult.AdSetId}\nAdId: {boostResult.AdId}\nCTA: {parsedBoost.CtaType}\nURL: {url}"
            };
        }

        default:
            return new[] { "Comando /ig desconhecido.\n" + BuildInstagramCommandHelp() };
    }
}

static async Task<(InstagramPublishDraft? Draft, string? Error)> ResolveInstagramDraftAsync(
    IInstagramPublishStore publishStore,
    string? idOrAlias,
    CancellationToken ct)
{
    var items = await publishStore.ListAsync(ct);
    if (items.Count == 0)
    {
        return (null, "Nenhum rascunho encontrado.");
    }

    var key = idOrAlias?.Trim() ?? string.Empty;
    if (string.IsNullOrWhiteSpace(key) || string.Equals(key, "ultimo", StringComparison.OrdinalIgnoreCase))
    {
        var latest = items.OrderByDescending(x => x.CreatedAt).FirstOrDefault();
        return latest is null ? (null, "Nenhum rascunho encontrado.") : (latest, null);
    }

    if (int.TryParse(key, out var indexRef) && indexRef > 0)
    {
        var ordered = items
            .OrderByDescending(x => x.CreatedAt)
            .ToList();

        if (indexRef <= ordered.Count)
        {
            return (ordered[indexRef - 1], null);
        }

        return (null, $"Indice {indexRef} fora do intervalo. Existem {ordered.Count} rascunhos.");
    }

    var exact = items.FirstOrDefault(x => string.Equals(x.Id, key, StringComparison.OrdinalIgnoreCase));
    if (exact is not null)
    {
        return (exact, null);
    }

    var byPrefix = items
        .Where(x => x.Id.StartsWith(key, StringComparison.OrdinalIgnoreCase))
        .OrderByDescending(x => x.CreatedAt)
        .ToList();

    if (byPrefix.Count == 1)
    {
        return (byPrefix[0], null);
    }

    if (byPrefix.Count > 1)
    {
        return (null, "ID parcial ambiguo. Envie mais caracteres do draft.");
    }

    return (null, $"Rascunho '{key}' nao encontrado.");
}

static string BuildInstagramCommandHelp()
{
    return string.Join('\n', new[]
    {
        "GUIA /ig - Instagram via WhatsApp",
        "",
        "FLUXO PADRAO:",
        "1) /ig criar <produto ou link> cta=BIKE",
        "2) /ig imagem ultimo <url> (se faltar imagem)",
        "3) /ig leg 1 ultimo  (ou /leg 1)",
        "4) /ig formatar ultimo",
        "5) /ig revisar ultimo",
        "6) /ig confirmar ultimo",
        "",
        "FLUXO RAPIDO:",
        "- /ig rapido <produto ou link> cta=BIKE img=https://... tipo=feed|story",
        "",
        "COMANDOS (com descricao):",
        "- /ig criar ... : cria rascunho com legenda, CTA e imagens detectadas.",
        "- /ig rapido ... : cria + tenta publicar automaticamente.",
        "- /ig imagem <id|ultimo> <url1,url2> : adiciona imagens no rascunho.",
        "- /ig imagens <id|ultimo> [1|1,2|2-4] : lista/seleciona quais imagens usar.",
        "- /ig tipo <id|ultimo> feed|story|reel|carrossel : define formato.",
        "- /ig cta <id|ultimo> PALAVRA1,PALAVRA2 : define palavra-chave do CTA.",
        "- /ig leg <numero> <id|ultimo> : escolhe uma das legendas geradas.",
        "- /ig legenda <id|ultimo> <texto> : sobrescreve a legenda manualmente.",
        "- /ig formatar <id|ultimo> : corrige espacos e quebras de linha.",
        "- /ig template <id|ultimo> <1|2|3> : aplica template de legenda.",
        "- /ig templates : lista templates disponiveis.",
        "- /ig revisar <id|ultimo> : mostra resumo do rascunho.",
        "- /ig confirmar <id|ultimo> : publica no Instagram.",
        "- /ig revisar <1|2|3> : atalho por ordem do rascunho mais recente.",
        "- /ig reset [tudo] : limpa estado do chat; com 'tudo' apaga os drafts.",
        "- /ig anunciar ... : cria anuncio (Meta Ads) do post publicado.",
        "- /ig menu : abre menu numerico rapido (1..8).",
        "",
        "ATALHOS:",
        "- /ig ajuda",
        "- /help ig",
        "- /bio",
        "",
        "OBS:",
        "- 'ultimo' sempre aponta para o rascunho mais recente.",
        "- Link clicavel no Instagram: Bio (/bio), DM ou anuncio."
    });
}

static string BuildWhatsAppHelpMessage()
{
    return string.Join('\n', new[]
    {
        "HELP - Menu Principal",
        "",
        "Categorias:",
        "1) Instagram (criacao/publicacao de post)",
        "2) CTA e respostas (comentario/DM)",
        "3) Links e bio (links clicaveis)",
        "4) Anuncios (boost com CTA)",
        "5) Atalhos rapidos (fluxo curto)",
        "",
        "Como usar:",
        "- /help <numero>  (ex.: /help 1)",
        "- Depois de /help, responda apenas 1, 2, 3, 4 ou 5",
        "- /help ig  (atalho para Instagram)",
        "- /help cta | /help links | /help ads | /help rapido",
        "",
        "Comandos base:",
        "- /help  |  \\help  |  /ajuda",
        "- /bio"
    });
}

static string BuildWhatsAppHelpMessageForScope(string scope)
{
    return scope switch
    {
        "instagram" => BuildInstagramCommandHelp(),
        "cta" => BuildWhatsAppCtaHelpMessage(),
        "links" => BuildWhatsAppLinksHelpMessage(),
        "ads" => BuildWhatsAppAdsHelpMessage(),
        "quick" => BuildWhatsAppQuickHelpMessage(),
        _ => BuildWhatsAppHelpMessage()
    };
}

static string BuildWhatsAppCtaHelpMessage()
{
    return string.Join('\n', new[]
    {
        "HELP 2 - CTA e Respostas",
        "",
        "Objetivo:",
        "- Capturar palavra-chave (ex.: BIKE) e entregar link.",
        "",
        "Comandos uteis:",
        "- /ig cta ultimo BIKE",
        "- /ig revisar ultimo",
        "- /ig confirmar ultimo",
        "",
        "Boas praticas:",
        "- Use palavra curta, sem acento e sem espaco.",
        "- Garanta que o link esteja no draft.",
        "- Prefira DM/Bio para link clicavel.",
        "",
        "Voltar ao menu: /help"
    });
}

static string BuildWhatsAppLinksHelpMessage()
{
    return string.Join('\n', new[]
    {
        "HELP 3 - Links e Bio",
        "",
        "Instagram nao permite link clicavel em comentario.",
        "Use estas opcoes:",
        "- /bio  (pagina com links clicaveis)",
        "- DM automatica com o link",
        "- anuncio com CTA (saiba mais/comprar)",
        "",
        "Fluxo recomendado:",
        "1) Definir CTA no post",
        "2) Publicar",
        "3) Entregar link por DM ou /bio",
        "",
        "Voltar ao menu: /help"
    });
}

static string BuildWhatsAppAdsHelpMessage()
{
    return string.Join('\n', new[]
    {
        "HELP 4 - Anuncios (Boost)",
        "",
        "Comando:",
        "- /ig anunciar <id|ultimo> conta=<ad_account_id> cta=SHOP_NOW url=<link>",
        "",
        "Requisitos:",
        "- Post ja publicado (/ig confirmar).",
        "- Token com permissoes de anuncios.",
        "- Conta de anuncios valida.",
        "",
        "Observacao:",
        "- Se a API retornar erro de capability (#3), o app nao tem permissao para esse endpoint.",
        "",
        "Voltar ao menu: /help"
    });
}

static string BuildWhatsAppQuickHelpMessage()
{
    return string.Join('\n', new[]
    {
        "HELP 5 - Atalhos Rapidos",
        "",
        "Criar + publicar:",
        "- /ig rapido <produto ou link> cta=BIKE img=https://... tipo=feed",
        "",
        "Menu por numero:",
        "- /ig menu",
        "- Responda 1..8 para a acao desejada",
        "",
        "Fluxo com mais controle:",
        "- /ig criar ...",
        "- /ig revisar ultimo",
        "- /ig confirmar ultimo",
        "",
        "Voltar ao menu: /help"
    });
}

static string BuildInstagramMenuMessage()
{
    return string.Join('\n', new[]
    {
        "MENU /ig (responda so com o numero):",
        "1) Revisar ultimo rascunho",
        "2) Confirmar/publicar ultimo",
        "3) Formatar legenda do ultimo",
        "4) Aplicar template 1 no ultimo",
        "5) Aplicar template 2 no ultimo",
        "6) Aplicar template 3 no ultimo",
        "7) Listar templates",
        "8) Ver ajuda do Instagram",
        "",
        "Validade: 15 minutos para este chat."
    });
}

#pragma warning disable CS8321
static string BuildPublicLinkConverterPageHtml(PublicLinkConverterViewModel model, string currentUrl)
{
    var input = System.Net.WebUtility.HtmlEncode(model.Input ?? string.Empty);
    var current = System.Net.WebUtility.HtmlEncode(currentUrl);
    var hasInput = !string.IsNullOrWhiteSpace(model.Input);
    var sb = new StringBuilder();
    sb.AppendLine("<!doctype html>");
    sb.AppendLine("<html lang=\"pt-BR\">");
    sb.AppendLine("<head>");
    sb.AppendLine("  <meta charset=\"utf-8\" />");
    sb.AppendLine("  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />");
    sb.AppendLine("  <title>Conversor Inteligente de Links - Rei das Ofertas</title>");
    sb.AppendLine("  <meta name=\"robots\" content=\"noindex,nofollow\" />");
    sb.AppendLine("  <style>");
    sb.AppendLine("    @import url('https://fonts.googleapis.com/css2?family=Manrope:wght@400;600;700&family=Sora:wght@600;700&display=swap');");
    sb.AppendLine("    :root{--bg:#f8f5f0;--bg2:#eef7ff;--card:#ffffff;--line:#e6e0d6;--text:#0f172a;--muted:#55637a;--brand:#ff7a18;--brand2:#0ea5a4;--brandText:#ffffff;--accent:#0f172a;--accentText:#ffffff;--ok:#0f766e;--warn:#b42318;--chip:#eef9f7;--shadow:0 20px 50px rgba(15,23,42,.08)}");
    sb.AppendLine("    *{box-sizing:border-box}");
    sb.AppendLine("    body{margin:0;color:var(--text);font-family:'Manrope','Sora',sans-serif;background:radial-gradient(900px 520px at -10% -20%,#ffe1c5 0%,rgba(255,225,197,0) 70%),radial-gradient(700px 400px at 110% 10%,#cfefff 0%,rgba(207,239,255,0) 60%),linear-gradient(180deg,#fbfbfb 0%,#f6f2ec 100%)}");
    sb.AppendLine("    .wrap{max-width:1120px;margin:0 auto;padding:28px 16px 64px}");
    sb.AppendLine("    .hero{position:relative;padding:26px;border:1px solid var(--line);border-radius:22px;background:linear-gradient(135deg,#ffffff 0%,#fff4e6 40%,#eff9ff 100%);box-shadow:var(--shadow);overflow:hidden}");
    sb.AppendLine("    .hero:after{content:'';position:absolute;right:-80px;top:-60px;width:220px;height:220px;background:radial-gradient(circle,#ffd1a8 0%,rgba(255,209,168,0) 70%);opacity:.8}");
    sb.AppendLine("    .badge{display:inline-flex;align-items:center;gap:6px;padding:6px 12px;border-radius:999px;background:#fff2e2;color:#a14a08;font-size:.78rem;font-weight:800;text-transform:uppercase;letter-spacing:.08em}");
    sb.AppendLine("    h1{margin:12px 0 6px;font-size:1.7rem;line-height:1.2;font-family:'Sora',sans-serif}");
    sb.AppendLine("    .subtitle{margin:0;color:var(--muted);max-width:760px;font-size:.98rem}");
    sb.AppendLine("    .form{margin-top:16px;display:flex;gap:12px;flex-wrap:wrap}");
    sb.AppendLine("    .form input{flex:1;min-width:260px;padding:14px 14px;border-radius:14px;border:1px solid var(--line);font-size:1rem;background:#fff;box-shadow:inset 0 0 0 1px rgba(255,255,255,.3)}");
    sb.AppendLine("    .form button{padding:14px 20px;border:0;border-radius:14px;background:linear-gradient(135deg,#ff7a18 0%,#ffb25b 100%);color:var(--brandText);font-weight:800;cursor:pointer;box-shadow:0 10px 20px rgba(255,122,24,.28)}");
    sb.AppendLine("    .metaRow{margin-top:12px;display:flex;gap:10px;flex-wrap:wrap;align-items:center}");
    sb.AppendLine("    .hint{font-size:.82rem;color:var(--muted)}");
    sb.AppendLine("    .copyMini{border:1px solid var(--line);background:#fff;padding:6px 10px;border-radius:10px;cursor:pointer;font-weight:700;color:#2f4768}");
    sb.AppendLine("    .chipRow{margin-top:12px;display:flex;flex-wrap:wrap;gap:8px}");
    sb.AppendLine("    .chip{padding:6px 10px;border-radius:999px;background:#f0f6ff;color:#1f3760;font-size:.78rem;font-weight:700}");
    sb.AppendLine("    .panel{margin-top:16px;padding:16px 18px;border-radius:16px;border:1px solid var(--line);background:var(--card);box-shadow:var(--shadow)}");
    sb.AppendLine("    .status{font-weight:800;font-family:'Sora',sans-serif}");
    sb.AppendLine("    .status.ok{color:var(--ok)}");
    sb.AppendLine("    .status.error{color:var(--warn)}");
    sb.AppendLine("    .steps{margin:10px 0 0;padding-left:18px;color:var(--muted);line-height:1.6;font-size:.95rem}");
    sb.AppendLine("    .result{margin-top:18px;display:grid;grid-template-columns:minmax(260px,380px) 1fr;gap:16px}");
    sb.AppendLine("    .media{border:1px solid var(--line);border-radius:18px;background:#fff;min-height:260px;display:flex;align-items:center;justify-content:center;overflow:hidden;box-shadow:var(--shadow)}");
    sb.AppendLine("    .media img{width:100%;height:100%;object-fit:cover;display:block}");
    sb.AppendLine("    .media .empty{padding:16px;color:var(--muted);font-size:.9rem;text-align:center}");
    sb.AppendLine("    .card{border:1px solid var(--line);border-radius:18px;background:#fff;padding:18px;box-shadow:var(--shadow)}");
    sb.AppendLine("    .topLine{display:flex;gap:8px;flex-wrap:wrap;align-items:center}");
    sb.AppendLine("    .store{display:inline-flex;align-items:center;padding:6px 12px;border-radius:999px;background:var(--chip);color:#0f6c59;font-size:.78rem;font-weight:800}");
    sb.AppendLine("    .aff{display:inline-flex;align-items:center;padding:6px 12px;border-radius:999px;background:#f1f5f9;color:#1f2a3a;font-size:.78rem;font-weight:800}");
    sb.AppendLine("    .pill{display:inline-flex;align-items:center;padding:6px 12px;border-radius:999px;background:#fff4e6;color:#a14a08;font-size:.78rem;font-weight:800}");
    sb.AppendLine("    .title{margin-top:10px;font-size:1.26rem;line-height:1.36;font-weight:800}");
    sb.AppendLine("    .desc{margin-top:8px;color:var(--muted);line-height:1.5}");
    sb.AppendLine("    .priceGrid{margin-top:14px;display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}");
    sb.AppendLine("    .stat{border:1px solid var(--line);border-radius:14px;padding:12px;background:#fff;display:flex;flex-direction:column;gap:6px}");
    sb.AppendLine("    .stat.main{grid-column:span 2;background:linear-gradient(135deg,#fff1e1 0%,#fff 55%)}");
    sb.AppendLine("    .stat-label{font-size:.78rem;text-transform:uppercase;letter-spacing:.12em;color:#7a8699;font-weight:800}");
    sb.AppendLine("    .stat-value{font-size:1.2rem;font-weight:800;color:#0f172a}");
    sb.AppendLine("    .stat-sub{font-size:.85rem;color:var(--muted)}");
    sb.AppendLine("    .meta{margin-top:10px;font-size:.84rem;color:var(--muted)}");
    sb.AppendLine("    .actions{margin-top:14px;display:flex;gap:10px;flex-wrap:wrap}");
    sb.AppendLine("    .btn{display:inline-flex;align-items:center;justify-content:center;text-decoration:none;padding:12px 14px;border-radius:12px;font-weight:800;border:0;cursor:pointer}");
    sb.AppendLine("    .btn.buy{background:linear-gradient(135deg,#0ea5a4 0%,#12c5b7 100%);color:#fff;box-shadow:0 10px 20px rgba(14,165,164,.25)}");
    sb.AppendLine("    .btn.secondary{background:#0f172a;color:#fff}");
    sb.AppendLine("    .btn.ghost{background:#f4f6fb;color:#1f2a3a;border:1px solid var(--line)}");
    sb.AppendLine("    .urlGrid{margin-top:14px;display:grid;gap:10px}");
    sb.AppendLine("    .urlRow{display:grid;grid-template-columns:1fr auto;gap:8px;align-items:start}");
    sb.AppendLine("    textarea.urlbox{width:100%;min-height:56px;resize:vertical;padding:10px 12px;border:1px dashed var(--line);border-radius:12px;background:#fbfdff;font-family:Consolas,'Courier New',monospace;font-size:.8rem;line-height:1.34;color:#1f2a3a}");
    sb.AppendLine("    .copyBtn{padding:10px 12px;border:1px solid var(--line);background:#fff;border-radius:12px;font-weight:800;color:#264467;cursor:pointer;min-width:110px}");
    sb.AppendLine("    .toast{margin-top:10px;font-size:.84rem;color:#1f5f42;font-weight:700;min-height:18px}");
    sb.AppendLine("    @media (max-width:860px){");
    sb.AppendLine("      .result{grid-template-columns:1fr}");
    sb.AppendLine("      .media{min-height:220px}");
    sb.AppendLine("    }");
    sb.AppendLine("    @media (max-width:680px){");
    sb.AppendLine("      .priceGrid{grid-template-columns:1fr}");
    sb.AppendLine("      .stat.main{grid-column:span 1}");
    sb.AppendLine("      .urlRow{grid-template-columns:1fr}");
    sb.AppendLine("      .copyBtn{width:100%}");
    sb.AppendLine("    }");
    sb.AppendLine("  </style>");
    sb.AppendLine("</head>");
    sb.AppendLine("<body><main class=\"wrap\">");
    sb.AppendLine("  <section class=\"hero\">");
    sb.AppendLine("    <span class=\"badge\">Ferramenta oficial de conversao</span>");
    sb.AppendLine("    <h1>Conversor de Link de Afiliado</h1>");
    sb.AppendLine("    <p class=\"subtitle\">Cole qualquer link de oferta. O sistema converte, valida e gera um link pronto para compartilhar com sua audiencia.</p>");
    sb.AppendLine("    <form class=\"form\" method=\"get\" action=\"/conversor\">");
    sb.AppendLine($"      <input id=\"converterInput\" name=\"url\" value=\"{input}\" placeholder=\"Ex: https://amzn.to/...\" autocomplete=\"off\" />");
    sb.AppendLine("      <button type=\"submit\">Converter agora</button>");
    sb.AppendLine("    </form>");
    sb.AppendLine("    <div class=\"metaRow\">");
    sb.AppendLine($"      <span class=\"hint\">Link desta pagina: {current}</span>");
    sb.AppendLine("      <button type=\"button\" class=\"copyMini\" onclick=\"copyById('pageLink','Link da pagina')\">Copiar pagina</button>");
    sb.AppendLine("      <textarea id=\"pageLink\" style=\"display:none;\">");
    sb.AppendLine(current);
    sb.AppendLine("      </textarea>");
    sb.AppendLine("    </div>");
    sb.AppendLine("    <div class=\"chipRow\">");
    sb.AppendLine("      <span class=\"chip\">Amazon</span>");
    sb.AppendLine("      <span class=\"chip\">Shopee</span>");
    sb.AppendLine("      <span class=\"chip\">Shein</span>");
    sb.AppendLine("      <span class=\"chip\">Mercado Livre</span>");
    sb.AppendLine("    </div>");
    sb.AppendLine("  </section>");

    if (!string.IsNullOrWhiteSpace(model.Error))
    {
        sb.AppendLine("  <section class=\"panel\">");
        sb.AppendLine($"    <div class=\"status error\">Falha na conversao</div>");
        sb.AppendLine($"    <div class=\"meta\">{System.Net.WebUtility.HtmlEncode(model.Error)}</div>");
        if (!string.IsNullOrWhiteSpace(model.OriginalUrl))
        {
            sb.AppendLine($"    <div class=\"meta\">URL analisada: {System.Net.WebUtility.HtmlEncode(model.OriginalUrl)}</div>");
        }
        if (!string.IsNullOrWhiteSpace(model.ValidationError))
        {
            sb.AppendLine($"    <div class=\"meta\">Validacao: {System.Net.WebUtility.HtmlEncode(model.ValidationError)}</div>");
        }
        sb.AppendLine("    <ol class=\"steps\">");
        sb.AppendLine("      <li>Confirme se o link abre normalmente no navegador.</li>");
        sb.AppendLine("      <li>Tente o link completo da loja (nao apenas texto sem URL).</li>");
        sb.AppendLine("      <li>Se persistir, envie outro link da mesma oferta.</li>");
        sb.AppendLine("    </ol>");
        sb.AppendLine("  </section>");
    }
    else if (model.Success)
    {
        var image = System.Net.WebUtility.HtmlEncode(model.ImageUrl ?? string.Empty);
        var store = System.Net.WebUtility.HtmlEncode(model.Store ?? "Loja");
        var title = System.Net.WebUtility.HtmlEncode(model.Title ?? "Oferta");
        var price = System.Net.WebUtility.HtmlEncode(model.Price ?? "Preco sob consulta");
        var previousPrice = System.Net.WebUtility.HtmlEncode(model.PreviousPrice ?? string.Empty);
        var desc = System.Net.WebUtility.HtmlEncode(model.Description ?? string.Empty);
        var host = System.Net.WebUtility.HtmlEncode(model.ConversionHost ?? "-");
        var domainHost = System.Net.WebUtility.HtmlEncode(model.DomainHost ?? "-");
        var converted = System.Net.WebUtility.HtmlEncode(model.ConvertedUrl ?? string.Empty);
        var tracked = System.Net.WebUtility.HtmlEncode(model.TrackedUrl ?? string.Empty);
        var correction = System.Net.WebUtility.HtmlEncode(model.CorrectionNote ?? string.Empty);
        var source = System.Net.WebUtility.HtmlEncode(model.DataSource ?? "meta");
        var couponCode = System.Net.WebUtility.HtmlEncode(model.CouponCode ?? string.Empty);
        var couponDesc = System.Net.WebUtility.HtmlEncode(model.CouponDescription ?? string.Empty);
        var couponDisplay = model.HasCoupon
            ? (string.IsNullOrWhiteSpace(model.CouponCode) ? "Cupom ativo" : couponCode)
            : "Sem cupom";
        var couponHint = model.HasCoupon
            ? (string.IsNullOrWhiteSpace(model.CouponDescription) ? "Cupom disponivel para esta loja" : couponDesc)
            : "Se houver cupom, ele aparece no carrinho";
        var previousDisplay = string.IsNullOrWhiteSpace(previousPrice) ? "—" : previousPrice;
        var discountText = model.DiscountPercent.HasValue && model.DiscountPercent.Value > 0
            ? System.Net.WebUtility.HtmlEncode($"{model.DiscountPercent.Value}% OFF")
            : string.Empty;
        var discountDisplay = string.IsNullOrWhiteSpace(discountText) ? "—" : discountText;
        var shareCoupon = model.HasCoupon && !string.IsNullOrWhiteSpace(model.CouponCode)
            ? $"\nCupom: {model.CouponCode}"
            : string.Empty;
        var shareText = $"{(string.IsNullOrWhiteSpace(model.Title) ? "Oferta" : model.Title)} | {(string.IsNullOrWhiteSpace(model.Price) ? "Preco sob consulta" : model.Price)}{shareCoupon}\nCompre aqui: {(string.IsNullOrWhiteSpace(model.TrackedUrl) ? model.ConvertedUrl : model.TrackedUrl)}";
        var shareTextEncoded = System.Net.WebUtility.HtmlEncode(shareText);
        var whatsAppShare = System.Net.WebUtility.HtmlEncode($"https://wa.me/?text={Uri.EscapeDataString(shareText)}");

        sb.AppendLine("  <section class=\"panel\">");
        sb.AppendLine($"    <div class=\"status ok\">Link convertido com sucesso ({(model.IsAffiliated ? "afiliado validado" : "sem validacao de afiliado")})</div>");
        sb.AppendLine("    <div class=\"meta\">Use o botao de compra ou compartilhe o texto pronto com seu publico.</div>");
        sb.AppendLine("  </section>");
        sb.AppendLine("  <section class=\"result\">");
        sb.AppendLine("    <div class=\"media\">");
        if (!string.IsNullOrWhiteSpace(model.ImageUrl))
        {
            sb.AppendLine($"      <img src=\"{image}\" alt=\"Imagem da oferta\" loading=\"lazy\" />");
        }
        else
        {
            sb.AppendLine("      <div class=\"empty\">Sem imagem disponivel para esta oferta.</div>");
        }
        sb.AppendLine("    </div>");
        sb.AppendLine("    <article class=\"card\">");
        sb.AppendLine("      <div class=\"topLine\">");
        sb.AppendLine($"        <span class=\"store\">{store}</span>");
        sb.AppendLine($"        <span class=\"aff\">{(model.IsAffiliated ? "Afiliado confirmado" : "Afiliado sem validacao")}</span>");
        sb.AppendLine($"        <span class=\"pill\">Fonte: {source}</span>");
        sb.AppendLine("      </div>");
        sb.AppendLine($"      <div class=\"title\">{title}</div>");
        sb.AppendLine("      <div class=\"priceGrid\">");
        sb.AppendLine("        <div class=\"stat main\">");
        sb.AppendLine("          <div class=\"stat-label\">Preco atual</div>");
        sb.AppendLine($"          <div class=\"stat-value\">{price}</div>");
        sb.AppendLine($"          <div class=\"stat-sub\">{(model.IsAffiliated ? "Link afiliado confirmado" : "Link sem validacao de afiliado")}</div>");
        sb.AppendLine("        </div>");
        sb.AppendLine("        <div class=\"stat\">");
        sb.AppendLine("          <div class=\"stat-label\">Preco anterior</div>");
        sb.AppendLine($"          <div class=\"stat-value\">{previousDisplay}</div>");
        sb.AppendLine("        </div>");
        sb.AppendLine("        <div class=\"stat\">");
        sb.AppendLine("          <div class=\"stat-label\">Desconto</div>");
        sb.AppendLine($"          <div class=\"stat-value\">{discountDisplay}</div>");
        sb.AppendLine("        </div>");
        sb.AppendLine("        <div class=\"stat\">");
        sb.AppendLine("          <div class=\"stat-label\">Cupom</div>");
        sb.AppendLine($"          <div class=\"stat-value\">{couponDisplay}</div>");
        sb.AppendLine($"          <div class=\"stat-sub\">{couponHint}</div>");
        sb.AppendLine("        </div>");
        sb.AppendLine("      </div>");
        if (!string.IsNullOrWhiteSpace(desc))
        {
            sb.AppendLine($"      <div class=\"desc\">{desc}</div>");
        }
        sb.AppendLine($"      <div class=\"meta\">Destino final: {host}</div>");
        sb.AppendLine($"      <div class=\"meta\">Link publico no seu dominio: {domainHost}</div>");
        sb.AppendLine("      <div class=\"actions\">");
        sb.AppendLine($"        <a class=\"btn buy\" href=\"{tracked}\" target=\"_blank\" rel=\"noopener noreferrer\">Comprar com meu link</a>");
        sb.AppendLine($"        <a class=\"btn secondary\" href=\"{whatsAppShare}\" target=\"_blank\" rel=\"noopener noreferrer\">Compartilhar no WhatsApp</a>");
        sb.AppendLine($"        <a class=\"btn ghost\" href=\"{converted}\" target=\"_blank\" rel=\"noopener noreferrer\">Abrir link convertido</a>");
        sb.AppendLine("      </div>");
        sb.AppendLine("      <div class=\"urlGrid\">");
        sb.AppendLine("        <div class=\"urlRow\">");
        sb.AppendLine($"          <textarea id=\"trackedLink\" class=\"urlbox\" readonly>{tracked}</textarea>");
        sb.AppendLine("          <button type=\"button\" class=\"copyBtn\" onclick=\"copyById('trackedLink','Link publico')\">Copiar link</button>");
        sb.AppendLine("        </div>");
        sb.AppendLine("        <div class=\"urlRow\">");
        sb.AppendLine($"          <textarea id=\"convertedLink\" class=\"urlbox\" readonly>{converted}</textarea>");
        sb.AppendLine("          <button type=\"button\" class=\"copyBtn\" onclick=\"copyById('convertedLink','Link convertido')\">Copiar convertido</button>");
        sb.AppendLine("        </div>");
        sb.AppendLine("        <div class=\"urlRow\">");
        sb.AppendLine($"          <textarea id=\"shareText\" class=\"urlbox\" readonly>{shareTextEncoded}</textarea>");
        sb.AppendLine("          <button type=\"button\" class=\"copyBtn\" onclick=\"copyById('shareText','Texto de divulgacao')\">Copiar texto</button>");
        sb.AppendLine("        </div>");
        sb.AppendLine("      </div>");
        sb.AppendLine("      <div id=\"copyToast\" class=\"toast\"></div>");
        if (!string.IsNullOrWhiteSpace(correction))
        {
            sb.AppendLine($"      <div class=\"meta\">Ajuste aplicado: {correction}</div>");
        }
        sb.AppendLine("    </article>");
        sb.AppendLine("  </section>");
    }
    else if (!hasInput)
    {
        sb.AppendLine("  <section class=\"panel\">");
        sb.AppendLine("    <div class=\"status\">Como usar</div>");
        sb.AppendLine("    <ol class=\"steps\">");
        sb.AppendLine("      <li>Cole o link original de produto no campo acima.</li>");
        sb.AppendLine("      <li>Clique em <strong>Converter agora</strong>.</li>");
        sb.AppendLine("      <li>Copie o <strong>Link publico</strong> ou o <strong>Texto de divulgacao</strong>.</li>");
        sb.AppendLine("      <li>Envie para seu publico em grupos, stories ou bio.</li>");
        sb.AppendLine("    </ol>");
        sb.AppendLine("  </section>");
    }

    sb.AppendLine("  <script>");
    sb.AppendLine("    function showCopyToast(msg){");
    sb.AppendLine("      var el=document.getElementById('copyToast');");
    sb.AppendLine("      if(!el){return;}");
    sb.AppendLine("      el.textContent=msg+' copiado com sucesso.';");
    sb.AppendLine("      clearTimeout(window.__copyToastTimer);");
    sb.AppendLine("      window.__copyToastTimer=setTimeout(function(){el.textContent='';},2200);");
    sb.AppendLine("    }");
    sb.AppendLine("    function copyById(id,label){");
    sb.AppendLine("      var el=document.getElementById(id);");
    sb.AppendLine("      if(!el){return;}");
    sb.AppendLine("      var value=('value' in el)?el.value:el.textContent;");
    sb.AppendLine("      if(!value){return;}");
    sb.AppendLine("      if(navigator.clipboard && window.isSecureContext){");
    sb.AppendLine("        navigator.clipboard.writeText(value).then(function(){showCopyToast(label);}).catch(function(){fallbackCopy(el,label);});");
    sb.AppendLine("      } else {");
    sb.AppendLine("        fallbackCopy(el,label);");
    sb.AppendLine("      }");
    sb.AppendLine("    }");
    sb.AppendLine("    function fallbackCopy(el,label){");
    sb.AppendLine("      if(el.select){el.select();el.setSelectionRange(0,99999);} ");
    sb.AppendLine("      document.execCommand('copy');");
    sb.AppendLine("      showCopyToast(label);");
    sb.AppendLine("    }");
    sb.AppendLine("  </script>");
    sb.AppendLine("</main></body></html>");
    return sb.ToString();
}
#pragma warning restore CS8321

static string? NormalizeConverterInputToUrl(string? input)
{
    if (string.IsNullOrWhiteSpace(input))
    {
        return null;
    }

    var raw = input.Trim().Trim('"', '\'');
    var detected = ExtractFirstUrl(raw) ?? raw;
    if (Uri.TryCreate(detected, UriKind.Absolute, out var absolute))
    {
        return absolute.ToString();
    }

    if (Uri.TryCreate($"https://{detected}", UriKind.Absolute, out var withScheme))
    {
        return withScheme.ToString();
    }

    return null;
}

static async Task<string?> TryResolveFinalUrlForMetaAsync(string? url, IHttpClientFactory httpClientFactory, CancellationToken ct)
{
    if (string.IsNullOrWhiteSpace(url))
    {
        return null;
    }

    if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
    {
        return null;
    }

    try
    {
        var client = httpClientFactory.CreateClient("default");
        using var req = new HttpRequestMessage(HttpMethod.Get, uri);
        using var res = await client.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct);
        var finalUri = res.RequestMessage?.RequestUri;
        if (finalUri is null)
        {
            return null;
        }

        return finalUri.ToString();
    }
    catch
    {
        return null;
    }
}

static LinkMetaResult MergeConverterMeta(LinkMetaResult primary, LinkMetaResult secondary)
{
    return new LinkMetaResult
    {
        Title = ChooseBestConverterTitle(primary.Title, secondary.Title),
        Description = ChooseBestConverterDescription(primary.Description, secondary.Description),
        PriceText = FirstNonEmpty(primary.PriceText ?? string.Empty, secondary.PriceText ?? string.Empty),
        Images = (primary.Images ?? new List<string>())
            .Concat(secondary.Images ?? new List<string>())
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList(),
        Videos = (primary.Videos ?? new List<string>())
            .Concat(secondary.Videos ?? new List<string>())
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList()
    };
}

static string ChooseBestConverterTitle(string? preferred, string? fallback)
{
    var candidates = new[] { preferred, fallback }
        .Where(x => !string.IsNullOrWhiteSpace(x))
        .Select(x => NormalizeConverterDisplayText(x))
        .Where(x => !string.IsNullOrWhiteSpace(x))
        .Distinct(StringComparer.OrdinalIgnoreCase)
        .ToList();

    if (candidates.Count == 0)
    {
        return string.Empty;
    }

    var ordered = candidates
        .Select(title => new { Title = title, Score = ScoreConverterTitle(title) })
        .OrderByDescending(x => x.Score)
        .ThenByDescending(x => x.Title.Length)
        .ToList();

    return ordered[0].Title;
}

static string ChooseBestConverterDescription(string? preferred, string? fallback)
{
    var first = NormalizeConverterDisplayText(preferred);
    var second = NormalizeConverterDisplayText(fallback);
    if (string.IsNullOrWhiteSpace(first)) return second;
    if (string.IsNullOrWhiteSpace(second)) return first;
    return second.Length > first.Length ? second : first;
}

static string NormalizeConverterDisplayText(string? value)
{
    var text = System.Net.WebUtility.HtmlDecode(value?.Trim()) ?? string.Empty;
    if (string.IsNullOrWhiteSpace(text) || !LooksLikeMojibake(text))
    {
        return text;
    }

    try
    {
        var repaired = Encoding.UTF8.GetString(Encoding.Latin1.GetBytes(text));
        if (ScoreMojibake(repaired) < ScoreMojibake(text))
        {
            return repaired.Trim();
        }
    }
    catch
    {
    }

    return text;
}

static bool LooksLikeMojibake(string value)
    => value.Contains('Ã') || value.Contains('â') || value.Contains('�') || value.Contains('├');

static int ScoreMojibake(string value)
    => Regex.Matches(value, "[Ãâ�├]", RegexOptions.CultureInvariant).Count;

static int ScoreConverterTitle(string title)
{
    if (string.IsNullOrWhiteSpace(title))
    {
        return 0;
    }

    var score = 0;
    var normalized = title.Trim().ToLowerInvariant();
    if (normalized.StartsWith("http", StringComparison.OrdinalIgnoreCase))
    {
        score -= 60;
    }

    var words = Regex.Matches(normalized, @"[a-z0-9À-ÿ]{2,}", RegexOptions.CultureInvariant).Count;
    score += Math.Min(words * 3, 45);
    score += Math.Min(normalized.Length / 8, 30);

    if (normalized.Contains("home", StringComparison.OrdinalIgnoreCase) ||
        normalized.Contains("inicio", StringComparison.OrdinalIgnoreCase) ||
        normalized.Contains("index", StringComparison.OrdinalIgnoreCase) ||
        normalized.Contains("login", StringComparison.OrdinalIgnoreCase))
    {
        score -= 40;
    }

    if (normalized.Contains("produto", StringComparison.OrdinalIgnoreCase) ||
        normalized.Contains("oferta", StringComparison.OrdinalIgnoreCase) ||
        normalized.Contains("kit", StringComparison.OrdinalIgnoreCase))
    {
        score += 8;
    }

    return score;
}

static string SelectBestConverterImage(IReadOnlyList<string>? images, string? title, string? description)
{
    if (images is null || images.Count == 0)
    {
        return string.Empty;
    }

    var valid = images
        .Where(x => !string.IsNullOrWhiteSpace(x))
        .Select(x => x.Trim())
        .Where(x => Uri.TryCreate(x, UriKind.Absolute, out _))
        .Distinct(StringComparer.OrdinalIgnoreCase)
        .ToList();
    if (valid.Count == 0)
    {
        return string.Empty;
    }

    var keywords = ExtractConverterImageKeywords(title, description);
    var ranked = valid
        .Select(url => new { Url = url, Score = ScoreConverterImage(url, keywords) })
        .OrderByDescending(x => x.Score)
        .ToList();

    return ranked[0].Url;
}

static int ScoreConverterImage(string url, IReadOnlyList<string> keywords)
{
    if (string.IsNullOrWhiteSpace(url))
    {
        return int.MinValue;
    }

    var score = 0;
    var lower = url.ToLowerInvariant();

    if (lower.Contains(".jpg", StringComparison.OrdinalIgnoreCase) ||
        lower.Contains(".jpeg", StringComparison.OrdinalIgnoreCase) ||
        lower.Contains(".png", StringComparison.OrdinalIgnoreCase) ||
        lower.Contains(".webp", StringComparison.OrdinalIgnoreCase))
    {
        score += 120;
    }
    else if (lower.Contains(".gif", StringComparison.OrdinalIgnoreCase))
    {
        score -= 40;
    }

    // Strong boost for product CDN images (known store-specific product URLs)
    if (lower.Contains("mlstatic.com", StringComparison.OrdinalIgnoreCase) &&
        lower.Contains("d_nq_np", StringComparison.OrdinalIgnoreCase))
    {
        score += 200; // ML product image from gallery
    }
    else if (lower.Contains("m.media-amazon.com/images/i/", StringComparison.OrdinalIgnoreCase))
    {
        score += 200; // Amazon product image
        
        // Massively boost actual product images (which contain AC_SL or AC_SX) to beat generic banners
        if (lower.Contains("_ac_sl", StringComparison.OrdinalIgnoreCase) ||
            lower.Contains("_ac_sy", StringComparison.OrdinalIgnoreCase) ||
            lower.Contains("_ac_sx", StringComparison.OrdinalIgnoreCase))
        {
            score += 150;
        }
    }
    else if (lower.Contains("susercontent.com/file/", StringComparison.OrdinalIgnoreCase))
    {
        score += 200; // Shopee product image
    }

    var badTokens = new[] { "logo", "icon", "avatar", "sprite", "placeholder", "favicon", "banner" };
    if (badTokens.Any(t => lower.Contains(t, StringComparison.OrdinalIgnoreCase)))
    {
        score -= 120;
    }

    if (lower.Contains("product", StringComparison.OrdinalIgnoreCase) ||
        lower.Contains("produto", StringComparison.OrdinalIgnoreCase) ||
        lower.Contains("item", StringComparison.OrdinalIgnoreCase))
    {
        score += 22;
    }

    foreach (var keyword in keywords.Take(5))
    {
        if (lower.Contains(keyword, StringComparison.OrdinalIgnoreCase))
        {
            score += 15;
        }
    }

    var widthMatch = Regex.Match(lower, @"(?:\?|&)(?:w|width)=(?<v>\d{1,4})", RegexOptions.CultureInvariant);
    if (widthMatch.Success && int.TryParse(widthMatch.Groups["v"].Value, out var width) && width > 0 && width <= 180)
    {
        score -= 45;
    }
    var heightMatch = Regex.Match(lower, @"(?:\?|&)(?:h|height)=(?<v>\d{1,4})", RegexOptions.CultureInvariant);
    if (heightMatch.Success && int.TryParse(heightMatch.Groups["v"].Value, out var height) && height > 0 && height <= 180)
    {
        score -= 45;
    }

    return score;
}

static List<string> ExtractConverterImageKeywords(string? title, string? description)
{
    var text = $"{title} {description}".ToLowerInvariant();
    if (string.IsNullOrWhiteSpace(text))
    {
        return new List<string>();
    }

    var stop = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "para","com","sem","de","da","do","das","dos","e","em","na","no","um","uma","por","pra","pro",
        "the","and","for","with","from","this","that","produto","oferta","link","loja","comprar","preco"
    };

    return Regex.Matches(text, @"[a-z0-9À-ÿ]{4,}", RegexOptions.CultureInvariant)
        .Select(m => m.Value.Trim())
        .Where(x => !stop.Contains(x))
        .Distinct(StringComparer.OrdinalIgnoreCase)
        .Take(8)
        .ToList();
}

static string ExtractPriceFromText(string? text)
{
    if (string.IsNullOrWhiteSpace(text))
    {
        return string.Empty;
    }

    var match = Regex.Match(
        text,
        @"(R\$\s?\d{1,3}(?:\.\d{3})*(?:,\d{2})?|\d{1,3}(?:\.\d{3})*,\d{2}\s?(?:reais|BRL))",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    return match.Success ? match.Value.Trim() : string.Empty;
}

static string BuildBioLinksPageHtml(
    IReadOnlyList<BioLinkItem> items,
    string currentUrl,
    BioHubSettings settings,
    string source,
    string? campaign)
{
    var sb = new StringBuilder();
    const string instagramUrl = "https://www.instagram.com/reidasofertasvip/";
    const string telegramUrl = "https://t.me/ReiDasOfertasVIP";
    const string whatsappUrl = "https://chat.whatsapp.com/CYy5lP0VOjTDlefARsexXi";
    var brandName = string.IsNullOrWhiteSpace(settings.BrandName) ? "Rei das Ofertas" : settings.BrandName.Trim();
    var headline = string.IsNullOrWhiteSpace(settings.Headline) ? "Achadinhos em destaque" : settings.Headline.Trim();
    var subheadline = string.IsNullOrWhiteSpace(settings.Subheadline) ? "Toque no botao para abrir a oferta." : settings.Subheadline.Trim();
    var buttonLabel = string.IsNullOrWhiteSpace(settings.ButtonLabel) ? "Abrir oferta" : settings.ButtonLabel.Trim();
    var whatsAppSymbol = GetBioChannelBadgeHtml("whatsapp");
    var telegramSymbol = GetBioChannelBadgeHtml("telegram");
    var instagramSymbol = GetBioChannelBadgeHtml("instagram");
    var catalogSymbol = GetBioChannelBadgeHtml("catalogo");
    var catalogUrl = currentUrl;
    var converterUrl = currentUrl;
    if (Uri.TryCreate(currentUrl, UriKind.Absolute, out var currentUri))
    {
        catalogUrl = $"{currentUri.GetLeftPart(UriPartial.Authority)}/catalogo";
        var primaryHost = currentUri.Host.StartsWith("bio.", StringComparison.OrdinalIgnoreCase)
            ? currentUri.Host["bio.".Length..]
            : currentUri.Host;
        converterUrl = $"{currentUri.Scheme}://{primaryHost}/conversor";
    }
    var converterSymbol = GetBioChannelBadgeHtml("conversor");
    var detailBaseUrl = converterUrl;
    if (detailBaseUrl.EndsWith("/conversor", StringComparison.OrdinalIgnoreCase))
    {
        detailBaseUrl = detailBaseUrl[..^"/conversor".Length];
    }
    var featuredItems = items.Take(3).ToList();
    var additionalItems = items.Skip(3).ToList();
    sb.AppendLine("<!doctype html>");
    sb.AppendLine("<html lang=\"pt-BR\">");
    sb.AppendLine("<head>");
    sb.AppendLine("  <meta charset=\"utf-8\" />");
    sb.AppendLine("  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />");
    sb.AppendLine($"  <title>{System.Net.WebUtility.HtmlEncode(brandName)} - Links</title>");
    sb.AppendLine("  <style>");
    sb.AppendLine("    :root {");
    sb.AppendLine("      --bg: #020617; /* Slate-950 */");
    sb.AppendLine("      --card: rgba(15, 23, 42, 0.7); /* Slate-900 with transparency */");
    sb.AppendLine("      --line: rgba(196, 164, 104, 0.2); /* Gold trace */");
    sb.AppendLine("      --gold: #c4a468;");
    sb.AppendLine("      --text: #f8fafc;");
    sb.AppendLine("      --muted: #94a3b8;");
    sb.AppendLine("      --btn: #c4a468;");
    sb.AppendLine("      --btnText: #020617;");
    sb.AppendLine("    }");
    sb.AppendLine("    * { box-sizing: border-box; }");
    sb.AppendLine("    body { margin: 0; font-family: 'Segoe UI', Tahoma, sans-serif; background: var(--bg); color: var(--text); background-attachment: fixed; }");
    sb.AppendLine("    .wrap { max-width: 600px; margin: 0 auto; padding: 40px 16px 80px; }");
    sb.AppendLine("    .head { text-align: center; margin-bottom: 40px; padding: 20px; border-radius: 20px; background: radial-gradient(circle at center, rgba(196,164,104,0.1) 0%, transparent 70%); }");
    sb.AppendLine("    .logo { width: 100px; height: 100px; margin: 0 auto 20px; border-radius: 50%; border: 2px solid var(--gold); padding: 5px; box-shadow: 0 0 20px rgba(196,164,104,0.3); }");
    sb.AppendLine("    h1 { margin: 0 0 8px; font-size: 1.6rem; color: var(--gold); letter-spacing: 1px; text-transform: uppercase; font-weight: 800; }");
    sb.AppendLine("    p { margin: 0; color: var(--muted); font-size: 0.95rem; }");
    sb.AppendLine("    .hero-sub { margin-top: 10px; max-width: 440px; margin-left: auto; margin-right: auto; line-height: 1.5; }");
    sb.AppendLine("    .quick-links { display: grid; gap: 12px; margin: 24px 0 32px; }");
    sb.AppendLine("    .quick-link { display: flex; align-items: center; justify-content: space-between; gap: 12px; border: 1px solid var(--line); border-radius: 18px; background: linear-gradient(135deg, rgba(15, 23, 42, 0.92), rgba(30, 41, 59, 0.75)); padding: 16px 18px; text-decoration: none; color: inherit; transition: all .3s ease; }");
    sb.AppendLine("    .quick-link:hover { border-color: var(--gold); transform: translateY(-2px); box-shadow: 0 14px 28px rgba(0,0,0,.28); }");
    sb.AppendLine("    .quick-link strong { display: flex; align-items: center; gap: 10px; color: var(--text); font-size: 1rem; margin-bottom: 4px; }");
    sb.AppendLine("    .quick-link span { color: var(--muted); font-size: .88rem; }");
    sb.AppendLine("    .quick-link em { color: var(--gold); font-style: normal; font-weight: 800; font-size: .85rem; text-transform: uppercase; letter-spacing: .08em; }");
    sb.AppendLine("    .section-title { margin: 26px 0 14px; color: var(--gold); font-size: 1rem; font-weight: 800; letter-spacing: .08em; text-transform: uppercase; }");
    sb.AppendLine("    .card { position: relative; border: 1px solid var(--line); border-radius: 18px; background: var(--card); backdrop-filter: blur(10px); -webkit-backdrop-filter: blur(10px); padding: 16px; margin-bottom: 16px; transition: all 0.3s ease; display: block; text-decoration: none; color: inherit; }");
    sb.AppendLine("    .card:hover { border-color: var(--gold); transform: translateY(-3px); box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.5), 0 0 15px rgba(196,164,104,0.1); }");
    sb.AppendLine("    .card-media { width: 100%; aspect-ratio: 16 / 10; border-radius: 14px; overflow: hidden; background: linear-gradient(135deg, rgba(15,23,42,.95), rgba(30,41,59,.75)); border: 1px solid rgba(255,255,255,.06); margin-bottom: 14px; display:flex; align-items:center; justify-content:center; }");
    sb.AppendLine("    .card-media img { width: 100%; height: 100%; object-fit: contain; display:block; background: rgba(2,6,23,.92); }");
    sb.AppendLine("    .title { display: flex; align-items: center; gap: 10px; font-weight: 700; font-size: 1.1rem; line-height: 1.4; color: var(--gold); margin-bottom: 4px; }");
    sb.AppendLine("    .label-badge { display: inline-flex; align-items: center; justify-content: center; width: 34px; height: 34px; border-radius: 999px; border: 1px solid rgba(255,255,255,.12); font-size: 1rem; font-weight: 900; line-height: 1; box-shadow: inset 0 1px 0 rgba(255,255,255,.08); flex: 0 0 auto; }");
    sb.AppendLine("    .badge-whatsapp { background: linear-gradient(135deg, rgba(34,197,94,.28), rgba(21,128,61,.18)); color: #86efac; border-color: rgba(34,197,94,.35); }");
    sb.AppendLine("    .badge-telegram { background: linear-gradient(135deg, rgba(56,189,248,.28), rgba(14,116,144,.18)); color: #7dd3fc; border-color: rgba(56,189,248,.35); }");
    sb.AppendLine("    .badge-instagram { background: linear-gradient(135deg, rgba(244,114,182,.24), rgba(168,85,247,.18)); color: #f9a8d4; border-color: rgba(244,114,182,.35); }");
    sb.AppendLine("    .badge-catalogo { background: linear-gradient(135deg, rgba(196,164,104,.28), rgba(133,77,14,.2)); color: #f5deb3; border-color: rgba(196,164,104,.38); }");
    sb.AppendLine("    .badge-lightning { display: inline-block; background: #e11d48; color: white; padding: 4px 10px; border-radius: 8px; font-size: 0.75rem; font-weight: 900; text-transform: uppercase; margin-bottom: 10px; animation: pulse-red 2s infinite; }");
    sb.AppendLine("    .badge-offer-amazon { background: linear-gradient(135deg, rgba(251,191,36,.24), rgba(180,83,9,.18)); color: #fde68a; border-color: rgba(251,191,36,.35); }");
    sb.AppendLine("    .badge-offer-shopee { background: linear-gradient(135deg, rgba(249,115,22,.24), rgba(194,65,12,.18)); color: #fdba74; border-color: rgba(249,115,22,.35); }");
    sb.AppendLine("    .badge-offer-ml { background: linear-gradient(135deg, rgba(250,204,21,.22), rgba(59,130,246,.16)); color: #fde68a; border-color: rgba(250,204,21,.32); }");
    sb.AppendLine("    .badge-offer-magalu { background: linear-gradient(135deg, rgba(59,130,246,.24), rgba(29,78,216,.18)); color: #93c5fd; border-color: rgba(59,130,246,.35); }");
    sb.AppendLine("    .badge-offer-default { background: linear-gradient(135deg, rgba(148,163,184,.22), rgba(71,85,105,.18)); color: #cbd5e1; border-color: rgba(148,163,184,.30); }");
    sb.AppendLine("    .meta { color: var(--muted); font-size: 0.85rem; display: flex; gap: 10px; align-items: center; }");
    sb.AppendLine("    .btn { display: block; width: 100%; text-align: center; margin-top: 14px; background: var(--btn); color: var(--btnText); text-decoration: none; padding: 12px; border-radius: 12px; font-weight: 800; text-transform: uppercase; letter-spacing: 0.5px; }");
    sb.AppendLine("    @keyframes pulse-red { 0% { box-shadow: 0 0 0 0 rgba(225, 29, 72, 0.7); } 70% { box-shadow: 0 0 0 10px rgba(225, 29, 72, 0); } 100% { box-shadow: 0 0 0 0 rgba(225, 29, 72, 0); } }");
    sb.AppendLine("    .coupon-tag { display: inline-flex; align-items: center; gap: 4px; background: rgba(196, 164, 104, 0.15); color: var(--gold); padding: 4px 10px; border-radius: 8px; font-size: 0.75rem; font-weight: 800; margin-top: 8px; border: 1px solid rgba(196, 164, 104, 0.3); }");
    sb.AppendLine("    .empty { padding: 30px; border: 1px dashed var(--line); border-radius: 20px; color: var(--muted); text-align: center; }");
    sb.AppendLine("    .foot { margin-top: 40px; text-align: center; font-size: 0.8rem; color: var(--muted); }");
    sb.AppendLine("  </style>");
    sb.AppendLine("  <script>");
    sb.AppendLine("    function updateCountdowns() {");
    sb.AppendLine("        const now = new Date().getTime();");
    sb.AppendLine("        document.querySelectorAll('[data-expiry]').forEach(el => {");
    sb.AppendLine("            const expiryStr = el.getAttribute('data-expiry');");
    sb.AppendLine("            if (!expiryStr) return;");
    sb.AppendLine("            const expiry = new Date(expiryStr).getTime();");
    sb.AppendLine("            const diff = expiry - now;");
    sb.AppendLine("            if (diff <= 0) {");
    sb.AppendLine("                el.innerHTML = 'Oferta Expirada';");
    sb.AppendLine("                el.style.animation = 'none'; el.style.background = '#444';");
    sb.AppendLine("                return;");
    sb.AppendLine("            }");
    sb.AppendLine("            const h = Math.floor(diff / 3600000);");
    sb.AppendLine("            const m = Math.floor((diff % 3600000) / 60000);");
    sb.AppendLine("            const s = Math.floor((diff % 60000) / 1000);");
    sb.AppendLine("            el.innerHTML = `⚡ ${h}h ${m}m ${s}s`;");
    sb.AppendLine("        });");
    sb.AppendLine("    }");
    sb.AppendLine("    function localizePublishedAt() {");
    sb.AppendLine("        document.querySelectorAll('[data-published-at]').forEach(el => {");
    sb.AppendLine("            const iso = el.getAttribute('data-published-at');");
    sb.AppendLine("            if (!iso) return;");
    sb.AppendLine("            const dt = new Date(iso);");
    sb.AppendLine("            if (Number.isNaN(dt.getTime())) return;");
    sb.AppendLine("            const formatted = dt.toLocaleString(undefined, { day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit' });");
    sb.AppendLine("            el.textContent = `Publicado em ${formatted}`;");
    sb.AppendLine("        });");
    sb.AppendLine("    }");
    sb.AppendLine("    function getAnalyticsId(key, prefix) {");
    sb.AppendLine("        try { const existing = localStorage.getItem(key); if (existing) return existing; const created = `${prefix}_${Math.random().toString(36).slice(2)}_${Date.now().toString(36)}`; localStorage.setItem(key, created); return created; } catch { return `${prefix}_${Math.random().toString(36).slice(2)}_${Date.now().toString(36)}`; }");
    sb.AppendLine("    }");
    sb.AppendLine("    function getSessionId() {");
    sb.AppendLine("        try { const existing = sessionStorage.getItem('ard_session_id'); if (existing) return existing; const created = `sess_${Math.random().toString(36).slice(2)}_${Date.now().toString(36)}`; sessionStorage.setItem('ard_session_id', created); return created; } catch { return `sess_${Math.random().toString(36).slice(2)}_${Date.now().toString(36)}`; }");
    sb.AppendLine("    }");
    sb.AppendLine("    function getScrollDepth() { const doc = document.documentElement; const scrollTop = window.scrollY || doc.scrollTop || 0; const height = Math.max((doc.scrollHeight || 0) - window.innerHeight, 1); return Math.max(0, Math.min(100, Math.round((scrollTop / height) * 100))); }");
    sb.AppendLine("    function getUtmContext() { const params = new URLSearchParams(window.location.search); return { utmSource: params.get('utm_source'), utmMedium: params.get('utm_medium'), utmCampaign: params.get('utm_campaign'), utmContent: params.get('utm_content'), utmTerm: params.get('utm_term') }; }");
    sb.AppendLine("    function buildBioPayload(targetUrl, source, eventType) {");
    sb.AppendLine("        const utm = getUtmContext();");
    sb.AppendLine("        return { TargetUrl: targetUrl, Source: source || 'bio', Category: 'bio', VisitorId: getAnalyticsId('ard_visitor_id', 'visitor'), SessionId: getSessionId(), EventType: eventType, PageType: 'bio', PageUrl: window.location.href, SourceComponent: source || 'bio', Language: navigator.language || null, Timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || null, ScreenWidth: window.screen?.width || null, ScreenHeight: window.screen?.height || null, ViewportWidth: window.innerWidth || null, ViewportHeight: window.innerHeight || null, ScrollDepth: getScrollDepth(), TimeOnPageMs: Math.max(0, Math.round(performance.now())), UtmSource: utm.utmSource, UtmMedium: utm.utmMedium, UtmCampaign: utm.utmCampaign, UtmContent: utm.utmContent, UtmTerm: utm.utmTerm };");
    sb.AppendLine("    }");
    sb.AppendLine("    function trackBioClick(targetUrl, source, eventType) {");
    sb.AppendLine("        if (!targetUrl) return;");
    sb.AppendLine("        const payload = JSON.stringify(buildBioPayload(targetUrl, source, eventType));");
    sb.AppendLine("        if (navigator.sendBeacon) { const blob = new Blob([payload], { type: 'application/json' }); navigator.sendBeacon('/api/analytics/click', blob); return; }");
    sb.AppendLine("        fetch('/api/analytics/click', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: payload, keepalive: true }).catch(() => {});");
    sb.AppendLine("    }");
    sb.AppendLine("    function trackBioView() { trackBioClick(window.location.href, 'bio_view', 'page_view'); }");
    sb.AppendLine("    document.addEventListener('click', function(e) {");
    sb.AppendLine("        const tracked = e.target.closest('[data-analytics-source]');");
    sb.AppendLine("        if (!tracked) return;");
    sb.AppendLine("        const source = tracked.getAttribute('data-analytics-source') || 'bio';");
    sb.AppendLine("        const target = tracked.getAttribute('data-analytics-target') || tracked.getAttribute('href') || window.location.href;");
    sb.AppendLine("        const eventType = tracked.getAttribute('data-analytics-event') || 'click';");
    sb.AppendLine("        trackBioClick(target, source, eventType);");
    sb.AppendLine("    });");
    sb.AppendLine("    setInterval(updateCountdowns, 1000);");
    sb.AppendLine("    window.onload = function() { updateCountdowns(); localizePublishedAt(); trackBioView(); };");
    sb.AppendLine("  </script>");
    sb.AppendLine("</head>");
    sb.AppendLine("<body><main class=\"wrap\">");
    sb.AppendLine("  <section class=\"head\">");
    sb.AppendLine("    <div class=\"logo\" aria-hidden=\"true\" style=\"display:flex;align-items:center;justify-content:center;font-weight:900;font-size:1.8rem;color:var(--gold);\">VIP</div>");
    sb.AppendLine($"    <h1>{System.Net.WebUtility.HtmlEncode(brandName)}</h1>");
    sb.AppendLine($"    <p>{System.Net.WebUtility.HtmlEncode(headline)}</p>");
    sb.AppendLine($"    <p class=\"hero-sub\">{System.Net.WebUtility.HtmlEncode(subheadline)}</p>");
    sb.AppendLine($"    <p style=\"margin-top:12px; font-size:0.8rem; opacity:0.7;\">Origem: {System.Net.WebUtility.HtmlEncode(source)}</p>");
    sb.AppendLine("  </section>");
    sb.AppendLine("  <section class=\"quick-links\">");
    sb.AppendLine($"    <a class=\"quick-link\" href=\"{System.Net.WebUtility.HtmlEncode(whatsappUrl)}\" target=\"_blank\" rel=\"noopener noreferrer\" data-analytics-source=\"bio_whatsapp\"><div><strong>{whatsAppSymbol} Entrar no WhatsApp</strong><span>Receba ofertas, alertas e os links primeiro por la.</span></div><em>WhatsApp</em></a>");
    sb.AppendLine($"    <a class=\"quick-link\" href=\"{System.Net.WebUtility.HtmlEncode(telegramUrl)}\" target=\"_blank\" rel=\"noopener noreferrer\" data-analytics-source=\"bio_telegram\"><div><strong>{telegramSymbol} Entrar no Telegram</strong><span>Entre no canal para acompanhar alertas e ofertas em tempo real.</span></div><em>Telegram</em></a>");
    sb.AppendLine($"    <a class=\"quick-link\" href=\"{System.Net.WebUtility.HtmlEncode(instagramUrl)}\" target=\"_blank\" rel=\"noopener noreferrer\" data-analytics-source=\"bio_instagram\"><div><strong>{instagramSymbol} Seguir no Instagram</strong><span>Acompanhe reels, stories e posts com os melhores achadinhos.</span></div><em>Instagram</em></a>");
    sb.AppendLine($"    <a class=\"quick-link\" href=\"{System.Net.WebUtility.HtmlEncode(catalogUrl)}\" data-analytics-source=\"bio_catalog\"><div><strong>{catalogSymbol} Abrir Catalogo VIP</strong><span>Veja todas as ofertas publicadas e acesse os links atualizados.</span></div><em>Catalogo</em></a>");
    sb.AppendLine($"    <a class=\"quick-link\" href=\"{System.Net.WebUtility.HtmlEncode(converterUrl)}\" target=\"_blank\" rel=\"noopener noreferrer\" data-analytics-source=\"bio_converter\"><div><strong>{converterSymbol} Abrir Conversor de Links</strong><span>Converta links rapidamente e encontre ofertas prontas para comprar.</span></div><em>Conversor</em></a>");
    sb.AppendLine("  </section>");

    if (featuredItems.Count == 0)
    {
        sb.AppendLine("  <section class=\"empty\">Nenhuma oferta publicada ainda.</section>");
    }
    else
    {
        sb.AppendLine("  <h2 class=\"section-title\">Top 3 ofertas em destaque</h2>");
        foreach (var item in featuredItems)
        {
            var title = System.Net.WebUtility.HtmlEncode(item.Title);
            var link = System.Net.WebUtility.HtmlEncode(item.Link);
            var detailLink = BuildBioDetailLink(detailBaseUrl, item);
            var keyword = System.Net.WebUtility.HtmlEncode(item.Keyword ?? string.Empty);
            var store = System.Net.WebUtility.HtmlEncode(string.IsNullOrWhiteSpace(item.Store) ? "Loja" : item.Store);
            var host = System.Net.WebUtility.HtmlEncode(ExtractHostForDisplay(item.OriginalLink));
            var createdAtIso = item.CreatedAt.UtcDateTime.ToString("O", CultureInfo.InvariantCulture);
            var imageUrl = System.Net.WebUtility.HtmlEncode(item.ImageUrl ?? string.Empty);

            var clickAttr = string.IsNullOrWhiteSpace(detailLink)
                ? string.Empty
                : $" onclick=\"window.location.href='{System.Net.WebUtility.HtmlEncode(detailLink)}'\" style=\"cursor:pointer;\" data-analytics-source=\"bio_top3_card\" data-analytics-target=\"{System.Net.WebUtility.HtmlEncode(detailLink)}\"";
            sb.AppendLine($"  <article class=\"card\"{clickAttr}>");
            if (item.IsLightningDeal)
            {
                var expiryAttr = item.LightningDealExpiry.HasValue 
                    ? $" data-expiry=\"{item.LightningDealExpiry.Value:yyyy-MM-ddTHH:mm:ssZ}\"" 
                    : "";
                sb.AppendLine($"    <div class=\"badge-lightning\"{expiryAttr}>Oferta Relâmpago</div>");
            }
            if (!string.IsNullOrWhiteSpace(item.ImageUrl))
            {
                sb.AppendLine($"    <div class=\"card-media\"><img src=\"{imageUrl}\" alt=\"{title}\" loading=\"lazy\" /></div>");
            }
            sb.AppendLine($"    <div class=\"title\">{GetBioOfferBadgeHtml(item)} <span>{title}</span></div>");
            if (!string.IsNullOrWhiteSpace(item.CouponCode))
            {
                sb.AppendLine($"    <div class=\"coupon-tag\">🎟️ Cupom: <strong>{System.Net.WebUtility.HtmlEncode(item.CouponCode)}</strong></div>");
            }
            if (item.ItemNumber.HasValue)
            {
                sb.AppendLine($"    <div class=\"meta\">Item: <strong>{item.ItemNumber.Value}</strong></div>");
            }
            sb.AppendLine($"    <div class=\"meta\">Loja: <strong>{store}</strong></div>");
            sb.AppendLine($"    <div class=\"meta\"><span data-published-at=\"{createdAtIso}\">Publicado em {createdAtIso}</span>" + (string.IsNullOrWhiteSpace(keyword) ? string.Empty : $" | Palavra: <strong>{keyword}</strong>") + "</div>");
            sb.AppendLine($"    <a class=\"btn\" href=\"{link}\" target=\"_blank\" rel=\"noopener noreferrer\" data-analytics-source=\"bio_top3_buy\" onclick=\"event.stopPropagation();\">{System.Net.WebUtility.HtmlEncode(buttonLabel)}</a>");
            sb.AppendLine($"    <div class=\"meta\" style=\"margin-top:8px;font-size:.8rem;\">Destino: {host}</div>");
            sb.AppendLine("  </article>");
        }

        if (additionalItems.Count > 0)
        {
            sb.AppendLine("  <h2 class=\"section-title\">Mais ofertas publicadas</h2>");
            foreach (var item in additionalItems)
            {
                var title = System.Net.WebUtility.HtmlEncode(item.Title);
                var link = System.Net.WebUtility.HtmlEncode(item.Link);
                var keyword = System.Net.WebUtility.HtmlEncode(item.Keyword ?? string.Empty);
                var store = System.Net.WebUtility.HtmlEncode(string.IsNullOrWhiteSpace(item.Store) ? "Loja" : item.Store);
                var host = System.Net.WebUtility.HtmlEncode(ExtractHostForDisplay(item.OriginalLink));
                var createdAtIso = item.CreatedAt.UtcDateTime.ToString("O", CultureInfo.InvariantCulture);
                var imageUrl = System.Net.WebUtility.HtmlEncode(item.ImageUrl ?? string.Empty);

                sb.AppendLine("  <article class=\"card\" data-analytics-source=\"bio_more_offer\">");
                if (item.IsLightningDeal)
                {
                    var expiryAttr = item.LightningDealExpiry.HasValue
                        ? $" data-expiry=\"{item.LightningDealExpiry.Value:yyyy-MM-ddTHH:mm:ssZ}\""
                        : "";
                    sb.AppendLine($"    <div class=\"badge-lightning\"{expiryAttr}>Oferta Relampago</div>");
                }
                if (!string.IsNullOrWhiteSpace(item.ImageUrl))
                {
                    sb.AppendLine($"    <div class=\"card-media\"><img src=\"{imageUrl}\" alt=\"{title}\" loading=\"lazy\" /></div>");
                }
                sb.AppendLine($"    <div class=\"title\">{GetBioOfferBadgeHtml(item)} <span>{title}</span></div>");
                if (!string.IsNullOrWhiteSpace(item.CouponCode))
                {
                    sb.AppendLine($"    <div class=\"coupon-tag\">Cupom: <strong>{System.Net.WebUtility.HtmlEncode(item.CouponCode)}</strong></div>");
                }
                if (item.ItemNumber.HasValue)
                {
                    sb.AppendLine($"    <div class=\"meta\">Item: <strong>{item.ItemNumber.Value}</strong></div>");
                }
                sb.AppendLine($"    <div class=\"meta\">Loja: <strong>{store}</strong></div>");
                sb.AppendLine($"    <div class=\"meta\"><span data-published-at=\"{createdAtIso}\">Publicado em {createdAtIso}</span>" + (string.IsNullOrWhiteSpace(keyword) ? string.Empty : $" | Palavra: <strong>{keyword}</strong>") + "</div>");
                sb.AppendLine($"    <a class=\"btn\" href=\"{link}\" target=\"_blank\" rel=\"noopener noreferrer\" data-analytics-source=\"bio_more_buy\">{System.Net.WebUtility.HtmlEncode(buttonLabel)}</a>");
                sb.AppendLine($"    <div class=\"meta\" style=\"margin-top:8px;font-size:.8rem;\">Destino: {host}</div>");
                sb.AppendLine("  </article>");
            }
        }
    }

    sb.AppendLine($"  <div class=\"foot\">Link desta pagina: {System.Net.WebUtility.HtmlEncode(currentUrl)}</div>");
    sb.AppendLine("</main></body></html>");
    return sb.ToString();
}

static string GetBioChannelBadgeHtml(string kind)
{
    var normalized = kind.ToLowerInvariant();
    var cssClass = normalized switch
    {
        "whatsapp" => "badge-whatsapp",
        "telegram" => "badge-telegram",
        "instagram" => "badge-instagram",
        "catalogo" => "badge-catalogo",
        "conversor" => "badge-catalogo",
        _ => "badge-offer-default"
    };

    var symbol = normalized switch
    {
        "whatsapp" => "&#128172;",
        "telegram" => "&#9992;&#65039;",
        "instagram" => "&#128247;",
        "catalogo" => "&#128722;",
        "conversor" => "&#128279;",
        _ => "&#10022;"
    };

    return $"<span class=\"label-badge {cssClass}\">{symbol}</span>";
}

static string GetBioOfferBadgeHtml(BioLinkItem item)
{
    if (item.IsLightningDeal)
    {
        return "<span class=\"label-badge badge-lightning\">&#9889;</span>";
    }

    var store = (item.Store ?? string.Empty).Trim().ToLowerInvariant();
    if (store.Contains("amazon", StringComparison.Ordinal))
    {
        return "<span class=\"label-badge badge-offer-amazon\">&#128230;</span>";
    }

    if (store.Contains("shopee", StringComparison.Ordinal))
    {
        return "<span class=\"label-badge badge-offer-shopee\">&#128717;&#65039;</span>";
    }

    if (store.Contains("mercado livre", StringComparison.Ordinal) || store.Contains("mercadolivre", StringComparison.Ordinal))
    {
        return "<span class=\"label-badge badge-offer-ml\">&#128176;</span>";
    }

    if (store.Contains("magalu", StringComparison.Ordinal) || store.Contains("magazine luiza", StringComparison.Ordinal))
    {
        return "<span class=\"label-badge badge-offer-magalu\">&#127970;</span>";
    }

    return "<span class=\"label-badge badge-offer-default\">&#127873;</span>";
}

static string? BuildBioDetailLink(string baseUrl, BioLinkItem item)
{
    var token = item.ItemNumber?.ToString(CultureInfo.InvariantCulture);
    if (string.IsNullOrWhiteSpace(token))
    {
        token = string.IsNullOrWhiteSpace(item.Keyword) ? null : item.Keyword.Trim();
    }

    if (string.IsNullOrWhiteSpace(token))
    {
        return null;
    }

    return $"{baseUrl}/item/{Uri.EscapeDataString(token)}";
}

IReadOnlyList<CatalogOfferItem> BuildCatalogFallbackItemsFromDrafts(
    IReadOnlyList<InstagramPublishDraft> drafts,
    IReadOnlyList<ConversionLogEntry> recentConversions,
    string catalogTarget,
    string? search = null)
{
    var normalizedTarget = CatalogTargets.Normalize(catalogTarget, CatalogTargets.Prod);
    var published = (drafts ?? Array.Empty<InstagramPublishDraft>())
        .Where(d => string.Equals(d.Status, "published", StringComparison.OrdinalIgnoreCase))
        .Where(d => CatalogTargets.Expand(d.CatalogTarget, d.SendToCatalog).Contains(normalizedTarget, StringComparer.OrdinalIgnoreCase))
        .OrderBy(d => d.CreatedAt)
        .ToList();

    var items = new List<CatalogOfferItem>(published.Count);
    var nextItemNumber = 1;
    foreach (var draft in published)
    {
        var offerUrl = ResolveCatalogOfferUrlForFallback(draft, recentConversions);
        if (string.IsNullOrWhiteSpace(offerUrl))
        {
            continue;
        }

        items.Add(new CatalogOfferItem
        {
            ItemNumber = nextItemNumber++,
            DraftId = draft.Id,
            Keyword = BuildKeywordFromDraft(draft, nextItemNumber - 1),
            ProductName = string.IsNullOrWhiteSpace(draft.ProductName) ? $"Item {nextItemNumber - 1}" : draft.ProductName.Trim(),
            Store = ResolveStoreNameFromUrl(offerUrl),
            OfferUrl = offerUrl.Trim(),
            ImageUrl = ResolveBioImageUrl(draft),
            PriceText = ExtractPriceFromText(draft.Caption),
            PostType = NormalizeCatalogPostType(draft.PostType),
            CatalogTarget = normalizedTarget,
            Active = true,
            PublishedAt = draft.CreatedAt,
            UpdatedAt = draft.CreatedAt
        });
    }

    var query = (search ?? string.Empty).Trim();
    if (string.IsNullOrWhiteSpace(query))
    {
        return items.OrderByDescending(x => x.ItemNumber).ToArray();
    }

    IEnumerable<CatalogOfferItem> filtered = items;
    if (int.TryParse(query, out var number))
    {
        filtered = filtered.Where(x => x.ItemNumber == number || x.Keyword.Contains(query, StringComparison.OrdinalIgnoreCase));
    }
    else
    {
        filtered = filtered.Where(x =>
            x.Keyword.Contains(query, StringComparison.OrdinalIgnoreCase) ||
            x.ProductName.Contains(query, StringComparison.OrdinalIgnoreCase) ||
            x.Store.Contains(query, StringComparison.OrdinalIgnoreCase));
    }

    return filtered
        .OrderByDescending(x => x.ItemNumber)
        .ToArray();
}

string BuildKeywordFromDraft(InstagramPublishDraft draft, int itemNumber)
{
    var ctaKeyword = draft.Ctas
        .Select(x => (x.Keyword ?? string.Empty).Trim())
        .FirstOrDefault(x => !string.IsNullOrWhiteSpace(x));
    if (!string.IsNullOrWhiteSpace(ctaKeyword))
    {
        return ctaKeyword.ToUpperInvariant();
    }

    return $"ITEM{itemNumber}";
}

string? ResolveBioImageUrl(InstagramPublishDraft draft)
{
    var selected = draft.SelectedImageIndexes ?? new List<int>();
    if (selected.Count > 0)
    {
        var first = selected[0] - 1;
        if (first >= 0 && first < draft.ImageUrls.Count)
        {
            return draft.ImageUrls[first];
        }
    }

    var firstImage = draft.ImageUrls.FirstOrDefault(x => !string.IsNullOrWhiteSpace(x));
    if (!string.IsNullOrWhiteSpace(firstImage))
    {
        return firstImage;
    }

    if (!string.IsNullOrWhiteSpace(draft.VideoCoverUrl))
    {
        return draft.VideoCoverUrl.Trim();
    }

    return null;
}

string ResolveCatalogOfferUrlForFallback(InstagramPublishDraft draft, IReadOnlyList<ConversionLogEntry> recentConversions)
{
    if (!string.IsNullOrWhiteSpace(draft.OfferUrl) && !IsInternalCatalogUrl(draft.OfferUrl))
    {
        return draft.OfferUrl.Trim();
    }

    var cta = draft.Ctas?.FirstOrDefault(x => !string.IsNullOrWhiteSpace(x.Link))?.Link;
    if (!string.IsNullOrWhiteSpace(cta) && !IsInternalCatalogUrl(cta))
    {
        return cta.Trim();
    }

    if (!string.IsNullOrWhiteSpace(draft.Caption))
    {
        var match = Regex.Match(draft.Caption, @"https?://\S+", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        if (match.Success && !IsInternalCatalogUrl(match.Value))
        {
            return match.Value.Trim();
        }
    }

    var candidates = (recentConversions ?? Array.Empty<ConversionLogEntry>())
        .Where(x => x.Success)
        .Where(x => !string.IsNullOrWhiteSpace(x.ConvertedUrl))
        .Where(x => Math.Abs((x.Timestamp - draft.CreatedAt).TotalMinutes) <= 10)
        .OrderBy(x => Math.Abs((x.Timestamp - draft.CreatedAt).TotalSeconds))
        .ToList();

    if (candidates.Count == 0)
    {
        return string.Empty;
    }

    var preferredStore = ResolveDraftMarketplace(draft);
    var candidate = candidates.FirstOrDefault(x =>
        !string.IsNullOrWhiteSpace(preferredStore) &&
        string.Equals(x.Store, preferredStore, StringComparison.OrdinalIgnoreCase));

    candidate ??= candidates.FirstOrDefault(x =>
        !string.IsNullOrWhiteSpace(draft.ProductName) &&
        x.OriginalUrl.Contains(draft.ProductName, StringComparison.OrdinalIgnoreCase));

    candidate ??= candidates.FirstOrDefault();

    if (candidate is not null)
    {
        return candidate.ConvertedUrl.Trim();
    }

    return string.Empty;
}

string? ResolveDraftMarketplace(InstagramPublishDraft draft)
{
    var urls = new List<string>();
    if (!string.IsNullOrWhiteSpace(draft.OfferUrl))
    {
        urls.Add(draft.OfferUrl);
    }

    urls.AddRange(draft.Ctas?.Select(x => x.Link ?? string.Empty) ?? Enumerable.Empty<string>());
    urls.AddRange(draft.ImageUrls ?? new List<string>());
    if (!string.IsNullOrWhiteSpace(draft.Caption))
    {
        urls.Add(draft.Caption);
    }

    foreach (var raw in urls)
    {
        var value = raw?.Trim();
        if (string.IsNullOrWhiteSpace(value))
        {
            continue;
        }

        if (value.Contains("shopee", StringComparison.OrdinalIgnoreCase))
        {
            return "Shopee";
        }

        if (value.Contains("amazon", StringComparison.OrdinalIgnoreCase) || value.Contains("amzn.", StringComparison.OrdinalIgnoreCase))
        {
            return "Amazon";
        }

        if (value.Contains("mercadolivre", StringComparison.OrdinalIgnoreCase) || value.Contains("meli.", StringComparison.OrdinalIgnoreCase))
        {
            return "Mercado Livre";
        }

        if (value.Contains("magalu", StringComparison.OrdinalIgnoreCase) || value.Contains("magazineluiza", StringComparison.OrdinalIgnoreCase))
        {
            return "Magalu";
        }
    }

    return null;
}

string ResolveEffectiveCatalogOfferUrl(
    CatalogOfferItem? catalogItem,
    InstagramPublishDraft? draft,
    IReadOnlyList<ConversionLogEntry> recentConversions)
{
    var stored = catalogItem?.OfferUrl?.Trim();
    if (!IsInternalCatalogUrl(stored))
    {
        return stored ?? string.Empty;
    }

    if (draft is not null)
    {
        var fallback = ResolveCatalogOfferUrlForFallback(draft, recentConversions);
        if (!string.IsNullOrWhiteSpace(fallback) && !IsInternalCatalogUrl(fallback))
        {
            return fallback.Trim();
        }
    }

    return stored ?? string.Empty;
}

InstagramPublishDraft? FindRelatedDraftForCatalogItem(
    CatalogOfferItem item,
    IReadOnlyDictionary<string, InstagramPublishDraft> draftsById,
    IReadOnlyList<InstagramPublishDraft> drafts)
{
    if (!string.IsNullOrWhiteSpace(item.DraftId) &&
        draftsById.TryGetValue(item.DraftId, out var byId))
    {
        return byId;
    }

    return (drafts ?? Array.Empty<InstagramPublishDraft>())
        .Where(d => string.Equals(d.Status, "published", StringComparison.OrdinalIgnoreCase))
        .Where(d => !string.IsNullOrWhiteSpace(d.ProductName))
        .Where(d => string.Equals(d.ProductName.Trim(), item.ProductName.Trim(), StringComparison.OrdinalIgnoreCase))
        .OrderByDescending(d => d.CreatedAt)
        .FirstOrDefault();
}

bool IsInternalCatalogUrl(string? url)
{
    if (string.IsNullOrWhiteSpace(url))
    {
        return true;
    }

    var value = url.Trim();
    if (value.StartsWith("/catalogo", StringComparison.OrdinalIgnoreCase) ||
        value.StartsWith("/item/", StringComparison.OrdinalIgnoreCase) ||
        value.StartsWith("/bio", StringComparison.OrdinalIgnoreCase))
    {
        return true;
    }

    if (!Uri.TryCreate(value, UriKind.Absolute, out var uri))
    {
        return false;
    }

    var host = uri.Host.ToLowerInvariant();
    if (!host.Contains("reidasofertas.ia.br", StringComparison.Ordinal))
    {
        return false;
    }

    var path = uri.AbsolutePath;
    return path.StartsWith("/catalogo", StringComparison.OrdinalIgnoreCase)
        || path.StartsWith("/item/", StringComparison.OrdinalIgnoreCase)
        || path.StartsWith("/bio", StringComparison.OrdinalIgnoreCase);
}

string? BuildPublicImageProxyUrl(string? publicBaseUrl, HttpRequest request, string? imageUrl)
{
    if (string.IsNullOrWhiteSpace(imageUrl))
    {
        return null;
    }

    var trimmed = imageUrl.Trim();
    if (!Uri.TryCreate(trimmed, UriKind.Absolute, out var uri))
    {
        return trimmed;
    }

    if (string.Equals(uri.Host, request.Host.Host, StringComparison.OrdinalIgnoreCase))
    {
        return trimmed;
    }

    var baseUrl = ResolvePublicBaseUrl(publicBaseUrl, null, request.Scheme, request.Host.ToString()).TrimEnd('/');
    return $"{baseUrl}/media/remote?url={Uri.EscapeDataString(trimmed)}";
}

string NormalizeCatalogPostType(string? postType)
{
    return (postType ?? string.Empty).Trim().ToLowerInvariant() switch
    {
        "reel" or "reels" => "reel",
        "story" => "story",
        _ => "feed"
    };
}

static string BuildBioCurrentUrl(string publicBaseUrl, string source, string? campaign)
{
    var parameters = new List<string>();
    if (!string.IsNullOrWhiteSpace(source))
    {
        parameters.Add($"src={Uri.EscapeDataString(source)}");
    }

    if (!string.IsNullOrWhiteSpace(campaign))
    {
        parameters.Add($"camp={Uri.EscapeDataString(campaign)}");
    }

    var query = parameters.Count == 0 ? string.Empty : "?" + string.Join("&", parameters);
    return $"{publicBaseUrl.TrimEnd('/')}/bio{query}";
}

static string ResolvePublicBaseUrl(string? primaryPublicBaseUrl, string? secondaryPublicBaseUrl, string requestScheme, string requestHost)
{
    if (TryNormalizePublicBaseUrl(primaryPublicBaseUrl, out var primary))
    {
        return primary;
    }

    if (TryNormalizePublicBaseUrl(secondaryPublicBaseUrl, out var secondary))
    {
        return secondary;
    }

    if (TryReadBundledPublicBaseUrl(out var bundled))
    {
        return bundled;
    }

    if (string.IsNullOrWhiteSpace(requestHost))
    {
        return string.Empty;
    }

    var scheme = string.IsNullOrWhiteSpace(requestScheme) ? "https" : requestScheme.Trim();
    return $"{scheme}://{requestHost}".TrimEnd('/');
}

static bool TryNormalizePublicBaseUrl(string? value, out string normalized)
{
    normalized = string.Empty;
    if (string.IsNullOrWhiteSpace(value))
    {
        return false;
    }

    var trimmed = value.Trim().TrimEnd('/');
    if (!Uri.TryCreate(trimmed, UriKind.Absolute, out var uri))
    {
        return false;
    }

    if (!string.Equals(uri.Scheme, "http", StringComparison.OrdinalIgnoreCase) &&
        !string.Equals(uri.Scheme, "https", StringComparison.OrdinalIgnoreCase))
    {
        return false;
    }

    normalized = uri.GetLeftPart(UriPartial.Authority).TrimEnd('/');
    return !string.IsNullOrWhiteSpace(normalized);
}

static bool TryReadBundledPublicBaseUrl(out string publicBaseUrl)
{
    publicBaseUrl = string.Empty;
    var file = Path.Combine(AppContext.BaseDirectory, "appsettings.json");
    if (!File.Exists(file))
    {
        return false;
    }

    try
    {
        using var stream = File.OpenRead(file);
        using var doc = JsonDocument.Parse(stream);
        if (doc.RootElement.TryGetProperty("Webhook", out var webhook) &&
            webhook.ValueKind == JsonValueKind.Object &&
            webhook.TryGetProperty("PublicBaseUrl", out var baseUrlProp))
        {
            var raw = baseUrlProp.GetString();
            if (TryNormalizePublicBaseUrl(raw, out var normalized))
            {
                publicBaseUrl = normalized;
                return true;
            }
        }
    }
    catch
    {
        // keep default fallback path
    }

    return false;
}

static string BuildTrackedRedirectUrl(string publicBaseUrl, string trackingId, string source, string? campaign)
{
    var parameters = new List<string>();
    if (!string.IsNullOrWhiteSpace(source))
    {
        parameters.Add($"src={Uri.EscapeDataString(source)}");
    }

    if (!string.IsNullOrWhiteSpace(campaign))
    {
        parameters.Add($"camp={Uri.EscapeDataString(campaign)}");
    }

    if (publicBaseUrl.Contains("ngrok-free", StringComparison.OrdinalIgnoreCase) ||
        publicBaseUrl.Contains("ngrok.app", StringComparison.OrdinalIgnoreCase))
    {
        parameters.Add("ngrok-skip-browser-warning=1");
    }

    var query = parameters.Count == 0 ? string.Empty : "?" + string.Join("&", parameters);
    return $"{publicBaseUrl.TrimEnd('/')}/r/{trackingId}{query}";
}

static string AppendBioCampaignParameters(string? url, string source, string medium, string? campaign, string title)
{
    if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
    {
        return url?.Trim() ?? string.Empty;
    }

    var query = ParseQueryMap(uri.Query);
    if (!string.IsNullOrWhiteSpace(source))
    {
        query["utm_source"] = source;
    }

    if (!string.IsNullOrWhiteSpace(medium))
    {
        query["utm_medium"] = medium;
    }

    if (!string.IsNullOrWhiteSpace(campaign))
    {
        query["utm_campaign"] = campaign;
    }

    var content = BuildUtmContentValue(title);
    if (!string.IsNullOrWhiteSpace(content))
    {
        query["utm_content"] = content;
    }

    var queryString = query.Count == 0
        ? string.Empty
        : string.Join("&", query.Select(kv => $"{Uri.EscapeDataString(kv.Key)}={Uri.EscapeDataString(kv.Value)}"));

    var builder = new UriBuilder(uri)
    {
        Query = queryString
    };
    return builder.Uri.ToString();
}

static Dictionary<string, string> ParseQueryMap(string? query)
{
    var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
    if (string.IsNullOrWhiteSpace(query))
    {
        return map;
    }

    foreach (var pair in query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries))
    {
        var idx = pair.IndexOf('=');
        if (idx < 0)
        {
            continue;
        }

        var key = Uri.UnescapeDataString(pair[..idx]);
        var value = Uri.UnescapeDataString(pair[(idx + 1)..]);
        if (!string.IsNullOrWhiteSpace(key))
        {
            map[key] = value;
        }
    }

    return map;
}

static string BuildUtmContentValue(string? title)
{
    if (string.IsNullOrWhiteSpace(title))
    {
        return "oferta";
    }

    var normalized = Regex.Replace(title.Trim().ToLowerInvariant(), @"[^a-z0-9]+", "-", RegexOptions.CultureInvariant);
    normalized = Regex.Replace(normalized, @"-+", "-", RegexOptions.CultureInvariant).Trim('-');
    if (normalized.Length > 60)
    {
        normalized = normalized[..60].Trim('-');
    }

    return string.IsNullOrWhiteSpace(normalized) ? "oferta" : normalized;
}

static string? NormalizeTrackingToken(string? value, string? fallback)
{
    if (string.IsNullOrWhiteSpace(value))
    {
        return fallback;
    }

    var normalized = Regex.Replace(value.Trim().ToLowerInvariant(), @"[^a-z0-9_.-]+", "-", RegexOptions.CultureInvariant);
    normalized = Regex.Replace(normalized, @"-+", "-", RegexOptions.CultureInvariant).Trim('-');
    if (normalized.Length > 48)
    {
        normalized = normalized[..48].Trim('-');
    }

    if (string.IsNullOrWhiteSpace(normalized))
    {
        return fallback;
    }

    return normalized;
}

static string ResolveStoreNameFromUrl(string? url)
{
    if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
    {
        return "Loja";
    }

    var host = uri.Host.ToLowerInvariant();
    if (host.Contains("amazon", StringComparison.Ordinal))
    {
        return "Amazon";
    }

    if (host.Contains("mercadolivre", StringComparison.Ordinal) || host.Contains("mercado-livre", StringComparison.Ordinal))
    {
        return "Mercado Livre";
    }

    if (host.Contains("shopee", StringComparison.Ordinal))
    {
        return "Shopee";
    }

    if (host.Contains("shein", StringComparison.Ordinal))
    {
        return "Shein";
    }

    return host.StartsWith("www.", StringComparison.OrdinalIgnoreCase) ? host[4..] : host;
}

static string ExtractHostForDisplay(string? url)
{
    if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
    {
        return "-";
    }

    var host = uri.Host;
    return host.StartsWith("www.", StringComparison.OrdinalIgnoreCase) ? host[4..] : host;
}

static string TruncateForLog(string? value, int maxLength)
{
    if (string.IsNullOrWhiteSpace(value))
    {
        return string.Empty;
    }

    var trimmed = value.Trim();
    return trimmed.Length <= maxLength ? trimmed : trimmed[..maxLength];
}

static string ResolveCatalogTargetForRequest(HttpRequest request)
{
    var host = request.Host.Host ?? string.Empty;
    return host.Contains("-dev.", StringComparison.OrdinalIgnoreCase) || host.StartsWith("achadinhos-dev", StringComparison.OrdinalIgnoreCase)
        ? CatalogTargets.Dev
        : CatalogTargets.Prod;
}

static string BuildCatalogPageHtml(IReadOnlyList<CatalogOfferItem> items, string? query, string currentUrl)
{
    var q = query?.Trim() ?? string.Empty;
    var qEncoded = System.Net.WebUtility.HtmlEncode(q);
    var currentUrlEncoded = System.Net.WebUtility.HtmlEncode(currentUrl);
    var sb = new StringBuilder();

    var headerHtml = $$$"""
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Catálogo VIP de Ofertas</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Montserrat:wght@400;700;800&family=Inter:wght@300;400;600&display=swap" rel="stylesheet">
    <script>
        tailwind.config = {
            theme: {
                extend: {
                    colors: {
                        primary: '#0f172a',
                        accent: '#c4a468',
                        accentHover: '#b39359',
                        vipRed: '#e11d48',
                        surface: '#1e293b'
                    },
                    fontFamily: {
                        display: ['Montserrat', 'sans-serif'],
                        body: ['Inter', 'sans-serif'],
                    }
                }
            }
        }
    </script>
    <style>
        body { font-family: 'Inter', sans-serif; background-color: #0f172a; color: #f8fafc; }
        h1, h2, h3 { font-family: 'Montserrat', sans-serif; }
        .glass-header { background: rgba(15, 23, 42, 0.9); backdrop-filter: blur(8px); border-bottom: 1px solid rgba(196, 164, 104, 0.2); }
        .vip-card { background: linear-gradient(145deg, #1e293b, #0f172a); border: 1px solid rgba(196, 164, 104, 0.15); transition: transform 0.3s ease, box-shadow 0.3s ease; }
        .vip-card:hover { transform: translateY(-5px); box-shadow: 0 10px 25px rgba(196, 164, 104, 0.15); border-color: rgba(196, 164, 104, 0.4); }
        .image-wrapper { background: #fff; display: flex; align-items: center; justify-content: center; overflow: hidden; height: 240px; border-bottom: 1px solid rgba(196, 164, 104, 0.1); }
        .badge-lightning { 
            background: #e11d48; 
            color: white; 
            animation: pulse-red 2s infinite; 
        }
        @keyframes pulse-red {
            0% { box-shadow: 0 0 0 0 rgba(225, 29, 72, 0.7); }
            70% { box-shadow: 0 0 0 10px rgba(225, 29, 72, 0); }
            100% { box-shadow: 0 0 0 0 rgba(225, 29, 72, 0); }
        }
    </style>
    <script>
        document.addEventListener('DOMContentLoaded', function() {
            function getAnalyticsId(key, prefix) {
                try { const existing = localStorage.getItem(key); if (existing) return existing; const created = `${prefix}_${Math.random().toString(36).slice(2)}_${Date.now().toString(36)}`; localStorage.setItem(key, created); return created; } catch { return `${prefix}_${Math.random().toString(36).slice(2)}_${Date.now().toString(36)}`; }
            }

            function getSessionId() {
                try { const existing = sessionStorage.getItem('ard_session_id'); if (existing) return existing; const created = `sess_${Math.random().toString(36).slice(2)}_${Date.now().toString(36)}`; sessionStorage.setItem('ard_session_id', created); return created; } catch { return `sess_${Math.random().toString(36).slice(2)}_${Date.now().toString(36)}`; }
            }

            function getScrollDepth() {
                const doc = document.documentElement;
                const scrollTop = window.scrollY || doc.scrollTop || 0;
                const height = Math.max((doc.scrollHeight || 0) - window.innerHeight, 1);
                return Math.max(0, Math.min(100, Math.round((scrollTop / height) * 100)));
            }

            function buildCatalogPayload(targetUrl, source, eventType) {
                const params = new URLSearchParams(window.location.search);
                return {
                    TargetUrl: targetUrl,
                    Source: source,
                    Category: 'catalog',
                    VisitorId: getAnalyticsId('ard_visitor_id', 'visitor'),
                    SessionId: getSessionId(),
                    EventType: eventType,
                    PageType: window.location.pathname.includes('/item/') ? 'item' : 'catalog',
                    PageUrl: window.location.href,
                    SourceComponent: source,
                    Language: navigator.language || null,
                    Timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || null,
                    ScreenWidth: window.screen?.width || null,
                    ScreenHeight: window.screen?.height || null,
                    ViewportWidth: window.innerWidth || null,
                    ViewportHeight: window.innerHeight || null,
                    ScrollDepth: getScrollDepth(),
                    TimeOnPageMs: Math.max(0, Math.round(performance.now())),
                    UtmSource: params.get('utm_source'),
                    UtmMedium: params.get('utm_medium'),
                    UtmCampaign: params.get('utm_campaign'),
                    UtmContent: params.get('utm_content'),
                    UtmTerm: params.get('utm_term')
                };
            }

            fetch('/api/analytics/click', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(buildCatalogPayload(window.location.href, 'catalog_view', 'page_view')),
                keepalive: true
            }).catch(() => {});

            document.addEventListener('click', function(e) {
                const link = e.target.closest('a');
                if (link && link.href) {
                    const eventType = link.href.includes('/item/') ? 'offer_detail_click' : (link.target === '_blank' ? 'checkout_intent' : 'catalog_navigation');
                    fetch('/api/analytics/click', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(buildCatalogPayload(link.href, 'catalog_web', eventType)),
                        keepalive: true
                    }).catch(() => {});
                }
            });

            function updateCountdowns() {
                const now = new Date().getTime();
                document.querySelectorAll('[data-expiry]').forEach(el => {
                    const expiryStr = el.getAttribute('data-expiry');
                    if (!expiryStr) return;
                    const expiry = new Date(expiryStr).getTime();
                    const diff = expiry - now;
                    if (diff <= 0) {
                        el.innerHTML = "Oferta Expirada";
                        el.classList.remove('badge-lightning');
                        el.classList.add('bg-slate-500');
                        return;
                    }
                    const h = Math.floor(diff / 3600000);
                    const m = Math.floor((diff % 3600000) / 60000);
                    const s = Math.floor((diff % 60000) / 1000);
                    el.innerHTML = `⚡ ${h}h ${m}m ${s}s`;
                });
            }
            setInterval(updateCountdowns, 1000);
            updateCountdowns();
        });
    </script>
</head>
<body class="min-h-screen pb-12">
    <!-- Header -->
    <header class="sticky top-0 z-50 glass-header">
        <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-5 flex flex-col md:flex-row gap-4 justify-between items-center">
            <div class="flex items-center gap-3">
                <div class="w-10 h-10 bg-accent rounded-full flex items-center justify-center shadow-[0_0_15px_rgba(196,164,104,0.4)]">
                    <span class="text-primary font-black text-sm tracking-tighter">VIP</span>
                </div>
                <h1 class="text-xl md:text-2xl font-extrabold uppercase tracking-widest text-white">Catálogo <span class="text-accent">Exclusivo</span></h1>
            </div>
            
            <form method="get" action="/catalogo" class="w-full md:w-auto flex flex-1 max-w-md">
                <input type="text" name="q" value="{{{qEncoded}}}" placeholder="Buscar produto ou marca..." class="w-full bg-surface/50 border border-accent/30 rounded-l-xl px-4 py-2 text-white placeholder-slate-400 focus:outline-none focus:border-accent focus:ring-1 focus:ring-accent transition-colors">
                <button type="submit" class="bg-accent hover:bg-accentHover text-primary font-bold px-6 py-2 rounded-r-xl transition-colors">
                    Buscar
                </button>
            </form>
        </div>
    </header>

    <main class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
""";

    sb.AppendLine(headerHtml);

    if (items.Count == 0)
    {
        sb.AppendLine($$"""
        <div class="mt-12 text-center p-12 vip-card rounded-2xl max-w-2xl mx-auto">
            <div class="text-accent mb-4"><svg class="w-16 h-16 mx-auto opacity-50" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"></path></svg></div>
            <h2 class="text-2xl font-bold text-white mb-2">Nenhum achadinho encontrado.</h2>
            <p class="text-slate-400">Tente buscar por outro termo ou volte mais tarde para novas ofertas.</p>
        </div>
""");
    }
    else
    {
        sb.AppendLine("        <div class=\"grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6\">");
        
        foreach (var item in items)
        {
            var title = System.Net.WebUtility.HtmlEncode(item.ProductName);
            var titleShort = title.Length > 60 ? title.Substring(0, 57) + "..." : title;
            var store = System.Net.WebUtility.HtmlEncode(item.Store);
            var detailLink = $"/item/{item.ItemNumber}";
            var image = string.IsNullOrWhiteSpace(item.ImageUrl) ? "https://via.placeholder.com/400" : System.Net.WebUtility.HtmlEncode(item.ImageUrl);
            
            var fullPrice = item.PriceText ?? "Indisponível";
            var price_val = fullPrice.Replace("R$ ", "").Replace("R$", "").Trim();
            
            var published = item.PublishedAt.ToString("dd/MM/yyyy");

            var dealBadge = "";
            if (item.IsLightningDeal)
            {
                var expiryAttr = item.LightningDealExpiry.HasValue 
                    ? $" data-expiry=\"{item.LightningDealExpiry.Value:yyyy-MM-ddTHH:mm:ssZ}\"" 
                    : "";
                dealBadge = $@"
                    <div class=""absolute top-3 right-3 badge-lightning text-[10px] font-bold uppercase tracking-wider px-2 py-1 rounded z-10 border border-white/20 shadow-lg""{expiryAttr}>
                        Oferta Relâmpago
                    </div>";
            }
            
            var couponBadge = "";
            if (!string.IsNullOrWhiteSpace(item.CouponCode))
            {
                couponBadge = $$$"""
                    <div class="mt-2 inline-flex items-center gap-1.5 bg-accent/10 border border-accent/20 px-2.5 py-1 rounded-lg">
                        <svg class="w-3.5 h-3.5 text-accent" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 7h.01M7 3h5c.512 0 1.024.195 1.414.586l7 7a2 2 0 010 2.828l-7 7a2 2 0 01-2.828 0l-7-7A1.994 1.994 0 013 12V7a4 4 0 014-4z"></path></svg>
                        <span class="text-accent text-[11px] font-bold uppercase">Cupom Ativo</span>
                    </div>
                """;
            }

            var cardHtml = $$$"""
            <article class="vip-card rounded-2xl overflow-hidden flex flex-col h-full group">
                <a href="{{{detailLink}}}" class="block relative image-wrapper">
                    <!-- Date badge inside image -->
                    <div class="absolute top-3 left-3 bg-primary/90 text-accent text-[10px] font-bold uppercase tracking-wider px-2 py-1 rounded backdrop-blur-sm border border-accent/20 z-10">
                        {{{published}}}
                    </div>
                    {{{dealBadge}}}
                    <!-- View overlay -->
                    <div class="absolute inset-0 bg-primary/40 opacity-0 group-hover:opacity-100 transition-opacity z-10 flex items-center justify-center backdrop-blur-[2px]">
                        <span class="bg-accent text-primary font-bold px-4 py-2 rounded-full transform translate-y-4 group-hover:translate-y-0 transition-transform">Ver Detalhes</span>
                    </div>
                    <img src="{{{image}}}" alt="{{{title}}}" loading="lazy" class="w-full h-full object-contain p-4 mix-blend-multiply group-hover:scale-110 transition-transform duration-500" />
                </a>
                
                <div class="p-5 flex flex-col flex-1">
                    <div class="text-[10px] font-bold uppercase tracking-widest text-slate-400 mb-2 flex items-center justify-between">
                        <span>{{{store}}}</span>
                        <span class="text-accent">#{{{item.ItemNumber}}}</span>
                    </div>
                    
                    <h3 class="text-white font-semibold flex-1 leading-snug mb-2">
                        <a href="{{{detailLink}}}" class="hover:text-accent transition-colors" title="{{{title}}}">{{{titleShort}}}</a>
                    </h3>
                    
                    {{{couponBadge}}}
                    
                    <div class="mt-auto pt-4 border-t border-white/5 flex items-center justify-between">
                        <div class="flex flex-col">
                            <span class="text-xs text-slate-500">Preço VIP</span>
                            <div class="flex items-baseline gap-1">
                                <span class="text-white text-sm">R$</span>
                                <span class="text-accent text-2xl font-bold tracking-tight">{{{price_val}}}</span>
                            </div>
                        </div>
                    </div>
                </div>
            </article>
""";
            sb.AppendLine(cardHtml);
        }
        
        sb.AppendLine("        </div>"); // End grid
    }

    sb.AppendLine($$"""
    </main>
    <footer class="mt-12 py-8 border-t border-white/10 text-center">
        <p class="text-slate-500 text-sm">Design VIP Exclusivo • Seu link: <span class="text-slate-400">{{{currentUrlEncoded}}}</span></p>
    </footer>
</body>
</html>
""");

    return sb.ToString();
}

static string BuildCatalogItemPageHtml(CatalogOfferItem item, string catalogUrl)
{
    var title = System.Net.WebUtility.HtmlEncode(item.ProductName);
    var store = System.Net.WebUtility.HtmlEncode(item.Store);
    var keyword = System.Net.WebUtility.HtmlEncode(item.Keyword);
    var fullPrice = System.Net.WebUtility.HtmlEncode(item.PriceText ?? "Preco indisponivel");
    var price_val = fullPrice.Replace("R$ ", "").Replace("R$", "").Trim();
    var offerUrl = System.Net.WebUtility.HtmlEncode(item.OfferUrl);
    var image = System.Net.WebUtility.HtmlEncode(item.ImageUrl ?? "https://via.placeholder.com/800");
    var catalog = System.Net.WebUtility.HtmlEncode(catalogUrl);
    var previous_price = "---";
    var savings_text = "Desconto aplicado";
    var publish_date = item.PublishedAt.ToString("dd/MM/yyyy HH:mm");
    
    // Enrichment
    var isLightning = item.IsLightningDeal;
    var expiry = item.LightningDealExpiry;
    var coupon = item.CouponCode ?? "";
    var couponDesc = item.CouponDescription ?? "";
    
    var dealBadge = "";
    if (isLightning)
    {
        var expiryAttr = expiry.HasValue 
            ? $" data-expiry=\"{expiry.Value:yyyy-MM-ddTHH:mm:ssZ}\"" 
            : "";
        dealBadge = $@"
            <div class=""absolute top-6 right-6 bg-vipRed text-white text-sm font-bold uppercase tracking-wider px-4 py-2 rounded-xl z-20 shadow-2xl animate-pulse""{expiryAttr}>
                ⚡ Oferta Relâmpago
            </div>";
    }
    var couponBlock1 = string.IsNullOrWhiteSpace(coupon) ? "" : $$"""
<div class="mt-8 p-6 bg-slate-50 rounded-2xl border-l-4 border-accent">
    <p class="text-sm font-bold text-slate-500 uppercase mb-2">Instrução de Compra:</p>
    <p class="text-primary font-semibold">Aplique o cupom <span class="bg-accent/20 text-accent px-2 py-0.5 rounded">{{coupon}}</span> no checkout para garantir este valor exclusivo.</p>
</div>
""";

    var couponBlock2 = string.IsNullOrWhiteSpace(coupon) ? "" : $$"""
<div class="mt-8 pt-8 border-t border-white/10">
    <div class="bg-white/5 rounded-xl p-6 text-center border border-accent/20">
        <p class="text-white/60 text-[10px] uppercase tracking-widest mb-2 font-bold">CUPOM ATIVO</p>
        <div class="flex items-center justify-center gap-3">
            <p id="couponCode" class="text-accent font-mono font-black text-2xl tracking-widest cursor-pointer hover:scale-105 transition-transform">{{coupon}}</p>
            <button onclick="copyCoupon('{{coupon}}')" class="bg-accent/20 hover:bg-accent/30 text-accent p-2 rounded-lg transition-colors" title="Copiar Cupom">
                <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 5H6a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2v-1M8 5a2 2 0 002 2h2a2 2 0 002-2M8 5a2 2 0 012-2h2a2 2 0 012 2m0 0h2a2 2 0 012 2v3m2 4H10m0 0l3-3m-3 3l3 3"></path></svg>
            </button>
        </div>
        <p class="text-accent/60 text-[10px] mt-2 italic">{{couponDesc}}</p>
    </div>
</div>
""";

    return $$"""
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Oferta VIP Exclusiva - {{title}}</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Montserrat:wght@400;700;800&family=Inter:wght@300;400;600&display=swap" rel="stylesheet">
    <script>
        tailwind.config = {
            theme: {
                extend: {
                    colors: {
                        primary: '#0f172a',
                        accent: '#c4a468',
                        accentHover: '#b39359',
                        vipRed: '#e11d48',
                        surface: '#f8fafc',
                    },
                    fontFamily: {
                        display: ['Montserrat', 'sans-serif'],
                        body: ['Inter', 'sans-serif'],
                    },
                    animation: {
                        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
                        'float': 'float 6s ease-in-out infinite',
                    },
                    keyframes: {
                        float: {
                            '0%, 100%': { transform: 'translateY(0)' },
                            '50%': { transform: 'translateY(-10px)' },
                        }
                    }
                }
            }
        }
    </script>
    <style>
        .glass-effect {
            background: rgba(255, 255, 255, 0.8);
            backdrop-filter: blur(12px);
            -webkit-backdrop-filter: blur(12px);
            border: 1px solid rgba(255, 255, 255, 0.3);
        }
        .hero-gradient {
            background: radial-gradient(circle at top right, #1e293b, #0f172a);
        }
        .price-tag {
            text-shadow: 0 0 20px rgba(196, 164, 104, 0.3);
        }
        body {
            font-family: 'Inter', sans-serif;
            background-color: #f1f5f9;
        }
        h1, h2, h3 {
            font-family: 'Montserrat', sans-serif;
        }
    </style>
    <script>
        document.addEventListener('DOMContentLoaded', function() {
            function getAnalyticsId(key, prefix) {
                try { const existing = localStorage.getItem(key); if (existing) return existing; const created = `${prefix}_${Math.random().toString(36).slice(2)}_${Date.now().toString(36)}`; localStorage.setItem(key, created); return created; } catch { return `${prefix}_${Math.random().toString(36).slice(2)}_${Date.now().toString(36)}`; }
            }

            function getSessionId() {
                try { const existing = sessionStorage.getItem('ard_session_id'); if (existing) return existing; const created = `sess_${Math.random().toString(36).slice(2)}_${Date.now().toString(36)}`; sessionStorage.setItem('ard_session_id', created); return created; } catch { return `sess_${Math.random().toString(36).slice(2)}_${Date.now().toString(36)}`; }
            }

            function getScrollDepth() {
                const doc = document.documentElement;
                const scrollTop = window.scrollY || doc.scrollTop || 0;
                const height = Math.max((doc.scrollHeight || 0) - window.innerHeight, 1);
                return Math.max(0, Math.min(100, Math.round((scrollTop / height) * 100)));
            }

            function buildCatalogPayload(targetUrl, source, eventType) {
                const params = new URLSearchParams(window.location.search);
                return {
                    TargetUrl: targetUrl,
                    Source: source,
                    Category: 'catalog',
                    VisitorId: getAnalyticsId('ard_visitor_id', 'visitor'),
                    SessionId: getSessionId(),
                    EventType: eventType,
                    PageType: window.location.pathname.includes('/item/') ? 'item' : 'catalog',
                    PageUrl: window.location.href,
                    SourceComponent: source,
                    Language: navigator.language || null,
                    Timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || null,
                    ScreenWidth: window.screen?.width || null,
                    ScreenHeight: window.screen?.height || null,
                    ViewportWidth: window.innerWidth || null,
                    ViewportHeight: window.innerHeight || null,
                    ScrollDepth: getScrollDepth(),
                    TimeOnPageMs: Math.max(0, Math.round(performance.now())),
                    UtmSource: params.get('utm_source'),
                    UtmMedium: params.get('utm_medium'),
                    UtmCampaign: params.get('utm_campaign'),
                    UtmContent: params.get('utm_content'),
                    UtmTerm: params.get('utm_term')
                };
            }

            fetch('/api/analytics/click', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(buildCatalogPayload(window.location.href, 'catalog_view', 'page_view')),
                keepalive: true
            }).catch(() => {});

            document.addEventListener('click', function(e) {
                const link = e.target.closest('a');
                if (link && link.href) {
                    const eventType = link.href.includes('/item/') ? 'offer_detail_click' : (link.target === '_blank' ? 'checkout_intent' : 'catalog_navigation');
                    fetch('/api/analytics/click', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(buildCatalogPayload(link.href, 'catalog_web', eventType)),
                        keepalive: true
                    }).catch(() => {});
                }
            });

            function updateCountdowns() {
                const now = new Date().getTime();
                document.querySelectorAll('[data-expiry]').forEach(el => {
                    const expiryStr = el.getAttribute('data-expiry');
                    if (!expiryStr) return;
                    const expiry = new Date(expiryStr).getTime();
                    const diff = expiry - now;
                    if (diff <= 0) {
                        el.innerHTML = "Oferta Expirada";
                        el.classList.add('bg-slate-500');
                        el.classList.remove('bg-vipRed', 'animate-pulse');
                        return;
                    }
                    const h = Math.floor(diff / 3600000);
                    const m = Math.floor((diff % 3600000) / 60000);
                    const s = Math.floor((diff % 60000) / 1000);
                    el.innerHTML = `⚡ Expira em: ${h}h ${m}m ${s}s`;
                });
            }
            setInterval(updateCountdowns, 1000);
            updateCountdowns();

            window.copyCoupon = function(code) {
                navigator.clipboard.writeText(code).then(() => {
                    const btn = event.currentTarget;
                    const original = btn.innerHTML;
                    btn.innerHTML = '<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path></svg>';
                    setTimeout(() => { btn.innerHTML = original; }, 2000);
                });
            };
        });
    </script>
</head>
<body class="text-slate-900 overflow-x-hidden">

    <!-- Fixed Header -->
    <header class="fixed top-0 w-full z-50 glass-effect shadow-sm">
        <div class="max-w-7xl mx-auto px-6 py-4 flex justify-between items-center">
            <div class="flex items-center gap-2">
                <div class="w-8 h-8 bg-accent rounded-full flex items-center justify-center">
                    <span class="text-primary font-bold text-xs">VIP</span>
                </div>
                <h1 class="text-lg font-extrabold uppercase tracking-widest text-primary">Oferta VIP Exclusiva</h1>
            </div>
            <div class="hidden md:block">
                <span class="text-xs font-semibold text-slate-500 uppercase tracking-tighter">Acesso prioritário liberado</span>
            </div>
        </div>
    </header>

    <main class="pt-24 pb-12">
        <!-- Hero Section -->
        <section class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 mb-12">
            <div class="hero-gradient rounded-3xl overflow-hidden shadow-2xl flex flex-col lg:flex-row items-center p-8 lg:p-16 gap-12">
                
                <!-- Product Image Area -->
                <div class="w-full lg:w-1/2 flex justify-center items-center animate-float relative">
                    {{dealBadge}}
                    <div class="relative group">
                        <div class="absolute -inset-4 bg-accent/20 rounded-full blur-3xl group-hover:bg-accent/30 transition duration-500"></div>
                        <div class="relative">
                            <a href="{{offerUrl}}" target="_blank" rel="noopener noreferrer">
                                <img src="{{image}}" alt="{{title}}" class="w-full h-auto max-w-md object-contain drop-shadow-[0_20px_50px_rgba(0,0,0,0.5)] transform transition-transform duration-500 hover:scale-105" />
                            </a>
                        </div>
                    </div>
                </div>

                <!-- Hero Content -->
                <div class="w-full lg:w-1/2 text-center lg:text-left space-y-8">
                    <div class="flex items-center justify-center lg:justify-start gap-3 mb-4">
                        <div class="inline-block px-4 py-1.5 rounded-full bg-accent/10 border border-accent/30 text-accent font-bold text-sm tracking-wider uppercase">
                            Desconto Imperdível
                        </div>
                        <div class="inline-block px-4 py-1.5 rounded-full bg-slate-800 text-slate-300 font-medium text-xs tracking-wide">
                            Postado em {{publish_date}}
                        </div>
                    </div>
                    <h2 class="text-4xl lg:text-6xl font-extrabold text-white leading-tight">
                        Eleve seu estilo a um <span class="text-accent">novo patamar</span>
                    </h2>
                    <p class="text-slate-300 text-lg lg:text-xl font-light leading-relaxed max-w-xl">
                        🚨 OFERTA EXCLUSIVA VIP! Conheça <strong>{{title}}</strong>. Performance e design premium para cada passo do seu dia.
                    </p>
                    
                    <div class="pt-4 flex flex-col sm:flex-row items-center gap-6 justify-center lg:justify-start">
                        <a href="{{offerUrl}}" target="_blank" class="group relative inline-flex items-center justify-center px-10 py-5 font-bold text-primary transition-all duration-200 bg-accent rounded-xl hover:bg-accentHover focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-accent w-full sm:w-auto shadow-lg shadow-accent/20">
                            Comprar Agora
                            <svg class="w-5 h-5 ml-2 transition-transform duration-200 group-hover:translate-x-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 7l5 5m0 0l-5 5m5-5H6"></path>
                            </svg>
                        </a>
                        <div class="text-white/60 text-sm font-medium italic">
                            *Estoque limitado
                        </div>
                    </div>
                </div>
            </div>
        </section>

        <!-- Bento Grid Details -->
        <section class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 grid grid-cols-1 md:grid-cols-3 gap-6">
            
            <!-- Description Card -->
            <div class="md:col-span-2 bg-white rounded-3xl p-8 lg:p-10 shadow-sm border border-slate-100">
                <h3 class="text-2xl font-bold mb-6 flex items-center gap-3">
                    <span class="w-2 h-8 bg-accent rounded-full"></span>
                    Detalhes do Produto
                </h3>
                <div class="space-y-4 text-slate-600 leading-relaxed text-lg">
                    <p class="font-bold text-primary uppercase tracking-wide">DETALHES DO PRODUTO</p>
                    <p>O {{title}} é projetado para oferecer versatilidade e estilo inigualável. Ideal para quem busca estar sempre no mais alto padrão de qualidade e conforto.</p>
                    <p>Aproveite esta oferta exclusiva do catálogo!</p>
                    {{couponBlock1}}
                </div>
            </div>

            <!-- Pricing Card -->
            <div class="bg-primary rounded-3xl p-8 flex flex-col justify-between shadow-2xl relative overflow-hidden group">
                <!-- Background decoration -->
                <div class="absolute top-0 right-0 -mr-16 -mt-16 w-48 h-48 bg-accent/10 rounded-full blur-3xl"></div>
                
                <div>
                    <span class="text-accent font-bold uppercase tracking-widest text-xs">Condição Especial</span>
                    <h3 class="text-white text-3xl font-bold mt-2 mb-8">Preço VIP</h3>
                    
                    <div class="space-y-2">
                        <p class="text-slate-400 line-through text-lg">Preço Original: {{previous_price}}</p>
                        <div class="flex items-baseline gap-2">
                            <span class="text-white text-2xl font-light">R$</span>
                            <span class="text-accent text-6xl font-extrabold tracking-tighter price-tag">{{price_val}}</span>
                        </div>
                    </div>
                </div>

                <div class="mt-12 space-y-4">
                    <div class="flex items-center gap-3 text-white/80 text-sm">
                        <svg class="w-5 h-5 text-green-500" fill="currentColor" viewBox="0 0 20 20">
                            <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd"></path>
                        </svg>
                        {{savings_text}}
                    </div>
                    <div class="flex items-center gap-3 text-white/80 text-sm">
                        <svg class="w-5 h-5 text-green-500" fill="currentColor" viewBox="0 0 20 20">
                            <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd"></path>
                        </svg>
                        Frete e condições oficiais
                    </div>
                </div>

                {{couponBlock2}}
            </div>

        </section>

        <!-- Trust Badges -->
        <section class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 mt-12 grid grid-cols-1 md:grid-cols-2 gap-4">
            <div class="bg-white border border-slate-200 rounded-2xl p-6 flex items-center gap-6 shadow-sm hover:shadow-md transition-shadow">
                <div class="w-16 h-16 bg-accent/10 rounded-full flex items-center justify-center text-accent">
                    <svg class="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4M7.835 4.697a3.42 3.42 0 001.946-.806 3.42 3.42 0 014.438 0 3.42 3.42 0 001.946.806 3.42 3.42 0 013.138 3.138 3.42 3.42 0 00.806 1.946 3.42 3.42 0 010 4.438 3.42 3.42 0 00-.806 1.946 3.42 3.42 0 01-3.138 3.138 3.42 3.42 0 00-1.946.806 3.42 3.42 0 01-4.438 0 3.42 3.42 0 00-1.946-.806 3.42 3.42 0 01-3.138-3.138 3.42 3.42 0 00-.806-1.946 3.42 3.42 0 010-4.438 3.42 3.42 0 00.806-1.946 3.42 3.42 0 013.138-3.138z"></path>
                    </svg>
                </div>
                <div>
                    <h4 class="font-bold text-primary">Oferta Exclusiva VIP</h4>
                    <p class="text-slate-500 text-sm">Preço reservado apenas para membros selecionados.</p>
                </div>
            </div>
            <div class="bg-white border border-slate-200 rounded-2xl p-6 flex items-center gap-6 shadow-sm hover:shadow-md transition-shadow">
                <div class="w-16 h-16 bg-vipRed/10 rounded-full flex items-center justify-center text-vipRed">
                    <svg class="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                    </svg>
                </div>
                <div>
                    <h4 class="font-bold text-primary">Tempo Limitado</h4>
                    <p class="text-slate-500 text-sm">Esta condição pode expirar a qualquer momento.</p>
                </div>
            </div>
        </section>
    </main>

    <footer class="bg-white border-t border-slate-200 mt-12">
        <div class="max-w-7xl mx-auto px-6 py-8 flex flex-col md:flex-row justify-between items-center gap-4">
            <div class="flex items-center gap-3">
                <div class="w-2 h-2 rounded-full bg-green-500 animate-pulse"></div>
                <span class="text-slate-500 text-sm font-medium">Registro no Catálogo Confirmado: <a href="{{catalog}}" class="hover:text-accent">Verificação Ativa</a></span>
            </div>
            <div class="text-slate-400 text-xs">
                © Vi no: @ReiDasOfertasVIP
            </div>
        </div>
    </footer>

</body>
</html>
""";
}

static string BuildInstagramDraftReviewMessage(InstagramPublishDraft draft)
{
    var sb = new StringBuilder();
    sb.AppendLine($"Draft: {draft.Id}");
    sb.AppendLine($"Status: {draft.Status}");
    sb.AppendLine($"Tipo: {NormalizeInstagramPostTypeValue(draft.PostType)}");
    sb.AppendLine($"Criado em: {draft.CreatedAt:yyyy-MM-dd HH:mm:ss} UTC");
    if (!string.IsNullOrWhiteSpace(draft.ProductName))
    {
        sb.AppendLine($"Produto: {draft.ProductName}");
    }
    sb.AppendLine($"Imagens: {draft.ImageUrls.Count}");
    if (draft.CaptionOptions.Count > 0)
    {
        var selected = draft.SelectedCaptionIndex <= 0 ? 1 : draft.SelectedCaptionIndex;
        sb.AppendLine($"Legendas: {draft.CaptionOptions.Count} (selecionada: {selected})");
    }
    if (!string.IsNullOrWhiteSpace(draft.MediaId))
    {
        sb.AppendLine($"MediaId: {draft.MediaId}");
    }
    if (!string.IsNullOrWhiteSpace(draft.Error))
    {
        sb.AppendLine($"Erro: {draft.Error}");
    }

    sb.AppendLine();
    sb.AppendLine("Legenda:");
    sb.AppendLine(draft.Caption ?? string.Empty);

    if (!string.IsNullOrWhiteSpace(draft.Hashtags))
    {
        sb.AppendLine();
        sb.AppendLine("Hashtags:");
        sb.AppendLine(draft.Hashtags);
    }

    if (draft.CaptionOptions.Count > 1)
    {
        sb.AppendLine();
        sb.AppendLine("Opcoes de legenda:");
        for (var i = 0; i < draft.CaptionOptions.Count; i++)
        {
            var preview = draft.CaptionOptions[i];
            preview = preview.Length > 90 ? preview[..90].TrimEnd() + "..." : preview;
            sb.AppendLine($"{i + 1}) {preview}");
        }
        var shortId = draft.Id.Length > 8 ? draft.Id[..8] : draft.Id;
        sb.AppendLine($"Escolher: /leg <numero> {shortId}");
    }

    if (draft.ImageUrls.Count > 0)
    {
        sb.AppendLine();
        sb.AppendLine("Imagens do post (todas):");
        for (var i = 0; i < draft.ImageUrls.Count; i++)
        {
            sb.AppendLine($"{i + 1}) {draft.ImageUrls[i]}");
        }

        var selectedIndexes = SanitizeInstagramSelectedIndexes(draft.SelectedImageIndexes, draft.ImageUrls.Count);
        if (selectedIndexes.Count > 0)
        {
            sb.AppendLine();
            sb.AppendLine($"Selecionadas para envio: {string.Join(", ", selectedIndexes)} (total: {selectedIndexes.Count})");
        }
        else
        {
            sb.AppendLine();
            sb.AppendLine("Selecionadas para envio: todas as imagens acima.");
        }

        var shortId = draft.Id.Length > 8 ? draft.Id[..8] : draft.Id;
        sb.AppendLine();
        sb.AppendLine($"Selecionar imagens: /ig imagens {shortId} 1,2");
        sb.AppendLine($"Listar novamente: /ig imagens {shortId}");
    }

    return sb.ToString().Trim();
}

static string BuildInstagramImageSelectionMessage(InstagramPublishDraft draft)
{
    var shortId = draft.Id.Length > 8 ? draft.Id[..8] : draft.Id;
    var selectedIndexes = SanitizeInstagramSelectedIndexes(draft.SelectedImageIndexes, draft.ImageUrls.Count);
    var sb = new StringBuilder();
    sb.AppendLine($"Imagens do draft {shortId} (total: {draft.ImageUrls.Count}):");
    sb.AppendLine();

    for (var i = 0; i < draft.ImageUrls.Count; i++)
    {
        sb.AppendLine($"{i + 1}) {draft.ImageUrls[i]}");
    }

    sb.AppendLine();
    if (selectedIndexes.Count > 0)
    {
        sb.AppendLine($"Selecionadas atualmente: {string.Join(", ", selectedIndexes)}");
    }
    else
    {
        sb.AppendLine("Selecionadas atualmente: todas");
    }
    sb.AppendLine();
    sb.AppendLine("Selecionar por indice:");
    sb.AppendLine($"- /ig imagens {shortId} 1");
    sb.AppendLine($"- /ig imagens {shortId} 2");
    sb.AppendLine($"- /ig imagens {shortId} 1,2");
    sb.AppendLine($"- /ig imagens {shortId} 2-4");

    return sb.ToString().Trim();
}

static List<int> SanitizeInstagramSelectedIndexes(IEnumerable<int>? indexes, int maxCount)
{
    if (indexes is null || maxCount <= 0)
    {
        return new List<int>();
    }

    return indexes
        .Where(i => i >= 1 && i <= maxCount)
        .Distinct()
        .OrderBy(i => i)
        .ToList();
}

static List<string> ResolveSelectedInstagramImageUrls(InstagramPublishDraft draft)
{
    var allImages = (draft.ImageUrls ?? new List<string>())
        .Where(x => !string.IsNullOrWhiteSpace(x))
        .ToList();
    if (allImages.Count == 0)
    {
        return new List<string>();
    }

    var selectedIndexes = SanitizeInstagramSelectedIndexes(draft.SelectedImageIndexes, allImages.Count);
    if (selectedIndexes.Count == 0)
    {
        return allImages
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    return selectedIndexes
        .Select(index => allImages[index - 1])
        .Where(x => !string.IsNullOrWhiteSpace(x))
        .Distinct(StringComparer.OrdinalIgnoreCase)
        .ToList();
}

static async Task<InstagramDraftBuildResult> BuildInstagramDraftFromCreateInputAsync(
    string rawArgument,
    InstagramPostSettings instaSettings,
    IInstagramPostComposer instagramComposer,
    InstagramLinkMetaService instagramMeta,
    CancellationToken ct)
{
    var parsedCreate = ParseInstagramCreateInput(rawArgument);
    if (string.IsNullOrWhiteSpace(parsedCreate.Input))
    {
        return new InstagramDraftBuildResult(null, "Uso: /ig criar <produto ou link>");
    }

    if (parsedCreate.PostType == "reel")
    {
        return new InstagramDraftBuildResult(null, "Tipo 'reel' ainda nao suportado via API atual. Use tipo=feed ou tipo=story.");
    }

    var input = parsedCreate.Input;
    var postText = await instagramComposer.BuildAsync(input, null, instaSettings, ct);
    var (captionOptionsRaw, hashtags) = ExtractInstagramCaptionOptionsAndHashtags(postText);
    var captionOptions = captionOptionsRaw
        .Select(FormatInstagramCaptionForReadability)
        .Where(x => !string.IsNullOrWhiteSpace(x))
        .Distinct(StringComparer.Ordinal)
        .ToList();
    if (captionOptions.Count == 0)
    {
        captionOptions.Add(FormatInstagramCaptionForReadability(postText.Trim()));
    }

    var link = ExtractFirstUrl(input) ?? ExtractLinkFromPost(postText);
    var imageUrls = new List<string>();
    imageUrls.AddRange(parsedCreate.ImageUrls);
    if (!string.IsNullOrWhiteSpace(link))
    {
        var meta = await instagramMeta.GetMetaAsync(link, ct);
        imageUrls.AddRange(meta.Images);
    }
    imageUrls.AddRange(ExtractImageUrlsFromInstagramPostText(postText));
    imageUrls = NormalizeExternalUrls(imageUrls, 10);

    var ctas = new List<InstagramCtaOption>();
    if (!string.IsNullOrWhiteSpace(link))
    {
        var captionKeywords = ExtractInstagramCtaKeywordsFromCaptions(captionOptions);
        var keywords = parsedCreate.CtaKeywords.Count > 0
            ? parsedCreate.CtaKeywords
            : captionKeywords.Count > 0
                ? captionKeywords
                : BuildDefaultCtaKeywords(BuildInstagramDraftProductName(input, postText));
        keywords = NormalizeInstagramCtaKeywords(keywords);

        foreach (var keyword in keywords.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            ctas.Add(new InstagramCtaOption
            {
                Keyword = keyword,
                Link = link
            });
        }
    }

    captionOptions = captionOptions
        .Select(c => EnsureInstagramCaptionContainsCta(c, ctas))
        .Select(c => c.Length > 2200 ? c[..2200].TrimEnd() + "..." : c)
        .ToList();

    var draft = new InstagramPublishDraft
    {
        PostType = parsedCreate.PostType,
        ProductName = BuildInstagramDraftProductName(input, postText),
        Caption = captionOptions[0],
        CaptionOptions = captionOptions,
        SelectedCaptionIndex = 1,
        Hashtags = hashtags,
        ImageUrls = imageUrls,
        Ctas = ctas
    };

    return new InstagramDraftBuildResult(draft, null);
}

static InstagramCreateInput ParseInstagramCreateInput(string raw)
{
    var input = raw?.Trim() ?? string.Empty;
    var keywords = new List<string>();
    var imageUrls = new List<string>();
    var postType = "feed";
    if (string.IsNullOrWhiteSpace(input))
    {
        return new InstagramCreateInput(string.Empty, keywords, imageUrls, postType);
    }

    var pattern = new Regex(@"(?:^|\s)(?<key>cta|img|imagem|imagens|tipo|formato)\s*[:=]\s*(?<value>.*?)(?=(?:\s+(?:cta|img|imagem|imagens|tipo|formato)\s*[:=])|$)", RegexOptions.IgnoreCase | RegexOptions.Singleline);
    var matches = pattern.Matches(input);
    foreach (Match match in matches)
    {
        if (!match.Success || !match.Groups["key"].Success || !match.Groups["value"].Success)
        {
            continue;
        }

        var key = match.Groups["key"].Value.Trim().ToLowerInvariant();
        var value = match.Groups["value"].Value.Trim();
        if (string.IsNullOrWhiteSpace(value))
        {
            continue;
        }

        if (key == "cta")
        {
            keywords = value
                .Split([',', ';', '|'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Where(x => !string.IsNullOrWhiteSpace(x))
                .Select(x => x.Trim())
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Take(10)
                .ToList();
            continue;
        }

        if (key is "img" or "imagem" or "imagens")
        {
            imageUrls.AddRange(ExtractUrls(value));
            continue;
        }

        if (key is "tipo" or "formato")
        {
            postType = NormalizeInstagramPostTypeValue(value);
        }
    }

    input = pattern.Replace(input, " ").Trim();
    imageUrls = NormalizeExternalUrls(imageUrls, 10);
    return new InstagramCreateInput(input, keywords, imageUrls, postType);
}

static string NormalizeInstagramPostTypeValue(string? value)
{
    if (string.IsNullOrWhiteSpace(value))
    {
        return "feed";
    }

    var normalized = value.Trim().ToLowerInvariant();
    if (normalized.StartsWith("story", StringComparison.OrdinalIgnoreCase) || normalized == "stories")
    {
        return "story";
    }

    if (normalized.StartsWith("reel", StringComparison.OrdinalIgnoreCase))
    {
        return "reel";
    }

    return "feed";
}

static List<string> ExtractUrls(string text)
{
    if (string.IsNullOrWhiteSpace(text))
    {
        return new List<string>();
    }

    return Regex.Matches(text, @"https?://\S+", RegexOptions.IgnoreCase)
        .Select(m => m.Value.Trim().TrimEnd(')', ']', '}', ',', ';', '.'))
        .Where(x => !string.IsNullOrWhiteSpace(x))
        .Distinct(StringComparer.OrdinalIgnoreCase)
        .ToList();
}

static List<string> NormalizeExternalUrls(IEnumerable<string> urls, int max)
{
    if (urls is null)
    {
        return new List<string>();
    }

    return urls
        .Where(x => !string.IsNullOrWhiteSpace(x))
        .Select(x => x.Trim())
        .Where(x => Uri.TryCreate(x, UriKind.Absolute, out var uri) && (uri.Scheme == Uri.UriSchemeHttp || uri.Scheme == Uri.UriSchemeHttps))
        .Distinct(StringComparer.OrdinalIgnoreCase)
        .Take(Math.Max(1, max))
        .ToList();
}

static List<string> ExtractImageUrlsFromInstagramPostText(string postText)
{
    if (string.IsNullOrWhiteSpace(postText))
    {
        return new List<string>();
    }

    var urls = ExtractUrls(postText);
    var knownImageExt = new[] { ".jpg", ".jpeg", ".png", ".webp", ".gif", ".bmp" };
    return urls
        .Where(url =>
        {
            if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
            {
                return false;
            }

            var path = uri.AbsolutePath.ToLowerInvariant();
            return knownImageExt.Any(path.EndsWith)
                   || uri.Query.Contains("format=", StringComparison.OrdinalIgnoreCase)
                   || uri.Query.Contains("image", StringComparison.OrdinalIgnoreCase);
        })
        .Distinct(StringComparer.OrdinalIgnoreCase)
        .Take(10)
        .ToList();
}

static InstagramImageCommandInput ParseInstagramImageCommandInput(string? argument)
{
    if (string.IsNullOrWhiteSpace(argument))
    {
        return new InstagramImageCommandInput("ultimo", new List<string>(), "Uso: /ig imagem <id|ultimo> <url1,url2> (ou /ig imagem <url1,url2>)");
    }

    var raw = argument.Trim();
    var urls = NormalizeExternalUrls(ExtractUrls(raw), 10);
    if (urls.Count == 0)
    {
        return new InstagramImageCommandInput("ultimo", new List<string>(), "Nenhuma URL valida encontrada. Exemplo: /ig imagem ultimo https://site.com/foto.jpg");
    }

    var firstUrl = urls[0];
    var idx = raw.IndexOf(firstUrl, StringComparison.OrdinalIgnoreCase);
    var prefix = idx > 0 ? raw[..idx].Trim() : string.Empty;
    var draftRef = string.IsNullOrWhiteSpace(prefix) ? "ultimo" : prefix.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).FirstOrDefault() ?? "ultimo";
    return new InstagramImageCommandInput(draftRef, urls, null);
}

static InstagramManageImagesInput ParseInstagramManageImagesInput(string? argument)
{
    const string usage = "Uso: /ig imagens <id|ultimo> [1|1,2|2-4] (ex.: /ig imagens ultimo 1,2)";
    if (string.IsNullOrWhiteSpace(argument))
    {
        return new InstagramManageImagesInput("ultimo", true, new List<int>(), null);
    }

    var raw = argument.Trim();
    var parts = raw.Split(' ', 2, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    string draftRef;
    string? indexesExpression = null;

    if (parts.Length == 1)
    {
        if (LooksLikeImageIndexExpression(parts[0]))
        {
            draftRef = "ultimo";
            indexesExpression = parts[0];
        }
        else
        {
            draftRef = parts[0];
        }
    }
    else
    {
        draftRef = parts[0];
        indexesExpression = parts[1];
    }

    if (string.IsNullOrWhiteSpace(indexesExpression))
    {
        return new InstagramManageImagesInput(draftRef, true, new List<int>(), null);
    }

    var indexes = ParseImageIndexExpression(indexesExpression!);
    if (indexes.Count == 0)
    {
        return new InstagramManageImagesInput("ultimo", false, new List<int>(), usage);
    }

    return new InstagramManageImagesInput(draftRef, false, indexes, null);
}

static bool LooksLikeImageIndexExpression(string value)
{
    if (string.IsNullOrWhiteSpace(value))
    {
        return false;
    }

    return Regex.IsMatch(value.Trim(), @"^\d+(?:\s*-\s*\d+)?(?:\s*,\s*\d+(?:\s*-\s*\d+)?)*$", RegexOptions.CultureInvariant);
}

static List<int> ParseImageIndexExpression(string expression)
{
    var result = new List<int>();
    if (string.IsNullOrWhiteSpace(expression))
    {
        return result;
    }

    var seen = new HashSet<int>();
    var chunks = expression.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
    foreach (var chunkRaw in chunks)
    {
        var chunk = chunkRaw.Trim();
        if (string.IsNullOrWhiteSpace(chunk))
        {
            continue;
        }

        if (chunk.Contains('-', StringComparison.Ordinal))
        {
            var edges = chunk.Split('-', 2, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            if (edges.Length != 2 ||
                !int.TryParse(edges[0], out var start) ||
                !int.TryParse(edges[1], out var end))
            {
                continue;
            }

            if (start <= 0 || end <= 0)
            {
                continue;
            }

            if (start > end)
            {
                (start, end) = (end, start);
            }

            for (var i = start; i <= end; i++)
            {
                if (seen.Add(i))
                {
                    result.Add(i);
                }
            }

            continue;
        }

        if (int.TryParse(chunk, out var single) && single > 0 && seen.Add(single))
        {
            result.Add(single);
        }
    }

    return result;
}

static InstagramTypeCommandInput ParseInstagramTypeCommandInput(string? argument)
{
    if (string.IsNullOrWhiteSpace(argument))
    {
        return new InstagramTypeCommandInput("ultimo", "feed", "Uso: /ig tipo <id|ultimo> <feed|story>");
    }

    var parts = argument.Trim()
        .Split(' ', 2, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    string draftRef;
    string requestedType;
    if (parts.Length == 1)
    {
        draftRef = "ultimo";
        requestedType = parts[0];
    }
    else
    {
        draftRef = parts[0];
        requestedType = parts[1];
    }

    var normalized = NormalizeInstagramPostTypeValue(requestedType);
    if (normalized == "reel")
    {
        return new InstagramTypeCommandInput(draftRef, "feed", "Tipo 'reel' ainda nao suportado. Use feed ou story.");
    }

    return new InstagramTypeCommandInput(draftRef, normalized, null);
}

static InstagramCaptionCommandInput ParseInstagramCaptionCommandInput(string? argument)
{
    if (string.IsNullOrWhiteSpace(argument))
    {
        return new InstagramCaptionCommandInput("ultimo", string.Empty, "Uso: /ig legenda <id|ultimo> <texto> (ou /ig legenda <texto>)");
    }

    var trimmed = argument.Trim();
    var parts = trimmed.Split(' ', 2, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
    if (parts.Length == 0)
    {
        return new InstagramCaptionCommandInput("ultimo", string.Empty, "Uso: /ig legenda <id|ultimo> <texto> (ou /ig legenda <texto>)");
    }

    var first = parts[0];
    var looksLikeDraftRef = string.Equals(first, "ultimo", StringComparison.OrdinalIgnoreCase)
                            || Regex.IsMatch(first, @"^[a-f0-9]{4,32}$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    var draftRef = looksLikeDraftRef ? first : "ultimo";
    var caption = looksLikeDraftRef
        ? (parts.Length > 1 ? parts[1].Trim() : string.Empty)
        : trimmed;

    if (string.IsNullOrWhiteSpace(caption))
    {
        return new InstagramCaptionCommandInput(draftRef, string.Empty, "Legenda vazia. Exemplo: /ig legenda ultimo Oferta de hoje... cta BIKE");
    }

    return new InstagramCaptionCommandInput(draftRef, caption, null);
}

static InstagramCaptionChoiceInput ParseInstagramCaptionChoiceInput(string? argument)
{
    if (string.IsNullOrWhiteSpace(argument))
    {
        return new InstagramCaptionChoiceInput(0, "ultimo", "Uso: /ig leg <numero> <id|ultimo> (ex.: /ig leg 2 ultimo)");
    }

    var parts = argument.Trim()
        .Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
    if (parts.Length == 0 || !int.TryParse(parts[0], out var option) || option <= 0)
    {
        return new InstagramCaptionChoiceInput(0, "ultimo", "Numero de legenda invalido. Exemplo: /ig leg 2");
    }

    var draftRef = parts.Length >= 2 ? parts[1] : "ultimo";
    return new InstagramCaptionChoiceInput(option, draftRef, null);
}

static InstagramCaptionTemplateInput ParseInstagramCaptionTemplateInput(string? argument)
{
    const string usage = "Uso: /ig template <id|ultimo> <1|2|3> (ou /ig template <1|2|3>)";
    if (string.IsNullOrWhiteSpace(argument))
    {
        return new InstagramCaptionTemplateInput("ultimo", 0, usage);
    }

    var parts = argument.Trim()
        .Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
    if (parts.Length == 0)
    {
        return new InstagramCaptionTemplateInput("ultimo", 0, usage);
    }

    var draftRef = "ultimo";
    var templateToken = parts[0];
    if (!int.TryParse(templateToken, out var templateNumber))
    {
        if (parts.Length < 2)
        {
            return new InstagramCaptionTemplateInput("ultimo", 0, usage);
        }

        draftRef = parts[0];
        templateToken = parts[1];
        if (!int.TryParse(templateToken, out templateNumber))
        {
            return new InstagramCaptionTemplateInput("ultimo", 0, "Template invalido. Use 1, 2 ou 3.");
        }
    }
    else if (parts.Length >= 2)
    {
        draftRef = parts[1];
    }

    if (templateNumber is < 1 or > 3)
    {
        return new InstagramCaptionTemplateInput("ultimo", 0, "Template invalido. Use 1, 2 ou 3.");
    }

    return new InstagramCaptionTemplateInput(draftRef, templateNumber, null);
}

static InstagramCtaCommandInput ParseInstagramCtaCommandInput(string? argument)
{
    if (string.IsNullOrWhiteSpace(argument))
    {
        return new InstagramCtaCommandInput("ultimo", new List<string>(), "Uso: /ig cta <id|ultimo> <palavra1,palavra2>");
    }

    var trimmed = argument.Trim();
    var parts = trimmed.Split(' ', 2, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
    if (parts.Length == 0)
    {
        return new InstagramCtaCommandInput("ultimo", new List<string>(), "Uso: /ig cta <id|ultimo> <palavra1,palavra2>");
    }

    var first = parts[0];
    var looksLikeDraftRef = string.Equals(first, "ultimo", StringComparison.OrdinalIgnoreCase)
                            || Regex.IsMatch(first, @"^[a-f0-9]{4,32}$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    var draftRef = looksLikeDraftRef ? first : "ultimo";
    var keywordsRaw = looksLikeDraftRef
        ? (parts.Length > 1 ? parts[1] : string.Empty)
        : trimmed;

    var rawKeywords = keywordsRaw.Contains(',', StringComparison.Ordinal)
        || keywordsRaw.Contains(';', StringComparison.Ordinal)
        || keywordsRaw.Contains('|', StringComparison.Ordinal)
        ? keywordsRaw.Split([',', ';', '|'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToList()
        : new List<string> { keywordsRaw };

    var keywords = NormalizeInstagramCtaKeywords(rawKeywords);
    if (keywords.Count == 0)
    {
        return new InstagramCtaCommandInput(draftRef, new List<string>(), "CTA invalido. Exemplo: /ig cta ultimo BIKE");
    }

    return new InstagramCtaCommandInput(draftRef, keywords, null);
}

static InstagramBoostCommandInput ParseInstagramBoostCommandInput(string? argument)
{
    const string usage = "Uso: /ig anunciar <id|ultimo> conta=act_123 pagina=123 url=https://... cta=SHOP_NOW budget=20 dias=3";
    if (string.IsNullOrWhiteSpace(argument))
    {
        return new InstagramBoostCommandInput("ultimo", string.Empty, null, null, null, null, "SHOP_NOW", 20m, 3, "BR", usage);
    }

    var tokens = argument.Trim()
        .Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
        .ToList();
    if (tokens.Count == 0)
    {
        return new InstagramBoostCommandInput("ultimo", string.Empty, null, null, null, null, "SHOP_NOW", 20m, 3, "BR", usage);
    }

    var draftRef = "ultimo";
    var startIdx = 0;
    if (!tokens[0].Contains('=', StringComparison.Ordinal) && !tokens[0].Contains(':', StringComparison.Ordinal))
    {
        draftRef = tokens[0];
        startIdx = 1;
    }

    var kv = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
    for (var i = startIdx; i < tokens.Count; i++)
    {
        var token = tokens[i];
        var eq = token.IndexOf('=');
        if (eq <= 0 || eq == token.Length - 1)
        {
            continue;
        }

        var key = token[..eq].Trim();
        var value = token[(eq + 1)..].Trim();
        if (string.IsNullOrWhiteSpace(key) || string.IsNullOrWhiteSpace(value))
        {
            continue;
        }

        kv[key] = value;
    }

    var rawAccount = GetFirst(kv, "conta", "adaccount", "act", "ad_account");
    if (string.IsNullOrWhiteSpace(rawAccount))
    {
        return new InstagramBoostCommandInput(draftRef, string.Empty, null, null, null, null, "SHOP_NOW", 20m, 3, "BR", "Conta de anuncio obrigatoria. Exemplo: conta=act_123456789");
    }

    var normalizedAccount = NormalizeAdAccountId(rawAccount);
    if (string.IsNullOrWhiteSpace(normalizedAccount))
    {
        return new InstagramBoostCommandInput(draftRef, string.Empty, null, null, null, null, "SHOP_NOW", 20m, 3, "BR", "Conta de anuncio invalida. Use apenas numeros ou act_123456.");
    }

    var pageId = GetFirst(kv, "pagina", "page", "pageid", "page_id");
    var adSetId = GetFirst(kv, "adset", "adsetid", "ad_set", "ad_set_id");
    var campaignId = GetFirst(kv, "campanha", "campaign", "campaignid", "campaign_id");
    var url = GetFirst(kv, "url", "link", "site", "website");

    var cta = (GetFirst(kv, "cta", "botao", "button") ?? "SHOP_NOW").Trim().ToUpperInvariant();
    cta = Regex.Replace(cta, @"\s+", "_", RegexOptions.CultureInvariant);

    var budgetRaw = (GetFirst(kv, "budget", "orcamento", "valor") ?? "20").Trim();
    budgetRaw = budgetRaw.Replace(',', '.');
    if (!decimal.TryParse(budgetRaw, System.Globalization.NumberStyles.Number, System.Globalization.CultureInfo.InvariantCulture, out var budget) || budget <= 0)
    {
        budget = 20m;
    }

    var daysRaw = GetFirst(kv, "dias", "days", "duracao", "duration");
    if (!int.TryParse(daysRaw, out var days) || days <= 0)
    {
        days = 3;
    }

    var country = (GetFirst(kv, "pais", "country") ?? "BR").Trim().ToUpperInvariant();
    if (country.Length != 2)
    {
        country = "BR";
    }

    return new InstagramBoostCommandInput(draftRef, normalizedAccount, pageId, adSetId, campaignId, url, cta, budget, days, country, null);
}

static string? GetFirst(IReadOnlyDictionary<string, string> source, params string[] keys)
{
    foreach (var key in keys)
    {
        if (source.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value))
        {
            return value.Trim();
        }
    }

    return null;
}

static string? NormalizeAdAccountId(string? value)
{
    if (string.IsNullOrWhiteSpace(value))
    {
        return null;
    }

    var raw = value.Trim();
    if (raw.StartsWith("act_", StringComparison.OrdinalIgnoreCase))
    {
        raw = raw[4..];
    }

    raw = raw.Trim();
    if (!Regex.IsMatch(raw, @"^\d{5,}$", RegexOptions.CultureInvariant))
    {
        return null;
    }

    return raw;
}

static List<string> BuildDefaultCtaKeywords(string productName)
{
    var list = new List<string> { "link" };
    if (string.IsNullOrWhiteSpace(productName))
    {
        return list;
    }

    var normalized = Regex.Replace(productName, @"[^\w\s]", " ");
    var parts = normalized
        .Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
        .Select(x => x.Trim().ToLowerInvariant())
        .Where(x => x.Length >= 3)
        .Distinct(StringComparer.OrdinalIgnoreCase)
        .Take(3);

    list.AddRange(parts);
    return NormalizeInstagramCtaKeywords(list);
}

static List<string> NormalizeInstagramCtaKeywords(IEnumerable<string>? keywords, int max = 10)
{
    if (keywords is null)
    {
        return new List<string>();
    }

    return keywords
        .Where(x => !string.IsNullOrWhiteSpace(x))
        .Select(x => x.Trim())
        .Select(x => x.Trim('\"', '\'', '`', '.', ',', ';', ':', '!', '?', '(', ')', '[', ']', '{', '}', '<', '>'))
        .Select(x => Regex.Replace(x, @"\s{2,}", " ", RegexOptions.CultureInvariant))
        .Where(IsLikelyInstagramCtaKeyword)
        .Select(x => x.ToUpperInvariant())
        .Distinct(StringComparer.OrdinalIgnoreCase)
        .Take(Math.Max(1, max))
        .ToList();
}

static List<string> ExtractInstagramCtaKeywordsFromCaptions(IEnumerable<string> captions)
{
    var found = new List<string>();
    if (captions is null)
    {
        return found;
    }

    var patterns = new[]
    {
        "\\b(?:comente|comenta|digite|mande|envie)\\b[^\\n\\r]{0,80}?[\\\"']\\s*(?<kw>[A-Za-z0-9][A-Za-z0-9 _-]{0,29})\\s*[\\\"']",
        "\\b(?:palavra(?:-|\\s)?chave|keyword|codigo)\\b\\s*(?:[:=-]|(?:e|eh))?\\s*(?<kw>[A-Za-z0-9][A-Za-z0-9 _-]{0,29})",
        "\\b(?:comente|comenta|digite|mande|envie)\\s+(?:a\\s+palavra\\s+|o\\s+codigo\\s+)?(?<kw>[A-Za-z0-9][A-Za-z0-9_-]{1,29})\\b"
    };

    foreach (var caption in captions)
    {
        if (string.IsNullOrWhiteSpace(caption))
        {
            continue;
        }

        foreach (var pattern in patterns)
        {
            foreach (Match match in Regex.Matches(caption, pattern, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant))
            {
                if (match.Success && match.Groups["kw"].Success)
                {
                    found.Add(match.Groups["kw"].Value);
                }
            }
        }
    }

    return NormalizeInstagramCtaKeywords(found);
}

static bool IsLikelyInstagramCtaKeyword(string? keyword)
{
    if (string.IsNullOrWhiteSpace(keyword))
    {
        return false;
    }

    var value = keyword.Trim();
    if (value.Length < 2 || value.Length > 30)
    {
        return false;
    }
    if (value.StartsWith("http://", StringComparison.OrdinalIgnoreCase) || value.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
    {
        return false;
    }

    var blocked = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "A", "O", "UM", "UMA", "NO", "NA", "PARA", "PRA", "COM", "DE", "DO", "DA"
    };

    return !blocked.Contains(value);
}

static void SyncDraftCtasFromCaptionIfPresent(InstagramPublishDraft draft, string? caption)
{
    if (draft is null || string.IsNullOrWhiteSpace(caption))
    {
        return;
    }

    var extracted = ExtractInstagramCtaKeywordsFromCaptions(new[] { caption });
    if (extracted.Count == 0)
    {
        return;
    }

    var link = draft.Ctas.FirstOrDefault(c => !string.IsNullOrWhiteSpace(c.Link))?.Link
               ?? ExtractFirstUrl(caption)
               ?? ExtractFirstUrl(draft.Caption)
               ?? ExtractFirstUrl(string.Join(" ", draft.CaptionOptions ?? new List<string>()));
    if (string.IsNullOrWhiteSpace(link))
    {
        return;
    }

    draft.Ctas = extracted
        .Select(keyword => new InstagramCtaOption
        {
            Keyword = keyword,
            Link = link
        })
        .ToList();
}

static List<InstagramCtaOption> BuildEffectiveDraftCtas(InstagramPublishDraft draft)
{
    if (draft is null)
    {
        return new List<InstagramCtaOption>();
    }

    var allCaptions = (draft.CaptionOptions ?? new List<string>())
        .Where(x => !string.IsNullOrWhiteSpace(x))
        .ToList();
    if (!string.IsNullOrWhiteSpace(draft.Caption))
    {
        allCaptions.Insert(0, draft.Caption);
    }

    var fallbackLink = draft.Ctas.FirstOrDefault(c => !string.IsNullOrWhiteSpace(c.Link))?.Link
                       ?? ExtractFirstUrl(draft.Caption)
                       ?? ExtractFirstUrl(string.Join(" ", allCaptions));

    var map = new Dictionary<string, InstagramCtaOption>(StringComparer.OrdinalIgnoreCase);
    foreach (var cta in draft.Ctas ?? new List<InstagramCtaOption>())
    {
        var keyword = NormalizeInstagramCtaKeywords(new[] { cta.Keyword }).FirstOrDefault();
        if (string.IsNullOrWhiteSpace(keyword))
        {
            continue;
        }

        map[keyword] = new InstagramCtaOption
        {
            Keyword = keyword,
            Link = string.IsNullOrWhiteSpace(cta.Link) ? (fallbackLink ?? string.Empty) : cta.Link
        };
    }

    var extracted = ExtractInstagramCtaKeywordsFromCaptions(allCaptions);
    foreach (var keyword in extracted)
    {
        if (!map.ContainsKey(keyword))
        {
            map[keyword] = new InstagramCtaOption
            {
                Keyword = keyword,
                Link = fallbackLink ?? string.Empty
            };
        }
    }

    if (extracted.Count > 0 && !extracted.Contains("LINK", StringComparer.OrdinalIgnoreCase))
    {
        map.Remove("LINK");
    }

    return map.Values
        .Where(x => !string.IsNullOrWhiteSpace(x.Keyword))
        .Where(x => !string.IsNullOrWhiteSpace(x.Link))
        .ToList();
}

static string BuildInstagramDraftProductName(string input, string postText)
{
    var cleaned = Regex.Replace(input ?? string.Empty, @"https?://\S+", string.Empty, RegexOptions.IgnoreCase).Trim();
    if (!string.IsNullOrWhiteSpace(cleaned))
    {
        return cleaned.Length <= 120 ? cleaned : cleaned[..120].TrimEnd();
    }

    var productLine = postText.Replace("\r", string.Empty)
        .Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
        .FirstOrDefault(x => x.StartsWith("Produto:", StringComparison.OrdinalIgnoreCase));
    if (!string.IsNullOrWhiteSpace(productLine))
    {
        return productLine["Produto:".Length..].Trim();
    }

    return "Produto Instagram";
}

static (List<string> Captions, string Hashtags) ExtractInstagramCaptionOptionsAndHashtags(string postText)
{
    if (string.IsNullOrWhiteSpace(postText))
    {
        return (new List<string>(), string.Empty);
    }

    var lines = postText.Replace("\r", string.Empty).Split('\n');
    var captions = ExtractAllInstagramCaptionSections(lines);
    var hashtags = ExtractInstagramSection(lines, line => line.Trim().StartsWith("Hashtags sugeridas", StringComparison.OrdinalIgnoreCase));

    if (captions.Count == 0)
    {
        var fallback = string.Join('\n', lines
            .Select(x => x.Trim())
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .Where(x => !x.StartsWith("POST PARA INSTAGRAM", StringComparison.OrdinalIgnoreCase))
            .Where(x => !x.StartsWith("Produto:", StringComparison.OrdinalIgnoreCase))
            .Where(x => !x.StartsWith("Link afiliado:", StringComparison.OrdinalIgnoreCase))
            .Where(x => !IsInstagramSectionHeader(x))
            .Take(10)).Trim();
        if (!string.IsNullOrWhiteSpace(fallback))
        {
            captions.Add(fallback);
        }
    }

    if (string.IsNullOrWhiteSpace(hashtags))
    {
        hashtags = string.Join(' ', Regex.Matches(postText, @"#\w+", RegexOptions.CultureInvariant)
            .Select(m => m.Value)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Take(20));
    }

    return (captions, hashtags.Trim());
}

static List<string> ExtractAllInstagramCaptionSections(string[] lines)
{
    var result = new List<string>();
    if (lines is null || lines.Length == 0)
    {
        return result;
    }

    for (var i = 0; i < lines.Length; i++)
    {
        var line = (lines[i] ?? string.Empty).Trim();
        if (!Regex.IsMatch(line, @"^Legenda\s+\d+\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant))
        {
            continue;
        }

        var sb = new StringBuilder();
        for (var j = i + 1; j < lines.Length; j++)
        {
            var candidate = (lines[j] ?? string.Empty).Trim();
            if (IsInstagramSectionHeader(candidate))
            {
                break;
            }

            if (string.IsNullOrWhiteSpace(candidate))
            {
                if (sb.Length > 0 && sb[^1] != '\n')
                {
                    sb.AppendLine();
                }
                continue;
            }

            if (sb.Length > 0 && sb[^1] != '\n')
            {
                sb.AppendLine();
            }
            sb.Append(candidate);
        }

        var caption = sb.ToString().Trim();
        if (!string.IsNullOrWhiteSpace(caption))
        {
            result.Add(caption);
        }
    }

    return result;
}

static string ExtractInstagramSection(string[] lines, Func<string, bool> isHeader)
{
    var headerIndex = Array.FindIndex(lines, line => isHeader(line ?? string.Empty));
    if (headerIndex < 0)
    {
        return string.Empty;
    }

    var sb = new StringBuilder();
    for (var i = headerIndex + 1; i < lines.Length; i++)
    {
        var line = (lines[i] ?? string.Empty).Trim();
        if (IsInstagramSectionHeader(line))
        {
            break;
        }

        if (string.IsNullOrWhiteSpace(line))
        {
            if (sb.Length > 0 && sb[^1] != '\n')
            {
                sb.AppendLine();
            }
            continue;
        }

        if (sb.Length > 0 && sb[^1] != '\n')
        {
            sb.AppendLine();
        }
        sb.Append(line);
    }

    return sb.ToString().Trim();
}

static async Task SendInstagramImagesIfAnyAsync(
    InstagramPostSettings settings,
    string? inputText,
    string? contextText,
    string postText,
    string? instanceName,
    string chatId,
    InstagramLinkMetaService metaService,
    InstagramImageDownloadService imageDownloader,
    IWhatsAppGateway gateway,
    CancellationToken ct)
{
    if (!settings.UseImageDownload) return;

    var link = ExtractFirstUrl(inputText) ?? ExtractFirstUrl(contextText) ?? ExtractLinkFromPost(postText);
    if (string.IsNullOrWhiteSpace(link)) return;

    var meta = await metaService.GetMetaAsync(link, ct);
    var urls = meta.Images;
    if (urls.Count == 0) return;

    var downloaded = await imageDownloader.DownloadAsync(urls, ct);
    if (downloaded.Count == 0) return;

    foreach (var url in downloaded)
    {
        await gateway.SendImageUrlAsync(instanceName, chatId, url, null, null, "insta.jpg", ct);
    }
}

static string? ExtractLinkFromPost(string text)
{
    if (string.IsNullOrWhiteSpace(text)) return null;
    var lines = text.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
    foreach (var line in lines)
    {
        if (line.StartsWith("Link afiliado:", StringComparison.OrdinalIgnoreCase))
        {
            var link = line.Replace("Link afiliado:", string.Empty, StringComparison.OrdinalIgnoreCase).Trim();
            var url = ExtractFirstUrl(link);
            if (!string.IsNullOrWhiteSpace(url)) return url;
        }
    }
    return ExtractFirstUrl(text);
}

static string? ExtractFirstUrl(string? text)
{
    if (string.IsNullOrWhiteSpace(text)) return null;
    var match = Regex.Match(text, @"https?://\S+", RegexOptions.IgnoreCase);
    return match.Success ? match.Value.Trim() : null;
}

static async Task<List<string>> NormalizeInstagramImagesAsync(
    IHttpClientFactory httpClientFactory,
    IMediaStore mediaStore,
    string? publicBaseUrl,
    List<string> imageUrls,
    CancellationToken ct)
{
    var results = new List<string>();
    if (imageUrls is null || imageUrls.Count == 0) return results;
    if (string.IsNullOrWhiteSpace(publicBaseUrl)) return results;

    var client = httpClientFactory.CreateClient("default");
    foreach (var url in imageUrls.Take(10))
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri)) continue;
        try
        {
            using var request = BuildImageFetchRequest(uri);
            using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);
            if (!response.IsSuccessStatusCode) continue;
            var bytes = await response.Content.ReadAsByteArrayAsync(ct);
            if (bytes.Length == 0) continue;

            var normalizedBytes = NormalizeImageBytes(bytes);
            if (normalizedBytes is null) continue;

            var id = mediaStore.Add(normalizedBytes, "image/jpeg", TimeSpan.FromHours(4));
            var publicUrl = BuildPublicMediaUrl(publicBaseUrl, id);
            if (!string.IsNullOrWhiteSpace(publicUrl))
            {
                results.Add(publicUrl);
            }
        }
        catch { }
    }
    return results;
}

static HttpRequestMessage BuildImageFetchRequest(Uri uri)
{
    var request = new HttpRequestMessage(HttpMethod.Get, uri);
    request.Headers.Accept.ParseAdd("image/avif,image/webp,image/apng,image/*,*/*;q=0.8");
    request.Headers.AcceptLanguage.ParseAdd("pt-BR,pt;q=0.9,en;q=0.8");
    request.Headers.CacheControl = new System.Net.Http.Headers.CacheControlHeaderValue { NoCache = true };
    request.Headers.Referrer = new Uri(uri.GetLeftPart(UriPartial.Authority));
    return request;
}

static byte[]? NormalizeImageBytes(byte[] input)
    => ImageNormalizationSupport.NormalizeForInstagramPublication(input, "feed");

static string BuildPublicMediaUrl(string publicBaseUrl, string id)
{
    var baseUrl = publicBaseUrl.TrimEnd('/');
    var url = baseUrl + $"/media/{id}.jpg";
    if (url.Contains("ngrok-free", StringComparison.OrdinalIgnoreCase) || url.Contains("ngrok.app", StringComparison.OrdinalIgnoreCase))
    {
        url += "?ngrok-skip-browser-warning=1";
    }
    return url;
}

static bool IsInstagramSectionHeader(string line)
{
    if (string.IsNullOrWhiteSpace(line)) return false;
    var t = line.Trim();
    return Regex.IsMatch(t, @"^Legenda\s+\d+\b", RegexOptions.IgnoreCase)
           || t.StartsWith("Hashtags sugeridas", StringComparison.OrdinalIgnoreCase)
           || t.StartsWith("SugestÃµes de imagem", StringComparison.OrdinalIgnoreCase)
           || t.StartsWith("Sugestoes de imagem", StringComparison.OrdinalIgnoreCase)
           || t.StartsWith("Post extra", StringComparison.OrdinalIgnoreCase)
           || t.StartsWith("SugestÃ£o rÃ¡pida", StringComparison.OrdinalIgnoreCase)
           || t.StartsWith("Sugestao rapida", StringComparison.OrdinalIgnoreCase);
}

static bool IsInstagramBotResponse(string text)
{
    if (string.IsNullOrWhiteSpace(text)) return false;
    return text.Contains("POST PARA INSTAGRAM", StringComparison.OrdinalIgnoreCase)
           || text.Contains("Legenda 1", StringComparison.OrdinalIgnoreCase)
           || text.Contains("Hashtags sugeridas", StringComparison.OrdinalIgnoreCase)
           || text.StartsWith("Qual produto?", StringComparison.OrdinalIgnoreCase)
           || text.Contains("Envie o nome ou o link", StringComparison.OrdinalIgnoreCase);
}

static bool TryGetInstagramInlineProduct(string text, List<string> triggers, out string product)
{
    product = string.Empty;
    if (string.IsNullOrWhiteSpace(text)) return false;
    if (triggers is null || triggers.Count == 0) return false;

    var normalized = text.Trim();
    foreach (var trigger in triggers)
    {
        if (string.IsNullOrWhiteSpace(trigger)) continue;
        var trimmedTrigger = trigger.Trim();
        if (!normalized.StartsWith(trimmedTrigger, StringComparison.OrdinalIgnoreCase)) continue;

        var remaining = normalized[trimmedTrigger.Length..].Trim();
        remaining = remaining.Trim('-', ':');
        if (!string.IsNullOrWhiteSpace(remaining))
        {
            product = remaining;
            return true;
        }
    }

    return false;
}

static string BuildResponderMessage(LinkResponderSettings responder, string convertedText)
{
    var template = responder.ReplyTemplate;
    if (string.IsNullOrWhiteSpace(template))
    {
        return convertedText;
    }

    var result = template;
    if (result.Contains("{link}", StringComparison.OrdinalIgnoreCase))
    {
        result = result.Replace("{link}", convertedText, StringComparison.OrdinalIgnoreCase);
    }

    if (result.Contains("{text}", StringComparison.OrdinalIgnoreCase))
    {
        result = result.Replace("{text}", convertedText, StringComparison.OrdinalIgnoreCase);
    }

    if (!result.Contains(convertedText, StringComparison.OrdinalIgnoreCase))
    {
        result = $"{result}\n{convertedText}";
    }

    return result;
}

static async Task<(string Text, List<string> TrackingIds)> ApplyTrackingAsync(string text, ILinkTrackingStore store, string? publicBaseUrl, bool trackingEnabled, CancellationToken ct)
{
    if (!trackingEnabled || string.IsNullOrWhiteSpace(text) || string.IsNullOrWhiteSpace(publicBaseUrl))
    {
        return (text, new List<string>());
    }

    var baseUrl = publicBaseUrl.TrimEnd('/');
    var trackingSuffix = GetTrackingSuffix(baseUrl);
    var matches = UrlRegex().Matches(text);
    if (matches.Count == 0)
    {
        return (text, new List<string>());
    }

    var sb = new StringBuilder(text.Length + 32);
    var lastIndex = 0;
    var trackingIds = new List<string>();
    foreach (Match match in matches)
    {
        sb.Append(text, lastIndex, match.Index - lastIndex);
        var url = match.Value;
        if (url.StartsWith(baseUrl, StringComparison.OrdinalIgnoreCase))
        {
            sb.Append(url);
        }
        else
        {
            var entry = await store.GetOrCreateAsync(url, ct);
            sb.Append($"{baseUrl}/r/{entry.Id}{trackingSuffix}");
            trackingIds.Add(entry.Id);
        }
        lastIndex = match.Index + match.Length;
    }
    sb.Append(text, lastIndex, text.Length - lastIndex);
    return (sb.ToString(), trackingIds);
}

static Regex UrlRegex() => new(@"https?://[^\s]+", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

static string GetTrackingSuffix(string baseUrl)
{
    var lower = baseUrl.ToLowerInvariant();
    if (lower.Contains("ngrok-free") || lower.Contains("ngrok.app"))
    {
        return "?ngrok-skip-browser-warning=1";
    }
    return string.Empty;
}

static string ExtractMessageText(JsonElement node)
{
    if (node.TryGetProperty("message", out var messageNode))
    {
        while (TryUnwrapMessageEnvelope(messageNode, out var innerMessage))
        {
            messageNode = innerMessage;
            var innerText = ExtractMessageText(messageNode);
            if (!string.IsNullOrWhiteSpace(innerText))
            {
                return innerText;
            }
        }

        var conversation = GetString(messageNode, "conversation", "text", "body");
        if (!string.IsNullOrWhiteSpace(conversation))
        {
            return conversation;
        }

        if (messageNode.TryGetProperty("extendedTextMessage", out var extended) &&
            extended.TryGetProperty("text", out var extText) &&
            extText.ValueKind == JsonValueKind.String)
        {
            return extText.GetString() ?? string.Empty;
        }

        if (TryGetCaption(messageNode, "imageMessage", out var caption) ||
            TryGetCaption(messageNode, "videoMessage", out caption) ||
            TryGetCaption(messageNode, "documentMessage", out caption))
        {
            return caption;
        }
    }

    var direct = GetString(node, "text", "body");
    return direct ?? string.Empty;
}

static bool TryGetCaption(JsonElement messageNode, string property, out string caption)
{
    caption = string.Empty;
    if (messageNode.TryGetProperty(property, out var mediaNode) &&
        mediaNode.TryGetProperty("caption", out var captionNode) &&
        captionNode.ValueKind == JsonValueKind.String)
    {
        caption = captionNode.GetString() ?? string.Empty;
        return !string.IsNullOrWhiteSpace(caption);
    }

    return false;
}

static string? GetString(JsonElement node, params string[] names)
{
    foreach (var name in names)
    {
        if (node.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String)
        {
            return value.GetString();
        }
    }

    return null;
}

static bool GetBool(JsonElement node, string name)
{
    if (node.TryGetProperty(name, out var value))
    {
        if (value.ValueKind == JsonValueKind.True) return true;
        if (value.ValueKind == JsonValueKind.False) return false;
    }

    return false;
}

static async Task<InstagramPublishExecutionResult> PublishInstagramDraftAsync(
    string id,
    InstagramPublishSettings publishSettings,
    VilaNvidiaSettings vilaSettings,
    GeminiSettings geminiSettings,
    IInstagramPublishStore publishStore,
    IInstagramPublishLogStore publishLogStore,
    IHttpClientFactory httpClientFactory,
    IMediaStore mediaStore,
    string? publicBaseUrl,
    CancellationToken ct)
{
    if (!publishSettings.Enabled)
    {
        const string error = "Publicacao Instagram desativada.";
        await publishLogStore.AppendAsync(new InstagramPublishLogEntry
        {
            Action = "publish",
            Success = false,
            DraftId = id,
            Error = error
        }, ct);
        return new InstagramPublishExecutionResult(false, StatusCodes.Status400BadRequest, null, error, id);
    }

    if (string.IsNullOrWhiteSpace(publishSettings.AccessToken) || publishSettings.AccessToken == "********")
    {
        const string error = "Access token nao configurado.";
        await publishLogStore.AppendAsync(new InstagramPublishLogEntry
        {
            Action = "publish",
            Success = false,
            DraftId = id,
            Error = error
        }, ct);
        return new InstagramPublishExecutionResult(false, StatusCodes.Status400BadRequest, null, error, id);
    }

    if (string.IsNullOrWhiteSpace(publishSettings.InstagramUserId))
    {
        const string error = "Instagram user id nao configurado.";
        await publishLogStore.AppendAsync(new InstagramPublishLogEntry
        {
            Action = "publish",
            Success = false,
            DraftId = id,
            Error = error
        }, ct);
        return new InstagramPublishExecutionResult(false, StatusCodes.Status400BadRequest, null, error, id);
    }

    var draft = await publishStore.GetAsync(id, ct);
    if (draft is null)
    {
        const string error = "Rascunho nao encontrado.";
        await publishLogStore.AppendAsync(new InstagramPublishLogEntry
        {
            Action = "publish",
            Success = false,
            DraftId = id,
            Error = error
        }, ct);
        return new InstagramPublishExecutionResult(false, StatusCodes.Status404NotFound, null, error, id);
    }

    var effectiveCaption = draft.Caption;
    if (string.IsNullOrWhiteSpace(effectiveCaption) && draft.CaptionOptions.Count > 0)
    {
        var idx = draft.SelectedCaptionIndex <= 0 ? 1 : draft.SelectedCaptionIndex;
        idx = Math.Min(idx, draft.CaptionOptions.Count);
        effectiveCaption = draft.CaptionOptions[idx - 1];
    }

    var caption = BuildInstagramCaption(effectiveCaption, draft.Hashtags, draft.Ctas);
    draft.SelectedImageIndexes = SanitizeInstagramSelectedIndexes(draft.SelectedImageIndexes, draft.ImageUrls.Count);
    var selectedImageUrls = ResolveSelectedInstagramImageUrls(draft);
    var publishImageUrls = selectedImageUrls;
    var normalized = await NormalizeInstagramImagesAsync(httpClientFactory, mediaStore, publicBaseUrl, selectedImageUrls, ct);
    if (normalized.Count > 0)
    {
        publishImageUrls = normalized;
    }
    var qualityCheck = await ValidateInstagramDraftQualityAsync(
        draft,
        effectiveCaption,
        publishImageUrls,
        vilaSettings,
        geminiSettings,
        httpClientFactory,
        ct);
    if (!qualityCheck.IsValid)
    {
        draft.Status = "failed";
        draft.MediaId = null;
        draft.Error = qualityCheck.Error;
        await publishStore.UpdateAsync(draft, ct);
        await publishLogStore.AppendAsync(new InstagramPublishLogEntry
        {
            Action = "publish",
            Success = false,
            DraftId = draft.Id,
            Error = qualityCheck.Error,
            Details = qualityCheck.Details
        }, ct);
        return new InstagramPublishExecutionResult(false, StatusCodes.Status400BadRequest, null, qualityCheck.Error, draft.Id);
    }
    draft.PostType = NormalizeInstagramPostTypeValue(draft.PostType);

    var (ok, mediaId, errorMessage) = await PublishToInstagramAsync(
        httpClientFactory,
        publishSettings.GraphBaseUrl,
        publishSettings.InstagramUserId!,
        publishSettings.AccessToken!,
        draft.PostType,
        publishImageUrls,
        caption,
        ct);
    if (!ok &&
        normalized.Count > 0 &&
        selectedImageUrls.Count > 0 &&
        IsInstagramMediaTypeError(errorMessage))
    {
        // Retry with original source URLs when hosted/transcoded URL is rejected by Graph.
        var fallbackOriginals = selectedImageUrls
            .Where(x => !IsLikelyWebpUrl(x))
            .ToList();
        if (fallbackOriginals.Count > 0)
        {
            (ok, mediaId, errorMessage) = await PublishToInstagramAsync(
                httpClientFactory,
                publishSettings.GraphBaseUrl,
                publishSettings.InstagramUserId!,
                publishSettings.AccessToken!,
                draft.PostType,
                fallbackOriginals,
                caption,
                ct);
        }
    }

    draft.Status = ok ? "published" : "failed";
    draft.MediaId = mediaId;
    draft.Error = ok ? null : errorMessage;
    await publishStore.UpdateAsync(draft, ct);
    await publishLogStore.AppendAsync(new InstagramPublishLogEntry
    {
        Action = "publish",
        Success = ok,
        DraftId = draft.Id,
        MediaId = mediaId,
        Error = ok ? null : errorMessage,
        Details = ok ? "Publicado com sucesso" : "Falha ao publicar"
    }, ct);

    return new InstagramPublishExecutionResult(ok, StatusCodes.Status200OK, mediaId, errorMessage, draft.Id);
}

static async Task<(bool IsValid, string? Error, string Details)> ValidateInstagramDraftQualityAsync(
    InstagramPublishDraft draft,
    string? effectiveCaption,
    IReadOnlyList<string> publishImageUrls,
    VilaNvidiaSettings vilaSettings,
    GeminiSettings geminiSettings,
    IHttpClientFactory httpClientFactory,
    CancellationToken ct)
{
    var productName = (draft.ProductName ?? string.Empty).Trim();
    if (string.IsNullOrWhiteSpace(productName))
    {
        return (false, "Produto vazio no rascunho. Defina um produto real antes de publicar.", "quality=product_missing");
    }

    if (publishImageUrls.Count == 0 || publishImageUrls.All(string.IsNullOrWhiteSpace))
    {
        return (false, "Sem imagens para validar/publicar.", "quality=image_missing");
    }

    if (!IsCaptionAlignedWithProduct(productName, effectiveCaption, out var captionDetails))
    {
        return (false, "Legenda nao condiz com o produto informado. Revise o texto antes de publicar.", $"quality=caption_mismatch;{captionDetails}");
    }

    if (!IsVisionValidationConfigured(vilaSettings, geminiSettings))
    {
        return (false, "Validacao de imagem/produto exige VILA ou Gemini configurado.", "quality=vision_not_configured");
    }

    var firstMedia = publishImageUrls.FirstOrDefault(x => !string.IsNullOrWhiteSpace(x));
    if (string.IsNullOrWhiteSpace(firstMedia))
    {
        return (false, "Imagem invalida para validacao.", "quality=image_invalid");
    }

    var probeClient = httpClientFactory.CreateClient("default");
    if (await IsLikelyVideoUrlAsync(probeClient, firstMedia, ct))
    {
        return (true, null, "quality=ok;video_validation_skipped=true");
    }

    var imageValidation = await EvaluateImageProductMatchWithVisionAsync(
        productName,
        effectiveCaption ?? string.Empty,
        firstMedia,
        vilaSettings,
        geminiSettings,
        httpClientFactory,
        ct);
    if (imageValidation is null)
    {
        return (false, "Nao foi possivel validar a imagem com IA. Tente outra imagem.", "quality=vision_validation_failed");
    }

    const int minimumMatchScore = 65;
    if (!imageValidation.Value.IsMatch || imageValidation.Value.Score < minimumMatchScore)
    {
        var reason = string.IsNullOrWhiteSpace(imageValidation.Value.Reason) ? "sem motivo informado" : imageValidation.Value.Reason;
        return (false, $"Imagem nao condiz com o produto (score {imageValidation.Value.Score}/100).", $"quality=image_mismatch;score={imageValidation.Value.Score};reason={reason}");
    }

    return (true, null, $"quality=ok;image_score={imageValidation.Value.Score}");
}

static bool IsVisionValidationConfigured(VilaNvidiaSettings vilaSettings, GeminiSettings geminiSettings)
    => GetVilaApiKeys(vilaSettings).Count > 0 || GetGeminiApiKeys(geminiSettings).Count > 0;

static bool IsCaptionAlignedWithProduct(string productName, string? caption, out string details)
{
    var productTokens = ExtractMeaningfulTokens(productName, minLength: 3).Take(8).ToHashSet(StringComparer.OrdinalIgnoreCase);
    if (productTokens.Count == 0)
    {
        details = "caption_check=skipped_no_product_tokens";
        return true;
    }

    var captionTokens = ExtractMeaningfulTokens(caption ?? string.Empty, minLength: 3).ToHashSet(StringComparer.OrdinalIgnoreCase);
    var overlap = productTokens.Count(token => captionTokens.Contains(token));
    var requiredOverlap = productTokens.Count >= 4 ? 2 : 1;
    var ok = overlap >= requiredOverlap;

    details = $"caption_overlap={overlap};required={requiredOverlap};product_tokens={productTokens.Count}";
    return ok;
}

static IEnumerable<string> ExtractMeaningfulTokens(string input, int minLength)
{
    var normalized = NormalizeForTokenization(input);
    foreach (Match match in Regex.Matches(normalized, @"[a-z0-9]+", RegexOptions.CultureInvariant))
    {
        var token = match.Value;
        if (token.Length < minLength)
        {
            continue;
        }

        if (IsInstagramConsistencyStopWord(token))
        {
            continue;
        }

        yield return token;
    }
}

static string NormalizeForTokenization(string input)
{
    if (string.IsNullOrWhiteSpace(input))
    {
        return string.Empty;
    }

    var formD = input.Normalize(NormalizationForm.FormD);
    var sb = new StringBuilder(formD.Length);
    foreach (var c in formD)
    {
        var category = CharUnicodeInfo.GetUnicodeCategory(c);
        if (category == UnicodeCategory.NonSpacingMark)
        {
            continue;
        }

        sb.Append(char.ToLowerInvariant(c));
    }

    return sb.ToString().Normalize(NormalizationForm.FormC);
}

static bool IsInstagramConsistencyStopWord(string token)
    => token is
        "de" or "da" or "do" or "das" or "dos" or
        "com" or "sem" or "para" or "por" or "em" or
        "na" or "no" or "nas" or "nos" or "e" or "ou" or
        "a" or "o" or "as" or "os" or "um" or "uma" or "uns" or "umas" or
        "oferta" or "ofertas" or "produto" or "produtos" or "link" or "bio" or
        "comente" or "comentario" or "comprar" or "promocao" or "promocaoo" or
        "desconto" or "imperdivel" or "reidasofertas" or "achadinho" or
        "achadinhos" or "hoje" or "agora" or "novo" or "nova" or "top" or
        "kit" or "item" or "loja" or "oficial";

static async Task<(int Score, bool IsMatch, string Reason)?> EvaluateImageProductMatchWithVisionAsync(
    string productName,
    string caption,
    string imageUrl,
    VilaNvidiaSettings vilaSettings,
    GeminiSettings geminiSettings,
    IHttpClientFactory httpClientFactory,
    CancellationToken ct)
{
    var vilaResult = await EvaluateImageProductMatchWithVilaAsync(
        productName,
        caption,
        imageUrl,
        vilaSettings,
        httpClientFactory,
        ct);
    if (vilaResult is not null)
    {
        return vilaResult;
    }

    return await EvaluateImageProductMatchWithGeminiAsync(
        productName,
        caption,
        imageUrl,
        geminiSettings,
        httpClientFactory,
        ct);
}

static async Task<(int Score, bool IsMatch, string Reason)?> EvaluateImageProductMatchWithVilaAsync(
    string productName,
    string caption,
    string imageUrl,
    VilaNvidiaSettings vilaSettings,
    IHttpClientFactory httpClientFactory,
    CancellationToken ct)
{
    try
    {
        var apiKeys = GetVilaApiKeys(vilaSettings);
        if (apiKeys.Count == 0)
        {
            return null;
        }

        var model = string.IsNullOrWhiteSpace(vilaSettings.Model) ? "nvidia/vila" : vilaSettings.Model.Trim();
        var baseUrl = string.IsNullOrWhiteSpace(vilaSettings.BaseUrl) ? "https://integrate.api.nvidia.com/v1" : vilaSettings.BaseUrl.Trim();
        var shortCaption = (caption ?? string.Empty).Trim();
        if (shortCaption.Length > 280)
        {
            shortCaption = shortCaption[..280];
        }

        var prompt =
            "Valide se a imagem representa exatamente o produto informado. " +
            $"Produto: {productName}. " +
            $"Legenda resumida: {shortCaption}. " +
            "Responda somente JSON valido no formato: " +
            "{\"score\":0-100,\"isMatch\":true|false,\"reason\":\"texto curto\",\"styleNotes\":\"texto curto opcional\"}.";

        var payload = new Dictionary<string, object?>
        {
            ["model"] = model,
            ["messages"] = new object[]
            {
                new Dictionary<string, object?>
                {
                    ["role"] = "system",
                    ["content"] = "Voce analisa imagens de ofertas e responde em portugues do Brasil."
                },
                new Dictionary<string, object?>
                {
                    ["role"] = "user",
                    ["content"] = new object[]
                    {
                        new Dictionary<string, object?> { ["type"] = "text", ["text"] = prompt },
                        new Dictionary<string, object?>
                        {
                            ["type"] = "image_url",
                            ["image_url"] = new Dictionary<string, object?> { ["url"] = imageUrl }
                        }
                    }
                }
            },
            ["temperature"] = vilaSettings.Temperature,
            ["top_p"] = vilaSettings.TopP,
            ["max_tokens"] = Math.Clamp(vilaSettings.MaxOutputTokens <= 0 ? 4096 : vilaSettings.MaxOutputTokens, 200, 16384),
            ["stream"] = false,
            ["chat_template_kwargs"] = new Dictionary<string, object?> { ["enable_thinking"] = vilaSettings.EnableThinking }
        };

        var client = httpClientFactory.CreateClient("default");
        foreach (var apiKey in apiKeys)
        {
            using var request = new HttpRequestMessage(HttpMethod.Post, $"{baseUrl.TrimEnd('/')}/chat/completions");
            request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", apiKey);
            request.Content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");
            using var response = await client.SendAsync(request, ct);
            var raw = await response.Content.ReadAsStringAsync(ct);
            if (!response.IsSuccessStatusCode)
            {
                if (ShouldTryNextGeminiKey(response.StatusCode, raw))
                {
                    continue;
                }

                return null;
            }

            var output = ExtractNvidiaChatOutputText(raw);
            if (string.IsNullOrWhiteSpace(output))
            {
                continue;
            }

            var json = ExtractFirstJsonObjectForImageValidation(output) ?? output.Trim();
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            var score = root.TryGetProperty("score", out var scoreNode) && scoreNode.TryGetInt32(out var parsedScore)
                ? parsedScore
                : 0;
            score = Math.Clamp(score, 0, 100);

            var isMatch = root.TryGetProperty("isMatch", out var matchNode) && matchNode.ValueKind is JsonValueKind.True or JsonValueKind.False
                ? matchNode.GetBoolean()
                : score >= 55;

            var reason = root.TryGetProperty("reason", out var reasonNode) ? reasonNode.GetString() : null;
            var styleNotes = root.TryGetProperty("styleNotes", out var styleNode) ? styleNode.GetString() : null;
            if (!string.IsNullOrWhiteSpace(styleNotes))
            {
                reason = string.IsNullOrWhiteSpace(reason) ? styleNotes : $"{reason} | estilo: {styleNotes}";
            }

            reason = string.IsNullOrWhiteSpace(reason) ? $"vila_match={isMatch}" : reason.Trim();
            return (score, isMatch, reason);
        }

        return null;
    }
    catch
    {
        return null;
    }
}

static async Task<(int Score, bool IsMatch, string Reason)?> EvaluateImageProductMatchWithGeminiAsync(
    string productName,
    string caption,
    string imageUrl,
    GeminiSettings geminiSettings,
    IHttpClientFactory httpClientFactory,
    CancellationToken ct)
{
    try
    {
        var apiKeys = GetGeminiApiKeys(geminiSettings);
        if (apiKeys.Count == 0)
        {
            return null;
        }

        var client = httpClientFactory.CreateClient("default");
        using var imageResponse = await client.GetAsync(imageUrl, HttpCompletionOption.ResponseHeadersRead, ct);
        if (!imageResponse.IsSuccessStatusCode)
        {
            return null;
        }

        var contentLength = imageResponse.Content.Headers.ContentLength;
        if (contentLength.HasValue && contentLength.Value > 5_000_000)
        {
            return null;
        }

        var imageBytes = await imageResponse.Content.ReadAsByteArrayAsync(ct);
        if (imageBytes.Length == 0 || imageBytes.Length > 5_000_000)
        {
            return null;
        }

        var mimeType = ResolveImageMimeTypeForPublishValidation(imageResponse.Content.Headers.ContentType?.MediaType, imageUrl);
        if (!mimeType.StartsWith("image/", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        var shortCaption = (caption ?? string.Empty).Trim();
        if (shortCaption.Length > 280)
        {
            shortCaption = shortCaption[..280];
        }

        var prompt =
            "Valide se a imagem representa exatamente o produto informado. " +
            $"Produto: {productName}. " +
            $"Legenda resumida: {shortCaption}. " +
            "Responda somente JSON valido no formato: " +
            "{\"score\":0-100,\"isMatch\":true|false,\"reason\":\"texto curto\"}.";

        var payload = new Dictionary<string, object?>
        {
            ["contents"] = new object[]
            {
                new Dictionary<string, object?>
                {
                    ["role"] = "user",
                    ["parts"] = new object[]
                    {
                        new Dictionary<string, object?> { ["text"] = prompt },
                        new Dictionary<string, object?>
                        {
                            ["inline_data"] = new Dictionary<string, object?>
                            {
                                ["mime_type"] = mimeType,
                                ["data"] = Convert.ToBase64String(imageBytes)
                            }
                        }
                    }
                }
            },
            ["generationConfig"] = new Dictionary<string, object?>
            {
                ["temperature"] = 0,
                ["response_mime_type"] = "application/json"
            }
        };

        var model = string.IsNullOrWhiteSpace(geminiSettings.Model) ? "gemini-2.5-flash" : geminiSettings.Model.Trim();
        var baseUrl = string.IsNullOrWhiteSpace(geminiSettings.BaseUrl) ? "https://generativelanguage.googleapis.com/v1beta" : geminiSettings.BaseUrl.Trim();
        var geminiClient = httpClientFactory.CreateClient("gemini");
        foreach (var apiKey in apiKeys)
        {
            var url = $"{baseUrl.TrimEnd('/')}/models/{model}:generateContent?key={Uri.EscapeDataString(apiKey)}";
            using var response = await geminiClient.PostAsync(
                url,
                new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json"),
                ct);
            var raw = await response.Content.ReadAsStringAsync(ct);
            if (!response.IsSuccessStatusCode)
            {
                if (ShouldTryNextGeminiKey(response.StatusCode, raw))
                {
                    continue;
                }

                return null;
            }

            var output = ExtractGeminiOutputTextForImageValidation(raw);
            if (string.IsNullOrWhiteSpace(output))
            {
                continue;
            }

            var json = ExtractFirstJsonObjectForImageValidation(output) ?? output.Trim();
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            var score = root.TryGetProperty("score", out var scoreNode) && scoreNode.TryGetInt32(out var parsedScore)
                ? parsedScore
                : 0;
            score = Math.Clamp(score, 0, 100);

            var isMatch = root.TryGetProperty("isMatch", out var matchNode) && matchNode.ValueKind is JsonValueKind.True or JsonValueKind.False
                ? matchNode.GetBoolean()
                : score >= 55;

            var reason = root.TryGetProperty("reason", out var reasonNode) ? reasonNode.GetString() : null;
            reason = string.IsNullOrWhiteSpace(reason) ? $"gemini_match={isMatch}" : reason.Trim();
            return (score, isMatch, reason);
        }

        return null;
    }
    catch
    {
        return null;
    }
}

static List<string> GetGeminiApiKeys(GeminiSettings settings)
{
    var keys = new List<string>();
    if (!string.IsNullOrWhiteSpace(settings.ApiKey) && settings.ApiKey != "********")
    {
        keys.Add(settings.ApiKey.Trim());
    }

    if (settings.ApiKeys is not null)
    {
        foreach (var key in settings.ApiKeys)
        {
            if (string.IsNullOrWhiteSpace(key))
            {
                continue;
            }

            var trimmed = key.Trim();
            if (trimmed == "********")
            {
                continue;
            }

            keys.Add(trimmed);
        }
    }

    return keys
        .Distinct(StringComparer.Ordinal)
        .ToList();
}

static List<string> GetVilaApiKeys(VilaNvidiaSettings settings)
{
    var keys = new List<string>();
    if (!string.IsNullOrWhiteSpace(settings.ApiKey) && settings.ApiKey != "********")
    {
        keys.Add(settings.ApiKey.Trim());
    }

    if (settings.ApiKeys is not null)
    {
        foreach (var key in settings.ApiKeys)
        {
            if (string.IsNullOrWhiteSpace(key))
            {
                continue;
            }

            var trimmed = key.Trim();
            if (trimmed == "********")
            {
                continue;
            }

            keys.Add(trimmed);
        }
    }

    return keys
        .Distinct(StringComparer.Ordinal)
        .ToList();
}

static string? ExtractNvidiaChatOutputText(string json)
{
    using var doc = JsonDocument.Parse(json);
    if (!doc.RootElement.TryGetProperty("choices", out var choices) || choices.ValueKind != JsonValueKind.Array)
    {
        return null;
    }

    foreach (var choice in choices.EnumerateArray())
    {
        if (!choice.TryGetProperty("message", out var message))
        {
            continue;
        }

        if (!message.TryGetProperty("content", out var content))
        {
            continue;
        }

        if (content.ValueKind == JsonValueKind.String)
        {
            return content.GetString();
        }

        if (content.ValueKind != JsonValueKind.Array)
        {
            continue;
        }

        var parts = content.EnumerateArray()
            .Select(part =>
            {
                if (part.ValueKind == JsonValueKind.String)
                {
                    return part.GetString();
                }

                if (part.TryGetProperty("text", out var textNode))
                {
                    return textNode.GetString();
                }

                return null;
            })
            .Where(x => !string.IsNullOrWhiteSpace(x));

        var joined = string.Join("\n", parts!);
        if (!string.IsNullOrWhiteSpace(joined))
        {
            return joined;
        }
    }

    return null;
}

static bool ShouldTryNextGeminiKey(System.Net.HttpStatusCode statusCode, string? body)
{
    var status = (int)statusCode;
    if (status is 401 or 403 or 429 or 500 or 502 or 503 or 504)
    {
        return true;
    }

    if (status == 400 && !string.IsNullOrWhiteSpace(body))
    {
        return body.Contains("RESOURCE_EXHAUSTED", StringComparison.OrdinalIgnoreCase) ||
               body.Contains("quota", StringComparison.OrdinalIgnoreCase) ||
               body.Contains("rate limit", StringComparison.OrdinalIgnoreCase);
    }

    return false;
}

static string ResolveImageMimeTypeForPublishValidation(string? contentType, string imageUrl)
{
    if (!string.IsNullOrWhiteSpace(contentType) && contentType.StartsWith("image/", StringComparison.OrdinalIgnoreCase))
    {
        return contentType;
    }

    var extension = Path.GetExtension(imageUrl ?? string.Empty).ToLowerInvariant();
    return extension switch
    {
        ".png" => "image/png",
        ".webp" => "image/webp",
        ".gif" => "image/gif",
        ".bmp" => "image/bmp",
        _ => "image/jpeg"
    };
}

static string? ExtractGeminiOutputTextForImageValidation(string json)
{
    if (string.IsNullOrWhiteSpace(json))
    {
        return null;
    }

    try
    {
        using var doc = JsonDocument.Parse(json);
        if (!doc.RootElement.TryGetProperty("candidates", out var candidates) || candidates.ValueKind != JsonValueKind.Array)
        {
            return null;
        }

        foreach (var candidate in candidates.EnumerateArray())
        {
            if (!candidate.TryGetProperty("content", out var content) || content.ValueKind != JsonValueKind.Object)
            {
                continue;
            }

            if (!content.TryGetProperty("parts", out var parts) || parts.ValueKind != JsonValueKind.Array)
            {
                continue;
            }

            var sb = new StringBuilder();
            foreach (var part in parts.EnumerateArray())
            {
                if (part.TryGetProperty("text", out var text))
                {
                    sb.Append(text.GetString());
                }
            }

            var combined = sb.ToString().Trim();
            if (!string.IsNullOrWhiteSpace(combined))
            {
                return combined;
            }
        }
    }
    catch
    {
        return null;
    }

    return null;
}

static string? ExtractFirstJsonObjectForImageValidation(string input)
{
    var trimmed = input?.Trim();
    if (string.IsNullOrWhiteSpace(trimmed))
    {
        return null;
    }

    var start = trimmed.IndexOf('{');
    if (start < 0)
    {
        return null;
    }

    var depth = 0;
    for (var i = start; i < trimmed.Length; i++)
    {
        if (trimmed[i] == '{')
        {
            depth++;
        }
        else if (trimmed[i] == '}')
        {
            depth--;
            if (depth == 0)
            {
                return trimmed[start..(i + 1)];
            }
        }
    }

    return null;
}

static string FormatInstagramCaptionForReadability(string? caption)
{
    if (string.IsNullOrWhiteSpace(caption))
    {
        return string.Empty;
    }

    var normalized = caption.Replace("\r", string.Empty).Trim();
    normalized = Regex.Replace(normalized, @"\\n", "\n", RegexOptions.CultureInvariant);
    normalized = Regex.Replace(normalized, @"[ \t]+", " ", RegexOptions.CultureInvariant);
    normalized = Regex.Replace(normalized, @"\s*(?=(?:[#â€¢\-]\s*|âœ…|ðŸ”¥|ðŸ‘‰|âœ”))", "\n", RegexOptions.CultureInvariant);
    normalized = Regex.Replace(normalized, @"\n{3,}", "\n\n", RegexOptions.CultureInvariant);

    if (!normalized.Contains('\n'))
    {
        var sentences = Regex.Split(normalized, @"(?<=[.!?])\s+", RegexOptions.CultureInvariant)
            .Where(s => !string.IsNullOrWhiteSpace(s))
            .ToList();
        if (sentences.Count > 1)
        {
            normalized = string.Join("\n\n", sentences);
        }
    }

    var lines = normalized.Split('\n', StringSplitOptions.None)
        .Select(line => line.Trim())
        .ToList();

    return string.Join('\n', lines).Trim();
}

static string BuildInstagramCaptionTemplateHelp(InstagramPostSettings settings)
{
    var templates = GetConfiguredInstagramCaptionTemplates(settings);
    return string.Join('\n', new[]
    {
        "TEMPLATES DE LEGENDA (/ig template)",
        "",
        "Modelos disponiveis:",
        $"1) {BuildTemplatePreview(templates[0])}",
        $"2) {BuildTemplatePreview(templates[1])}",
        $"3) {BuildTemplatePreview(templates[2])}",
        "",
        "Placeholders suportados: {title}, {lead}, {body}, {short}, {keyword}, {hashtags}, {bullet1}, {bullet2}, {bullet3}",
        "",
        "Uso:",
        "- /ig template <id|ultimo> <1|2|3>",
        "- /ig template <1|2|3>  (usa ultimo)",
        "- /ig templates  (mostra esta ajuda)",
        "",
        "Exemplo:",
        "- /ig template ultimo 2",
        "",
        "Dica: edite os templates no painel Instagram para customizar o estilo."
    });
}

static string ApplyInstagramCaptionTemplate(InstagramPublishDraft draft, int templateNumber, InstagramPostSettings settings)
{
    var formatted = FormatInstagramCaptionForReadability(draft.Caption);
    var hashtags = ExtractHashtagLines(formatted);
    var bodyText = RemoveHashtagLines(formatted);
    var keyword = draft.Ctas
        .Select(c => c.Keyword?.Trim())
        .FirstOrDefault(k => !string.IsNullOrWhiteSpace(k)) ?? "LINK";
    var title = !string.IsNullOrWhiteSpace(draft.ProductName)
        ? draft.ProductName.Trim()
        : "Oferta imperdivel";

    var sentences = SplitCaptionSentences(bodyText);
    var lead = sentences.Count > 0 ? sentences[0] : bodyText;
    var extra = sentences.Skip(1).Take(3).ToList();

    var bullets = extra.Count > 0
        ? extra
        : SplitCaptionSentences(bodyText).Take(3).ToList();
    if (bullets.Count == 0 && !string.IsNullOrWhiteSpace(bodyText))
    {
        bullets.Add(bodyText);
    }

    var shortParts = new List<string>();
    if (!string.IsNullOrWhiteSpace(lead))
    {
        shortParts.Add(lead);
    }
    if (extra.Count > 0)
    {
        shortParts.Add(extra[0]);
    }
    var shortBody = string.Join(" ", shortParts).Trim();
    if (string.IsNullOrWhiteSpace(shortBody))
    {
        shortBody = bodyText;
    }
    if (shortBody.Length > 280)
    {
        shortBody = shortBody[..280].TrimEnd() + "...";
    }

    var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
    {
        ["title"] = title,
        ["lead"] = string.IsNullOrWhiteSpace(lead) ? bodyText : lead,
        ["body"] = bodyText,
        ["short"] = shortBody,
        ["keyword"] = keyword,
        ["hashtags"] = hashtags,
        ["bullet1"] = bullets.Count > 0 ? bullets[0] : bodyText,
        ["bullet2"] = bullets.Count > 1 ? bullets[1] : bullets.Count > 0 ? bullets[0] : bodyText,
        ["bullet3"] = bullets.Count > 2 ? bullets[2] : bullets.Count > 0 ? bullets[^1] : bodyText
    };

    var templates = GetConfiguredInstagramCaptionTemplates(settings);
    var index = Math.Clamp(templateNumber, 1, templates.Count) - 1;
    var templateCaption = RenderInstagramCaptionTemplate(templates[index], values);
    if (string.IsNullOrWhiteSpace(templateCaption))
    {
        templateCaption = $"Oferta em destaque: {title}\n\n{values["lead"]}";
    }

    templateCaption = EnsureInstagramCaptionContainsCta(templateCaption, draft.Ctas);
    if (!string.IsNullOrWhiteSpace(hashtags))
    {
        templateCaption = string.Join("\n\n", new[] { templateCaption.Trim(), hashtags.Trim() });
    }

    if (templateCaption.Length > 2200)
    {
        templateCaption = templateCaption[..2200].TrimEnd() + "...";
    }

    return templateCaption.Trim();
}

static List<string> GetConfiguredInstagramCaptionTemplates(InstagramPostSettings settings)
{
    var configured = settings.CaptionTemplates?
        .Where(x => !string.IsNullOrWhiteSpace(x))
        .Select(x => x.Trim())
        .Take(3)
        .ToList() ?? new List<string>();

    var defaults = new List<string>
    {
        "Oferta em destaque: {title}\n\n{lead}\n\nComente \"{keyword}\" para receber o link.\n\n{hashtags}",
        "Oferta: {title}\n\nPontos principais:\n- {bullet1}\n- {bullet2}\n- {bullet3}\n\nComente \"{keyword}\" para receber o link.\n\n{hashtags}",
        "Oferta do dia: {title}\n\n{short}\n\nComente \"{keyword}\" para receber o link.\n\n{hashtags}"
    };

    while (configured.Count < 3)
    {
        configured.Add(defaults[configured.Count]);
    }

    return configured;
}

static string BuildTemplatePreview(string template)
{
    var normalized = template.Replace("\r", string.Empty).Replace('\n', ' ').Trim();
    normalized = Regex.Replace(normalized, @"\s+", " ", RegexOptions.CultureInvariant);
    if (normalized.Length > 58)
    {
        normalized = normalized[..58].TrimEnd() + "...";
    }

    return string.IsNullOrWhiteSpace(normalized) ? "Template vazio" : normalized;
}

static string RenderInstagramCaptionTemplate(string template, IReadOnlyDictionary<string, string> values)
{
    var output = template ?? string.Empty;
    foreach (var pair in values)
    {
        output = output.Replace($"{{{pair.Key}}}", pair.Value ?? string.Empty, StringComparison.OrdinalIgnoreCase);
    }

    // Limpa placeholders desconhecidos que sobraram.
    output = Regex.Replace(output, @"\{[a-z0-9_]+\}", string.Empty, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    output = Regex.Replace(output, @"\n{3,}", "\n\n", RegexOptions.CultureInvariant);
    return output.Trim();
}

static string RemoveHashtagLines(string caption)
{
    if (string.IsNullOrWhiteSpace(caption))
    {
        return string.Empty;
    }

    var lines = caption.Replace("\r", string.Empty)
        .Split('\n', StringSplitOptions.None)
        .Select(x => x.Trim())
        .Where(x => !x.StartsWith("#", StringComparison.Ordinal))
        .ToList();
    return string.Join('\n', lines).Trim();
}

static string ExtractHashtagLines(string caption)
{
    if (string.IsNullOrWhiteSpace(caption))
    {
        return string.Empty;
    }

    var lines = caption.Replace("\r", string.Empty)
        .Split('\n', StringSplitOptions.None)
        .Select(x => x.Trim())
        .Where(x => x.StartsWith("#", StringComparison.Ordinal))
        .ToList();
    return string.Join('\n', lines).Trim();
}

static List<string> SplitCaptionSentences(string text)
{
    if (string.IsNullOrWhiteSpace(text))
    {
        return new List<string>();
    }

    var normalized = Regex.Replace(text.Replace('\n', ' '), @"\s+", " ", RegexOptions.CultureInvariant).Trim();
    return Regex.Split(normalized, @"(?<=[.!?])\s+", RegexOptions.CultureInvariant)
        .Select(x => x.Trim())
        .Where(x => !string.IsNullOrWhiteSpace(x))
        .Distinct(StringComparer.Ordinal)
        .Take(6)
        .ToList();
}

static string BuildInstagramCaption(string caption, string hashtags, IReadOnlyCollection<InstagramCtaOption>? ctas = null)
{
    caption = FormatInstagramCaptionForReadability(caption);
    caption = EnsureInstagramCaptionContainsCta(caption, ctas ?? Array.Empty<InstagramCtaOption>());
    caption = EnsureInstagramEngagementHook(caption);

    var normalizedHashtags = NormalizeInstagramHashtags(hashtags, caption);
    var finalCaption = string.Join("\n\n", new[] { caption.Trim(), normalizedHashtags }.Where(x => !string.IsNullOrWhiteSpace(x)));
    if (finalCaption.Length > 2200)
    {
        finalCaption = finalCaption[..2200].TrimEnd() + "...";
    }

    return finalCaption.Trim();
}

static string EnsureInstagramCaptionContainsCta(string caption, IReadOnlyCollection<InstagramCtaOption> ctas)
{
    var baseCaption = (caption ?? string.Empty).Trim();
    if (ctas is null || ctas.Count == 0)
    {
        return baseCaption;
    }

    var primaryKeyword = ctas
        .Select(c => c.Keyword?.Trim())
        .FirstOrDefault(k => !string.IsNullOrWhiteSpace(k));
    if (string.IsNullOrWhiteSpace(primaryKeyword))
    {
        return baseCaption;
    }

    var alreadyHasKeyword = Regex.IsMatch(baseCaption, $@"\b{Regex.Escape(primaryKeyword)}\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    if (alreadyHasKeyword)
    {
        return baseCaption;
    }

    var ctaLine = BuildInstagramCtaLine(primaryKeyword, baseCaption);
    if (string.IsNullOrWhiteSpace(baseCaption))
    {
        return ctaLine;
    }

    return $"{baseCaption}\n\n{ctaLine}";
}

static string BuildInstagramCtaLine(string primaryKeyword, string seed)
{
    var templates = new[]
    {
        "Comente \"{0}\" para receber o link.",
        "Quer o link? Escreva \"{0}\" nos comentarios.",
        "Digita \"{0}\" aqui embaixo que eu te envio o link.",
        "Comenta \"{0}\" e te mando o link completo.",
        "Para receber o link, comente \"{0}\"."
    };

    var idx = ComputeDeterministicIndex($"{primaryKeyword}|{seed}", templates.Length);
    return string.Format(templates[idx], primaryKeyword);
}

static int ComputeDeterministicIndex(string seed, int length)
{
    if (length <= 0)
    {
        return 0;
    }

    var hash = SHA256.HashData(Encoding.UTF8.GetBytes(seed ?? string.Empty));
    var value = BitConverter.ToInt32(hash, 0) & int.MaxValue;
    return value % length;
}

static string EnsureInstagramEngagementHook(string caption)
{
    var text = (caption ?? string.Empty).Trim();
    if (string.IsNullOrWhiteSpace(text))
    {
        return text;
    }

    var hasEngagementHook = Regex.IsMatch(
        text,
        @"\b(comente|comenta|salve|compartilhe|link na bio|direct|dm|chama no direct)\b",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    if (hasEngagementHook)
    {
        return text;
    }

    return $"{text}\n\nSalve este post e compartilhe com quem ama promocoes.";
}

static string NormalizeInstagramHashtags(string hashtags, string caption)
{
    var allTags = new List<string>();
    var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

    static IEnumerable<string> ExtractTags(string? input)
    {
        if (string.IsNullOrWhiteSpace(input))
        {
            yield break;
        }

        foreach (Match match in Regex.Matches(input, @"#([A-Za-z0-9_À-ÖØ-öø-ÿ]+)", RegexOptions.CultureInvariant))
        {
            var raw = match.Groups[1].Value;
            if (string.IsNullOrWhiteSpace(raw))
            {
                continue;
            }

            var normalized = "#" + raw.Trim().TrimStart('#');
            if (normalized.Length > 1)
            {
                yield return normalized;
            }
        }
    }

    foreach (var tag in ExtractTags(hashtags))
    {
        if (seen.Add(tag))
        {
            allTags.Add(tag);
        }
    }

    foreach (var tag in ExtractTags(caption))
    {
        if (seen.Add(tag))
        {
            allTags.Add(tag);
        }
    }

    var fallback = new List<string>
    {
        "#achadinhos",
        "#ofertas",
        "#promocoes",
        "#descontos",
        "#custobeneficio",
        "#dicadecompra"
    };

    var lowerCaption = (caption ?? string.Empty).ToLowerInvariant();
    if (lowerCaption.Contains("amazon", StringComparison.Ordinal))
    {
        fallback.Add("#amazonbr");
    }
    if (lowerCaption.Contains("mercado livre", StringComparison.Ordinal) || lowerCaption.Contains("mercadolivre", StringComparison.Ordinal))
    {
        fallback.Add("#mercadolivre");
    }
    if (lowerCaption.Contains("shopee", StringComparison.Ordinal))
    {
        fallback.Add("#shopeebrasil");
    }
    if (lowerCaption.Contains("shein", StringComparison.Ordinal))
    {
        fallback.Add("#sheinbrasil");
    }

    const int minTags = 5;
    const int maxTags = 10;
    foreach (var tag in fallback)
    {
        if (allTags.Count >= minTags)
        {
            break;
        }

        if (seen.Add(tag))
        {
            allTags.Add(tag);
        }
    }

    if (allTags.Count == 0)
    {
        return string.Empty;
    }

    return string.Join(' ', allTags.Take(maxTags));
}

static async Task<(bool Success, string? MediaId, string? Error)> PublishToInstagramAsync(
    IHttpClientFactory httpClientFactory,
    string baseUrl,
    string igUserId,
    string accessToken,
    string postType,
    List<string> imageUrls,
    string caption,
    CancellationToken ct)
{
    try
    {
        if (imageUrls is null || imageUrls.Count == 0)
        {
            return (false, null, "Sem midia para publicar.");
        }

        var client = httpClientFactory.CreateClient("default");
        baseUrl = string.IsNullOrWhiteSpace(baseUrl) ? "https://graph.facebook.com/v19.0" : baseUrl.TrimEnd('/');
        var normalizedType = NormalizeInstagramPostTypeValue(postType);
        var mediaUrls = imageUrls
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .Select(x => x.Trim())
            .ToList();
        if (mediaUrls.Count == 0)
        {
            return (false, null, "Sem midia valida para publicar.");
        }

        if (normalizedType == "story")
        {
            var firstMedia = mediaUrls.FirstOrDefault();
            if (string.IsNullOrWhiteSpace(firstMedia))
            {
                return (false, null, "Sem midia para publicar story.");
            }

            var isStoryVideo = await IsLikelyVideoUrlAsync(client, firstMedia, ct);
            var (containerId, containerError) = await CreateMediaContainerAsync(client, baseUrl, igUserId, accessToken, firstMedia, string.Empty, false, "STORIES", isStoryVideo, ct);
            if (string.IsNullOrWhiteSpace(containerId))
            {
                return (false, null, $"Falha ao criar story. {containerError}");
            }
            var (mediaId, publishError) = await PublishMediaAsync(client, baseUrl, igUserId, accessToken, containerId!, ct);
            return string.IsNullOrWhiteSpace(mediaId) ? (false, null, $"Falha ao publicar story. {publishError}") : (true, mediaId, null);
        }

        if (normalizedType == "reel")
        {
            var firstMedia = mediaUrls.FirstOrDefault();
            if (string.IsNullOrWhiteSpace(firstMedia))
            {
                return (false, null, "Sem midia para publicar reel.");
            }

            var isReelVideo = await IsLikelyVideoUrlAsync(client, firstMedia, ct);
            if (!isReelVideo)
            {
                return (false, null, "Reel requer URL de video valida.");
            }

            var (containerId, containerError) = await CreateMediaContainerAsync(client, baseUrl, igUserId, accessToken, firstMedia, caption, false, "REELS", true, ct);
            if (string.IsNullOrWhiteSpace(containerId))
            {
                return (false, null, $"Falha ao criar reel. {containerError}");
            }
            var (mediaId, publishError) = await PublishMediaAsync(client, baseUrl, igUserId, accessToken, containerId!, ct);
            return string.IsNullOrWhiteSpace(mediaId) ? (false, null, $"Falha ao publicar reel. {publishError}") : (true, mediaId, null);
        }

        if (mediaUrls.Count == 1)
        {
            var singleMedia = mediaUrls[0];
            var isSingleVideo = await IsLikelyVideoUrlAsync(client, singleMedia, ct);
            var mediaType = isSingleVideo ? "VIDEO" : null;
            var (containerId, containerError) = await CreateMediaContainerAsync(client, baseUrl, igUserId, accessToken, singleMedia, caption, false, mediaType, isSingleVideo, ct);
            if (string.IsNullOrWhiteSpace(containerId))
            {
                return (false, null, $"Falha ao criar container. {containerError}");
            }
            var (mediaId, publishErrorSingle) = await PublishMediaAsync(client, baseUrl, igUserId, accessToken, containerId!, ct);
            return string.IsNullOrWhiteSpace(mediaId) ? (false, null, $"Falha ao publicar. {publishErrorSingle}") : (true, mediaId, null);
        }

        foreach (var candidate in mediaUrls)
        {
            if (await IsLikelyVideoUrlAsync(client, candidate, ct))
            {
                return (false, null, "Carrossel com video nao suportado neste fluxo automatico.");
            }
        }

        var childIds = new List<string>();
        string? firstError = null;
        foreach (var url in mediaUrls)
        {
            var (child, childError) = await CreateMediaContainerAsync(client, baseUrl, igUserId, accessToken, url, string.Empty, true, null, false, ct);
            if (!string.IsNullOrWhiteSpace(child)) childIds.Add(child!);
            if (firstError is null && !string.IsNullOrWhiteSpace(childError)) firstError = childError;
        }
        if (childIds.Count == 0)
        {
            return (false, null, $"Falha ao criar itens do carrossel. {firstError}");
        }

        var (parentId, parentError) = await CreateCarouselContainerAsync(client, baseUrl, igUserId, accessToken, childIds, caption, ct);
        if (string.IsNullOrWhiteSpace(parentId))
        {
            return (false, null, $"Falha ao criar carrossel. {parentError}");
        }

        var (publishId, publishErrorCarousel) = await PublishMediaAsync(client, baseUrl, igUserId, accessToken, parentId!, ct);
        return string.IsNullOrWhiteSpace(publishId) ? (false, null, $"Falha ao publicar carrossel. {publishErrorCarousel}") : (true, publishId, null);
    }
    catch (Exception ex)
    {
        return (false, null, ex.Message);
    }
}

static bool IsInstagramMediaTypeError(string? error)
{
    if (string.IsNullOrWhiteSpace(error)) return false;
    return error.Contains("Only photo or video can be accepted as media type", StringComparison.OrdinalIgnoreCase)
           || error.Contains("image format is not supported", StringComparison.OrdinalIgnoreCase)
           || error.Contains("code 9004", StringComparison.OrdinalIgnoreCase);
}

static bool IsLikelyWebpUrl(string? url)
{
    if (string.IsNullOrWhiteSpace(url))
    {
        return false;
    }

    return Regex.IsMatch(url, @"\.webp(\?|$)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
}

static bool IsLikelyVideoUrl(string? url)
{
    if (string.IsNullOrWhiteSpace(url))
    {
        return false;
    }

    var normalized = url.ToLowerInvariant();
    return normalized.Contains(".mp4", StringComparison.Ordinal) ||
           normalized.Contains(".mov", StringComparison.Ordinal) ||
           normalized.Contains(".m4v", StringComparison.Ordinal) ||
           normalized.Contains(".webm", StringComparison.Ordinal) ||
           normalized.Contains(".m3u8", StringComparison.Ordinal);
}

static async Task<bool> IsLikelyVideoUrlAsync(HttpClient client, string? url, CancellationToken ct)
{
    if (string.IsNullOrWhiteSpace(url))
    {
        return false;
    }

    if (IsLikelyVideoUrl(url))
    {
        return true;
    }

    if (!Uri.TryCreate(url, UriKind.Absolute, out _))
    {
        return false;
    }

    try
    {
        using var headRequest = new HttpRequestMessage(HttpMethod.Head, url);
        using var headResponse = await client.SendAsync(headRequest, HttpCompletionOption.ResponseHeadersRead, ct);
        if (headResponse.Content.Headers.ContentType?.MediaType?.StartsWith("video/", StringComparison.OrdinalIgnoreCase) == true)
        {
            return true;
        }
    }
    catch
    {
        // ignored
    }

    try
    {
        using var getRequest = new HttpRequestMessage(HttpMethod.Get, url);
        getRequest.Headers.Range = new System.Net.Http.Headers.RangeHeaderValue(0, 0);
        using var getResponse = await client.SendAsync(getRequest, HttpCompletionOption.ResponseHeadersRead, ct);
        return getResponse.Content.Headers.ContentType?.MediaType?.StartsWith("video/", StringComparison.OrdinalIgnoreCase) == true;
    }
    catch
    {
        return false;
    }
}

static async Task<(string? Id, string? Error)> CreateMediaContainerAsync(HttpClient client, string baseUrl, string igUserId, string token, string mediaUrl, string caption, bool carouselItem, string? mediaType, bool isVideo, CancellationToken ct)
{
    var url = $"{baseUrl}/{igUserId}/media";
    var data = new Dictionary<string, string>
    {
        ["access_token"] = token
    };
    if (isVideo)
    {
        data["video_url"] = mediaUrl;
        if (string.IsNullOrWhiteSpace(mediaType))
        {
            data["media_type"] = "VIDEO";
        }
    }
    else
    {
        data["image_url"] = mediaUrl;
    }
    if (!string.IsNullOrWhiteSpace(mediaType))
    {
        data["media_type"] = mediaType;
    }
    if (!string.IsNullOrWhiteSpace(caption))
    {
        data["caption"] = caption;
    }
    if (carouselItem)
    {
        data["is_carousel_item"] = "true";
    }
    using var response = await client.PostAsync(url, new FormUrlEncodedContent(data), ct);
    var body = await response.Content.ReadAsStringAsync(ct);
    if (!response.IsSuccessStatusCode) return (null, ExtractGraphError(body));
    return (TryGetIdFromJson(body), null);
}

static async Task<(string? Id, string? Error)> CreateCarouselContainerAsync(HttpClient client, string baseUrl, string igUserId, string token, List<string> children, string caption, CancellationToken ct)
{
    var url = $"{baseUrl}/{igUserId}/media";
    var data = new Dictionary<string, string>
    {
        ["access_token"] = token,
        ["media_type"] = "CAROUSEL",
        ["children"] = string.Join(",", children)
    };
    if (!string.IsNullOrWhiteSpace(caption))
    {
        data["caption"] = caption;
    }
    using var response = await client.PostAsync(url, new FormUrlEncodedContent(data), ct);
    var body = await response.Content.ReadAsStringAsync(ct);
    if (!response.IsSuccessStatusCode) return (null, ExtractGraphError(body));
    return (TryGetIdFromJson(body), null);
}

static async Task<(string? Id, string? Error)> PublishMediaAsync(HttpClient client, string baseUrl, string igUserId, string token, string creationId, CancellationToken ct)
{
    var url = $"{baseUrl}/{igUserId}/media_publish";
    var data = new Dictionary<string, string>
    {
        ["creation_id"] = creationId,
        ["access_token"] = token
    };

    // Meta pode demorar para deixar o creation_id pronto.
    // Quando isso acontece retorna code=9007 / sub=2207027 ("Media ID is not available").
    var retryDelays = new[] { 0, 4, 8, 12, 16, 22 };
    string? lastError = null;

    foreach (var delaySeconds in retryDelays)
    {
        if (delaySeconds > 0)
        {
            await Task.Delay(TimeSpan.FromSeconds(delaySeconds), ct);
        }

        using var response = await client.PostAsync(url, new FormUrlEncodedContent(data), ct);
        var body = await response.Content.ReadAsStringAsync(ct);
        if (response.IsSuccessStatusCode)
        {
            return (TryGetIdFromJson(body), null);
        }

        var graphError = ExtractGraphError(body) ?? body;
        lastError = graphError;
        if (!IsGraphMediaNotReadyError(body))
        {
            return (null, graphError);
        }
    }

    return (null, lastError ?? "Media ainda nao ficou pronta para publicacao.");
}

static string? TryGetIdFromJson(string json)
{
    try
    {
        using var doc = JsonDocument.Parse(json);
        if (doc.RootElement.TryGetProperty("id", out var idNode) && idNode.ValueKind == JsonValueKind.String)
        {
            return idNode.GetString();
        }
    }
    catch { }
    return null;
}

static string? ExtractGraphError(string json)
{
    try
    {
        using var doc = JsonDocument.Parse(json);
        if (doc.RootElement.TryGetProperty("error", out var err))
        {
            var msg = GetJsonValueAsString(err, "message");
            var code = GetJsonValueAsString(err, "code");
            var sub = GetJsonValueAsString(err, "error_subcode");
            return $"Graph error: {msg} (code {code}, sub {sub})";
        }
    }
    catch { }
    return json;
}

static bool IsGraphMediaNotReadyError(string json)
{
    try
    {
        using var doc = JsonDocument.Parse(json);
        if (!doc.RootElement.TryGetProperty("error", out var err))
        {
            return false;
        }

        var code = GetJsonValueAsString(err, "code");
        var sub = GetJsonValueAsString(err, "error_subcode");
        if (string.Equals(code, "9007", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(sub, "2207027", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        var message = GetJsonValueAsString(err, "message") ?? string.Empty;
        var userMessage = GetJsonValueAsString(err, "error_user_msg") ?? string.Empty;
        return message.Contains("not available", StringComparison.OrdinalIgnoreCase)
               || message.Contains("not ready", StringComparison.OrdinalIgnoreCase)
               || userMessage.Contains("nao esta pronta", StringComparison.OrdinalIgnoreCase)
               || userMessage.Contains("aguarde", StringComparison.OrdinalIgnoreCase);
    }
    catch
    {
        return false;
    }
}

static string? GetJsonValueAsString(JsonElement node, string propertyName)
{
    if (!node.TryGetProperty(propertyName, out var value))
    {
        return null;
    }

    return value.ValueKind switch
    {
        JsonValueKind.String => value.GetString(),
        JsonValueKind.Number => value.ToString(),
        JsonValueKind.True => "true",
        JsonValueKind.False => "false",
        _ => value.ToString()
    };
}

static async Task<string?> TryResolvePageIdForInstagramUserAsync(
    IHttpClientFactory httpClientFactory,
    string baseUrl,
    string accessToken,
    string instagramUserId,
    CancellationToken ct)
{
    try
    {
        var client = httpClientFactory.CreateClient("default");
        baseUrl = string.IsNullOrWhiteSpace(baseUrl) ? "https://graph.facebook.com/v19.0" : baseUrl.TrimEnd('/');
        var url = $"{baseUrl}/me/accounts?fields=id,instagram_business_account{{id}}&limit=50&access_token={Uri.EscapeDataString(accessToken)}";
        using var response = await client.GetAsync(url, ct);
        var body = await response.Content.ReadAsStringAsync(ct);
        if (!response.IsSuccessStatusCode)
        {
            return null;
        }

        using var doc = JsonDocument.Parse(body);
        if (!doc.RootElement.TryGetProperty("data", out var data) || data.ValueKind != JsonValueKind.Array)
        {
            return null;
        }

        string? firstPage = null;
        foreach (var page in data.EnumerateArray())
        {
            var pageId = GetString(page, "id");
            if (string.IsNullOrWhiteSpace(firstPage) && !string.IsNullOrWhiteSpace(pageId))
            {
                firstPage = pageId;
            }

            if (!page.TryGetProperty("instagram_business_account", out var igNode) || igNode.ValueKind != JsonValueKind.Object)
            {
                continue;
            }

            var igId = GetString(igNode, "id");
            if (!string.IsNullOrWhiteSpace(igId) && string.Equals(igId, instagramUserId, StringComparison.OrdinalIgnoreCase))
            {
                return pageId;
            }
        }

        return firstPage;
    }
    catch
    {
        return null;
    }
}

static async Task<InstagramBoostAdResult> CreateInstagramBoostAdAsync(
    IHttpClientFactory httpClientFactory,
    InstagramPublishSettings settings,
    string mediaId,
    InstagramBoostCommandInput input,
    string pageId,
    string linkUrl,
    CancellationToken ct)
{
    if (string.IsNullOrWhiteSpace(settings.AccessToken) || settings.AccessToken == "********")
    {
        return new InstagramBoostAdResult(false, null, null, null, "Access token nao configurado.");
    }
    if (string.IsNullOrWhiteSpace(settings.InstagramUserId))
    {
        return new InstagramBoostAdResult(false, null, null, null, "Instagram user id nao configurado.");
    }

    var adAccountId = NormalizeAdAccountId(input.AdAccountId);
    var normalizedPageId = NormalizeGraphNumericId(pageId);
    var normalizedMediaId = NormalizeGraphNumericId(mediaId);
    var normalizedAdSetId = NormalizeGraphNumericId(input.AdSetId);
    var normalizedCampaignId = NormalizeGraphNumericId(input.CampaignId);
    var normalizedCta = NormalizeInstagramAdCta(input.CtaType);

    if (string.IsNullOrWhiteSpace(adAccountId))
    {
        return new InstagramBoostAdResult(false, null, null, null, "Conta de anuncio invalida.");
    }
    if (string.IsNullOrWhiteSpace(normalizedPageId))
    {
        return new InstagramBoostAdResult(false, null, null, null, "Page ID invalido.");
    }
    if (string.IsNullOrWhiteSpace(normalizedMediaId))
    {
        return new InstagramBoostAdResult(false, null, null, null, "Media ID invalido.");
    }

    var client = httpClientFactory.CreateClient("default");
    var baseUrl = string.IsNullOrWhiteSpace(settings.GraphBaseUrl) ? "https://graph.facebook.com/v19.0" : settings.GraphBaseUrl.TrimEnd('/');
    var token = settings.AccessToken!;
    var now = DateTimeOffset.UtcNow;
    var campaignName = $"IG Boost {now:yyyyMMddHHmmss}";
    var adSetName = $"IG Boost Set {now:yyyyMMddHHmmss}";
    var creativeName = $"IG Boost Creative {now:yyyyMMddHHmmss}";
    var adName = $"IG Boost Ad {now:yyyyMMddHHmmss}";

    var campaignId = normalizedCampaignId;
    if (string.IsNullOrWhiteSpace(campaignId) && string.IsNullOrWhiteSpace(normalizedAdSetId))
    {
        (var createdCampaignId, var campaignError) = await CreateBoostCampaignAsync(client, baseUrl, adAccountId!, token, campaignName, ct);
        if (string.IsNullOrWhiteSpace(createdCampaignId))
        {
            return new InstagramBoostAdResult(false, null, null, null, $"Falha ao criar campanha: {campaignError}");
        }
        campaignId = createdCampaignId;
    }

    var adSetId = normalizedAdSetId;
    if (string.IsNullOrWhiteSpace(adSetId))
    {
        (var createdAdSetId, var adSetError) = await CreateBoostAdSetAsync(
            client,
            baseUrl,
            adAccountId!,
            token,
            adSetName,
            campaignId!,
            normalizedPageId!,
            input.Country,
            input.Budget,
            input.Days,
            ct);

        if (string.IsNullOrWhiteSpace(createdAdSetId))
        {
            return new InstagramBoostAdResult(false, campaignId, null, null, $"Falha ao criar ad set: {adSetError}");
        }
        adSetId = createdAdSetId;
    }

    (var creativeId, var creativeError) = await CreateBoostCreativeFromMediaAsync(
        client,
        baseUrl,
        adAccountId!,
        token,
        creativeName,
        normalizedPageId!,
        settings.InstagramUserId!,
        normalizedMediaId!,
        normalizedCta,
        linkUrl,
        ct);
    if (string.IsNullOrWhiteSpace(creativeId))
    {
        return new InstagramBoostAdResult(false, campaignId, adSetId, null, $"Falha ao criar criativo: {creativeError}");
    }

    (var adId, var adError) = await CreateBoostAdAsync(client, baseUrl, adAccountId!, token, adName, adSetId!, creativeId!, ct);
    if (string.IsNullOrWhiteSpace(adId))
    {
        return new InstagramBoostAdResult(false, campaignId, adSetId, null, $"Falha ao criar anuncio: {adError}");
    }

    return new InstagramBoostAdResult(true, campaignId, adSetId, adId, null);
}

static async Task<(string? CampaignId, string? Error)> CreateBoostCampaignAsync(
    HttpClient client,
    string baseUrl,
    string adAccountId,
    string token,
    string name,
    CancellationToken ct)
{
    // New Ads API outcomes (ODAX): prioriza TRAFFIC para botao "compre agora".
    var objectives = new[] { "OUTCOME_TRAFFIC", "OUTCOME_SALES", "OUTCOME_ENGAGEMENT" };
    string? lastError = null;
    foreach (var objective in objectives)
    {
        var url = $"{baseUrl}/act_{adAccountId}/campaigns";
        var data = new Dictionary<string, string>
        {
            ["name"] = name,
            ["objective"] = objective,
            ["status"] = "PAUSED",
            ["special_ad_categories"] = "[]",
            // Obrigatorio em contas ODAX para informar se o budget fica no nivel da campanha.
            // Como usamos daily_budget no adset, mantemos desabilitado (ABO).
            ["is_adset_budget_sharing_enabled"] = "false",
            ["access_token"] = token
        };

        using var response = await client.PostAsync(url, new FormUrlEncodedContent(data), ct);
        var body = await response.Content.ReadAsStringAsync(ct);
        if (response.IsSuccessStatusCode)
        {
            var id = TryGetIdFromJson(body);
            if (!string.IsNullOrWhiteSpace(id))
            {
                return (id, null);
            }
        }

        lastError = ExtractGraphError(body);
    }

    return (null, lastError ?? "Erro desconhecido ao criar campanha.");
}

static async Task<(string? AdSetId, string? Error)> CreateBoostAdSetAsync(
    HttpClient client,
    string baseUrl,
    string adAccountId,
    string token,
    string name,
    string campaignId,
    string pageId,
    string country,
    decimal budgetAmount,
    int days,
    CancellationToken ct)
{
    var budgetMinor = Math.Max(100, (int)Math.Round(budgetAmount * 100m, MidpointRounding.AwayFromZero));
    var start = DateTimeOffset.UtcNow.AddMinutes(5).ToUnixTimeSeconds().ToString(System.Globalization.CultureInfo.InvariantCulture);
    var end = DateTimeOffset.UtcNow.AddDays(Math.Max(1, days)).ToUnixTimeSeconds().ToString(System.Globalization.CultureInfo.InvariantCulture);
    var normalizedCountry = string.IsNullOrWhiteSpace(country) ? "BR" : country.Trim().ToUpperInvariant();
    if (normalizedCountry.Length != 2) normalizedCountry = "BR";

    var targeting = JsonSerializer.Serialize(new
    {
        geo_locations = new { countries = new[] { normalizedCountry } },
        publisher_platforms = new[] { "instagram" },
        instagram_positions = new[] { "stream", "story", "reels" },
        device_platforms = new[] { "mobile" }
    });

    var promotedObject = JsonSerializer.Serialize(new { page_id = pageId });
    var url = $"{baseUrl}/act_{adAccountId}/adsets";
    var data = new Dictionary<string, string>
    {
        ["name"] = name,
        ["campaign_id"] = campaignId,
        ["daily_budget"] = budgetMinor.ToString(System.Globalization.CultureInfo.InvariantCulture),
        ["billing_event"] = "IMPRESSIONS",
        ["optimization_goal"] = "LINK_CLICKS",
        ["bid_strategy"] = "LOWEST_COST_WITHOUT_CAP",
        ["targeting"] = targeting,
        ["promoted_object"] = promotedObject,
        ["start_time"] = start,
        ["end_time"] = end,
        ["status"] = "PAUSED",
        ["access_token"] = token
    };

    using var response = await client.PostAsync(url, new FormUrlEncodedContent(data), ct);
    var body = await response.Content.ReadAsStringAsync(ct);
    if (!response.IsSuccessStatusCode)
    {
        return (null, ExtractGraphError(body));
    }

    var id = TryGetIdFromJson(body);
    return string.IsNullOrWhiteSpace(id)
        ? (null, "Graph nao retornou id do ad set.")
        : (id, null);
}

static async Task<(string? CreativeId, string? Error)> CreateBoostCreativeFromMediaAsync(
    HttpClient client,
    string baseUrl,
    string adAccountId,
    string token,
    string name,
    string pageId,
    string instagramUserId,
    string mediaId,
    string ctaType,
    string linkUrl,
    CancellationToken ct)
{
    var url = $"{baseUrl}/act_{adAccountId}/adcreatives";
    var data = new Dictionary<string, string>
    {
        ["name"] = name,
        ["object_id"] = pageId,
        ["instagram_user_id"] = instagramUserId,
        ["source_instagram_media_id"] = mediaId,
        ["call_to_action_type"] = ctaType,
        ["link_url"] = linkUrl,
        ["access_token"] = token
    };

    using var response = await client.PostAsync(url, new FormUrlEncodedContent(data), ct);
    var body = await response.Content.ReadAsStringAsync(ct);
    if (!response.IsSuccessStatusCode)
    {
        return (null, ExtractGraphError(body));
    }

    var id = TryGetIdFromJson(body);
    return string.IsNullOrWhiteSpace(id)
        ? (null, "Graph nao retornou id do criativo.")
        : (id, null);
}

static async Task<(string? AdId, string? Error)> CreateBoostAdAsync(
    HttpClient client,
    string baseUrl,
    string adAccountId,
    string token,
    string name,
    string adSetId,
    string creativeId,
    CancellationToken ct)
{
    var url = $"{baseUrl}/act_{adAccountId}/ads";
    var creativePayload = JsonSerializer.Serialize(new { creative_id = creativeId });
    var data = new Dictionary<string, string>
    {
        ["name"] = name,
        ["adset_id"] = adSetId,
        ["creative"] = creativePayload,
        ["status"] = "PAUSED",
        ["access_token"] = token
    };

    using var response = await client.PostAsync(url, new FormUrlEncodedContent(data), ct);
    var body = await response.Content.ReadAsStringAsync(ct);
    if (!response.IsSuccessStatusCode)
    {
        return (null, ExtractGraphError(body));
    }

    var id = TryGetIdFromJson(body);
    return string.IsNullOrWhiteSpace(id)
        ? (null, "Graph nao retornou id do anuncio.")
        : (id, null);
}

static string? NormalizeGraphNumericId(string? value)
{
    if (string.IsNullOrWhiteSpace(value))
    {
        return null;
    }

    var normalized = value.Trim();
    if (normalized.StartsWith("act_", StringComparison.OrdinalIgnoreCase))
    {
        normalized = normalized[4..];
    }

    return Regex.IsMatch(normalized, @"^\d+$", RegexOptions.CultureInvariant) ? normalized : null;
}

static string NormalizeInstagramAdCta(string? cta)
{
    var normalized = (cta ?? "SHOP_NOW").Trim().ToUpperInvariant();
    normalized = Regex.Replace(normalized, @"\s+", "_", RegexOptions.CultureInvariant);

    var allowed = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "SHOP_NOW",
        "LEARN_MORE",
        "SIGN_UP",
        "BOOK_TRAVEL",
        "CONTACT_US",
        "APPLY_NOW",
        "DOWNLOAD",
        "GET_OFFER",
        "GET_QUOTE",
        "ORDER_NOW"
    };

    return allowed.Contains(normalized) ? normalized : "SHOP_NOW";
}

static async Task<bool> ReplyToInstagramCommentAsync(IHttpClientFactory httpClientFactory, string baseUrl, string commentId, string message, string token, CancellationToken ct)
{
    var client = httpClientFactory.CreateClient("default");
    baseUrl = string.IsNullOrWhiteSpace(baseUrl) ? "https://graph.facebook.com/v19.0" : baseUrl.TrimEnd('/');
    var url = $"{baseUrl}/{commentId}/replies";
    var data = new Dictionary<string, string>
    {
        ["message"] = message,
        ["access_token"] = token
    };
    using var response = await client.PostAsync(url, new FormUrlEncodedContent(data), ct);
    return response.IsSuccessStatusCode;
}

static IEnumerable<InstagramCommentPending> ExtractInstagramComments(string json)
{
    var list = new List<InstagramCommentPending>();
    try
    {
        using var doc = JsonDocument.Parse(json);
        if (!doc.RootElement.TryGetProperty("entry", out var entry) || entry.ValueKind != JsonValueKind.Array)
        {
            return list;
        }
        foreach (var e in entry.EnumerateArray())
        {
            if (!e.TryGetProperty("changes", out var changes) || changes.ValueKind != JsonValueKind.Array) continue;
            foreach (var change in changes.EnumerateArray())
            {
                var field = change.TryGetProperty("field", out var f) ? f.GetString() : null;
                if (!string.Equals(field, "comments", StringComparison.OrdinalIgnoreCase)) continue;
                if (!change.TryGetProperty("value", out var value)) continue;

                var commentId = GetString(value, "id", "comment_id") ?? string.Empty;
                var text = GetString(value, "text", "message") ?? string.Empty;
                var mediaId = string.Empty;
                if (value.TryGetProperty("media", out var mediaNode))
                {
                    mediaId = GetString(mediaNode, "id") ?? string.Empty;
                }
                mediaId = string.IsNullOrWhiteSpace(mediaId) ? GetString(value, "media_id") ?? string.Empty : mediaId;

                var from = string.Empty;
                var fromId = string.Empty;
                if (value.TryGetProperty("from", out var fromNode))
                {
                    from = GetString(fromNode, "username", "name") ?? string.Empty;
                    fromId = GetString(fromNode, "id") ?? string.Empty;
                }

                if (!string.IsNullOrWhiteSpace(commentId))
                {
                    list.Add(new InstagramCommentPending
                    {
                        CommentId = commentId,
                        MediaId = mediaId,
                        Text = text,
                        From = from,
                        FromId = string.IsNullOrWhiteSpace(fromId) ? null : fromId
                    });
                }
            }
        }
    }
    catch { }
    return list;
}

static IEnumerable<InstagramIncomingDirectMessage> ExtractInstagramDirectMessages(string json)
{
    var list = new List<InstagramIncomingDirectMessage>();
    try
    {
        using var doc = JsonDocument.Parse(json);
        if (!doc.RootElement.TryGetProperty("entry", out var entry) || entry.ValueKind != JsonValueKind.Array)
        {
            return list;
        }

        foreach (var e in entry.EnumerateArray())
        {
            if (e.TryGetProperty("messaging", out var messaging) && messaging.ValueKind == JsonValueKind.Array)
            {
                foreach (var item in messaging.EnumerateArray())
                {
                    var fromId = item.TryGetProperty("sender", out var senderNode) ? GetString(senderNode, "id") ?? string.Empty : string.Empty;
                    var toId = item.TryGetProperty("recipient", out var recipientNode) ? GetString(recipientNode, "id") : null;
                    var text = string.Empty;
                    var messageId = string.Empty;
                    var isEcho = false;
                    if (item.TryGetProperty("message", out var messageNode))
                    {
                        text = GetString(messageNode, "text", "body") ?? string.Empty;
                        messageId = GetString(messageNode, "mid", "id") ?? string.Empty;
                        isEcho = GetBool(messageNode, "is_echo");
                    }

                    if (!string.IsNullOrWhiteSpace(fromId) && !string.IsNullOrWhiteSpace(text))
                    {
                        list.Add(new InstagramIncomingDirectMessage(
                            string.IsNullOrWhiteSpace(messageId) ? null : messageId,
                            fromId,
                            toId,
                            text,
                            isEcho));
                    }
                }
            }

            if (!e.TryGetProperty("changes", out var changes) || changes.ValueKind != JsonValueKind.Array)
            {
                continue;
            }

            foreach (var change in changes.EnumerateArray())
            {
                var field = change.TryGetProperty("field", out var f) ? f.GetString() : null;
                if (!string.Equals(field, "messages", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }
                if (!change.TryGetProperty("value", out var value))
                {
                    continue;
                }

                if (value.TryGetProperty("messages", out var messagesArray) && messagesArray.ValueKind == JsonValueKind.Array)
                {
                    foreach (var m in messagesArray.EnumerateArray())
                    {
                        var text = GetString(m, "text", "body", "message") ?? string.Empty;
                        var messageId = GetString(m, "id", "mid");
                        var fromId = GetString(value, "from", "sender_id") ?? GetString(m, "from") ?? string.Empty;
                        var toId = GetString(value, "to", "recipient_id") ?? GetString(m, "to");
                        var isEcho = GetBool(m, "is_echo");
                        if (!string.IsNullOrWhiteSpace(fromId) && !string.IsNullOrWhiteSpace(text))
                        {
                            list.Add(new InstagramIncomingDirectMessage(messageId, fromId, toId, text, isEcho));
                        }
                    }
                    continue;
                }

                var singleText = string.Empty;
                if (value.TryGetProperty("message", out var singleMessageNode))
                {
                    singleText = singleMessageNode.ValueKind == JsonValueKind.String
                        ? singleMessageNode.GetString() ?? string.Empty
                        : GetString(singleMessageNode, "text", "body") ?? string.Empty;
                }
                if (string.IsNullOrWhiteSpace(singleText))
                {
                    singleText = GetString(value, "text", "body") ?? string.Empty;
                }

                var singleMessageId = GetString(value, "id", "mid");
                var singleFromId = value.TryGetProperty("from", out var fromNode)
                    ? GetString(fromNode, "id") ?? string.Empty
                    : GetString(value, "from", "sender_id") ?? string.Empty;
                var singleToId = value.TryGetProperty("to", out var toNode)
                    ? GetString(toNode, "id")
                    : GetString(value, "to", "recipient_id");
                var singleIsEcho = GetBool(value, "is_echo");
                if (!string.IsNullOrWhiteSpace(singleFromId) && !string.IsNullOrWhiteSpace(singleText))
                {
                    list.Add(new InstagramIncomingDirectMessage(singleMessageId, singleFromId, singleToId, singleText, singleIsEcho));
                }
            }
        }
    }
    catch { }

    return list;
}

static async Task<InstagramPublishDraft?> FindDraftByMediaIdAsync(IInstagramPublishStore store, string mediaId, CancellationToken ct)
{
    if (string.IsNullOrWhiteSpace(mediaId)) return null;
    var items = await store.ListAsync(ct);
    return items.FirstOrDefault(x => string.Equals(x.MediaId, mediaId, StringComparison.OrdinalIgnoreCase));
}

static InstagramCtaResolution ResolveInstagramCtaReply(InstagramPublishDraft? draft, InstagramPublishSettings settings, string commentText)
{
    var defaultReply = settings.ReplyNoMatchTemplate ?? string.Empty;
    if (draft is null)
    {
        return new InstagramCtaResolution(defaultReply, false, null, null);
    }

    var effectiveCtas = BuildEffectiveDraftCtas(draft);
    if (effectiveCtas.Count == 0)
    {
        return new InstagramCtaResolution(defaultReply, false, null, null);
    }

    var text = commentText ?? string.Empty;
    var exactMatch = effectiveCtas.FirstOrDefault(c => !string.IsNullOrWhiteSpace(c.Keyword) && text.Contains(c.Keyword, StringComparison.OrdinalIgnoreCase));
    var hasKeywordMatch = exactMatch is not null;
    var match = exactMatch;

    if (match is null && !settings.AutoReplyOnlyOnKeywordMatch && effectiveCtas.Count == 1)
    {
        match = effectiveCtas[0];
    }

    if (match is null)
    {
        return new InstagramCtaResolution(defaultReply, false, null, null);
    }

    var template = settings.ReplyTemplate ?? "Aqui esta o link: {link}";
    var reply = template.Replace("{link}", match.Link ?? string.Empty, StringComparison.OrdinalIgnoreCase)
                        .Replace("{keyword}", match.Keyword ?? string.Empty, StringComparison.OrdinalIgnoreCase);

    return new InstagramCtaResolution(reply, hasKeywordMatch, match.Keyword, match.Link);
}

static async Task<InstagramCtaResolution> ResolveInstagramDmKeywordReplyAsync(
    IInstagramPublishStore publishStore,
    InstagramPublishSettings settings,
    string messageText,
    CancellationToken ct)
{
    var defaultReply = settings.ReplyNoMatchTemplate ?? string.Empty;
    if (string.IsNullOrWhiteSpace(messageText))
    {
        return new InstagramCtaResolution(defaultReply, false, null, null);
    }

    var drafts = await publishStore.ListAsync(ct);
    if (drafts.Count == 0)
    {
        return new InstagramCtaResolution(defaultReply, false, null, null);
    }

    var ordered = drafts
        .OrderByDescending(d => string.Equals(d.Status, "published", StringComparison.OrdinalIgnoreCase))
        .ThenByDescending(d => d.CreatedAt);

    foreach (var draft in ordered)
    {
        var effectiveCtas = BuildEffectiveDraftCtas(draft);
        if (effectiveCtas.Count == 0)
        {
            continue;
        }

        var match = effectiveCtas.FirstOrDefault(c =>
            !string.IsNullOrWhiteSpace(c.Keyword) &&
            messageText.Contains(c.Keyword, StringComparison.OrdinalIgnoreCase));

        if (match is null)
        {
            continue;
        }

        var template = settings.ReplyTemplate ?? "Aqui esta o link: {link}";
        var reply = template.Replace("{link}", match.Link ?? string.Empty, StringComparison.OrdinalIgnoreCase)
                            .Replace("{keyword}", match.Keyword ?? string.Empty, StringComparison.OrdinalIgnoreCase);

        return new InstagramCtaResolution(reply, true, match.Keyword, match.Link);
    }

    return new InstagramCtaResolution(defaultReply, false, null, null);
}

static string BuildInstagramDmMessage(InstagramPublishSettings settings, InstagramCommentPending comment, InstagramCtaResolution cta)
{
    return BuildInstagramDmMessageTemplate(settings, cta.Link, cta.Keyword, comment.From, comment.Text);
}

static string BuildInstagramInboundDmMessage(InstagramPublishSettings settings, InstagramCtaResolution cta, string inboundText)
{
    if (!cta.HasKeywordMatch)
    {
        return cta.Reply;
    }

    return BuildInstagramDmMessageTemplate(settings, cta.Link, cta.Keyword, string.Empty, inboundText);
}

static string BuildInstagramDmMessageTemplate(InstagramPublishSettings settings, string? link, string? keyword, string? name, string? commentText)
{
    var template = settings.DmTemplate;
    if (string.IsNullOrWhiteSpace(template))
    {
        template = "Oi {name}! Aqui esta seu link: {link}";
    }

    return template.Replace("{link}", link ?? string.Empty, StringComparison.OrdinalIgnoreCase)
                   .Replace("{keyword}", keyword ?? string.Empty, StringComparison.OrdinalIgnoreCase)
                   .Replace("{name}", name ?? string.Empty, StringComparison.OrdinalIgnoreCase)
                   .Replace("{comment}", commentText ?? string.Empty, StringComparison.OrdinalIgnoreCase);
}

static async Task<InstagramDmSendResult> SendInstagramAutoDmAsync(
    IHttpClientFactory httpClientFactory,
    InstagramPublishSettings settings,
    InstagramCommentPending comment,
    string message,
    CancellationToken ct)
{
    var provider = (settings.DmProvider ?? "meta").Trim().ToLowerInvariant();
    if (provider == "manychat")
    {
        return await SendManyChatDmAsync(httpClientFactory, settings, comment, message, ct);
    }

    var metaResult = await SendMetaInstagramDmAsync(httpClientFactory, settings, comment, message, ct);
    if (metaResult.Success)
    {
        return metaResult;
    }

    if (settings.DmFallbackToManyChatOnError)
    {
        var manyChatResult = await SendManyChatDmAsync(httpClientFactory, settings, comment, message, ct);
        if (manyChatResult.Success)
        {
            return new InstagramDmSendResult(true, manyChatResult.Provider, null);
        }

        var combinedError = string.Join(" | ", new[] { metaResult.Error, manyChatResult.Error }.Where(x => !string.IsNullOrWhiteSpace(x)));
        return new InstagramDmSendResult(false, "meta+manychat", combinedError);
    }

    return metaResult;
}

static async Task<InstagramDmSendResult> SendMetaInstagramDmAsync(
    IHttpClientFactory httpClientFactory,
    InstagramPublishSettings settings,
    InstagramCommentPending comment,
    string message,
    CancellationToken ct)
{
    if (string.IsNullOrWhiteSpace(comment.FromId))
    {
        return new InstagramDmSendResult(false, "meta", "Comment sem from.id para envio de DM.");
    }
    if (string.IsNullOrWhiteSpace(settings.AccessToken) || settings.AccessToken == "********")
    {
        return new InstagramDmSendResult(false, "meta", "Access token nao configurado.");
    }
    if (string.IsNullOrWhiteSpace(settings.InstagramUserId))
    {
        return new InstagramDmSendResult(false, "meta", "Instagram user id nao configurado.");
    }

    var client = httpClientFactory.CreateClient("default");
    var baseUrl = string.IsNullOrWhiteSpace(settings.GraphBaseUrl) ? "https://graph.facebook.com/v19.0" : settings.GraphBaseUrl.TrimEnd('/');
    var url = $"{baseUrl}/{settings.InstagramUserId}/messages";
    var data = new Dictionary<string, string>
    {
        ["recipient"] = $"{{\"id\":\"{comment.FromId}\"}}",
        ["message"] = $"{{\"text\":\"{EscapeJsonValue(message)}\"}}",
        ["access_token"] = settings.AccessToken!
    };

    using var response = await client.PostAsync(url, new FormUrlEncodedContent(data), ct);
    var body = await response.Content.ReadAsStringAsync(ct);
    if (response.IsSuccessStatusCode)
    {
        return new InstagramDmSendResult(true, "meta", null);
    }

    var graphError = ExtractGraphError(body);
    return new InstagramDmSendResult(false, "meta", string.IsNullOrWhiteSpace(graphError) ? body : graphError);
}

static async Task<InstagramDmSendResult> SendManyChatDmAsync(
    IHttpClientFactory httpClientFactory,
    InstagramPublishSettings settings,
    InstagramCommentPending comment,
    string message,
    CancellationToken ct)
{
    if (string.IsNullOrWhiteSpace(settings.ManyChatWebhookUrl))
    {
        return new InstagramDmSendResult(false, "manychat", "ManyChat webhook URL nao configurada.");
    }

    try
    {
        var client = httpClientFactory.CreateClient("default");
        using var req = new HttpRequestMessage(HttpMethod.Post, settings.ManyChatWebhookUrl);
        if (!string.IsNullOrWhiteSpace(settings.ManyChatApiKey) && settings.ManyChatApiKey != "********")
        {
            req.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", settings.ManyChatApiKey);
        }

        var payload = new
        {
            channel = "instagram",
            eventName = "cta_dm",
            from = comment.From,
            fromId = comment.FromId,
            commentId = comment.CommentId,
            mediaId = comment.MediaId,
            keyword = comment.MatchedKeyword,
            link = comment.MatchedLink,
            message
        };
        req.Content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");
        using var response = await client.SendAsync(req, ct);
        var body = await response.Content.ReadAsStringAsync(ct);
        if (response.IsSuccessStatusCode)
        {
            return new InstagramDmSendResult(true, "manychat", null);
        }

        return new InstagramDmSendResult(false, "manychat", $"{(int)response.StatusCode} {response.ReasonPhrase}: {body}");
    }
    catch (Exception ex)
    {
        return new InstagramDmSendResult(false, "manychat", ex.Message);
    }
}

static List<string> ExtractCouponCodesFromText(string text)
{
    if (string.IsNullOrWhiteSpace(text))
    {
        return new List<string>();
    }

    var hint = text.Contains("cupom", StringComparison.OrdinalIgnoreCase)
               || text.Contains("coupon", StringComparison.OrdinalIgnoreCase)
               || text.Contains("código", StringComparison.OrdinalIgnoreCase)
               || text.Contains("codigo", StringComparison.OrdinalIgnoreCase);

    if (!hint)
    {
        return new List<string>();
    }

    var blocked = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "CUPOM",
        "COUPON",
        "CODIGO",
        "CÓDIGO",
        "OFF",
        "R",
        "RS"
    };

    var matches = Regex.Matches(text.ToUpperInvariant(), @"\b[A-Z0-9]{4,16}\b");
    return matches
        .Select(m => m.Value.Trim())
        .Where(v => !blocked.Contains(v))
        .Where(v => v.Any(char.IsDigit))
        .Distinct(StringComparer.OrdinalIgnoreCase)
        .Take(20)
        .ToList();
}

static string EscapeJsonValue(string value)
{
    return (value ?? string.Empty)
        .Replace("\\", "\\\\", StringComparison.Ordinal)
        .Replace("\"", "\\\"", StringComparison.Ordinal)
        .Replace("\r", "\\r", StringComparison.Ordinal)
        .Replace("\n", "\\n", StringComparison.Ordinal);
}

static string NormalizeWebConversorSource(string? source)
{
    var normalized = (source ?? string.Empty).Trim().ToLowerInvariant();
    if (string.IsNullOrWhiteSpace(normalized))
    {
        return "conversor_web";
    }

    if (normalized is "instagram_ofertas" or "whatsapp" or "telegram")
    {
        return normalized;
    }

    if (normalized.StartsWith("telegram_", StringComparison.Ordinal)
        || normalized.StartsWith("whatsapp_", StringComparison.Ordinal)
        || normalized.StartsWith("instagram_", StringComparison.Ordinal)
        || normalized.StartsWith("catalogo_", StringComparison.Ordinal)
        || normalized is "site_conversor" or "conversor_web")
    {
        return normalized;
    }

    return "conversor_web";
}

internal sealed record LoginRequest(string Username, string Password, bool RememberMe = false);
internal sealed record PlaygroundRequest(string Text);
internal sealed record MercadoLivreDecisionRequest(string? Note, bool? SendNow, string? OverrideUrl);
internal sealed record WhatsAppInstanceRequest(string? InstanceName);
internal sealed record TelegramBotConnectRequest(string? BotToken);
internal sealed record TelegramUserbotReplayRequest(long SourceChatId, int Count = 10, bool AllowOfficialDestination = false);
internal sealed record CouponUpsertRequest(
    string? Id,
    string Store,
    string Code,
    string? Description,
    string? AffiliateLink,
    DateTimeOffset? StartsAt,
    DateTimeOffset? EndsAt,
    int? Priority,
    bool? Enabled,
    string? Source);
internal sealed record CouponExtractRequest(
    string Store,
    string Text,
    string? Description,
    string? AffiliateLink,
    DateTimeOffset? EndsAt,
    int? Priority,
    string? Source);
internal sealed record CouponOfficialSyncRequest(string? Store);
internal sealed record WhatsAppForwardSendOutcome(WhatsAppSendResult Result, string Mode, string? Diagnostic = null);
internal sealed record WhatsAppIncomingMessage(
    string ChatId,
    string? SenderId,
    string Text,
    bool FromMe,
    string? InstanceName,
    string? MessageId,
    bool HasMedia,
    string? MediaUrl,
    string? MediaBase64,
    string? MediaMimeType,
    string? MediaFileName,
    string? RawPayloadJson);
internal sealed record WhatsAppHelpCommand(string Scope);
internal sealed record InstagramWhatsAppCommand(string Action, string? Argument);
internal sealed record InstagramDraftBuildResult(InstagramPublishDraft? Draft, string? Error);
internal sealed record InstagramCreateInput(string Input, List<string> CtaKeywords, List<string> ImageUrls, string PostType);
internal sealed record InstagramImageCommandInput(string DraftRef, List<string> ImageUrls, string? Error);
internal sealed record InstagramManageImagesInput(string DraftRef, bool ListOnly, List<int> SelectedIndexes, string? Error);
internal sealed record InstagramTypeCommandInput(string DraftRef, string PostType, string? Error);
internal sealed record InstagramCaptionCommandInput(string DraftRef, string Caption, string? Error);
internal sealed record InstagramCaptionChoiceInput(int OptionNumber, string DraftRef, string? Error);
internal sealed record InstagramCaptionTemplateInput(string DraftRef, int TemplateNumber, string? Error);
internal sealed record InstagramCaptionChoiceCommand(int OptionNumber, string DraftRef);
internal sealed record InstagramCtaCommandInput(string DraftRef, List<string> Keywords, string? Error);
internal sealed record InstagramBoostCommandInput(
    string DraftRef,
    string AdAccountId,
    string? PageId,
    string? AdSetId,
    string? CampaignId,
    string? LinkUrl,
    string CtaType,
    decimal Budget,
    int Days,
    string Country,
    string? Error);
internal sealed record BioLinkItem
{
    public DateTimeOffset CreatedAt { get; init; }
    public string Title { get; init; } = string.Empty;
    public string Link { get; init; } = string.Empty;
    public string OriginalLink { get; init; } = string.Empty;
    public string Store { get; init; } = "Loja";
    public int? ItemNumber { get; init; }
    public bool IsHighlightedOnBio { get; init; }
    public DateTimeOffset? BioHighlightedAt { get; init; }
    public string? Keyword { get; init; }
    public bool IsLightningDeal { get; init; }
    public DateTimeOffset? LightningDealExpiry { get; init; }
    public string? CouponCode { get; init; }
    public string? CouponDescription { get; init; }
    public string? ImageUrl { get; init; }
}
internal sealed record PublicLinkConverterViewModel
{
    public string Input { get; set; } = string.Empty;
    public bool Success { get; set; }
    public string? Error { get; set; }
    public string Store { get; set; } = "Loja";
    public string OriginalUrl { get; set; } = string.Empty;
    public string ConvertedUrl { get; set; } = string.Empty;
    public string TrackedUrl { get; set; } = string.Empty;
    public string Title { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string Price { get; set; } = string.Empty;
    public string PreviousPrice { get; set; } = string.Empty;
    public int? DiscountPercent { get; set; }
    public bool IsLightningDeal { get; set; }
    public DateTimeOffset? LightningDealExpiry { get; set; }
    public string EstimatedDelivery { get; set; } = string.Empty;
    public bool HasCoupon { get; set; }
    public string? CouponCode { get; set; }
    public string? CouponDescription { get; set; }
    public string ImageUrl { get; set; } = string.Empty;
    public string VideoUrl { get; set; } = string.Empty;
    public bool IsAffiliated { get; set; }
    public string? ValidationError { get; set; }
    public string? CorrectionNote { get; set; }
    public string? ConversionHost { get; set; }
    public string? DomainHost { get; set; }
    public string? DataSource { get; set; }
}

internal sealed record InstagramPublishExecutionResult(bool Success, int StatusCode, string? MediaId, string? Error, string? DraftId);
internal sealed record InstagramBoostAdResult(bool Success, string? CampaignId, string? AdSetId, string? AdId, string? Error);
internal sealed record InstagramCtaResolution(string Reply, bool HasKeywordMatch, string? Keyword, string? Link);
internal sealed record InstagramIncomingDirectMessage(string? MessageId, string FromId, string? ToId, string Text, bool IsEcho);
internal sealed record InstagramDmSendResult(bool Success, string Provider, string? Error);
internal sealed record InstagramDraftRequest(
    string ProductName,
    string Caption,
    string Hashtags,
    List<InstagramCtaOption> Ctas,
    List<string> ImageUrls,
    string? PostType);
internal sealed record InstagramApproveRequest(string Message);

public record ConversorWebRequest(string Url, string? Source = null);
public partial class Program { } 


