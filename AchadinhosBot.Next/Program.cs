using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Runtime.Versioning;
using System.Drawing;
using System.Drawing.Imaging;
using System.Net.Http.Headers;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Application.Services;
using AchadinhosBot.Next.Configuration;
using AchadinhosBot.Next.Domain.Logs;
using AchadinhosBot.Next.Domain.Instagram;
using AchadinhosBot.Next.Domain.Compliance;
using AchadinhosBot.Next.Domain.Requests;
using AchadinhosBot.Next.Domain.Settings;
using AchadinhosBot.Next.Infrastructure.Audit;
using AchadinhosBot.Next.Infrastructure.Coupons;
using AchadinhosBot.Next.Infrastructure.Idempotency;
using AchadinhosBot.Next.Infrastructure.Instagram;
using AchadinhosBot.Next.Infrastructure.Logs;
using AchadinhosBot.Next.Infrastructure.MercadoLivre;
using AchadinhosBot.Next.Infrastructure.Media;
using AchadinhosBot.Next.Infrastructure.Monitoring;
using AchadinhosBot.Next.Infrastructure.Security;
using AchadinhosBot.Next.Infrastructure.Storage;
using AchadinhosBot.Next.Infrastructure.Telegram;
using AchadinhosBot.Next.Infrastructure.WhatsApp;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.Options;

LoadDotEnvIfPresent();

var builder = WebApplication.CreateBuilder(args);

// Evita falha de permissao no EventLog em ambientes sem privilegio administrativo.
builder.Logging.ClearProviders();
builder.Logging.AddConsole();
builder.Logging.AddDebug();

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

var telegramStartupOptions = builder.Configuration.GetSection("Telegram").Get<TelegramOptions>() ?? new TelegramOptions();
var startTelegramBotWorker = !string.IsNullOrWhiteSpace(telegramStartupOptions.BotToken);
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

builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    options.AddFixedWindowLimiter("login", l =>
    {
        l.PermitLimit = 10;
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
});
builder.Services.AddHttpClient("evolution", c => c.Timeout = TimeSpan.FromSeconds(30));
builder.Services.AddHttpClient("evolution-groups", c => c.Timeout = TimeSpan.FromSeconds(120));
builder.Services.AddHttpClient("openai", c => c.Timeout = TimeSpan.FromSeconds(60));
builder.Services.AddHttpClient("gemini", c => c.Timeout = TimeSpan.FromSeconds(60));

builder.Services.AddSingleton<IAffiliateLinkService, AffiliateLinkService>();
builder.Services.AddSingleton<IAffiliateCouponSyncService, AffiliateCouponSyncService>();
builder.Services.AddSingleton<IAffiliateCouponProvider, AmazonOfficialCouponProvider>();
builder.Services.AddSingleton<IAffiliateCouponProvider, ShopeeOfficialCouponProvider>();
builder.Services.AddSingleton<IAffiliateCouponProvider, SheinOfficialCouponProvider>();
builder.Services.AddSingleton<IAffiliateCouponProvider, MercadoLivreOfficialCouponProvider>();
builder.Services.AddSingleton<IMercadoLivreOAuthService, MercadoLivreOAuthService>();
builder.Services.AddSingleton<IConversionLogStore, ConversionLogStore>();
builder.Services.AddSingleton<ICouponSelector, CouponSelector>();
builder.Services.AddSingleton<ILinkTrackingStore, LinkTrackingStore>();
builder.Services.AddSingleton<IClickLogStore, ClickLogStore>();
builder.Services.AddSingleton<IInstagramAiLogStore, InstagramAiLogStore>();
builder.Services.AddSingleton<IInstagramPublishLogStore, InstagramPublishLogStore>();
builder.Services.AddSingleton<InstagramLinkMetaService>();
builder.Services.AddSingleton<InstagramImageDownloadService>();
builder.Services.AddSingleton<IMessageProcessor, MessageProcessor>();
builder.Services.AddSingleton<OpenAiInstagramPostGenerator>();
builder.Services.AddSingleton<GeminiInstagramPostGenerator>();
builder.Services.AddSingleton<IInstagramPostComposer, InstagramPostComposer>();
builder.Services.AddSingleton<IInstagramPublishStore, InstagramPublishStore>();
builder.Services.AddSingleton<IInstagramCommentStore, InstagramCommentStore>();
builder.Services.AddSingleton<IMercadoLivreApprovalStore, MercadoLivreApprovalStore>();
builder.Services.AddSingleton<ISettingsStore, JsonSettingsStore>();
builder.Services.AddSingleton<IWhatsAppGateway, EvolutionWhatsAppGateway>();
builder.Services.AddSingleton<IMediaStore, InMemoryMediaStore>();
builder.Services.AddSingleton<InstagramConversationStore>();
builder.Services.AddSingleton<InstagramCommandMenuStore>();
builder.Services.AddSingleton<WhatsAppHelpMenuStore>();
builder.Services.AddSingleton<ITelegramGateway, TelegramBotApiGateway>();
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

builder.Services.AddSingleton<IAuditTrail, FileAuditTrail>();
builder.Services.AddSingleton<IIdempotencyStore, MemoryIdempotencyStore>();
builder.Services.AddSingleton<LoginAttemptStore>();
builder.Services.AddSingleton<IMediaFailureLogStore, MediaFailureLogStore>();
builder.Services.AddHostedService<UptimeHeartbeatService>();

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
    var valid = user is not null && PasswordHasher.Verify(request.Password, user.PasswordHash);

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
    await httpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(identity));
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

app.MapPost("/converter", async (
    ConvertRequest payload,
    HttpContext context,
    IMessageProcessor processor,
    IOptions<WebhookOptions> options,
    CancellationToken ct) =>
{
    if (!context.Request.Headers.TryGetValue("x-api-key", out var provided) || provided != options.Value.ApiKey)
    {
        return Results.Json(new { success = false, error = "forbidden" }, statusCode: StatusCodes.Status403Forbidden);
    }

    if (string.IsNullOrWhiteSpace(payload.Text))
    {
        return Results.BadRequest(new { success = false, error = "payload invÃ¡lido" });
    }

    var result = await processor.ProcessAsync(payload.Text, payload.Source ?? "Webhook", ct);
    return Results.Ok(new
    {
        success = result.Success,
        converted = result.ConvertedText,
        convertedLinks = result.ConvertedLinks,
        source = result.Source
    });
});

app.MapGet("/health", () => Results.Ok(new
{
    status = "ok",
    service = "AchadinhosBot.Next",
    ts = DateTimeOffset.UtcNow,
    telegramBotWorkerEnabled = startTelegramBotWorker,
    telegramUserbotWorkerEnabled = startTelegramUserbotWorker
}));

app.MapGet("/health/live", () => Results.Ok(new
{
    status = "ok",
    service = "AchadinhosBot.Next",
    kind = "liveness",
    ts = DateTimeOffset.UtcNow
}));

app.MapGet("/health/ready", (ITelegramUserbotService userbot) =>
{
    var userbotReady = !startTelegramUserbotWorker || userbot.IsReady;
    var ready = userbotReady;

    if (!ready)
    {
        return Results.Json(new
        {
            status = "degraded",
            kind = "readiness",
            telegramUserbotReady = userbotReady,
            ts = DateTimeOffset.UtcNow
        }, statusCode: StatusCodes.Status503ServiceUnavailable);
    }

    return Results.Ok(new
    {
        status = "ok",
        kind = "readiness",
        telegramUserbotReady = userbotReady,
        ts = DateTimeOffset.UtcNow
    });
});

app.MapGet("/bio", async (HttpContext context, IInstagramPublishStore publishStore, CancellationToken ct) =>
{
    var drafts = await publishStore.ListAsync(ct);
    var items = drafts
        .Where(d => string.Equals(d.Status, "published", StringComparison.OrdinalIgnoreCase))
        .Select(d =>
        {
            var cta = d.Ctas.FirstOrDefault(c => !string.IsNullOrWhiteSpace(c.Link));
            var link = cta?.Link ?? ExtractFirstUrl(d.Caption);
            var title = !string.IsNullOrWhiteSpace(d.ProductName) ? d.ProductName : "Oferta";
            return new BioLinkItem
            {
                CreatedAt = d.CreatedAt,
                Title = title.Trim(),
                Link = link?.Trim() ?? string.Empty,
                Keyword = cta?.Keyword?.Trim()
            };
        })
        .Where(x => !string.IsNullOrWhiteSpace(x.Link))
        .OrderByDescending(x => x.CreatedAt)
        .GroupBy(x => x.Link, StringComparer.OrdinalIgnoreCase)
        .Select(g => g.First())
        .Take(40)
        .ToList();

    var request = context.Request;
    var currentUrl = $"{request.Scheme}://{request.Host}/bio";
    var html = BuildBioLinksPageHtml(items, currentUrl);
    return Results.Content(html, "text/html; charset=utf-8");
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

    if (!VerifyWebhookSignature(request, body, evolution.Value.WebhookSecret))
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
    IOptions<AffiliateOptions> affiliate,
    IOptions<EvolutionOptions> evolutionOptions,
    IOptions<WebhookOptions> webhookOptions,
    IHttpClientFactory httpClientFactory,
    ILogger<Program> logger,
    CancellationToken ct) =>
{
    var body = await new StreamReader(request.Body).ReadToEndAsync(ct);
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

        if (TryParseInstagramCaptionChoiceCommand(msg.Text, out var captionChoice))
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

        if (TryParseWhatsAppHelpCommand(msg.Text, out var helpCommand))
        {
            var senderKey = string.IsNullOrWhiteSpace(msg.SenderId) ? "unknown" : msg.SenderId;
            var helpKey = $"wa-help:{msg.InstanceName ?? "default"}:{msg.ChatId}:{senderKey}:{msg.FromMe}:{ComputeStableHash(msg.Text)}";
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

        if (TryParseInstagramWhatsAppCommand(msg.Text, out var igCommand))
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
            !IsInstagramBotResponse(msg.Text) &&
            instaSettings.Enabled &&
            instaSettings.AllowWhatsApp &&
            IsInstagramAllowed(instaSettings, msg.ChatId))
        {
            var instaKey = $"wa:{msg.ChatId}";
            if (instagramStore.TryConsume(instaKey, out var convo))
            {
                var post = await instagramComposer.BuildAsync(msg.Text, convo.Context, instaSettings, ct);
                foreach (var chunk in SplitInstagramMessages(post))
                {
                    await gateway.SendTextAsync(responderInstance, msg.ChatId, chunk, ct);
                }
                await SendInstagramImagesIfAnyAsync(instaSettings, msg.Text, convo.Context, post, responderInstance, msg.ChatId, instagramMeta, instagramImages, gateway, ct);
                continue;
            }

            if (IsInstagramTrigger(msg.Text, instaSettings.Triggers))
            {
                if (TryGetInstagramInlineProduct(msg.Text, instaSettings.Triggers, out var inlineProduct))
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
                    instagramStore.SetPending(instaKey, msg.Text);
                    await gateway.SendTextAsync(responderInstance, msg.ChatId, "Qual produto? Envie o nome ou o link.", ct);
                }
                continue;
            }
        }

        var autoReply = GetAutoReply(settings, msg.Text);
        if (!msg.FromMe && !string.IsNullOrWhiteSpace(autoReply))
        {
            var tracked = await ApplyTrackingAsync(autoReply, linkTrackingStore, webhookOptions.Value.PublicBaseUrl, responder.TrackingEnabled, ct);
            await gateway.SendTextAsync(responderInstance, msg.ChatId, tracked.Text, ct);
            _ = conversionLogStore.AppendAsync(new ConversionLogEntry
            {
                Source = "AutoReply",
                Store = "AutoReply",
                Success = true,
                OriginalUrl = msg.Text,
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
            msg.Text.Contains("http", StringComparison.OrdinalIgnoreCase) &&
            IsWhatsAppResponderAllowed(responder, msg))
        {
            var responderResult = await processor.ProcessAsync(
                msg.Text,
                "WhatsAppResponder",
                ct,
                originChatRef: msg.ChatId,
                destinationChatRef: msg.ChatId);

            if (responderResult.Success && !string.IsNullOrWhiteSpace(responderResult.ConvertedText))
            {
                var replyText = BuildResponderMessage(responder, responderResult.ConvertedText);
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

                await gateway.SendTextAsync(responderInstance, msg.ChatId, tracked.Text, ct);
                _ = conversionLogStore.AppendAsync(new ConversionLogEntry
                {
                    Source = "WhatsAppResponder",
                    Store = "Unknown",
                    Success = true,
                    OriginalUrl = msg.Text,
                    ConvertedUrl = tracked.Text,
                    TrackingIds = tracked.TrackingIds,
                    OriginChatRef = msg.ChatId,
                    DestinationChatRef = msg.ChatId
                }, ct);
                responderProcessed++;
            }
            else if (!IsWhatsAppGroupChat(msg.ChatId) && !string.IsNullOrWhiteSpace(responder.ReplyOnFailure))
            {
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

            var destinations = waRoute.DestinationGroupIds
                .Where(x => !string.IsNullOrWhiteSpace(x))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray();
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
                msg.Text,
                "WhatsApp",
                ct,
                originChatRef: msg.ChatId,
                destinationChatRef: string.Join(",", destinations));

            if (!result.Success || string.IsNullOrWhiteSpace(result.ConvertedText))
            {
                continue;
            }

            var finalText = result.ConvertedText;
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

api.MapGet("/settings", async (ISettingsStore store, CancellationToken ct) =>
{
    var settings = await store.GetAsync(ct);
    if (!string.IsNullOrWhiteSpace(settings.OpenAI?.ApiKey))
    {
        settings.OpenAI.ApiKey = "********";
    }
    if (!string.IsNullOrWhiteSpace(settings.Gemini?.ApiKey))
    {
        settings.Gemini.ApiKey = "********";
    }
    if (!string.IsNullOrWhiteSpace(settings.InstagramPublish?.AccessToken))
    {
        settings.InstagramPublish.AccessToken = "********";
    }
    if (!string.IsNullOrWhiteSpace(settings.InstagramPublish?.ManyChatApiKey))
    {
        settings.InstagramPublish.ManyChatApiKey = "********";
    }
    return Results.Ok(settings);
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
        var key = payload.OpenAI.ApiKey;
        if (string.IsNullOrWhiteSpace(key) || key == "********")
        {
            payload.OpenAI.ApiKey = current.OpenAI?.ApiKey;
        }
    }

    if (payload.Gemini is null)
    {
        payload.Gemini = current.Gemini ?? new GeminiSettings();
    }
    else
    {
        var key = payload.Gemini.ApiKey;
        if (string.IsNullOrWhiteSpace(key) || key == "********")
        {
            payload.Gemini.ApiKey = current.Gemini?.ApiKey;
        }
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
    ITelegramGateway gateway,
    ISettingsStore store,
    IAuditTrail audit,
    HttpContext context,
    CancellationToken ct) =>
{
    var result = await gateway.ConnectAsync(ct);

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
    CancellationToken ct) =>
{
    if (string.IsNullOrWhiteSpace(payload.Input))
    {
        return Results.BadRequest(new { error = "Informe o texto para teste." });
    }

    var settings = await store.GetAsync(ct);
    var insta = settings.InstagramPosts ?? new InstagramPostSettings();
    var text = await composer.BuildAsync(payload.Input, payload.Context, insta, ct);
    return Results.Ok(new { text });
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
    CancellationToken ct) =>
{
    var items = await approvalStore.ListAsync(status, limit ?? 200, ct);
    return Results.Ok(new { items });
}).RequireAuthorization("AdminOnly");

api.MapPost("/mercadolivre/pending/{id}/approve", async (
    string id,
    MercadoLivreDecisionRequest payload,
    IMercadoLivreApprovalStore approvalStore,
    IMessageProcessor processor,
    ISettingsStore settingsStore,
    IWhatsAppGateway gateway,
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

    var result = await processor.ProcessAsync(
        item.OriginalText,
        "MercadoLivreManualApproval",
        ct,
        originChatId: item.OriginChatId,
        destinationChatId: item.DestinationChatId,
        originChatRef: item.OriginChatRef,
        destinationChatRef: item.DestinationChatRef);

    if (!result.Success || string.IsNullOrWhiteSpace(result.ConvertedText))
    {
        return Results.BadRequest(new { error = "Falha ao converter link durante aprovacao manual." });
    }

    var convertedText = result.ConvertedText ?? item.OriginalText;
    var sendNow = payload.SendNow ?? true;
    var sendSuccess = 0;
    var sendFailures = new List<string>();
    var targets = Array.Empty<string>();

    if (sendNow)
    {
        var settings = await settingsStore.GetAsync(ct);
        var rawTargets = string.IsNullOrWhiteSpace(item.DestinationChatRef)
            ? item.OriginChatRef
            : item.DestinationChatRef;
        targets = ParseChatRefs(rawTargets)
            .Where(x => x.Contains("@", StringComparison.OrdinalIgnoreCase))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        foreach (var target in targets)
        {
            var sendResult = await gateway.SendTextAsync(settings.WhatsAppForwarding?.InstanceName, target, convertedText, ct);
            if (sendResult.Success)
            {
                sendSuccess++;
            }
            else
            {
                sendFailures.Add($"{target}: {sendResult.Message}");
            }
        }
    }

    var reviewNote = payload.Note;
    if (sendNow)
    {
        var summary = $"Envio WhatsApp manual: sucesso={sendSuccess}, falhas={sendFailures.Count}.";
        reviewNote = string.IsNullOrWhiteSpace(reviewNote) ? summary : $"{reviewNote} | {summary}";
    }

    var ok = await approvalStore.DecideAsync(
        id,
        "approved",
        context.User.Identity?.Name ?? "unknown",
        reviewNote,
        convertedText,
        result.ConvertedLinks,
        ct);

    if (!ok)
    {
        return Results.BadRequest(new { error = "Falha ao salvar aprovacao." });
    }

    await audit.WriteAsync("mercadolivre.pending.approved", context.User.Identity?.Name ?? "unknown", new
    {
        id,
        result.ConvertedLinks,
        sendNow,
        sendSuccess,
        sendFailures = sendFailures.Count
    }, ct);
    return Results.Ok(new
    {
        success = true,
        converted = convertedText,
        convertedLinks = result.ConvertedLinks,
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
    var items = await clickLogStore.QueryAsync(q, limit ?? 200, ct);
    return Results.Ok(new { items });
});

api.MapPost("/logs/clicks/clear", async (IClickLogStore clickLogStore, IAuditTrail audit, HttpContext ctx, CancellationToken ct) =>
{
    await clickLogStore.ClearAsync(ct);
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
    var result = await userbot.ReplayRecentOffersToWhatsAppAsync(payload.SourceChatId, count, ct);

    await audit.WriteAsync("telegram.userbot.replay_to_whatsapp", context.User.Identity?.Name ?? "unknown", new
    {
        payload.SourceChatId,
        Count = count,
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

app.MapGet("/media/{id}", (string id, IMediaStore store) =>
{
    if (!store.TryGet(id, out var item))
    {
        return Results.NotFound();
    }

    return Results.File(item.Bytes, item.MimeType);
});

app.MapGet("/r/{id}", async (
    string id,
    ILinkTrackingStore trackingStore,
    IClickLogStore clickLogStore,
    CancellationToken ct) =>
{
    var entry = await trackingStore.RegisterClickAsync(id, ct);
    if (entry is null)
    {
        return Results.NotFound();
    }

    await clickLogStore.AppendAsync(new ClickLogEntry
    {
        TrackingId = entry.Id,
        TargetUrl = entry.TargetUrl
    }, ct);

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
            if (string.IsNullOrWhiteSpace(key) || Environment.GetEnvironmentVariable(key) is not null)
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

            Environment.SetEnvironmentVariable(key, value, EnvironmentVariableTarget.Process);
        }
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
}

static bool VerifyWebhookSignature(HttpRequest request, string body, string? secret)
{
    if (string.IsNullOrWhiteSpace(secret)) return true;

    if (!request.Headers.TryGetValue("x-signature", out var signatureHeader)) return false;

    using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(secret));
    var hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(body));
    var expectedHex = Convert.ToHexString(hash).ToLowerInvariant();
    var provided = signatureHeader.ToString().Trim().ToLowerInvariant();

    return expectedHex == provided;
}

static string ComputeStableHash(string? input)
{
    var value = input ?? string.Empty;
    var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(value));
    return Convert.ToHexString(bytes).ToLowerInvariant();
}

static string[] ParseChatRefs(string? input)
{
    if (string.IsNullOrWhiteSpace(input))
    {
        return Array.Empty<string>();
    }

    return input
        .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
        .Where(x => !string.IsNullOrWhiteSpace(x))
        .Select(x => x.Trim())
        .ToArray();
}

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
        using var input = new MemoryStream(payload);
        using var image = Image.FromStream(input, useEmbeddedColorManagement: false, validateImageData: true);
        using var output = new MemoryStream();
        image.Save(output, ImageFormat.Png);
        return output.ToArray();
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

            draft.ImageUrls = selected;
            await publishStore.UpdateAsync(draft, ct);
            await publishLogStore.AppendAsync(new InstagramPublishLogEntry
            {
                Action = "wa_command_draft_select_images",
                Success = true,
                DraftId = draft.Id,
                Details = $"Indexes={string.Join(",", parsedManage.SelectedIndexes)},Total={selected.Count}"
            }, ct);

            var shortId = draft.Id.Length > 8 ? draft.Id[..8] : draft.Id;
            return new[]
            {
                $"Imagens selecionadas no draft {shortId}: {string.Join(", ", parsedManage.SelectedIndexes)}.",
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

static string BuildBioLinksPageHtml(IReadOnlyList<BioLinkItem> items, string currentUrl)
{
    var sb = new StringBuilder();
    sb.AppendLine("<!doctype html>");
    sb.AppendLine("<html lang=\"pt-BR\">");
    sb.AppendLine("<head>");
    sb.AppendLine("  <meta charset=\"utf-8\" />");
    sb.AppendLine("  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />");
    sb.AppendLine("  <title>Achadinhos - Links</title>");
    sb.AppendLine("  <style>");
    sb.AppendLine("    :root{--bg:#f7f5ef;--card:#fffaf2;--line:#e8dfcc;--text:#1f1a14;--muted:#6a5f4e;--btn:#1f8f5f;--btnText:#fff;}");
    sb.AppendLine("    *{box-sizing:border-box} body{margin:0;font-family:'Segoe UI',Tahoma,sans-serif;background:linear-gradient(180deg,#fffdf8 0%,var(--bg) 100%);color:var(--text)}");
    sb.AppendLine("    .wrap{max-width:760px;margin:0 auto;padding:24px 16px 48px}");
    sb.AppendLine("    .head{padding:18px;border:1px solid var(--line);border-radius:16px;background:var(--card);margin-bottom:18px}");
    sb.AppendLine("    h1{margin:0 0 8px;font-size:1.4rem} p{margin:0;color:var(--muted)}");
    sb.AppendLine("    .card{border:1px solid var(--line);border-radius:14px;background:#fff;padding:14px 14px 12px;margin-bottom:10px}");
    sb.AppendLine("    .title{font-weight:700;font-size:1rem;line-height:1.35}");
    sb.AppendLine("    .meta{margin-top:6px;color:var(--muted);font-size:.9rem}");
    sb.AppendLine("    .btn{display:inline-block;margin-top:10px;background:var(--btn);color:var(--btnText);text-decoration:none;padding:10px 14px;border-radius:10px;font-weight:700}");
    sb.AppendLine("    .empty{padding:14px;border:1px dashed var(--line);border-radius:12px;color:var(--muted)}");
    sb.AppendLine("    .foot{margin-top:14px;font-size:.82rem;color:var(--muted)}");
    sb.AppendLine("  </style>");
    sb.AppendLine("</head>");
    sb.AppendLine("<body><main class=\"wrap\">");
    sb.AppendLine("  <section class=\"head\">");
    sb.AppendLine("    <h1>Achadinhos em destaque</h1>");
    sb.AppendLine("    <p>Toque no botao para abrir a oferta.</p>");
    sb.AppendLine("  </section>");

    if (items.Count == 0)
    {
        sb.AppendLine("  <section class=\"empty\">Nenhuma oferta publicada ainda.</section>");
    }
    else
    {
        foreach (var item in items)
        {
            var title = System.Net.WebUtility.HtmlEncode(item.Title);
            var link = System.Net.WebUtility.HtmlEncode(item.Link);
            var keyword = System.Net.WebUtility.HtmlEncode(item.Keyword ?? string.Empty);
            var createdAt = item.CreatedAt.ToLocalTime().ToString("dd/MM/yyyy HH:mm");

            sb.AppendLine("  <article class=\"card\">");
            sb.AppendLine($"    <div class=\"title\">{title}</div>");
            sb.AppendLine($"    <div class=\"meta\">Publicado em {createdAt}" + (string.IsNullOrWhiteSpace(keyword) ? string.Empty : $" Â· Palavra: <strong>{keyword}</strong>") + "</div>");
            sb.AppendLine($"    <a class=\"btn\" href=\"{link}\" target=\"_blank\" rel=\"noopener noreferrer\">Abrir oferta</a>");
            sb.AppendLine("  </article>");
        }
    }

    sb.AppendLine($"  <div class=\"foot\">Link desta pagina: {System.Net.WebUtility.HtmlEncode(currentUrl)}</div>");
    sb.AppendLine("</main></body></html>");
    return sb.ToString();
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
        sb.AppendLine("Primeiras imagens:");
        foreach (var url in draft.ImageUrls.Take(3))
        {
            sb.AppendLine(url);
        }
        if (draft.ImageUrls.Count > 3)
        {
            sb.AppendLine($"... +{draft.ImageUrls.Count - 3} imagens");
        }
    }

    return sb.ToString().Trim();
}

static string BuildInstagramImageSelectionMessage(InstagramPublishDraft draft)
{
    var shortId = draft.Id.Length > 8 ? draft.Id[..8] : draft.Id;
    var sb = new StringBuilder();
    sb.AppendLine($"Imagens do draft {shortId} (total: {draft.ImageUrls.Count}):");
    sb.AppendLine();

    for (var i = 0; i < draft.ImageUrls.Count; i++)
    {
        sb.AppendLine($"{i + 1}) {draft.ImageUrls[i]}");
    }

    sb.AppendLine();
    sb.AppendLine("Selecionar por indice:");
    sb.AppendLine($"- /ig imagens {shortId} 1");
    sb.AppendLine($"- /ig imagens {shortId} 2");
    sb.AppendLine($"- /ig imagens {shortId} 1,2");
    sb.AppendLine($"- /ig imagens {shortId} 2-4");

    return sb.ToString().Trim();
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
{
    if (!OperatingSystem.IsWindows())
    {
        // Keep original bytes on non-Windows hosts to avoid dropping media.
        return input;
    }

    return NormalizeImageBytesWindows(input);
}

[SupportedOSPlatform("windows")]
#pragma warning disable CA1416
static byte[]? NormalizeImageBytesWindows(byte[] input)
{
    try
    {
        using var ms = new MemoryStream(input);
        using var image = Image.FromStream(ms);
        var width = image.Width;
        var height = image.Height;
        if (width == 0 || height == 0) return null;

        var ratio = width / (double)height;
        const double minRatio = 0.8;
        const double maxRatio = 1.91;

        Rectangle cropRect = new Rectangle(0, 0, width, height);
        if (ratio < minRatio || ratio > maxRatio)
        {
            // normalize to 4:5 ratio (0.8)
            var targetRatio = minRatio;
            if (ratio > targetRatio)
            {
                var newWidth = (int)Math.Round(height * targetRatio);
                var x = Math.Max(0, (width - newWidth) / 2);
                cropRect = new Rectangle(x, 0, Math.Min(newWidth, width), height);
            }
            else
            {
                var newHeight = (int)Math.Round(width / targetRatio);
                var y = Math.Max(0, (height - newHeight) / 2);
                cropRect = new Rectangle(0, y, width, Math.Min(newHeight, height));
            }
        }

        using var cropped = new Bitmap(cropRect.Width, cropRect.Height);
        using (var g = Graphics.FromImage(cropped))
        {
            g.InterpolationMode = System.Drawing.Drawing2D.InterpolationMode.HighQualityBicubic;
            g.DrawImage(image, new Rectangle(0, 0, cropped.Width, cropped.Height), cropRect, GraphicsUnit.Pixel);
        }

        // Resize to Instagram-friendly size (max 1350 height)
        int targetWidth = cropped.Width;
        int targetHeight = cropped.Height;
        const int maxHeight = 1350;
        if (targetHeight > maxHeight)
        {
            var scale = maxHeight / (double)targetHeight;
            targetWidth = (int)Math.Round(targetWidth * scale);
            targetHeight = maxHeight;
        }

        using var resized = new Bitmap(cropped, new Size(targetWidth, targetHeight));
        using var outStream = new MemoryStream();
        var encoder = ImageCodecInfo.GetImageEncoders().FirstOrDefault(c => c.MimeType == "image/jpeg");
        if (encoder is null)
        {
            resized.Save(outStream, ImageFormat.Jpeg);
        }
        else
        {
            using var encParams = new EncoderParameters(1);
            encParams.Param[0] = new EncoderParameter(System.Drawing.Imaging.Encoder.Quality, 90L);
            resized.Save(outStream, encoder, encParams);
        }
        return outStream.ToArray();
    }
    catch
    {
        return null;
    }
}
#pragma warning restore CA1416

static string BuildPublicMediaUrl(string publicBaseUrl, string id)
{
    var baseUrl = publicBaseUrl.TrimEnd('/');
    var url = baseUrl + $"/media/{id}";
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
            var entry = await store.CreateAsync(url, ct);
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

    var caption = BuildInstagramCaption(effectiveCaption, draft.Hashtags);
    var selectedImageUrls = (draft.ImageUrls ?? new List<string>())
        .Where(x => !string.IsNullOrWhiteSpace(x))
        .Distinct(StringComparer.OrdinalIgnoreCase)
        .ToList();
    var publishImageUrls = selectedImageUrls;
    var normalized = await NormalizeInstagramImagesAsync(httpClientFactory, mediaStore, publicBaseUrl, selectedImageUrls, ct);
    if (normalized.Count > 0)
    {
        publishImageUrls = normalized;
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
        (ok, mediaId, errorMessage) = await PublishToInstagramAsync(
            httpClientFactory,
            publishSettings.GraphBaseUrl,
            publishSettings.InstagramUserId!,
            publishSettings.AccessToken!,
            draft.PostType,
            selectedImageUrls,
            caption,
            ct);
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

static string BuildInstagramCaption(string caption, string hashtags)
{
    caption = FormatInstagramCaptionForReadability(caption);
    hashtags ??= string.Empty;
    if (string.IsNullOrWhiteSpace(hashtags)) return caption.Trim();
    if (caption.Contains(hashtags, StringComparison.OrdinalIgnoreCase)) return caption.Trim();
    return string.Join("\n\n", new[] { caption.Trim(), hashtags.Trim() }.Where(x => !string.IsNullOrWhiteSpace(x)));
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

    var ctaLine = $"Comente \"{primaryKeyword}\" para receber o link.";
    if (string.IsNullOrWhiteSpace(baseCaption))
    {
        return ctaLine;
    }

    return $"{baseCaption}\n\n{ctaLine}";
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
            return (false, null, "Sem imagens para publicar.");
        }

        var client = httpClientFactory.CreateClient("default");
        baseUrl = string.IsNullOrWhiteSpace(baseUrl) ? "https://graph.facebook.com/v19.0" : baseUrl.TrimEnd('/');
        var normalizedType = NormalizeInstagramPostTypeValue(postType);

        if (normalizedType == "story")
        {
            var firstImage = imageUrls.FirstOrDefault();
            if (string.IsNullOrWhiteSpace(firstImage))
            {
                return (false, null, "Sem imagens para publicar story.");
            }

            var (containerId, containerError) = await CreateMediaContainerAsync(client, baseUrl, igUserId, accessToken, firstImage, string.Empty, false, "STORIES", ct);
            if (string.IsNullOrWhiteSpace(containerId))
            {
                return (false, null, $"Falha ao criar story. {containerError}");
            }
            var (mediaId, publishError) = await PublishMediaAsync(client, baseUrl, igUserId, accessToken, containerId!, ct);
            return string.IsNullOrWhiteSpace(mediaId) ? (false, null, $"Falha ao publicar story. {publishError}") : (true, mediaId, null);
        }

        if (imageUrls.Count == 1)
        {
            var (containerId, containerError) = await CreateMediaContainerAsync(client, baseUrl, igUserId, accessToken, imageUrls[0], caption, false, null, ct);
            if (string.IsNullOrWhiteSpace(containerId))
            {
                return (false, null, $"Falha ao criar container. {containerError}");
            }
            var (mediaId, publishErrorSingle) = await PublishMediaAsync(client, baseUrl, igUserId, accessToken, containerId!, ct);
            return string.IsNullOrWhiteSpace(mediaId) ? (false, null, $"Falha ao publicar. {publishErrorSingle}") : (true, mediaId, null);
        }

        var childIds = new List<string>();
        string? firstError = null;
        foreach (var url in imageUrls)
        {
            var (child, childError) = await CreateMediaContainerAsync(client, baseUrl, igUserId, accessToken, url, string.Empty, true, null, ct);
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

static async Task<(string? Id, string? Error)> CreateMediaContainerAsync(HttpClient client, string baseUrl, string igUserId, string token, string imageUrl, string caption, bool carouselItem, string? mediaType, CancellationToken ct)
{
    var url = $"{baseUrl}/{igUserId}/media";
    var data = new Dictionary<string, string>
    {
        ["image_url"] = imageUrl,
        ["access_token"] = token
    };
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

internal sealed record LoginRequest(string Username, string Password);
internal sealed record ConvertRequest(string Text, string? Source);
internal sealed record PlaygroundRequest(string Text);
internal sealed record MercadoLivreDecisionRequest(string? Note, bool? SendNow);
internal sealed record WhatsAppInstanceRequest(string? InstanceName);
internal sealed record TelegramUserbotReplayRequest(long SourceChatId, int Count = 10);
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
    public string? Keyword { get; init; }
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
