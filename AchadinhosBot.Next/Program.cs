using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Drawing;
using System.Drawing.Imaging;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Application.Services;
using AchadinhosBot.Next.Configuration;
using AchadinhosBot.Next.Domain.Logs;
using AchadinhosBot.Next.Domain.Instagram;
using AchadinhosBot.Next.Domain.Requests;
using AchadinhosBot.Next.Domain.Settings;
using AchadinhosBot.Next.Infrastructure.Audit;
using AchadinhosBot.Next.Infrastructure.Idempotency;
using AchadinhosBot.Next.Infrastructure.Instagram;
using AchadinhosBot.Next.Infrastructure.Logs;
using AchadinhosBot.Next.Infrastructure.Media;
using AchadinhosBot.Next.Infrastructure.Security;
using AchadinhosBot.Next.Infrastructure.Storage;
using AchadinhosBot.Next.Infrastructure.Telegram;
using AchadinhosBot.Next.Infrastructure.WhatsApp;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.Options;

var builder = WebApplication.CreateBuilder(args);

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
    .AddOptions<AuthOptions>()
    .Bind(builder.Configuration.GetSection("Auth"))
    .ValidateDataAnnotations()
    .ValidateOnStart();

builder.Services
    .AddOptions<EvolutionOptions>()
    .Bind(builder.Configuration.GetSection("Evolution"))
    .ValidateDataAnnotations();

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
builder.Services.AddHttpClient("openai", c => c.Timeout = TimeSpan.FromSeconds(60));
builder.Services.AddHttpClient("gemini", c => c.Timeout = TimeSpan.FromSeconds(60));

builder.Services.AddSingleton<IAffiliateLinkService, AffiliateLinkService>();
builder.Services.AddSingleton<IConversionLogStore, ConversionLogStore>();
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
builder.Services.AddSingleton<ISettingsStore, JsonSettingsStore>();
builder.Services.AddSingleton<IWhatsAppGateway, EvolutionWhatsAppGateway>();
builder.Services.AddSingleton<IMediaStore, InMemoryMediaStore>();
builder.Services.AddSingleton<InstagramConversationStore>();
builder.Services.AddSingleton<ITelegramGateway, TelegramBotApiGateway>();
builder.Services.AddHostedService<TelegramBotPollingService>();
builder.Services.AddSingleton<ITelegramUserbotService, TelegramUserbotService>();
builder.Services.AddHostedService(provider => (TelegramUserbotService)provider.GetRequiredService<ITelegramUserbotService>());
builder.Services.AddSingleton<IAuditTrail, FileAuditTrail>();
builder.Services.AddSingleton<IIdempotencyStore, MemoryIdempotencyStore>();
builder.Services.AddSingleton<LoginAttemptStore>();
builder.Services.AddSingleton<IMediaFailureLogStore, MediaFailureLogStore>();

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
        return Results.BadRequest(new { success = false, error = "payload inválido" });
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

app.MapGet("/health", () => Results.Ok(new { status = "ok", service = "AchadinhosBot.Next", ts = DateTimeOffset.UtcNow }));

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
    ISettingsStore settingsStore,
    IConversionLogStore conversionLogStore,
    ILinkTrackingStore linkTrackingStore,
    IInstagramPostComposer instagramComposer,
    InstagramConversationStore instagramStore,
    InstagramLinkMetaService instagramMeta,
    InstagramImageDownloadService instagramImages,
    IOptions<AffiliateOptions> affiliate,
    IOptions<WebhookOptions> webhookOptions,
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
    var waSettings = settings.WhatsAppForwarding;
    var responder = settings.LinkResponder ?? new LinkResponderSettings();
    var forwardingEnabled = waSettings.Enabled;
    var destinations = forwardingEnabled
        ? waSettings.DestinationGroupIds.Where(x => !string.IsNullOrWhiteSpace(x)).Distinct().ToArray()
        : Array.Empty<string>();

    var processed = 0;
    var responderProcessed = 0;
    foreach (var msg in messages)
    {
        var instaSettings = settings.InstagramPosts;
        if (!IsInstagramBotResponse(msg.Text) &&
            instaSettings.Enabled &&
            instaSettings.AllowWhatsApp &&
            IsInstagramAllowed(instaSettings, msg.ChatId))
        {
            var instaKey = $"wa:{msg.ChatId}";
            if (instagramStore.TryConsume(instaKey, out var convo))
            {
                var post = await instagramComposer.BuildAsync(msg.Text, convo.Context, instaSettings, ct);
                var responderInstance = string.IsNullOrWhiteSpace(waSettings.InstanceName) ? msg.InstanceName : waSettings.InstanceName;
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
                    var responderInstance = string.IsNullOrWhiteSpace(waSettings.InstanceName) ? msg.InstanceName : waSettings.InstanceName;
                    foreach (var chunk in SplitInstagramMessages(post))
                    {
                        await gateway.SendTextAsync(responderInstance, msg.ChatId, chunk, ct);
                    }
                    await SendInstagramImagesIfAnyAsync(instaSettings, inlineProduct, null, post, responderInstance, msg.ChatId, instagramMeta, instagramImages, gateway, ct);
                }
                else
                {
                    instagramStore.SetPending(instaKey, msg.Text);
                    var responderInstance = string.IsNullOrWhiteSpace(waSettings.InstanceName) ? msg.InstanceName : waSettings.InstanceName;
                    await gateway.SendTextAsync(responderInstance, msg.ChatId, "Qual produto? Envie o nome ou o link.", ct);
                }
                continue;
            }
        }

        var autoReply = GetAutoReply(settings, msg.Text);
        if (!msg.FromMe && !string.IsNullOrWhiteSpace(autoReply))
        {
            var responderInstance = string.IsNullOrWhiteSpace(waSettings.InstanceName) ? msg.InstanceName : waSettings.InstanceName;
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

                var responderInstance = string.IsNullOrWhiteSpace(waSettings.InstanceName) ? msg.InstanceName : waSettings.InstanceName;
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
                var responderInstance = string.IsNullOrWhiteSpace(waSettings.InstanceName) ? msg.InstanceName : waSettings.InstanceName;
                await gateway.SendTextAsync(responderInstance, msg.ChatId, responder.ReplyOnFailure, ct);
                responderProcessed++;
            }
        }

        if (!forwardingEnabled)
        {
            continue;
        }

        if (msg.FromMe)
        {
            if (!waSettings.ProcessFromMeOnly) continue;
            if (waSettings.SourceChatIds.Count == 0 || !waSettings.SourceChatIds.Contains(msg.ChatId)) continue;
        }
        else if (waSettings.ProcessFromMeOnly)
        {
            continue;
        }

        if (waSettings.SourceChatIds.Count > 0 && !waSettings.SourceChatIds.Contains(msg.ChatId))
        {
            continue;
        }
        if (destinations.Length == 0 || waSettings.SourceChatIds.Count == 0)
        {
            continue;
        }

        if (destinations.Contains(msg.ChatId, StringComparer.OrdinalIgnoreCase))
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
        if (waSettings.AppendSheinCode &&
            finalText.Contains("shein", StringComparison.OrdinalIgnoreCase) &&
            !string.IsNullOrWhiteSpace(affiliate.Value.SheinCode) &&
            !finalText.Contains(affiliate.Value.SheinCode, StringComparison.OrdinalIgnoreCase))
        {
            finalText += $"\n\nCodigo Shein: {affiliate.Value.SheinCode}";
        }

        if (!string.IsNullOrWhiteSpace(waSettings.FooterText))
        {
            finalText += $"\n\n{waSettings.FooterText}";
        }

        var instanceToUse = string.IsNullOrWhiteSpace(waSettings.InstanceName) ? msg.InstanceName : waSettings.InstanceName;
        foreach (var destination in destinations)
        {
            var sendResult = await gateway.SendTextAsync(instanceToUse, destination, finalText, ct);
            if (!sendResult.Success)
            {
                logger.LogWarning("Falha ao enviar WhatsApp destino {Destination}: {Message}", destination, sendResult.Message);
            }
        }

        processed++;
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
    CancellationToken ct) =>
{
    var body = await new StreamReader(request.Body).ReadToEndAsync(ct);
    if (string.IsNullOrWhiteSpace(body)) return Results.Ok();

    var settings = await store.GetAsync(ct);
    var publishSettings = settings.InstagramPublish ?? new InstagramPublishSettings();
    var pending = await commentStore.ListPendingAsync(ct);

    foreach (var comment in ExtractInstagramComments(body))
    {
        if (pending.Any(x => x.CommentId == comment.CommentId)) continue;
        var draft = await FindDraftByMediaIdAsync(publishStore, comment.MediaId, ct);
        comment.SuggestedReply = BuildSuggestedReply(draft, publishSettings, comment.Text);
        await commentStore.AddAsync(comment, ct);
        await publishLogStore.AppendAsync(new InstagramPublishLogEntry
        {
            Action = "comment_received",
            Success = true,
            MediaId = comment.MediaId,
            Details = $"CommentId={comment.CommentId}"
        }, ct);
    }

    return Results.Ok(new { success = true });
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
    settings.Integrations.WhatsApp.Notes = result.Message ?? "Conexão solicitada";
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
        return Results.BadRequest(new { success = false, message = "InstanceName obrigatório" });
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
    settings.Integrations.Telegram.Notes = result.Message ?? "Conexão solicitada";
    await store.SaveAsync(settings, ct);

    await audit.WriteAsync("integration.telegram.connect", context.User.Identity?.Name ?? "unknown", new { result.Success, result.Username }, ct);
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
    var publishSettings = settings.InstagramPublish ?? new InstagramPublishSettings();
    if (!publishSettings.Enabled)
    {
        await publishLogStore.AppendAsync(new InstagramPublishLogEntry
        {
            Action = "publish",
            Success = false,
            DraftId = id,
            Error = "Publicacao Instagram desativada."
        }, ct);
        return Results.BadRequest(new { error = "Publicacao Instagram desativada." });
    }
    if (string.IsNullOrWhiteSpace(publishSettings.AccessToken) || publishSettings.AccessToken == "********")
    {
        await publishLogStore.AppendAsync(new InstagramPublishLogEntry
        {
            Action = "publish",
            Success = false,
            DraftId = id,
            Error = "Access token nao configurado."
        }, ct);
        return Results.BadRequest(new { error = "Access token nao configurado." });
    }
    if (string.IsNullOrWhiteSpace(publishSettings.InstagramUserId))
    {
        await publishLogStore.AppendAsync(new InstagramPublishLogEntry
        {
            Action = "publish",
            Success = false,
            DraftId = id,
            Error = "Instagram user id nao configurado."
        }, ct);
        return Results.BadRequest(new { error = "Instagram user id nao configurado." });
    }

    var draft = await publishStore.GetAsync(id, ct);
    if (draft is null)
    {
        await publishLogStore.AppendAsync(new InstagramPublishLogEntry
        {
            Action = "publish",
            Success = false,
            DraftId = id,
            Error = "Rascunho nao encontrado."
        }, ct);
        return Results.NotFound();
    }

    var caption = BuildInstagramCaption(draft.Caption, draft.Hashtags);
    var normalized = await NormalizeInstagramImagesAsync(httpClientFactory, mediaStore, webhookOptions.Value.PublicBaseUrl, draft.ImageUrls, ct);
    if (normalized.Count > 0)
    {
        draft.ImageUrls = normalized;
    }
    var (ok, mediaId, error) = await PublishToInstagramAsync(
        httpClientFactory,
        publishSettings.GraphBaseUrl,
        publishSettings.InstagramUserId!,
        publishSettings.AccessToken!,
        draft.ImageUrls,
        caption,
        ct);

    draft.Status = ok ? "published" : "failed";
    draft.MediaId = mediaId;
    draft.Error = ok ? null : error;
    await publishStore.UpdateAsync(draft, ct);
    await publishLogStore.AppendAsync(new InstagramPublishLogEntry
    {
        Action = "publish",
        Success = ok,
        DraftId = draft.Id,
        MediaId = mediaId,
        Error = ok ? null : error,
        Details = ok ? "Publicado com sucesso" : "Falha ao publicar"
    }, ct);

    return Results.Ok(new { success = ok, mediaId, error });
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

static IEnumerable<string> ValidateSettings(AutomationSettings settings)
{
    var triggers = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
    foreach (var rule in settings.AutoReplies)
    {
        if (string.IsNullOrWhiteSpace(rule.Trigger) || string.IsNullOrWhiteSpace(rule.ResponseTemplate))
        {
            yield return $"Regra '{rule.Name}' inválida (gatilho/resposta obrigatórios).";
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
    msg = new WhatsAppIncomingMessage(string.Empty, string.Empty, false, instanceName);

    var chatId = string.Empty;
    var fromMe = false;

    if (node.TryGetProperty("key", out var key))
    {
        chatId = GetString(key, "remoteJid") ?? string.Empty;
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

    var text = ExtractMessageText(node);
    if (string.IsNullOrWhiteSpace(text))
    {
        return false;
    }

    msg = new WhatsAppIncomingMessage(chatId, text, fromMe, instanceName);
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
        if (normalized.Contains(trigger, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }
    }
    return false;
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
            using var response = await client.GetAsync(uri, ct);
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

static byte[]? NormalizeImageBytes(byte[] input)
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
    return t.StartsWith("Legenda 1", StringComparison.OrdinalIgnoreCase)
           || t.StartsWith("Legenda 2", StringComparison.OrdinalIgnoreCase)
           || t.StartsWith("Hashtags sugeridas", StringComparison.OrdinalIgnoreCase)
           || t.StartsWith("Sugestões de imagem", StringComparison.OrdinalIgnoreCase)
           || t.StartsWith("Sugestoes de imagem", StringComparison.OrdinalIgnoreCase)
           || t.StartsWith("Post extra", StringComparison.OrdinalIgnoreCase)
           || t.StartsWith("Sugestão rápida", StringComparison.OrdinalIgnoreCase)
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
        var idx = normalized.IndexOf(trigger, StringComparison.OrdinalIgnoreCase);
        if (idx < 0) continue;

        var remaining = normalized.Remove(idx, trigger.Length).Trim();
        remaining = remaining.Trim('-', ':', '—', '–');
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
        if (messageNode.TryGetProperty("ephemeralMessage", out var ephemeral) &&
            ephemeral.TryGetProperty("message", out var innerMessage))
        {
            var innerText = ExtractMessageText(innerMessage);
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

static string BuildInstagramCaption(string caption, string hashtags)
{
    caption ??= string.Empty;
    hashtags ??= string.Empty;
    if (string.IsNullOrWhiteSpace(hashtags)) return caption.Trim();
    if (caption.Contains(hashtags, StringComparison.OrdinalIgnoreCase)) return caption.Trim();
    return string.Join("\n\n", new[] { caption.Trim(), hashtags.Trim() }.Where(x => !string.IsNullOrWhiteSpace(x)));
}

static async Task<(bool Success, string? MediaId, string? Error)> PublishToInstagramAsync(
    IHttpClientFactory httpClientFactory,
    string baseUrl,
    string igUserId,
    string accessToken,
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

        if (imageUrls.Count == 1)
        {
            var (containerId, containerError) = await CreateMediaContainerAsync(client, baseUrl, igUserId, accessToken, imageUrls[0], caption, false, ct);
            if (string.IsNullOrWhiteSpace(containerId))
            {
                return (false, null, $"Falha ao criar container. {containerError}");
            }
            var mediaId = await PublishMediaAsync(client, baseUrl, igUserId, accessToken, containerId!, ct);
            return string.IsNullOrWhiteSpace(mediaId) ? (false, null, "Falha ao publicar.") : (true, mediaId, null);
        }

        var childIds = new List<string>();
        string? firstError = null;
        foreach (var url in imageUrls)
        {
            var (child, childError) = await CreateMediaContainerAsync(client, baseUrl, igUserId, accessToken, url, string.Empty, true, ct);
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

        var publishId = await PublishMediaAsync(client, baseUrl, igUserId, accessToken, parentId!, ct);
        return string.IsNullOrWhiteSpace(publishId) ? (false, null, "Falha ao publicar carrossel.") : (true, publishId, null);
    }
    catch (Exception ex)
    {
        return (false, null, ex.Message);
    }
}

static async Task<(string? Id, string? Error)> CreateMediaContainerAsync(HttpClient client, string baseUrl, string igUserId, string token, string imageUrl, string caption, bool carouselItem, CancellationToken ct)
{
    var url = $"{baseUrl}/{igUserId}/media";
    var data = new Dictionary<string, string>
    {
        ["image_url"] = imageUrl,
        ["access_token"] = token
    };
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

static async Task<string?> PublishMediaAsync(HttpClient client, string baseUrl, string igUserId, string token, string creationId, CancellationToken ct)
{
    var url = $"{baseUrl}/{igUserId}/media_publish";
    var data = new Dictionary<string, string>
    {
        ["creation_id"] = creationId,
        ["access_token"] = token
    };
    using var response = await client.PostAsync(url, new FormUrlEncodedContent(data), ct);
    var body = await response.Content.ReadAsStringAsync(ct);
    if (!response.IsSuccessStatusCode) return null;
    return TryGetIdFromJson(body);
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
            var msg = GetString(err, "message");
            var code = GetString(err, "code");
            var sub = GetString(err, "error_subcode");
            return $"Graph error: {msg} (code {code}, sub {sub})";
        }
    }
    catch { }
    return json;
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
                if (value.TryGetProperty("from", out var fromNode))
                {
                    from = GetString(fromNode, "username", "name") ?? string.Empty;
                }

                if (!string.IsNullOrWhiteSpace(commentId))
                {
                    list.Add(new InstagramCommentPending
                    {
                        CommentId = commentId,
                        MediaId = mediaId,
                        Text = text,
                        From = from
                    });
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

static string BuildSuggestedReply(InstagramPublishDraft? draft, InstagramPublishSettings settings, string commentText)
{
    var defaultReply = settings.ReplyNoMatchTemplate ?? string.Empty;
    if (draft is null || draft.Ctas.Count == 0)
    {
        return defaultReply;
    }

    var text = commentText ?? string.Empty;
    var match = draft.Ctas.FirstOrDefault(c => !string.IsNullOrWhiteSpace(c.Keyword) && text.Contains(c.Keyword, StringComparison.OrdinalIgnoreCase));
    if (match is null && draft.Ctas.Count == 1)
    {
        match = draft.Ctas[0];
    }
    if (match is null)
    {
        return defaultReply;
    }

    var template = settings.ReplyTemplate ?? "Aqui esta o link: {link}";
    return template.Replace("{link}", match.Link ?? string.Empty, StringComparison.OrdinalIgnoreCase)
                   .Replace("{keyword}", match.Keyword ?? string.Empty, StringComparison.OrdinalIgnoreCase);
}

internal sealed record LoginRequest(string Username, string Password);
internal sealed record ConvertRequest(string Text, string? Source);
internal sealed record PlaygroundRequest(string Text);
internal sealed record WhatsAppInstanceRequest(string? InstanceName);
internal sealed record WhatsAppIncomingMessage(string ChatId, string Text, bool FromMe, string? InstanceName);
internal sealed record InstagramDraftRequest(
    string ProductName,
    string Caption,
    string Hashtags,
    List<InstagramCtaOption> Ctas,
    List<string> ImageUrls);
internal sealed record InstagramApproveRequest(string Message);
