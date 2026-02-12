using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Application.Services;
using AchadinhosBot.Next.Configuration;
using AchadinhosBot.Next.Domain.Settings;
using AchadinhosBot.Next.Infrastructure.Audit;
using AchadinhosBot.Next.Infrastructure.Idempotency;
using AchadinhosBot.Next.Infrastructure.Security;
using AchadinhosBot.Next.Infrastructure.Storage;
using AchadinhosBot.Next.Infrastructure.Telegram;
using AchadinhosBot.Next.Infrastructure.WhatsApp;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.Options;

// Carregar variáveis do arquivo .env
LoadEnvFile();

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
    c.Timeout = TimeSpan.FromSeconds(30);
    c.DefaultRequestHeaders.UserAgent.ParseAdd("AchadinhosBot.Next/1.0");
});
builder.Services.AddHttpClient("evolution", c => c.Timeout = TimeSpan.FromSeconds(30));

builder.Services.AddSingleton<IAffiliateLinkService, AffiliateLinkService>();
builder.Services.AddSingleton<IMessageProcessor, MessageProcessor>();
builder.Services.AddSingleton<ISettingsStore, JsonSettingsStore>();
builder.Services.AddSingleton<IWhatsAppGateway, EvolutionWhatsAppGateway>();
builder.Services.AddSingleton<ITelegramGateway, TelegramBotApiGateway>();
builder.Services.AddSingleton<IAuditTrail, FileAuditTrail>();
builder.Services.AddSingleton<IIdempotencyStore, MemoryIdempotencyStore>();
builder.Services.AddSingleton<LoginAttemptStore>();

var app = builder.Build();

var webhookOptions = app.Services.GetRequiredService<IOptions<WebhookOptions>>().Value;
app.Urls.Clear();
app.Urls.Add($"http://0.0.0.0:{webhookOptions.Port}");

// Ajuste para abrir dashboard.html quando acessar "/"
var defaultFilesOptions = new DefaultFilesOptions();
defaultFilesOptions.DefaultFileNames.Clear();
defaultFilesOptions.DefaultFileNames.Add("dashboard.html");

app.UseDefaultFiles(defaultFilesOptions);
app.UseStaticFiles();
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

var api = app.MapGroup("/api").RequireAuthorization("ReadAccess");

api.MapGet("/settings", async (ISettingsStore store, CancellationToken ct) =>
{
    var settings = await store.GetAsync(ct);
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

    await store.SaveAsync(payload, ct);
    await audit.WriteAsync("settings.updated", context.User.Identity?.Name ?? "unknown", new { autoReplies = payload.AutoReplies.Count }, ct);
    return Results.Ok(new { success = true });
}).RequireAuthorization("AdminOnly");

api.MapPost("/integrations/whatsapp/connect", async (
    IWhatsAppGateway gateway,
    ISettingsStore store,
    IAuditTrail audit,
    HttpContext context,
    CancellationToken ct) =>
{
    var result = await gateway.ConnectAsync(ct);

    var settings = await store.GetAsync(ct);
    settings.Integrations.WhatsApp.Connected = result.Success;
    settings.Integrations.WhatsApp.Identifier = "evolution-instance";
    settings.Integrations.WhatsApp.LastLoginAt = DateTimeOffset.UtcNow;
    settings.Integrations.WhatsApp.Notes = result.Message ?? "Conexão solicitada";
    await store.SaveAsync(settings, ct);

    await audit.WriteAsync("integration.whatsapp.connect", context.User.Identity?.Name ?? "unknown", new { result.Success }, ct);
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

static void LoadEnvFile()
{
    // Tentar encontrar .env em múltiplos locais
    var possiblePaths = new[]
    {
        Path.Combine(AppContext.BaseDirectory, ".env"),
        Path.Combine(Directory.GetCurrentDirectory(), ".env"),
        Path.Combine(AppContext.BaseDirectory, "../.env"),
        Path.Combine(Directory.GetCurrentDirectory(), "../.env"),
    };

    var envFile = possiblePaths.FirstOrDefault(File.Exists);
    if (envFile == null) return;

    Console.WriteLine($"[ENV] Carregando variáveis de: {Path.GetFullPath(envFile)}");

    foreach (var line in File.ReadAllLines(envFile))
    {
        if (string.IsNullOrWhiteSpace(line) || line.StartsWith("#")) continue;
        
        var parts = line.Split('=', 2);
        if (parts.Length == 2)
        {
            var key = parts[0].Trim();
            var value = parts[1].Trim();
            Environment.SetEnvironmentVariable(key, value);
        }
    }
}

internal sealed record LoginRequest(string Username, string Password);
internal sealed record ConvertRequest(string Text, string? Source);
internal sealed record PlaygroundRequest(string Text);
