using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Domain.Settings;
using AchadinhosBot.Next.Configuration;
using Microsoft.Extensions.Options;

namespace AchadinhosBot.Next.Infrastructure.Web;

public sealed class WebhookServerService : BackgroundService
{
    private readonly IMessageProcessor _messageProcessor;
    private readonly ISettingsStore _settingsStore;
    private readonly WebhookOptions _options;
    private readonly ILogger<WebhookServerService> _logger;

    public WebhookServerService(
        IMessageProcessor messageProcessor,
        ISettingsStore settingsStore,
        IOptions<WebhookOptions> options,
        ILogger<WebhookServerService> logger)
    {
        _messageProcessor = messageProcessor;
        _settingsStore = settingsStore;
        _options = options.Value;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var listener = new HttpListener();
        listener.Prefixes.Add($"http://*:{_options.Port}/");
        listener.Start();

        _logger.LogInformation("Dashboard/Webhook ouvindo na porta {Port}", _options.Port);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                var context = await listener.GetContextAsync();
                _ = Task.Run(() => HandleRequestAsync(context, stoppingToken), stoppingToken);
            }
            catch (ObjectDisposedException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Erro no loop principal do servidor web");
            }
        }
    }

    private async Task HandleRequestAsync(HttpListenerContext context, CancellationToken ct)
    {
        try
        {
            var path = context.Request.Url?.AbsolutePath ?? "/";
            var method = context.Request.HttpMethod;

            if (path == "/")
            {
                await ServeDashboardAsync(context.Response, ct);
                return;
            }

            if (path == "/converter" && method == HttpMethod.Post.Method)
            {
                if (!Authorize(context.Request))
                {
                    context.Response.StatusCode = 403;
                    await WriteJsonAsync(context.Response, new { success = false, error = "forbidden" }, ct);
                    return;
                }

                var payload = await ReadJsonAsync<ConvertRequest>(context.Request, ct);
                if (payload is null || string.IsNullOrWhiteSpace(payload.Text))
                {
                    context.Response.StatusCode = 400;
                    await WriteJsonAsync(context.Response, new { success = false, error = "payload inválido" }, ct);
                    return;
                }

                var result = await _messageProcessor.ProcessAsync(payload.Text, payload.Source ?? "Webhook", ct);
                await WriteJsonAsync(context.Response, new
                {
                    success = result.Success,
                    converted = result.ConvertedText,
                    convertedLinks = result.ConvertedLinks,
                    source = result.Source
                }, ct);
                return;
            }

            if (path == "/api/settings" && method == HttpMethod.Get.Method)
            {
                var settings = await _settingsStore.GetAsync(ct);
                if (!string.IsNullOrWhiteSpace(settings.OpenAI?.ApiKey))
                {
                    settings.OpenAI.ApiKey = "********";
                }
                if (!string.IsNullOrWhiteSpace(settings.Gemini?.ApiKey))
                {
                    settings.Gemini.ApiKey = "********";
                }
                await WriteJsonAsync(context.Response, settings, ct);
                return;
            }

            if (path == "/api/settings" && method == HttpMethod.Put.Method)
            {
                var payload = await ReadJsonAsync<AutomationSettings>(context.Request, ct);
                if (payload is null)
                {
                    context.Response.StatusCode = 400;
                    await WriteJsonAsync(context.Response, new { success = false, error = "json inválido" }, ct);
                    return;
                }

                var current = await _settingsStore.GetAsync(ct);
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

                await _settingsStore.SaveAsync(payload, ct);
                await WriteJsonAsync(context.Response, new { success = true }, ct);
                return;
            }

            if (path == "/api/integrations/telegram/login" && method == HttpMethod.Post.Method)
            {
                var payload = await ReadJsonAsync<LoginRequest>(context.Request, ct);
                var settings = await _settingsStore.GetAsync(ct);
                settings.Integrations.Telegram = new IntegrationStatus
                {
                    Connected = true,
                    Identifier = payload?.Identifier,
                    LastLoginAt = DateTimeOffset.UtcNow,
                    Notes = "Login sinalizado pela UI (modo sandbox)"
                };
                await _settingsStore.SaveAsync(settings, ct);
                await WriteJsonAsync(context.Response, new { success = true, mode = "sandbox" }, ct);
                return;
            }

            if (path == "/api/integrations/whatsapp/login" && method == HttpMethod.Post.Method)
            {
                var payload = await ReadJsonAsync<LoginRequest>(context.Request, ct);
                var settings = await _settingsStore.GetAsync(ct);
                settings.Integrations.WhatsApp = new IntegrationStatus
                {
                    Connected = true,
                    Identifier = payload?.Identifier,
                    LastLoginAt = DateTimeOffset.UtcNow,
                    Notes = "Login sinalizado pela UI (modo sandbox)"
                };
                await _settingsStore.SaveAsync(settings, ct);
                await WriteJsonAsync(context.Response, new { success = true, mode = "sandbox" }, ct);
                return;
            }

            context.Response.StatusCode = 404;
            await WriteJsonAsync(context.Response, new { success = false, error = "not_found" }, ct);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao processar request {Method} {Path}", context.Request.HttpMethod, context.Request.Url?.AbsolutePath);
            context.Response.StatusCode = 500;
            await WriteJsonAsync(context.Response, new { success = false, error = "erro interno" }, ct);
        }
        finally
        {
            context.Response.Close();
        }
    }

    private bool Authorize(HttpListenerRequest request)
    {
        var key = request.Headers["x-api-key"] ?? string.Empty;
        var provided = Encoding.UTF8.GetBytes(key);
        var expected = Encoding.UTF8.GetBytes(_options.ApiKey);
        return provided.Length == expected.Length && CryptographicOperations.FixedTimeEquals(provided, expected);
    }

    private static async Task<T?> ReadJsonAsync<T>(HttpListenerRequest request, CancellationToken ct)
    {
        using var reader = new StreamReader(request.InputStream, request.ContentEncoding);
        var body = await reader.ReadToEndAsync(ct);
        if (string.IsNullOrWhiteSpace(body)) return default;
        return JsonSerializer.Deserialize<T>(body, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
    }

    private async Task ServeDashboardAsync(HttpListenerResponse response, CancellationToken ct)
    {
        var dashboardPath = Path.Combine(AppContext.BaseDirectory, "wwwroot", "dashboard.html");
        string html;
        if (File.Exists(dashboardPath))
        {
            html = await File.ReadAllTextAsync(dashboardPath, ct);
        }
        else
        {
            html = "<h1>Dashboard não encontrado</h1>";
        }

        response.ContentType = "text/html; charset=utf-8";
        var bytes = Encoding.UTF8.GetBytes(html);
        await response.OutputStream.WriteAsync(bytes, ct);
    }

    private static async Task WriteJsonAsync(HttpListenerResponse response, object data, CancellationToken ct)
    {
        response.ContentType = "application/json";
        var bytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(data));
        await response.OutputStream.WriteAsync(bytes, ct);
    }

    private sealed record ConvertRequest(string Text, string? Source);
    private sealed record LoginRequest(string? Identifier);
}
