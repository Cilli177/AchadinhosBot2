using System.Security.Cryptography;
using System.Text;
using AchadinhosBot.Next.Configuration;
using AchadinhosBot.Next.Infrastructure.Security;
using MassTransit;
using Microsoft.Extensions.Options;

namespace AchadinhosBot.Next.Application.Consumers;

public sealed class ProcessBotConversorWebhookCommand
{
    public string MessageId { get; set; } = Guid.NewGuid().ToString("N");
    public string Body { get; set; } = string.Empty;
    public Dictionary<string, string> Headers { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    public DateTimeOffset ReceivedAtUtc { get; set; } = DateTimeOffset.UtcNow;
    public string Source { get; set; } = "webhook/bot-conversor";
}

public sealed class BotConversorWebhookConsumer : IConsumer<ProcessBotConversorWebhookCommand>
{
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ILogger<BotConversorWebhookConsumer> _logger;
    private readonly WebhookOptions _webhookOptions;
    private readonly EvolutionOptions _evolutionOptions;

    public BotConversorWebhookConsumer(
        IHttpClientFactory httpClientFactory,
        IOptions<WebhookOptions> webhookOptions,
        IOptions<EvolutionOptions> evolutionOptions,
        ILogger<BotConversorWebhookConsumer> logger)
    {
        _httpClientFactory = httpClientFactory;
        _webhookOptions = webhookOptions.Value;
        _evolutionOptions = evolutionOptions.Value;
        _logger = logger;
    }

    public async Task Consume(ConsumeContext<ProcessBotConversorWebhookCommand> context)
    {
        var command = context.Message;

        try
        {
            var client = _httpClientFactory.CreateClient("evolution-webhook-internal");
            using var request = new HttpRequestMessage(HttpMethod.Post, "/internal/webhook/bot-conversor")
            {
                Content = new StringContent(command.Body ?? string.Empty, Encoding.UTF8, "application/json")
            };

            foreach (var header in command.Headers)
            {
                if (string.IsNullOrWhiteSpace(header.Key))
                {
                    continue;
                }

                if (string.Equals(header.Key, "Content-Type", StringComparison.OrdinalIgnoreCase))
                {
                    // StringContent already defines the content type for this internal relay.
                    continue;
                }

                if (!request.Headers.TryAddWithoutValidation(header.Key, header.Value))
                {
                    request.Content?.Headers.Remove(header.Key);
                    request.Content?.Headers.TryAddWithoutValidation(header.Key, header.Value);
                }
            }

            if (!string.IsNullOrWhiteSpace(_webhookOptions.ApiKey))
            {
                request.Headers.Remove("x-api-key");
                request.Headers.TryAddWithoutValidation("x-api-key", _webhookOptions.ApiKey);
            }

            if (!string.IsNullOrWhiteSpace(_evolutionOptions.WebhookSecret))
            {
                var signature = BuildSignature(command.Body ?? string.Empty, _evolutionOptions.WebhookSecret);
                request.Headers.Remove(WebhookSignatureVerifier.SignatureHeaderName);
                request.Headers.TryAddWithoutValidation(WebhookSignatureVerifier.SignatureHeaderName, signature);
            }

            using var response = await client.SendAsync(request, context.CancellationToken);
            response.EnsureSuccessStatusCode();

            _logger.LogInformation(
                "Webhook BotConversor processado com sucesso. MessageId={MessageId} Source={Source}",
                command.MessageId,
                command.Source);
        }
        catch (Exception ex)
        {
            _logger.LogError(
                ex,
                "Falha ao processar webhook BotConversor. MessageId={MessageId} Source={Source}",
                command.MessageId,
                command.Source);
            throw;
        }
    }

    private static string BuildSignature(string body, string secret)
    {
        using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(secret.Trim()));
        var bytes = hmac.ComputeHash(Encoding.UTF8.GetBytes(body ?? string.Empty));
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }
}
