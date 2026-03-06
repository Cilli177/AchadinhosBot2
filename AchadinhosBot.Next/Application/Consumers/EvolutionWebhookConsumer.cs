using MassTransit;
using System.Text;
using AchadinhosBot.Next.Configuration;
using AchadinhosBot.Next.Infrastructure.Security;
using Microsoft.Extensions.Options;
using System.Security.Cryptography;

namespace AchadinhosBot.Next.Application.Consumers;

public class ProcessEvolutionWebhookEvent
{
    public string Body { get; set; } = string.Empty;
    public Dictionary<string, string> Headers { get; set; } = new();

    public ProcessEvolutionWebhookEvent() { }

    public ProcessEvolutionWebhookEvent(string body, Dictionary<string, string> headers)
    {
        Body = body;
        Headers = headers;
    }
}

public class EvolutionWebhookConsumer : IConsumer<ProcessEvolutionWebhookEvent>
{
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ILogger<EvolutionWebhookConsumer> _logger;
    private readonly WebhookOptions _webhookOptions;
    private readonly EvolutionOptions _evolutionOptions;

    public EvolutionWebhookConsumer(
        IHttpClientFactory httpClientFactory,
        IOptions<WebhookOptions> webhookOptions,
        IOptions<EvolutionOptions> evolutionOptions,
        ILogger<EvolutionWebhookConsumer> logger)
    {
        _httpClientFactory = httpClientFactory;
        _webhookOptions = webhookOptions.Value;
        _evolutionOptions = evolutionOptions.Value;
        _logger = logger;
    }

    public async Task Consume(ConsumeContext<ProcessEvolutionWebhookEvent> context)
    {
        try
        {
            var client = _httpClientFactory.CreateClient("evolution-webhook-internal");
            var request = new HttpRequestMessage(HttpMethod.Post, "/internal/webhook/bot-conversor");
            
            request.Content = new StringContent(context.Message.Body, Encoding.UTF8, "application/json");
            
            foreach (var header in context.Message.Headers)
            {
                if (string.IsNullOrWhiteSpace(header.Key))
                {
                    continue;
                }

                // Keep propagated headers only at request level to avoid duplicated
                // values (notably x-api-key) when Content.Headers is also populated.
                request.Headers.Remove(header.Key);
                request.Headers.TryAddWithoutValidation(header.Key, header.Value);
            }

            // Internal webhook endpoint also enforces x-api-key; guarantee it here even when
            // the external provider did not include this header.
            if (!string.IsNullOrWhiteSpace(_webhookOptions.ApiKey))
            {
                request.Headers.Remove("x-api-key");
                request.Headers.TryAddWithoutValidation("x-api-key", _webhookOptions.ApiKey);
            }

            if (!string.IsNullOrWhiteSpace(_evolutionOptions.WebhookSecret))
            {
                var signature = BuildSignature(context.Message.Body ?? string.Empty, _evolutionOptions.WebhookSecret);
                request.Headers.Remove(WebhookSignatureVerifier.SignatureHeaderName);
                request.Headers.TryAddWithoutValidation(WebhookSignatureVerifier.SignatureHeaderName, signature);
            }

            var response = await client.SendAsync(request, context.CancellationToken);
            response.EnsureSuccessStatusCode();
            
            _logger.LogInformation("Mensagem do webhook processada com sucesso no consumidor.");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Falha ao processar webhook internamente no consumidor.");
            throw; // Permite que o RabbitMQ faça retry automatico gerando re-delivery
        }
    }

    private static string BuildSignature(string body, string secret)
    {
        using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(secret.Trim()));
        var bytes = hmac.ComputeHash(Encoding.UTF8.GetBytes(body ?? string.Empty));
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }
}
