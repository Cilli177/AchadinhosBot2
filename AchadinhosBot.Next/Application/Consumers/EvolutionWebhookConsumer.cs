using MassTransit;
using System.Text;

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

    public EvolutionWebhookConsumer(IHttpClientFactory httpClientFactory, ILogger<EvolutionWebhookConsumer> logger)
    {
        _httpClientFactory = httpClientFactory;
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
                request.Content.Headers.TryAddWithoutValidation(header.Key, header.Value);
                request.Headers.TryAddWithoutValidation(header.Key, header.Value);
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
}
