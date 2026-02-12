using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Configuration;
using Microsoft.Extensions.Options;

namespace AchadinhosBot.Next.Infrastructure.WhatsApp;

public sealed class EvolutionWhatsAppGateway : IWhatsAppGateway
{
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly EvolutionOptions _options;
    private readonly ILogger<EvolutionWhatsAppGateway> _logger;

    public EvolutionWhatsAppGateway(
        IHttpClientFactory httpClientFactory,
        IOptions<EvolutionOptions> options,
        ILogger<EvolutionWhatsAppGateway> logger)
    {
        _httpClientFactory = httpClientFactory;
        _options = options.Value;
        _logger = logger;
    }

    public async Task<WhatsAppConnectResult> ConnectAsync(CancellationToken cancellationToken)
    {
        try
        {
            var client = _httpClientFactory.CreateClient("evolution");
            client.BaseAddress = new Uri(_options.BaseUrl);
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", _options.ApiKey);

            // 1) Garante instância
            var instancePayload = JsonSerializer.Serialize(new
            {
                instanceName = _options.InstanceName,
                qrcode = true,
                integration = "WHATSAPP-BAILEYS"
            });

            var createResponse = await client.PostAsync(
                "/instance/create",
                new StringContent(instancePayload, Encoding.UTF8, "application/json"),
                cancellationToken);

            if (!createResponse.IsSuccessStatusCode)
            {
                var err = await createResponse.Content.ReadAsStringAsync(cancellationToken);
                _logger.LogWarning("Falha ao criar/validar instância Evolution: {Status} {Body}", createResponse.StatusCode, err);
            }

            // 2) Pede QR code
            var qrResponse = await client.GetAsync($"/instance/connect/{_options.InstanceName}", cancellationToken);
            var qrBody = await qrResponse.Content.ReadAsStringAsync(cancellationToken);

            if (!qrResponse.IsSuccessStatusCode)
            {
                return new WhatsAppConnectResult(false, null, $"Falha ao obter QR: {qrResponse.StatusCode}");
            }

            string? qrBase64 = ExtractQrCode(qrBody);
            return new WhatsAppConnectResult(true, qrBase64, "QR code gerado com sucesso.");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao conectar com Evolution API");
            return new WhatsAppConnectResult(false, null, "Erro ao conectar na Evolution API.");
        }
    }

    private static string? ExtractQrCode(string body)
    {
        try
        {
            using var doc = JsonDocument.Parse(body);
            var root = doc.RootElement;

            if (root.TryGetProperty("base64", out var base64Node))
            {
                return base64Node.GetString();
            }

            if (root.TryGetProperty("qrcode", out var qrcodeNode) && qrcodeNode.ValueKind == JsonValueKind.Object)
            {
                if (qrcodeNode.TryGetProperty("base64", out var qrBase64Node))
                {
                    return qrBase64Node.GetString();
                }
            }

            return null;
        }
        catch
        {
            return null;
        }
    }
}
