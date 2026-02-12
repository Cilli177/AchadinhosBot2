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
            // Validar configurações
            if (string.IsNullOrWhiteSpace(_options.BaseUrl))
                return new WhatsAppConnectResult(false, null, "Evolution BaseUrl não configurada");
            
            if (string.IsNullOrWhiteSpace(_options.ApiKey))
                return new WhatsAppConnectResult(false, null, "Evolution ApiKey não configurada");

            var client = _httpClientFactory.CreateClient("evolution");
            client.BaseAddress = new Uri(_options.BaseUrl);
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", _options.ApiKey);

            _logger.LogInformation("Conectando Evolution API em {BaseUrl} com instância {InstanceName}", _options.BaseUrl, _options.InstanceName);

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
                var msg = $"Falha ao obter QR: {qrResponse.StatusCode} - {qrBody}";
                _logger.LogError(msg);
                return new WhatsAppConnectResult(false, null, msg);
            }

            string? qrBase64 = ExtractQrCode(qrBody);
            if (string.IsNullOrWhiteSpace(qrBase64))
            {
                _logger.LogWarning("QR code não encontrado na resposta: {Body}", qrBody);
                return new WhatsAppConnectResult(false, null, "QR code não gerado - Evolution pode estar indisponível");
            }

            _logger.LogInformation("QR code gerado com sucesso");
            return new WhatsAppConnectResult(true, qrBase64, "QR code gerado com sucesso.");
        }
        catch (HttpRequestException hexc)
        {
            var msg = $"Erro de conexão com Evolution API ({_options.BaseUrl}): {hexc.Message}";
            _logger.LogError(hexc, msg);
            return new WhatsAppConnectResult(false, null, msg);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao conectar com Evolution API");
            return new WhatsAppConnectResult(false, null, $"Erro: {ex.Message}");
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
