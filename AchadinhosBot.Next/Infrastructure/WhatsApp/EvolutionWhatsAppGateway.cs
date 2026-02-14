using System.Net.Http.Headers;
using System.Collections.Generic;
using System.Linq;
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

    public async Task<WhatsAppConnectResult> ConnectAsync(string? instanceName, CancellationToken cancellationToken)
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
            // Some Evolution setups require api key in a custom header.
            if (!client.DefaultRequestHeaders.Contains("apikey"))
            {
                client.DefaultRequestHeaders.Add("apikey", _options.ApiKey);
            }
            if (!client.DefaultRequestHeaders.Contains("x-api-key"))
            {
                client.DefaultRequestHeaders.Add("x-api-key", _options.ApiKey);
            }

            var targetInstance = string.IsNullOrWhiteSpace(instanceName) ? _options.InstanceName : instanceName.Trim();
            _logger.LogInformation("Conectando Evolution API em {BaseUrl} com instância {InstanceName}", _options.BaseUrl, targetInstance);

            // 1) Garante instância
            var instancePayload = JsonSerializer.Serialize(new
            {
                instanceName = targetInstance,
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
            var qrResponse = await client.GetAsync($"/instance/connect/{targetInstance}", cancellationToken);
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
                var state = ExtractInstanceState(qrBody);
                if (!string.IsNullOrWhiteSpace(state) && state.Equals("open", StringComparison.OrdinalIgnoreCase))
                {
                    _logger.LogInformation("Instância Evolution já conectada: {State}", state);
                    return new WhatsAppConnectResult(true, null, "Instância já conectada.");
                }

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

    private static string? ExtractInstanceState(string body)
    {
        try
        {
            using var doc = JsonDocument.Parse(body);
            var root = doc.RootElement;

            if (root.TryGetProperty("instance", out var instanceNode) && instanceNode.ValueKind == JsonValueKind.Object)
            {
                if (instanceNode.TryGetProperty("state", out var stateNode))
                {
                    return stateNode.GetString();
                }
            }

            if (root.TryGetProperty("state", out var rootState))
            {
                return rootState.GetString();
            }

            return null;
        }
        catch
        {
            return null;
        }
    }

    public async Task<WhatsAppInstanceResult> CreateInstanceAsync(string instanceName, CancellationToken cancellationToken)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(_options.BaseUrl))
                return new WhatsAppInstanceResult(false, null, "Evolution BaseUrl não configurada");
            if (string.IsNullOrWhiteSpace(_options.ApiKey))
                return new WhatsAppInstanceResult(false, null, "Evolution ApiKey não configurada");

            var client = _httpClientFactory.CreateClient("evolution");
            client.BaseAddress = new Uri(_options.BaseUrl);
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", _options.ApiKey);
            if (!client.DefaultRequestHeaders.Contains("apikey"))
            {
                client.DefaultRequestHeaders.Add("apikey", _options.ApiKey);
            }
            if (!client.DefaultRequestHeaders.Contains("x-api-key"))
            {
                client.DefaultRequestHeaders.Add("x-api-key", _options.ApiKey);
            }

            var name = instanceName.Trim();
            var payload = JsonSerializer.Serialize(new
            {
                instanceName = name,
                qrcode = true,
                integration = "WHATSAPP-BAILEYS"
            });

            var res = await client.PostAsync(
                "/instance/create",
                new StringContent(payload, Encoding.UTF8, "application/json"),
                cancellationToken);
            var body = await res.Content.ReadAsStringAsync(cancellationToken);

            if (!res.IsSuccessStatusCode)
            {
                return new WhatsAppInstanceResult(false, null, $"Falha ao criar instância: {res.StatusCode} - {body}");
            }

            var qrBase64 = ExtractQrCode(body);
            return new WhatsAppInstanceResult(true, qrBase64, "Instância criada com sucesso.");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao criar instância Evolution");
            return new WhatsAppInstanceResult(false, null, $"Erro: {ex.Message}");
        }
    }
    public async Task<IReadOnlyList<WhatsAppGroupInfo>> GetGroupsAsync(string? instanceName, CancellationToken cancellationToken)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(_options.BaseUrl))
                return Array.Empty<WhatsAppGroupInfo>();
            if (string.IsNullOrWhiteSpace(_options.ApiKey))
                return Array.Empty<WhatsAppGroupInfo>();

            var client = _httpClientFactory.CreateClient("evolution");
            client.BaseAddress = new Uri(_options.BaseUrl);
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", _options.ApiKey);
            if (!client.DefaultRequestHeaders.Contains("apikey"))
            {
                client.DefaultRequestHeaders.Add("apikey", _options.ApiKey);
            }
            if (!client.DefaultRequestHeaders.Contains("x-api-key"))
            {
                client.DefaultRequestHeaders.Add("x-api-key", _options.ApiKey);
            }

            var targetInstance = string.IsNullOrWhiteSpace(instanceName) ? _options.InstanceName : instanceName.Trim();

            var endpoints = new List<string>();
            if (!string.IsNullOrWhiteSpace(_options.GroupsEndpoint))
            {
                endpoints.Add(_options.GroupsEndpoint!);
            }
            endpoints.AddRange(new[]
            {
                "/group/fetchAllGroups/{instance}?getParticipants=true",
                "/group/fetchAllGroups/{instance}?getParticipants=false",
                "/group/fetchAll/{instance}",
                "/group/list/{instance}",
                "/group/getAllGroups/{instance}",
                "/groups/{instance}"
            });

            foreach (var endpoint in endpoints)
            {
                var path = ResolveEndpoint(endpoint, targetInstance);
                var res = await client.GetAsync(path, cancellationToken);
                var body = await res.Content.ReadAsStringAsync(cancellationToken);
                if (!res.IsSuccessStatusCode)
                {
                    if (res.StatusCode == System.Net.HttpStatusCode.BadRequest &&
                        body.Contains("getParticipants", StringComparison.OrdinalIgnoreCase) &&
                        !endpoint.Contains("getParticipants", StringComparison.OrdinalIgnoreCase))
                    {
                        foreach (var suffix in new[] { "?getParticipants=true", "?getParticipants=false" })
                        {
                            var retryPath = ResolveEndpoint(endpoint, targetInstance) + suffix;
                            var retryRes = await client.GetAsync(retryPath, cancellationToken);
                            var retryBody = await retryRes.Content.ReadAsStringAsync(cancellationToken);
                            if (retryRes.IsSuccessStatusCode)
                            {
                                var retryGroups = ExtractGroups(retryBody);
                                if (retryGroups.Count > 0)
                                {
                                    return retryGroups;
                                }
                            }
                            else
                            {
                                _logger.LogWarning("Falha ao listar grupos Evolution: {Status} {Body}", retryRes.StatusCode, retryBody);
                            }
                        }
                    }

                    _logger.LogWarning("Falha ao listar grupos Evolution: {Status} {Body}", res.StatusCode, body);
                    continue;
                }

                var groups = ExtractGroups(body);
                if (groups.Count > 0)
                {
                    return groups;
                }
            }

            return Array.Empty<WhatsAppGroupInfo>();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao listar grupos Evolution");
            return Array.Empty<WhatsAppGroupInfo>();
        }
    }

    public async Task<WhatsAppSendResult> SendTextAsync(string? instanceName, string to, string text, CancellationToken cancellationToken)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(_options.BaseUrl))
                return new WhatsAppSendResult(false, "Evolution BaseUrl nao configurada");
            if (string.IsNullOrWhiteSpace(_options.ApiKey))
                return new WhatsAppSendResult(false, "Evolution ApiKey nao configurada");
            if (string.IsNullOrWhiteSpace(to))
                return new WhatsAppSendResult(false, "Destino invalido");

            var client = _httpClientFactory.CreateClient("evolution");
            client.BaseAddress = new Uri(_options.BaseUrl);
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", _options.ApiKey);
            if (!client.DefaultRequestHeaders.Contains("apikey"))
            {
                client.DefaultRequestHeaders.Add("apikey", _options.ApiKey);
            }
            if (!client.DefaultRequestHeaders.Contains("x-api-key"))
            {
                client.DefaultRequestHeaders.Add("x-api-key", _options.ApiKey);
            }

            var targetInstance = string.IsNullOrWhiteSpace(instanceName) ? _options.InstanceName : instanceName.Trim();
            var endpoints = new List<string>();
            if (!string.IsNullOrWhiteSpace(_options.SendTextEndpoint))
            {
                endpoints.Add(_options.SendTextEndpoint!);
            }
            endpoints.AddRange(new[]
            {
                "/message/sendText/{instance}",
                "/message/sendText/{instanceName}",
                "/message/sendText"
            });

            foreach (var endpoint in endpoints)
            {
                var path = ResolveEndpoint(endpoint, targetInstance);
                var includeInstance = !endpoint.Contains("{instance}", StringComparison.OrdinalIgnoreCase) &&
                                      !endpoint.Contains("{instanceName}", StringComparison.OrdinalIgnoreCase);

                var payload = new Dictionary<string, object?>
                {
                    ["number"] = to,
                    ["text"] = text
                };
                if (includeInstance)
                {
                    payload["instanceName"] = targetInstance;
                }

                var content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8);
                content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
                var res = await client.PostAsync(path, content, cancellationToken);
                var body = await res.Content.ReadAsStringAsync(cancellationToken);

                if (res.IsSuccessStatusCode)
                {
                    return new WhatsAppSendResult(true, "Mensagem enviada");
                }

                _logger.LogWarning("Falha ao enviar mensagem Evolution: {Status} {Body}", res.StatusCode, body);
            }

            return new WhatsAppSendResult(false, "Falha ao enviar mensagem");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao enviar mensagem Evolution");
            return new WhatsAppSendResult(false, $"Erro: {ex.Message}");
        }
    }

    public async Task<WhatsAppSendResult> SendImageAsync(string? instanceName, string to, byte[] imageBytes, string? caption, string? mimeType, CancellationToken cancellationToken)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(_options.BaseUrl))
                return new WhatsAppSendResult(false, "Evolution BaseUrl nao configurada");
            if (string.IsNullOrWhiteSpace(_options.ApiKey))
                return new WhatsAppSendResult(false, "Evolution ApiKey nao configurada");
            if (string.IsNullOrWhiteSpace(to))
                return new WhatsAppSendResult(false, "Destino invalido");
            if (imageBytes is null || imageBytes.Length == 0)
                return new WhatsAppSendResult(false, "Imagem vazia");

            var client = _httpClientFactory.CreateClient("evolution");
            client.BaseAddress = new Uri(_options.BaseUrl);
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", _options.ApiKey);
            if (!client.DefaultRequestHeaders.Contains("apikey"))
            {
                client.DefaultRequestHeaders.Add("apikey", _options.ApiKey);
            }
            if (!client.DefaultRequestHeaders.Contains("x-api-key"))
            {
                client.DefaultRequestHeaders.Add("x-api-key", _options.ApiKey);
            }

            var targetInstance = string.IsNullOrWhiteSpace(instanceName) ? _options.InstanceName : instanceName.Trim();
            var base64 = Convert.ToBase64String(imageBytes);
            var resolvedMime = string.IsNullOrWhiteSpace(mimeType) ? "image/jpeg" : mimeType;
            var dataUri = $"data:{resolvedMime};base64,{base64}";

            var endpoints = new List<string>();
            if (!string.IsNullOrWhiteSpace(_options.SendImageEndpoint))
            {
                endpoints.Add(_options.SendImageEndpoint!);
            }
            endpoints.AddRange(new[]
            {
                "/message/sendMedia/{instance}",
                "/message/sendMedia/{instanceName}",
                "/message/sendMedia",
                "/message/sendImage/{instance}",
                "/message/sendImage/{instanceName}",
                "/message/sendImage"
            });

            var payloads = new List<Dictionary<string, object?>>
            {
                new()
                {
                    ["number"] = to,
                    ["caption"] = caption ?? string.Empty,
                    ["mediatype"] = "image",
                    ["mimetype"] = resolvedMime,
                    ["media"] = base64,
                    ["fileName"] = "image.jpg"
                },
                new()
                {
                    ["number"] = to,
                    ["caption"] = caption ?? string.Empty,
                    ["mediatype"] = "image",
                    ["base64"] = base64,
                    ["mimetype"] = resolvedMime,
                    ["fileName"] = "image.jpg"
                }
            };

            foreach (var endpoint in endpoints)
            {
                var path = ResolveEndpoint(endpoint, targetInstance);
                var includeInstance = !endpoint.Contains("{instance}", StringComparison.OrdinalIgnoreCase) &&
                                      !endpoint.Contains("{instanceName}", StringComparison.OrdinalIgnoreCase);

                foreach (var payload in payloads)
                {
                    if (includeInstance)
                    {
                        payload["instanceName"] = targetInstance;
                    }

                    var content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8);
                    content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
                    var res = await client.PostAsync(path, content, cancellationToken);
                    var body = await res.Content.ReadAsStringAsync(cancellationToken);

                    if (res.IsSuccessStatusCode)
                    {
                        return new WhatsAppSendResult(true, "Imagem enviada");
                    }

                    _logger.LogWarning("Falha ao enviar imagem Evolution: {Status} {Body}", res.StatusCode, body);
                }
            }

            return new WhatsAppSendResult(false, "Falha ao enviar imagem");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao enviar imagem Evolution");
            return new WhatsAppSendResult(false, $"Erro: {ex.Message}");
        }
    }

    public async Task<WhatsAppSendResult> SendImageUrlAsync(string? instanceName, string to, string mediaUrl, string? caption, string? mimeType, string? fileName, CancellationToken cancellationToken)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(_options.BaseUrl))
                return new WhatsAppSendResult(false, "Evolution BaseUrl nao configurada");
            if (string.IsNullOrWhiteSpace(_options.ApiKey))
                return new WhatsAppSendResult(false, "Evolution ApiKey nao configurada");
            if (string.IsNullOrWhiteSpace(to))
                return new WhatsAppSendResult(false, "Destino invalido");
            if (string.IsNullOrWhiteSpace(mediaUrl))
                return new WhatsAppSendResult(false, "Media URL invalida");

            var client = _httpClientFactory.CreateClient("evolution");
            client.BaseAddress = new Uri(_options.BaseUrl);
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", _options.ApiKey);
            if (!client.DefaultRequestHeaders.Contains("apikey"))
            {
                client.DefaultRequestHeaders.Add("apikey", _options.ApiKey);
            }
            if (!client.DefaultRequestHeaders.Contains("x-api-key"))
            {
                client.DefaultRequestHeaders.Add("x-api-key", _options.ApiKey);
            }

            var targetInstance = string.IsNullOrWhiteSpace(instanceName) ? _options.InstanceName : instanceName.Trim();
            var resolvedMime = string.IsNullOrWhiteSpace(mimeType) ? "image/jpeg" : mimeType;
            var resolvedFileName = string.IsNullOrWhiteSpace(fileName) ? "image.jpg" : fileName;

            var endpoints = new List<string>();
            if (!string.IsNullOrWhiteSpace(_options.SendImageEndpoint))
            {
                endpoints.Add(_options.SendImageEndpoint!);
            }
            endpoints.AddRange(new[]
            {
                "/message/sendMedia/{instance}",
                "/message/sendMedia/{instanceName}",
                "/message/sendMedia",
                "/message/sendImage/{instance}",
                "/message/sendImage/{instanceName}",
                "/message/sendImage"
            });

            foreach (var endpoint in endpoints)
            {
                var path = ResolveEndpoint(endpoint, targetInstance);
                var includeInstance = !endpoint.Contains("{instance}", StringComparison.OrdinalIgnoreCase) &&
                                      !endpoint.Contains("{instanceName}", StringComparison.OrdinalIgnoreCase);

                var payload = new Dictionary<string, object?>
                {
                    ["number"] = to,
                    ["mediatype"] = "image",
                    ["mimetype"] = resolvedMime,
                    ["caption"] = caption ?? string.Empty,
                    ["media"] = mediaUrl,
                    ["fileName"] = resolvedFileName
                };
                if (includeInstance)
                {
                    payload["instanceName"] = targetInstance;
                }

                var content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8);
                content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
                var res = await client.PostAsync(path, content, cancellationToken);
                var body = await res.Content.ReadAsStringAsync(cancellationToken);

                if (res.IsSuccessStatusCode)
                {
                    return new WhatsAppSendResult(true, "Imagem enviada");
                }

                _logger.LogWarning("Falha ao enviar imagem Evolution (url): {Status} {Body}", res.StatusCode, body);
            }

            return new WhatsAppSendResult(false, "Falha ao enviar imagem");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao enviar imagem Evolution (url)");
            return new WhatsAppSendResult(false, $"Erro: {ex.Message}");
        }
    }

    private static string ResolveEndpoint(string template, string instanceName)
    {
        var path = template.Replace("{instance}", instanceName, StringComparison.OrdinalIgnoreCase)
            .Replace("{instanceName}", instanceName, StringComparison.OrdinalIgnoreCase);
        if (!path.StartsWith("/"))
        {
            path = "/" + path;
        }

        return path;
    }

    private static IReadOnlyList<WhatsAppGroupInfo> ExtractGroups(string body)
    {
        try
        {
            using var doc = JsonDocument.Parse(body);
            var groups = new List<WhatsAppGroupInfo>();
            ExtractGroupsFromElement(doc.RootElement, groups);
            return groups
                .GroupBy(g => g.Id)
                .Select(g => g.First())
                .OrderBy(g => g.Name)
                .ToArray();
        }
        catch
        {
            return Array.Empty<WhatsAppGroupInfo>();
        }
    }

    private static void ExtractGroupsFromElement(JsonElement element, List<WhatsAppGroupInfo> groups)
    {
        if (element.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in element.EnumerateArray())
            {
                if (item.ValueKind == JsonValueKind.Object && TryCreateGroupInfo(item, out var info))
                {
                    groups.Add(info);
                }
                else if (item.ValueKind == JsonValueKind.Object || item.ValueKind == JsonValueKind.Array)
                {
                    ExtractGroupsFromElement(item, groups);
                }
            }
            return;
        }

        if (element.ValueKind != JsonValueKind.Object)
        {
            return;
        }

        if (TryCreateGroupInfo(element, out var direct))
        {
            groups.Add(direct);
        }

        foreach (var prop in element.EnumerateObject())
        {
            if (prop.Value.ValueKind == JsonValueKind.Object || prop.Value.ValueKind == JsonValueKind.Array)
            {
                ExtractGroupsFromElement(prop.Value, groups);
            }
        }
    }

    private static bool TryCreateGroupInfo(JsonElement obj, out WhatsAppGroupInfo info)
    {
        info = new WhatsAppGroupInfo(string.Empty, string.Empty, 0, "group");
        var id = GetString(obj, "id", "jid", "groupId", "remoteJid", "chatId");
        var name = GetString(obj, "name", "subject", "title", "topic");
        var type = GetString(obj, "type") ?? "group";

        if (string.IsNullOrWhiteSpace(id) || string.IsNullOrWhiteSpace(name))
        {
            return false;
        }

        var isGroup = id.Contains("@g.us", StringComparison.OrdinalIgnoreCase) ||
                      string.Equals(type, "group", StringComparison.OrdinalIgnoreCase) ||
                      (obj.TryGetProperty("isGroup", out var isGroupNode) && isGroupNode.ValueKind == JsonValueKind.True);

        if (!isGroup)
        {
            return false;
        }

        var count = 0;
        if (obj.TryGetProperty("participantsCount", out var countNode) && countNode.TryGetInt32(out var parsedCount))
        {
            count = parsedCount;
        }
        else if (obj.TryGetProperty("size", out var sizeNode) && sizeNode.TryGetInt32(out var parsedSize))
        {
            count = parsedSize;
        }
        else if (obj.TryGetProperty("participants", out var participantsNode) && participantsNode.ValueKind == JsonValueKind.Array)
        {
            count = participantsNode.GetArrayLength();
        }

        info = new WhatsAppGroupInfo(id, name, count, type);
        return true;
    }

    private static string? GetString(JsonElement obj, params string[] names)
    {
        foreach (var name in names)
        {
            if (obj.TryGetProperty(name, out var node) && node.ValueKind == JsonValueKind.String)
            {
                return node.GetString();
            }
        }

        return null;
    }
}

