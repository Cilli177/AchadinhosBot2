using System.Net.Http.Headers;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Application.Services;
using AchadinhosBot.Next.Configuration;
using AchadinhosBot.Next.Domain.Compliance;
using AchadinhosBot.Next.Infrastructure.Safety;
using Microsoft.Extensions.Options;

namespace AchadinhosBot.Next.Infrastructure.WhatsApp;

public sealed class EvolutionWhatsAppGateway : IWhatsAppGateway, IWhatsAppTransport
{
    private static async Task<HttpResponseMessage> PostWithAttemptTimeoutAsync(HttpClient client, string path, HttpContent content, CancellationToken cancellationToken, TimeSpan? timeout = null)
    {
        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutCts.CancelAfter(timeout ?? TimeSpan.FromSeconds(8));
        return await client.PostAsync(path, content, timeoutCts.Token);
    }

    private readonly IHttpClientFactory _httpClientFactory;
    private readonly EvolutionOptions _options;
    private readonly DeliverySafetyPolicy _deliverySafetyPolicy;
    private readonly IMercadoLivreApprovalStore _approvalStore;
    private readonly ILogger<EvolutionWhatsAppGateway> _logger;
    private readonly ConcurrentDictionary<string, CachedGroupsEntry> _groupsCache = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, CachedParticipantsEntry> _participantsCache = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, DateTimeOffset> _groupsRateLimitedUntil = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, DateTimeOffset> _participantsRateLimitedUntil = new(StringComparer.OrdinalIgnoreCase);

    public EvolutionWhatsAppGateway(
        IHttpClientFactory httpClientFactory,
        IOptions<EvolutionOptions> options,
        DeliverySafetyPolicy deliverySafetyPolicy,
        IMercadoLivreApprovalStore approvalStore,
        ILogger<EvolutionWhatsAppGateway> logger)
    {
        _httpClientFactory = httpClientFactory;
        _options = options.Value;
        _deliverySafetyPolicy = deliverySafetyPolicy;
        _approvalStore = approvalStore;
        _logger = logger;
    }

    public async Task<WhatsAppConnectResult> ConnectAsync(string? instanceName, CancellationToken cancellationToken)
    {
        try
        {
            // Validar configurações
            var baseUrl = SafeCreateUri(_options.BaseUrl);
            if (baseUrl == null)
                return new WhatsAppConnectResult(false, null, "Evolution BaseUrl não configurada ou inválida");
            
            if (string.IsNullOrWhiteSpace(_options.ApiKey))
                return new WhatsAppConnectResult(false, null, "Evolution ApiKey não configurada");

            var client = _httpClientFactory.CreateClient("evolution-groups");
            client.BaseAddress = baseUrl;
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

            var targetInstance = ResolveInstanceName(instanceName);
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

            var (qrBase64, fetchedQrBody) = await TryFetchQrCodeWithRetriesAsync(client, targetInstance, qrBody, cancellationToken);
            qrBody = fetchedQrBody;
            if (string.IsNullOrWhiteSpace(qrBase64))
            {
                var state = await TryFetchInstanceStateAsync(client, targetInstance, qrBody, cancellationToken);
                if (!string.IsNullOrWhiteSpace(state) && state.Equals("open", StringComparison.OrdinalIgnoreCase))
                {
                    _logger.LogInformation("Instância Evolution já conectada: {State}", state);
                    return new WhatsAppConnectResult(true, null, "Instância já conectada.");
                }

                if (!string.IsNullOrWhiteSpace(state) && state.Equals("connecting", StringComparison.OrdinalIgnoreCase))
                {
                    _logger.LogInformation("Instância Evolution ainda em pareamento: {State}", state);
                    return new WhatsAppConnectResult(false, null, "Pareamento iniciado, mas o QR Code ainda não foi disponibilizado pela Evolution. Aguarde alguns segundos e tente novamente.");
                }

                _logger.LogWarning("QR code não encontrado na resposta da Evolution. Estado: {State}. Body: {Body}", state, qrBody);
                return new WhatsAppConnectResult(false, null, "QR code não gerado pela Evolution. Verifique se a instância está ativa e tente novamente.");
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

    public async Task<WhatsAppConnectResult> TestConnectionAsync(string? instanceName, CancellationToken cancellationToken)
    {
        try
        {
            var baseUrl = SafeCreateUri(_options.BaseUrl);
            if (baseUrl == null)
                return new WhatsAppConnectResult(false, null, "Evolution BaseUrl não configurada ou inválida");

            if (string.IsNullOrWhiteSpace(_options.ApiKey))
                return new WhatsAppConnectResult(false, null, "Evolution ApiKey não configurada");

            var client = _httpClientFactory.CreateClient("evolution-groups");
            client.BaseAddress = baseUrl;
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", _options.ApiKey);
            if (!client.DefaultRequestHeaders.Contains("apikey"))
            {
                client.DefaultRequestHeaders.Add("apikey", _options.ApiKey);
            }
            if (!client.DefaultRequestHeaders.Contains("x-api-key"))
            {
                client.DefaultRequestHeaders.Add("x-api-key", _options.ApiKey);
            }

            var targetInstance = ResolveInstanceName(instanceName);
            var response = await client.GetAsync($"/instance/connectionState/{targetInstance}", cancellationToken);
            var body = await response.Content.ReadAsStringAsync(cancellationToken);

            if (!response.IsSuccessStatusCode)
            {
                var msg = $"Falha ao consultar estado: {response.StatusCode} - {body}";
                _logger.LogWarning(msg);
                return new WhatsAppConnectResult(false, null, msg);
            }

            var state = ExtractInstanceState(body);
            if (string.IsNullOrWhiteSpace(state))
            {
                return new WhatsAppConnectResult(false, null, "Estado da instância não informado pela Evolution.");
            }

            if (state.Equals("open", StringComparison.OrdinalIgnoreCase))
            {
                return new WhatsAppConnectResult(true, null, "Instância conectada e pronta para envio.");
            }

            return new WhatsAppConnectResult(false, null, $"Instância está {state}.");
        }
        catch (HttpRequestException hexc)
        {
            var msg = $"Erro de conexão com Evolution API ({_options.BaseUrl}): {hexc.Message}";
            _logger.LogError(hexc, msg);
            return new WhatsAppConnectResult(false, null, msg);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao testar conexão com Evolution API");
            return new WhatsAppConnectResult(false, null, $"Erro: {ex.Message}");
        }
    }

    public async Task<WhatsAppConnectionSnapshot> GetConnectionSnapshotAsync(string? instanceName, CancellationToken cancellationToken)
    {
        try
        {
            var baseUrl = SafeCreateUri(_options.BaseUrl);
            if (baseUrl == null)
                return new WhatsAppConnectionSnapshot(false, null, null, "Evolution BaseUrl não configurada ou inválida");

            if (string.IsNullOrWhiteSpace(_options.ApiKey))
                return new WhatsAppConnectionSnapshot(false, null, null, "Evolution ApiKey não configurada");

            var client = _httpClientFactory.CreateClient("evolution-groups");
            client.BaseAddress = baseUrl;
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", _options.ApiKey);
            if (!client.DefaultRequestHeaders.Contains("apikey"))
            {
                client.DefaultRequestHeaders.Add("apikey", _options.ApiKey);
            }

            if (!client.DefaultRequestHeaders.Contains("x-api-key"))
            {
                client.DefaultRequestHeaders.Add("x-api-key", _options.ApiKey);
            }

            var targetInstance = ResolveInstanceName(instanceName);
            var stateResponse = await client.GetAsync($"/instance/connectionState/{targetInstance}", cancellationToken);
            var stateBody = await stateResponse.Content.ReadAsStringAsync(cancellationToken);
            if (!stateResponse.IsSuccessStatusCode)
            {
                return new WhatsAppConnectionSnapshot(false, null, null, $"Falha ao consultar estado: {stateResponse.StatusCode} - {stateBody}");
            }

            var state = ExtractInstanceState(stateBody);
            if (!string.IsNullOrWhiteSpace(state) && state.Equals("open", StringComparison.OrdinalIgnoreCase))
            {
                return new WhatsAppConnectionSnapshot(true, state, null, "Instância conectada e pronta para envio.");
            }

            var qrResponse = await client.GetAsync($"/instance/connect/{targetInstance}", cancellationToken);
            var qrBody = await qrResponse.Content.ReadAsStringAsync(cancellationToken);
            if (!qrResponse.IsSuccessStatusCode)
            {
                return new WhatsAppConnectionSnapshot(false, state, null, $"Falha ao obter QR: {qrResponse.StatusCode} - {qrBody}");
            }

            var (qrBase64, fetchedQrBody) = await TryFetchQrCodeWithRetriesAsync(client, targetInstance, qrBody, cancellationToken);
            var effectiveState = ExtractInstanceState(fetchedQrBody ?? qrBody) ?? state;
            if (!string.IsNullOrWhiteSpace(qrBase64))
            {
                return new WhatsAppConnectionSnapshot(false, effectiveState, qrBase64, "QR code disponível. Escaneie com o WhatsApp para concluir a conexão.");
            }

            return new WhatsAppConnectionSnapshot(false, effectiveState, null, $"Instância está {effectiveState ?? "desconhecida"} e ainda não expôs QR.");
        }
        catch (HttpRequestException hexc)
        {
            var msg = $"Erro de conexão com Evolution API ({_options.BaseUrl}): {hexc.Message}";
            _logger.LogError(hexc, msg);
            return new WhatsAppConnectionSnapshot(false, null, null, msg);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao consultar snapshot de conexão com Evolution API");
            return new WhatsAppConnectionSnapshot(false, null, null, $"Erro: {ex.Message}");
        }
    }

    private async Task<(string? QrBase64, string? Body)> TryFetchQrCodeWithRetriesAsync(HttpClient client, string targetInstance, string initialBody, CancellationToken cancellationToken)
    {
        var qrBase64 = ExtractQrCode(initialBody);
        if (!string.IsNullOrWhiteSpace(qrBase64))
        {
            return (qrBase64, initialBody);
        }

        var lastBody = initialBody;
        for (var attempt = 0; attempt < 3; attempt++)
        {
            await Task.Delay(TimeSpan.FromSeconds(2), cancellationToken);

            var qrResponse = await client.GetAsync($"/instance/connect/{targetInstance}", cancellationToken);
            lastBody = await qrResponse.Content.ReadAsStringAsync(cancellationToken);
            if (!qrResponse.IsSuccessStatusCode)
            {
                var msg = $"Falha ao obter QR: {qrResponse.StatusCode} - {lastBody}";
                _logger.LogError(msg);
                throw new InvalidOperationException(msg);
            }

            qrBase64 = ExtractQrCode(lastBody);
            if (!string.IsNullOrWhiteSpace(qrBase64))
            {
                return (qrBase64, lastBody);
            }
        }

        return (null, lastBody);
    }

    private async Task<string?> TryFetchInstanceStateAsync(HttpClient client, string targetInstance, string? qrBody, CancellationToken cancellationToken)
    {
        var state = string.IsNullOrWhiteSpace(qrBody) ? null : ExtractInstanceState(qrBody);
        if (!string.IsNullOrWhiteSpace(state))
        {
            return state;
        }

        try
        {
            var stateResponse = await client.GetAsync($"/instance/connectionState/{targetInstance}", cancellationToken);
            if (!stateResponse.IsSuccessStatusCode)
            {
                return null;
            }

            var stateBody = await stateResponse.Content.ReadAsStringAsync(cancellationToken);
            return ExtractInstanceState(stateBody);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Falha ao consultar estado da instancia Evolution durante connect");
            return null;
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
            var baseUrl = SafeCreateUri(_options.BaseUrl);
            if (baseUrl == null)
                return new WhatsAppInstanceResult(false, null, "Evolution BaseUrl não configurada ou inválida");
            if (string.IsNullOrWhiteSpace(_options.ApiKey))
                return new WhatsAppInstanceResult(false, null, "Evolution ApiKey não configurada");

            var client = _httpClientFactory.CreateClient("evolution-groups");
            client.BaseAddress = baseUrl;
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
            var baseUrl = SafeCreateUri(_options.BaseUrl);
            if (baseUrl == null)
                return Array.Empty<WhatsAppGroupInfo>();
            if (string.IsNullOrWhiteSpace(_options.ApiKey))
                return Array.Empty<WhatsAppGroupInfo>();

            var client = _httpClientFactory.CreateClient("evolution-groups");
            client.BaseAddress = baseUrl;
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", _options.ApiKey);
            if (!client.DefaultRequestHeaders.Contains("apikey"))
            {
                client.DefaultRequestHeaders.Add("apikey", _options.ApiKey);
            }
            if (!client.DefaultRequestHeaders.Contains("x-api-key"))
            {
                client.DefaultRequestHeaders.Add("x-api-key", _options.ApiKey);
            }

            var targetInstance = ResolveInstanceName(instanceName);
            var cacheKey = targetInstance;
            var now = DateTimeOffset.UtcNow;
            _groupsCache.TryGetValue(cacheKey, out var cachedGroups);
            if (cachedGroups is not null && cachedGroups.ExpiresAt > now)
            {
                return cachedGroups.Groups;
            }

            if (_groupsRateLimitedUntil.TryGetValue(cacheKey, out var blockedUntil) && blockedUntil > now)
            {
                if (cachedGroups is not null && cachedGroups.Groups.Count > 0)
                {
                    _logger.LogInformation("Listagem de grupos Evolution em cooldown ate {BlockedUntil}. Retornando cache com {Count} grupo(s).", blockedUntil, cachedGroups.Groups.Count);
                    return cachedGroups.Groups;
                }

                _logger.LogWarning("Listagem de grupos Evolution em cooldown ate {BlockedUntil}. Ignorando nova consulta remota.", blockedUntil);
                return Array.Empty<WhatsAppGroupInfo>();
            }

            var endpoints = new List<string>();
            if (!string.IsNullOrWhiteSpace(_options.GroupsEndpoint))
            {
                endpoints.Add(_options.GroupsEndpoint!);
            }
            endpoints.AddRange(new[]
            {
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
                    if (IsRateOverlimit(body))
                    {
                        _groupsRateLimitedUntil[cacheKey] = now.AddSeconds(45);
                        if (cachedGroups is not null && cachedGroups.Groups.Count > 0)
                        {
                            _logger.LogWarning("Evolution retornou rate-overlimit ao listar grupos. Retornando cache com {Count} grupo(s).", cachedGroups.Groups.Count);
                            return cachedGroups.Groups;
                        }
                    }

                    if (res.StatusCode == System.Net.HttpStatusCode.BadRequest &&
                        body.Contains("getParticipants", StringComparison.OrdinalIgnoreCase) &&
                        !endpoint.Contains("getParticipants", StringComparison.OrdinalIgnoreCase))
                    {
                        foreach (var suffix in new[] { "?getParticipants=false", "?getParticipants=true" })
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
                    _logger.LogWarning("Falha ao listar grupos Evolution (retry) no endpoint {Endpoint}: {Status} {Body}", retryPath, retryRes.StatusCode, retryBody);
                            }
                        }
                    }

                    _logger.LogWarning("Falha ao listar grupos Evolution no endpoint {Endpoint}: {Status} {Body}", path, res.StatusCode, body);
                    continue;
                }

                var groups = ExtractGroups(body);
                if (groups.Count > 0)
                {
                    _groupsCache[cacheKey] = new CachedGroupsEntry(groups, now.AddMinutes(2));
                    _groupsRateLimitedUntil.TryRemove(cacheKey, out _);
                    return groups;
                }
            }

            if (cachedGroups is not null && cachedGroups.Groups.Count > 0)
            {
                return cachedGroups.Groups;
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
            var baseUrl = SafeCreateUri(_options.BaseUrl);
            if (baseUrl == null)
                return new WhatsAppSendResult(false, "Evolution BaseUrl nao configurada ou inválida");
            if (string.IsNullOrWhiteSpace(_options.ApiKey))
                return new WhatsAppSendResult(false, "Evolution ApiKey nao configurada");
            if (string.IsNullOrWhiteSpace(to))
                return new WhatsAppSendResult(false, "Destino invalido");
            if (_deliverySafetyPolicy.IsOfficialWhatsAppDestination(to))
            {
                _logger.LogWarning(
                    "Envio WhatsApp texto bloqueado para grupo oficial no transporte Evolution. Instance={InstanceName} Destination={Destination}",
                    instanceName,
                    to);
                return new WhatsAppSendResult(false, "Grupo oficial exige imagem; envio de texto bloqueado.");
            }

            if (!_deliverySafetyPolicy.IsWhatsAppDestinationAllowed(to, out var blockReason))
            {
                _logger.LogWarning("Envio WhatsApp bloqueado por safety policy. Destino={Destination} Reason={Reason}", to, blockReason);
                await QueueManualApprovalAsync(
                    source: "DeliverySafetyWhatsApp",
                    reason: blockReason ?? "Destino bloqueado por safety policy",
                    originalText: text,
                    destinationChatRef: to,
                    cancellationToken);
                return new WhatsAppSendResult(true, "Mensagem enviada para fila de aprovação manual no dashboard.");
            }

            var client = _httpClientFactory.CreateClient("evolution");
            client.BaseAddress = baseUrl;
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", _options.ApiKey);
            if (!client.DefaultRequestHeaders.Contains("apikey"))
            {
                client.DefaultRequestHeaders.Add("apikey", _options.ApiKey);
            }
            if (!client.DefaultRequestHeaders.Contains("x-api-key"))
            {
                client.DefaultRequestHeaders.Add("x-api-key", _options.ApiKey);
            }

            var targetInstance = ResolveInstanceName(instanceName);
            if (string.IsNullOrWhiteSpace(targetInstance))
                return new WhatsAppSendResult(false, "InstanceName da Evolution nao configurado");

            var safeText = SanitizeOfficialOfferText(targetInstance, to, text);
            if (!string.Equals(safeText, text, StringComparison.Ordinal))
            {
                _logger.LogInformation("Marcador replay/reply removido de mensagem oficial para o destino {Destination}.", to);
            }

            var stateCheck = await EnsureInstanceOpenForSendAsync(client, targetInstance, cancellationToken);
            if (!stateCheck.Success)
            {
                return new WhatsAppSendResult(false, stateCheck.Message ?? "Instancia WhatsApp nao conectada");
            }

            var endpoints = new List<string>();
            if (!string.IsNullOrWhiteSpace(_options.SendTextEndpoint))
            {
                if (_options.SendTextEndpoint.Contains("sendText", StringComparison.OrdinalIgnoreCase))
                {
                    endpoints.Add(_options.SendTextEndpoint!);
                }
                else
                {
                    _logger.LogInformation("Ignorando endpoint customizado de texto sem sendText: {Endpoint}", _options.SendTextEndpoint);
                }
            }
            endpoints.Add("/message/sendText/{instanceName}");

            string? lastFailureDetail = null;

            foreach (var endpoint in endpoints)
            {
                var path = ResolveEndpoint(endpoint, targetInstance);

                var payload = new Dictionary<string, object?>
                {
                    ["number"] = to,
                    ["text"] = safeText
                };

                var content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");
                var res = await PostWithAttemptTimeoutAsync(client, path, content, cancellationToken);
                var body = await res.Content.ReadAsStringAsync(cancellationToken);

                if (res.IsSuccessStatusCode)
                {
                    return new WhatsAppSendResult(true, "Mensagem enviada");
                }

                _logger.LogWarning("Falha ao enviar mensagem Evolution: {Status} {Body}", res.StatusCode, body);
                lastFailureDetail = $"endpoint={path} status={(int)res.StatusCode} body={body}";
            }

            return new WhatsAppSendResult(false, $"Falha ao enviar mensagem ({lastFailureDetail ?? "sem detalhes"})");
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
            var baseUrl = SafeCreateUri(_options.BaseUrl);
            if (baseUrl == null)
                return new WhatsAppSendResult(false, "Evolution BaseUrl nao configurada ou inválida");
            if (string.IsNullOrWhiteSpace(_options.ApiKey))
                return new WhatsAppSendResult(false, "Evolution ApiKey nao configurada");
            if (string.IsNullOrWhiteSpace(to))
                return new WhatsAppSendResult(false, "Destino invalido");
            if (imageBytes is null || imageBytes.Length == 0)
                return new WhatsAppSendResult(false, "Imagem vazia");
            if (!_deliverySafetyPolicy.IsWhatsAppDestinationAllowed(to, out var blockReason))
            {
                _logger.LogWarning("Envio WhatsApp de imagem bloqueado por safety policy. Destino={Destination} Reason={Reason}", to, blockReason);
                var pendingText = string.IsNullOrWhiteSpace(caption) ? "[midia sem legenda]" : caption;
                await QueueManualApprovalAsync(
                    source: "DeliverySafetyWhatsApp",
                    reason: blockReason ?? "Destino bloqueado por safety policy",
                    originalText: pendingText,
                    destinationChatRef: to,
                    cancellationToken);
                return new WhatsAppSendResult(true, "Mídia enviada para fila de aprovação manual no dashboard.");
            }

            var client = _httpClientFactory.CreateClient("evolution");
            client.BaseAddress = baseUrl;
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", _options.ApiKey);
            if (!client.DefaultRequestHeaders.Contains("apikey"))
            {
                client.DefaultRequestHeaders.Add("apikey", _options.ApiKey);
            }
            if (!client.DefaultRequestHeaders.Contains("x-api-key"))
            {
                client.DefaultRequestHeaders.Add("x-api-key", _options.ApiKey);
            }

            var targetInstance = ResolveInstanceName(instanceName);
            if (string.IsNullOrWhiteSpace(targetInstance))
                return new WhatsAppSendResult(false, "InstanceName da Evolution nao configurado");

            var safeCaption = SanitizeOfficialOfferText(targetInstance, to, caption ?? string.Empty);

            var stateCheck = await EnsureInstanceOpenForSendAsync(client, targetInstance, cancellationToken);
            if (!stateCheck.Success)
            {
                return new WhatsAppSendResult(false, stateCheck.Message ?? "Instancia WhatsApp nao conectada");
            }

            var base64 = Convert.ToBase64String(imageBytes);
            var resolvedMime = string.IsNullOrWhiteSpace(mimeType) ? "image/jpeg" : mimeType;
            var dataUri = $"data:{resolvedMime};base64,{base64}";

            var endpoints = new List<string>();
            if (!string.IsNullOrWhiteSpace(_options.SendImageEndpoint))
            {
                if (_options.SendImageEndpoint.Contains("sendMedia", StringComparison.OrdinalIgnoreCase))
                {
                    endpoints.Add(_options.SendImageEndpoint!);
                }
                else
                {
                    _logger.LogInformation("Ignorando endpoint customizado de imagem sem sendMedia: {Endpoint}", _options.SendImageEndpoint);
                }
            }
            endpoints.Add("/message/sendMedia/{instanceName}");

            var payloadFactories = new List<Func<Dictionary<string, object?>>>
            {
                () => new()
                {
                    ["number"] = to,
                    ["caption"] = safeCaption,
                    ["mediatype"] = "image",
                    ["mimetype"] = resolvedMime,
                    ["media"] = base64,
                    ["fileName"] = "image.jpg"
                },
                () => new()
                {
                    ["number"] = to,
                    ["caption"] = safeCaption,
                    ["mediatype"] = "image",
                    ["mimetype"] = resolvedMime,
                    ["media"] = dataUri,
                    ["fileName"] = "image.jpg"
                },
                () => new()
                {
                    ["number"] = to,
                    ["caption"] = safeCaption,
                    ["mediatype"] = "image",
                    ["base64"] = base64,
                    ["mimetype"] = resolvedMime,
                    ["fileName"] = "image.jpg"
                }
            };

            string? lastFailure = null;
            var attemptTrace = new List<string>();
            foreach (var endpoint in endpoints)
            {
                var path = ResolveEndpoint(endpoint, targetInstance);

                for (var i = 0; i < payloadFactories.Count; i++)
                {
                    var payload = payloadFactories[i]();

                    var content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");
                    var res = await PostWithAttemptTimeoutAsync(client, path, content, cancellationToken);
                    var body = await res.Content.ReadAsStringAsync(cancellationToken);

                    if (res.IsSuccessStatusCode)
                    {
                        return new WhatsAppSendResult(true, "Imagem enviada");
                    }

                    lastFailure =
                        $"endpoint={path};payload={i + 1};status={(int)res.StatusCode} {res.ReasonPhrase};body={(string.IsNullOrWhiteSpace(body) ? "sem body" : body[..Math.Min(body.Length, 200)])}";
                    attemptTrace.Add($"endpoint={path};payload={i + 1};status={(int)res.StatusCode}");
                    _logger.LogWarning("Falha ao enviar imagem Evolution: {Status} {Body}", res.StatusCode, body);
                }
            }

            var trace = attemptTrace.Count > 0 ? string.Join(" | ", attemptTrace.Take(8)) : "sem tentativas";
            return new WhatsAppSendResult(false, $"Falha ao enviar imagem ({lastFailure ?? "sem detalhes"}); trace={trace}");
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
            var baseUrl = SafeCreateUri(_options.BaseUrl);
            if (baseUrl == null)
                return new WhatsAppSendResult(false, "Evolution BaseUrl nao configurada ou inválida");
            if (string.IsNullOrWhiteSpace(_options.ApiKey))
                return new WhatsAppSendResult(false, "Evolution ApiKey nao configurada");
            if (string.IsNullOrWhiteSpace(to))
                return new WhatsAppSendResult(false, "Destino invalido");
            if (string.IsNullOrWhiteSpace(mediaUrl))
                return new WhatsAppSendResult(false, "Media URL invalida");
            if (!_deliverySafetyPolicy.IsWhatsAppDestinationAllowed(to, out var blockReason))
            {
                _logger.LogWarning("Envio WhatsApp de imagem por URL bloqueado por safety policy. Destino={Destination} Reason={Reason}", to, blockReason);
                var pendingText = string.IsNullOrWhiteSpace(caption)
                    ? $"[midia-url] {mediaUrl}"
                    : $"{caption}\n\n[midia-url] {mediaUrl}";
                await QueueManualApprovalAsync(
                    source: "DeliverySafetyWhatsApp",
                    reason: blockReason ?? "Destino bloqueado por safety policy",
                    originalText: pendingText,
                    destinationChatRef: to,
                    cancellationToken);
                return new WhatsAppSendResult(true, "Mídia enviada para fila de aprovação manual no dashboard.");
            }

            var client = _httpClientFactory.CreateClient("evolution");
            client.BaseAddress = baseUrl;
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", _options.ApiKey);
            if (!client.DefaultRequestHeaders.Contains("apikey"))
            {
                client.DefaultRequestHeaders.Add("apikey", _options.ApiKey);
            }
            if (!client.DefaultRequestHeaders.Contains("x-api-key"))
            {
                client.DefaultRequestHeaders.Add("x-api-key", _options.ApiKey);
            }

            var targetInstance = ResolveInstanceName(instanceName);
            if (string.IsNullOrWhiteSpace(targetInstance))
                return new WhatsAppSendResult(false, "InstanceName da Evolution nao configurado");

            var safeCaption = SanitizeOfficialOfferText(targetInstance, to, caption ?? string.Empty);

            var stateCheck = await EnsureInstanceOpenForSendAsync(client, targetInstance, cancellationToken);
            if (!stateCheck.Success)
            {
                return new WhatsAppSendResult(false, stateCheck.Message ?? "Instancia WhatsApp nao conectada");
            }

            var resolvedMime = string.IsNullOrWhiteSpace(mimeType) ? "image/jpeg" : mimeType;
            var resolvedMediaType = resolvedMime.StartsWith("video/", StringComparison.OrdinalIgnoreCase)
                ? "video"
                : "image";
            var resolvedFileName = string.IsNullOrWhiteSpace(fileName)
                ? (string.Equals(resolvedMediaType, "video", StringComparison.OrdinalIgnoreCase) ? "video.mp4" : "image.jpg")
                : fileName;

            var endpoints = new List<string>();
            if (!string.IsNullOrWhiteSpace(_options.SendImageEndpoint))
            {
                if (_options.SendImageEndpoint.Contains("sendMedia", StringComparison.OrdinalIgnoreCase))
                {
                    endpoints.Add(_options.SendImageEndpoint!);
                }
                else
                {
                    _logger.LogInformation("Ignorando endpoint customizado de imagem sem sendMedia: {Endpoint}", _options.SendImageEndpoint);
                }
            }
            endpoints.Add("/message/sendMedia/{instanceName}");

            var payloadFactories = new List<Func<Dictionary<string, object?>>>
            {
                () => new()
                {
                    ["number"] = to,
                    ["mediatype"] = resolvedMediaType,
                    ["mimetype"] = resolvedMime,
                    ["caption"] = safeCaption,
                    ["media"] = mediaUrl,
                    ["fileName"] = resolvedFileName
                },
                () => new()
                {
                    ["number"] = to,
                    ["mediatype"] = resolvedMediaType,
                    ["mimetype"] = resolvedMime,
                    ["caption"] = safeCaption,
                    ["mediaUrl"] = mediaUrl,
                    ["fileName"] = resolvedFileName
                },
                () => new()
                {
                    ["number"] = to,
                    ["mediatype"] = resolvedMediaType,
                    ["mimetype"] = resolvedMime,
                    ["caption"] = safeCaption,
                    ["url"] = mediaUrl,
                    ["fileName"] = resolvedFileName
                }
            };

            string? lastFailure = null;
            var attemptTrace = new List<string>();
            foreach (var endpoint in endpoints)
            {
                var path = ResolveEndpoint(endpoint, targetInstance);

                for (var i = 0; i < payloadFactories.Count; i++)
                {
                    var payload = payloadFactories[i]();

                    var content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");
                    var mediaTimeout = string.Equals(resolvedMediaType, "video", StringComparison.OrdinalIgnoreCase)
                        ? TimeSpan.FromSeconds(60)
                        : (TimeSpan?)null;
                    var res = await PostWithAttemptTimeoutAsync(client, path, content, cancellationToken, mediaTimeout);
                    var body = await res.Content.ReadAsStringAsync(cancellationToken);

                    if (res.IsSuccessStatusCode)
                    {
                        return new WhatsAppSendResult(true, string.Equals(resolvedMediaType, "video", StringComparison.OrdinalIgnoreCase) ? "Video enviado" : "Imagem enviada");
                    }

                    lastFailure =
                        $"endpoint={path};payload={i + 1};status={(int)res.StatusCode} {res.ReasonPhrase};body={(string.IsNullOrWhiteSpace(body) ? "sem body" : body[..Math.Min(body.Length, 200)])}";
                    attemptTrace.Add($"endpoint={path};payload={i + 1};status={(int)res.StatusCode}");
                    _logger.LogWarning("Falha ao enviar imagem Evolution (url): {Status} {Body}", res.StatusCode, body);
                }
            }

            var trace = attemptTrace.Count > 0 ? string.Join(" | ", attemptTrace.Take(8)) : "sem tentativas";
            var fallbackByBytes = await TrySendImageUrlAsBytesAsync(
                client,
                targetInstance,
                to,
                mediaUrl,
                safeCaption,
                resolvedMediaType,
                resolvedMime,
                resolvedFileName,
                cancellationToken);
            if (fallbackByBytes.Success)
            {
                return fallbackByBytes;
            }

            return new WhatsAppSendResult(false, $"Falha ao enviar imagem ({lastFailure ?? "sem detalhes"}); trace={trace}; fallback={fallbackByBytes.Message ?? "sem detalhes"}");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao enviar imagem Evolution (url)");
            return new WhatsAppSendResult(false, $"Erro: {ex.Message}");
        }
    }

    private async Task<WhatsAppSendResult> TrySendImageUrlAsBytesAsync(
        HttpClient evolutionClient,
        string targetInstance,
        string to,
        string mediaUrl,
        string? caption,
        string fallbackMediaType,
        string fallbackMimeType,
        string fallbackFileName,
        CancellationToken cancellationToken)
    {
        try
        {
            var downloaded = await TryDownloadImageAsync(mediaUrl, fallbackMimeType, cancellationToken);
            if (downloaded.Bytes is null || downloaded.Bytes.Length == 0)
            {
                return new WhatsAppSendResult(false, downloaded.Error ?? "Falha ao baixar a midia para fallback.");
            }

            var resolvedMime = !string.IsNullOrWhiteSpace(downloaded.MimeType)
                ? downloaded.MimeType!
                : fallbackMimeType;
            var base64 = Convert.ToBase64String(downloaded.Bytes);
            var dataUri = $"data:{resolvedMime};base64,{base64}";
            var payloadFactories = new List<Func<Dictionary<string, object?>>>
            {
                () => new()
                {
                    ["number"] = to,
                    ["caption"] = caption ?? string.Empty,
                    ["mediatype"] = fallbackMediaType,
                    ["mimetype"] = resolvedMime,
                    ["media"] = dataUri,
                    ["fileName"] = fallbackFileName
                },
                () => new()
                {
                    ["number"] = to,
                    ["caption"] = caption ?? string.Empty,
                    ["mediatype"] = fallbackMediaType,
                    ["mimetype"] = resolvedMime,
                    ["media"] = base64,
                    ["fileName"] = fallbackFileName
                },
                () => new()
                {
                    ["number"] = to,
                    ["caption"] = caption ?? string.Empty,
                    ["mediatype"] = fallbackMediaType,
                    ["base64"] = base64,
                    ["mimetype"] = resolvedMime,
                    ["fileName"] = fallbackFileName
                }
            };

            var path = ResolveEndpoint("/message/sendMedia/{instanceName}", targetInstance);
            for (var i = 0; i < payloadFactories.Count; i++)
            {
                var payload = payloadFactories[i]();
                var content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");
                var res = await evolutionClient.PostAsync(path, content, cancellationToken);
                var body = await res.Content.ReadAsStringAsync(cancellationToken);
                if (res.IsSuccessStatusCode)
                {
                    _logger.LogInformation("Midia enviada via fallback por bytes apos falha de URL. Instance={Instance} Destination={Destination} MediaType={MediaType}", targetInstance, to, fallbackMediaType);
                    return new WhatsAppSendResult(true, "Midia enviada via fallback por bytes.");
                }

                _logger.LogWarning("Falha ao enviar midia Evolution via fallback por bytes: {Status} {Body}", res.StatusCode, body);
            }

            return new WhatsAppSendResult(false, "Fallback por bytes também falhou.");
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Falha no fallback por bytes para midia da Evolution. Url={MediaUrl}", mediaUrl);
            return new WhatsAppSendResult(false, ex.Message);
        }
    }

    private async Task<(byte[]? Bytes, string? MimeType, string? Error)> TryDownloadImageAsync(string mediaUrl, string fallbackMimeType, CancellationToken cancellationToken)
    {
        try
        {
            var client = _httpClientFactory.CreateClient("default");
            using var req = new HttpRequestMessage(HttpMethod.Get, mediaUrl);
            req.Headers.UserAgent.ParseAdd("Mozilla/5.0 (compatible; AchadinhosBot/1.0)");
            req.Headers.Accept.ParseAdd("image/*,video/*,*/*;q=0.8");

            using var res = await client.SendAsync(req, cancellationToken);
            if (!res.IsSuccessStatusCode)
            {
                return (null, null, $"Download da imagem retornou {(int)res.StatusCode} {res.ReasonPhrase}.");
            }

            var bytes = await res.Content.ReadAsByteArrayAsync(cancellationToken);
            if (bytes.Length == 0)
            {
                return (null, null, "Download da imagem retornou vazio.");
            }

            var mimeType = res.Content.Headers.ContentType?.MediaType;
            if (string.IsNullOrWhiteSpace(mimeType) || mimeType.Equals("application/octet-stream", StringComparison.OrdinalIgnoreCase))
            {
                mimeType = DetectMimeTypeFromBytes(bytes) ?? fallbackMimeType;
            }

            return (bytes, mimeType, null);
        }
        catch (Exception ex)
        {
            return (null, null, ex.Message);
        }
    }

    public async Task<WhatsAppSendResult> UpdateProfilePictureAsync(string? instanceName, string picture, CancellationToken cancellationToken)
    {
        try
        {
            var normalizedPicture = NormalizeProfilePictureValue(picture);
            if (string.IsNullOrWhiteSpace(normalizedPicture))
            {
                return new WhatsAppSendResult(false, "Imagem de perfil inválida. Envie uma URL HTTPS, data URI ou base64.");
            }

            var baseUrl = SafeCreateUri(_options.BaseUrl);
            if (baseUrl == null)
            {
                return new WhatsAppSendResult(false, "Evolution BaseUrl nao configurada ou invalida");
            }

            if (string.IsNullOrWhiteSpace(_options.ApiKey))
            {
                return new WhatsAppSendResult(false, "Evolution ApiKey nao configurada");
            }

            var client = _httpClientFactory.CreateClient("evolution");
            client.BaseAddress = baseUrl;
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", _options.ApiKey);
            if (!client.DefaultRequestHeaders.Contains("apikey"))
            {
                client.DefaultRequestHeaders.Add("apikey", _options.ApiKey);
            }
            if (!client.DefaultRequestHeaders.Contains("x-api-key"))
            {
                client.DefaultRequestHeaders.Add("x-api-key", _options.ApiKey);
            }

            var targetInstance = ResolveInstanceName(instanceName);
            if (string.IsNullOrWhiteSpace(targetInstance))
            {
                return new WhatsAppSendResult(false, "InstanceName da Evolution nao configurado");
            }

            var stateCheck = await EnsureInstanceOpenForSendAsync(client, targetInstance, cancellationToken);
            if (!stateCheck.Success)
            {
                return new WhatsAppSendResult(false, stateCheck.Message ?? "Instancia WhatsApp nao conectada");
            }

            var path = ResolveEndpoint("/chat/updateProfilePicture/{instance}", targetInstance);
            var payloadFactories = new List<Func<Dictionary<string, object?>>>
            {
                () => new() { ["picture"] = normalizedPicture },
                () => new() { ["url"] = normalizedPicture },
                () => new() { ["image"] = normalizedPicture },
                () => new() { ["media"] = normalizedPicture }
            };

            foreach (var method in new[] { HttpMethod.Post, HttpMethod.Put })
            {
                for (var i = 0; i < payloadFactories.Count; i++)
                {
                    var payload = payloadFactories[i]();
                    using var request = new HttpRequestMessage(method, path)
                    {
                        Content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json")
                    };

                    using var response = await client.SendAsync(request, cancellationToken);
                    var body = await response.Content.ReadAsStringAsync(cancellationToken);
                    if (response.IsSuccessStatusCode)
                    {
                        _logger.LogInformation(
                            "Foto de perfil atualizada via Evolution. Instance={Instance} Method={Method} PayloadVariant={Variant}",
                            targetInstance,
                            method.Method,
                            i + 1);
                        return new WhatsAppSendResult(true, "Foto de perfil atualizada com sucesso.");
                    }

                    _logger.LogWarning(
                        "Falha ao atualizar foto de perfil via Evolution. Instance={Instance} Method={Method} PayloadVariant={Variant} Status={Status} Body={Body}",
                        targetInstance,
                        method.Method,
                        i + 1,
                        response.StatusCode,
                        body);
                }
            }

            return new WhatsAppSendResult(false, "Evolution nao aceitou a imagem de perfil com os formatos tentados.");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao atualizar foto de perfil do WhatsApp via Evolution");
            return new WhatsAppSendResult(false, $"Erro: {ex.Message}");
        }
    }

    private static string? DetectMimeTypeFromBytes(byte[] bytes)
    {
        if (bytes.Length >= 3 &&
            bytes[0] == 0xFF &&
            bytes[1] == 0xD8 &&
            bytes[2] == 0xFF)
        {
            return "image/jpeg";
        }

        if (bytes.Length >= 8 &&
            bytes[0] == 0x89 &&
            bytes[1] == 0x50 &&
            bytes[2] == 0x4E &&
            bytes[3] == 0x47 &&
            bytes[4] == 0x0D &&
            bytes[5] == 0x0A &&
            bytes[6] == 0x1A &&
            bytes[7] == 0x0A)
        {
            return "image/png";
        }

        if (bytes.Length >= 12 &&
            bytes[4] == 0x66 &&
            bytes[5] == 0x74 &&
            bytes[6] == 0x79 &&
            bytes[7] == 0x70)
        {
            return "video/mp4";
        }

        if (bytes.Length >= 12 &&
            bytes[0] == 0x52 &&
            bytes[1] == 0x49 &&
            bytes[2] == 0x46 &&
            bytes[3] == 0x46 &&
            bytes[8] == 0x57 &&
            bytes[9] == 0x45 &&
            bytes[10] == 0x42 &&
            bytes[11] == 0x50)
        {
            return "image/webp";
        }

        if (bytes.Length >= 6)
        {
            var header = Encoding.ASCII.GetString(bytes, 0, Math.Min(bytes.Length, 6));
            if (string.Equals(header, "GIF87a", StringComparison.Ordinal) ||
                string.Equals(header, "GIF89a", StringComparison.Ordinal))
            {
                return "image/gif";
            }
        }

        return null;
    }

    private async Task QueueManualApprovalAsync(
        string source,
        string reason,
        string originalText,
        string destinationChatRef,
        CancellationToken cancellationToken)
    {
        var urls = Regex.Matches(originalText ?? string.Empty, @"https?://[^\s]+", RegexOptions.IgnoreCase)
            .Select(m => m.Value.Trim())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        await _approvalStore.AppendAsync(new MercadoLivrePendingApproval
        {
            Source = source,
            Reason = reason,
            OriginalText = originalText ?? string.Empty,
            ExtractedUrls = urls,
            DestinationChatRef = destinationChatRef
        }, cancellationToken);
    }

    private async Task<WhatsAppSendResult> EnsureInstanceOpenForSendAsync(HttpClient client, string instanceName, CancellationToken cancellationToken)
    {
        try
        {
            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeoutCts.CancelAfter(TimeSpan.FromSeconds(8));

            var res = await client.GetAsync($"/instance/connectionState/{instanceName}", timeoutCts.Token);
            var body = await res.Content.ReadAsStringAsync(timeoutCts.Token);

            if (!res.IsSuccessStatusCode)
            {
                if (res.StatusCode == System.Net.HttpStatusCode.NotFound)
                {
                    // For compatibility with providers without this route, let send flow continue.
                    return new WhatsAppSendResult(true, null);
                }

                _logger.LogWarning("Falha ao consultar estado da instancia Evolution: {Status} {Body}", res.StatusCode, body);
                // Some providers keep connectionState unstable/intermittent even when send endpoints work.
                // Do not block message delivery when this health probe fails.
                return new WhatsAppSendResult(true, $"Falha ao consultar estado da instancia {instanceName}; envio sera tentado mesmo assim");
            }

            var state = ExtractInstanceState(body);
            if (string.Equals(state, "open", StringComparison.OrdinalIgnoreCase))
            {
                return new WhatsAppSendResult(true, null);
            }

            if (string.IsNullOrWhiteSpace(state))
            {
                _logger.LogWarning("Instancia {InstanceName} sem estado definido na Evolution; prosseguindo com tentativa de envio.", instanceName);
                return new WhatsAppSendResult(true, $"Instancia {instanceName} sem estado definido; envio sera tentado");
            }

            return new WhatsAppSendResult(false, $"Instancia {instanceName} esta {state}; conecte no Evolution antes de enviar");
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            _logger.LogWarning("Timeout ao consultar estado da instancia {InstanceName}; prosseguindo com tentativa de envio.", instanceName);
            return new WhatsAppSendResult(true, $"Timeout ao consultar estado da instancia {instanceName}; envio sera tentado");
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Erro ao consultar estado da instancia Evolution para envio");
            return new WhatsAppSendResult(true, $"Erro ao consultar estado da instancia {instanceName}; envio sera tentado");
        }
    }

    private static string SanitizeOfficialOfferText(string targetInstance, string destination, string text)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return text;
        }

        var normalizedText = NormalizeOutgoingTextEncoding(text);
        // Ensure institutional bio URL is always clickable and stable.
        normalizedText = Regex.Replace(
            normalizedText,
            @"(?<!https?://)\bbio\.reidasofertas\.ia\.br\b",
            "https://bio.reidasofertas.ia.br",
            RegexOptions.IgnoreCase);

        if (!string.Equals(targetInstance, WhatsAppInstanceRoutingPolicy.OfficialOffersInstance, StringComparison.OrdinalIgnoreCase))
        {
            return normalizedText;
        }

        if (!destination.EndsWith("@g.us", StringComparison.OrdinalIgnoreCase))
        {
            return normalizedText;
        }

        var sanitized = Regex.Replace(
            normalizedText,
            "\\[(?:REPLAY|REPLY)[^\\]]*\\]\\s*",
            string.Empty,
            RegexOptions.IgnoreCase);

        sanitized = Regex.Replace(sanitized, "\\n{3,}", "\\n\\n");
        return sanitized.Trim();
    }

    private static string NormalizeOutgoingTextEncoding(string text)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return text;
        }

        var sanitized = text.Replace("\uFFFD", string.Empty, StringComparison.Ordinal);

        // Do not run Latin1 heuristics on strings that already contain Unicode beyond Latin1
        // (e.g. emojis), because it can corrupt otherwise valid characters.
        if (sanitized.Any(ch => ch > '\u00FF'))
        {
            return sanitized;
        }

        if (!LooksLikeMojibake(sanitized))
        {
            return sanitized;
        }

        try
        {
            var latin1 = Encoding.GetEncoding("ISO-8859-1");
            var bytes = latin1.GetBytes(sanitized);
            var repaired = Encoding.UTF8.GetString(bytes);

            if (CountMojibakeMarkers(repaired) < CountMojibakeMarkers(sanitized))
            {
                return repaired.Replace("\uFFFD", string.Empty, StringComparison.Ordinal);
            }
        }
        catch
        {
            // Keep original text when heuristic repair is not possible.
        }

        return sanitized;
    }

    private static bool LooksLikeMojibake(string text)
        => text.Contains('Ã')
           || text.Contains('Â')
           || text.Contains('â')
           || text.Contains("ðŸ", StringComparison.Ordinal)
           || text.Contains("�", StringComparison.Ordinal);

    private static int CountMojibakeMarkers(string text)
    {
        if (string.IsNullOrEmpty(text))
        {
            return 0;
        }

        var count = 0;
        foreach (var ch in text)
        {
            if (ch is 'Ã' or 'Â' or 'â' or '\uFFFD')
            {
                count++;
            }
        }

        if (text.Contains("ðŸ", StringComparison.Ordinal))
        {
            count += 2;
        }

        return count;
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

    private string? ResolveInstanceName(string? instanceName)
    {
        var configured = string.IsNullOrWhiteSpace(_options.InstanceName) ? null : _options.InstanceName.Trim();
        if (string.IsNullOrWhiteSpace(instanceName))
        {
            return configured;
        }

        var requested = instanceName.Trim();
        if (!string.IsNullOrWhiteSpace(configured) &&
            string.Equals(requested, configured, StringComparison.OrdinalIgnoreCase))
        {
            // Evolution trata instanceName como case-sensitive em algumas rotas.
            // Se o request vier com case diferente, usa o formato canonico configurado.
            return configured;
        }

        return requested;
    }

    private static string? NormalizeProfilePictureValue(string? picture)
    {
        if (string.IsNullOrWhiteSpace(picture))
        {
            return null;
        }

        var trimmed = picture.Trim();
        if (trimmed.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
            trimmed.StartsWith("https://", StringComparison.OrdinalIgnoreCase) ||
            trimmed.StartsWith("data:", StringComparison.OrdinalIgnoreCase))
        {
            return trimmed;
        }

        trimmed = trimmed.Replace("\r", string.Empty, StringComparison.Ordinal)
                         .Replace("\n", string.Empty, StringComparison.Ordinal);

        return string.IsNullOrWhiteSpace(trimmed) ? null : trimmed;
    }

    public async Task<IReadOnlyList<WhatsAppInstanceInfo>> FetchInstancesAsync(CancellationToken cancellationToken)
    {
        static bool IsActiveState(string? state)
        {
            if (string.IsNullOrWhiteSpace(state)) return false;
            return string.Equals(state, "open", StringComparison.OrdinalIgnoreCase)
                || string.Equals(state, "connected", StringComparison.OrdinalIgnoreCase)
                || string.Equals(state, "online", StringComparison.OrdinalIgnoreCase);
        }

        static bool? ReadBool(JsonElement node, string propertyName)
        {
            if (!node.TryGetProperty(propertyName, out var prop)) return null;
            return prop.ValueKind switch
            {
                JsonValueKind.True => true,
                JsonValueKind.False => false,
                JsonValueKind.String when bool.TryParse(prop.GetString(), out var parsed) => parsed,
                _ => null
            };
        }

        try
        {
            var baseUrl = SafeCreateUri(_options.BaseUrl);
            if (baseUrl == null) return Array.Empty<WhatsAppInstanceInfo>();
            if (string.IsNullOrWhiteSpace(_options.ApiKey)) return Array.Empty<WhatsAppInstanceInfo>();

            var client = _httpClientFactory.CreateClient("evolution-groups");
            client.BaseAddress = baseUrl;
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", _options.ApiKey);
            if (!client.DefaultRequestHeaders.Contains("apikey"))
                client.DefaultRequestHeaders.Add("apikey", _options.ApiKey);
            if (!client.DefaultRequestHeaders.Contains("x-api-key"))
                client.DefaultRequestHeaders.Add("x-api-key", _options.ApiKey);

            var response = await client.GetAsync("/instance/fetchInstances", cancellationToken);
            if (!response.IsSuccessStatusCode) return Array.Empty<WhatsAppInstanceInfo>();

            var json = await response.Content.ReadAsStringAsync(cancellationToken);
            using var doc = JsonDocument.Parse(json);
            var result = new List<WhatsAppInstanceInfo>();

            var root = doc.RootElement;
            var arr = root.ValueKind == JsonValueKind.Array ? root
                : root.TryGetProperty("instances", out var instancesNode) ? instancesNode
                : root.TryGetProperty("response", out var responseNode) ? responseNode
                : root.TryGetProperty("data", out var dataNode) ? dataNode
                : default;

            if (arr.ValueKind != JsonValueKind.Array)
                return Array.Empty<WhatsAppInstanceInfo>();

            foreach (var item in arr.EnumerateArray())
            {
                string? name = null;
                string? state = null;
                bool? isConnected = null;

                if (item.ValueKind == JsonValueKind.Object && item.TryGetProperty("instance", out var nested) && nested.ValueKind == JsonValueKind.Object)
                {
                    if (nested.TryGetProperty("instanceName", out var nestedName)) name = nestedName.GetString();
                    if (nested.TryGetProperty("name", out var nestedNameAlt) && string.IsNullOrWhiteSpace(name)) name = nestedNameAlt.GetString();
                    if (nested.TryGetProperty("state", out var nestedState)) state = nestedState.GetString();
                    if (nested.TryGetProperty("status", out var nestedStatus) && string.IsNullOrWhiteSpace(state)) state = nestedStatus.GetString();
                    isConnected ??= ReadBool(nested, "connectionStatus");
                    isConnected ??= ReadBool(nested, "connected");
                    isConnected ??= ReadBool(nested, "isConnected");
                }

                if (item.ValueKind == JsonValueKind.Object)
                {
                    if (item.TryGetProperty("instanceName", out var itemName) && string.IsNullOrWhiteSpace(name)) name = itemName.GetString();
                    if (item.TryGetProperty("name", out var itemNameAlt) && string.IsNullOrWhiteSpace(name)) name = itemNameAlt.GetString();
                    if (item.TryGetProperty("state", out var itemState) && string.IsNullOrWhiteSpace(state)) state = itemState.GetString();
                    if (item.TryGetProperty("status", out var itemStatus) && string.IsNullOrWhiteSpace(state)) state = itemStatus.GetString();
                    isConnected ??= ReadBool(item, "connectionStatus");
                    isConnected ??= ReadBool(item, "connected");
                    isConnected ??= ReadBool(item, "isConnected");
                }

                if (isConnected == true)
                    state = "open";
                else if (isConnected == false && string.IsNullOrWhiteSpace(state))
                    state = "close";

                if (!string.IsNullOrWhiteSpace(name))
                    result.Add(new WhatsAppInstanceInfo(name, string.IsNullOrWhiteSpace(state) ? "unknown" : state));
            }

            var deduped = result
                .GroupBy(x => x.Name, StringComparer.OrdinalIgnoreCase)
                .Select(x => x.First())
                .OrderBy(x => x.Name, StringComparer.OrdinalIgnoreCase)
                .ToArray();

            var active = deduped.Where(x => IsActiveState(x.State)).ToArray();
            return active.Length > 0 ? active : deduped;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Falha ao listar instâncias Evolution");
            return Array.Empty<WhatsAppInstanceInfo>();
        }
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

    public async Task<WhatsAppSendResult> DeleteMessageAsync(string? instanceName, string chatId, string messageId, bool isGroup, CancellationToken cancellationToken)
    {
        try
        {
            var baseUrl = SafeCreateUri(_options.BaseUrl);
            if (baseUrl == null)
                return new WhatsAppSendResult(false, "Evolution BaseUrl não configurada ou inválida");
            if (string.IsNullOrWhiteSpace(_options.ApiKey))
                return new WhatsAppSendResult(false, "Evolution ApiKey não configurada");
            if (string.IsNullOrWhiteSpace(chatId) || string.IsNullOrWhiteSpace(messageId))
                return new WhatsAppSendResult(false, "ChatId ou MessageId inválidos");

            var client = _httpClientFactory.CreateClient("evolution");
            client.BaseAddress = baseUrl;
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", _options.ApiKey);
            if (!client.DefaultRequestHeaders.Contains("apikey")) client.DefaultRequestHeaders.Add("apikey", _options.ApiKey);
            if (!client.DefaultRequestHeaders.Contains("x-api-key")) client.DefaultRequestHeaders.Add("x-api-key", _options.ApiKey);

            var targetInstance = ResolveInstanceName(instanceName);
            if (string.IsNullOrWhiteSpace(targetInstance))
                return new WhatsAppSendResult(false, "InstanceName da Evolution não configurado");

            var payload = new
            {
                number = chatId,
                messageId = messageId,
                isGroup = isGroup
            };

            var request = new HttpRequestMessage(HttpMethod.Delete, $"/chat/deleteMessage/{targetInstance}")
            {
                Content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json")
            };
            var res = await client.SendAsync(request, cancellationToken);
            var body = await res.Content.ReadAsStringAsync(cancellationToken);

            if (res.IsSuccessStatusCode)
            {
                return new WhatsAppSendResult(true, "Mensagem deletada");
            }

            _logger.LogWarning("Falha ao deletar mensagem Evolution: {Status} {Body}", res.StatusCode, body);
            return new WhatsAppSendResult(false, $"Status: {res.StatusCode}");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao deletar mensagem Evolution");
            return new WhatsAppSendResult(false, $"Erro: {ex.Message}");
        }
    }

    public async Task<IReadOnlyList<string>> GetGroupParticipantsAsync(string? instanceName, string groupId, CancellationToken cancellationToken)
    {
        try
        {
            var baseUrl = SafeCreateUri(_options.BaseUrl);
            if (baseUrl == null || string.IsNullOrWhiteSpace(groupId)) return Array.Empty<string>();

            var client = _httpClientFactory.CreateClient("evolution-groups");
            client.BaseAddress = baseUrl;
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", _options.ApiKey);
            if (!client.DefaultRequestHeaders.Contains("apikey")) client.DefaultRequestHeaders.Add("apikey", _options.ApiKey);
            if (!client.DefaultRequestHeaders.Contains("x-api-key")) client.DefaultRequestHeaders.Add("x-api-key", _options.ApiKey);

            var targetInstance = ResolveInstanceName(instanceName);
            
            var cacheKey = $"{targetInstance}:{groupId}";
            var now = DateTimeOffset.UtcNow;
            _participantsCache.TryGetValue(cacheKey, out var cachedParticipants);
            if (cachedParticipants is not null && cachedParticipants.ExpiresAt > now)
            {
                return cachedParticipants.Participants;
            }

            if (_participantsRateLimitedUntil.TryGetValue(cacheKey, out var blockedUntil) && blockedUntil > now)
            {
                if (cachedParticipants is not null && cachedParticipants.Participants.Count > 0)
                {
                    _logger.LogInformation("Leitura de participantes do grupo {GroupId} em cooldown até {BlockedUntil}. Retornando cache com {Count} item(ns).", groupId, blockedUntil, cachedParticipants.Participants.Count);
                    return cachedParticipants.Participants;
                }

                _logger.LogWarning("Leitura de participantes do grupo {GroupId} em cooldown até {BlockedUntil}. Ignorando nova consulta remota.", groupId, blockedUntil);
                return Array.Empty<string>();
            }

            // Tentar múltiplos endpoints possíveis da Evolution
            var endpoints = new[]
            {
                $"/group/getParticipants/{targetInstance}?groupId={Uri.EscapeDataString(groupId)}",
                $"/group/getParticipants/{targetInstance}/{Uri.EscapeDataString(groupId)}",
                $"/group/listParticipants/{targetInstance}/{Uri.EscapeDataString(groupId)}",
                $"/group/fetchAllGroups/{targetInstance}?getParticipants=true"
            };

            foreach (var endpoint in endpoints)
            {
                var res = await client.GetAsync(endpoint, cancellationToken);
                if (!res.IsSuccessStatusCode)
                {
                    var failedBody = await res.Content.ReadAsStringAsync(cancellationToken);
                    if (IsRateOverlimit(failedBody))
                    {
                        _participantsRateLimitedUntil[cacheKey] = now.AddSeconds(45);
                        if (cachedParticipants is not null && cachedParticipants.Participants.Count > 0)
                        {
                            return cachedParticipants.Participants;
                        }
                    }

                    continue;
                }

                var body = await res.Content.ReadAsStringAsync(cancellationToken);
                var participants = ExtractParticipants(body, groupId);

                if (participants.Count > 0)
                {
                    _participantsCache[cacheKey] = new CachedParticipantsEntry(participants, now.AddMinutes(1));
                    _participantsRateLimitedUntil.TryRemove(cacheKey, out _);
                    _logger.LogInformation("Obtidos {Count} participantes do grupo {GroupId}. Exemplo: {Example}", participants.Count, groupId, participants[0]);
                    return participants;
                }
                else
                {
                    _logger.LogWarning("Nenhum participante extraído do corpo do endpoint {Endpoint}. Body: {Body}", endpoint, body);
                }
            }

            if (cachedParticipants is not null && cachedParticipants.Participants.Count > 0)
            {
                return cachedParticipants.Participants;
            }

            return Array.Empty<string>();
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Falha ao obter participantes do grupo {GroupId} via Evolution", groupId);
            return Array.Empty<string>();
        }
    }

    public async Task<WhatsAppSendResult> AddParticipantsAsync(string? instanceName, string groupId, IReadOnlyList<string> participantJids, CancellationToken cancellationToken)
    {
        try
        {
            var sanitizedJids = participantJids
                .Where(j => !string.IsNullOrWhiteSpace(j))
                .Select(j => j.Contains("@") ? j.Trim() : j.Trim() + "@s.whatsapp.net")
                .Where(j => j.EndsWith("@s.whatsapp.net", StringComparison.OrdinalIgnoreCase))
                .Distinct()
                .ToList();

            if (sanitizedJids.Count == 0)
                return new WhatsAppSendResult(true, "Nenhum participante válido para adicionar após sanitização");

            var baseUrl = SafeCreateUri(_options.BaseUrl);
            if (baseUrl == null || string.IsNullOrWhiteSpace(groupId)) 
                return new WhatsAppSendResult(false, "Evolution BaseUrl não configurada ou groupId inválido");

            var client = _httpClientFactory.CreateClient("evolution-groups");
            client.BaseAddress = baseUrl;
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", _options.ApiKey);
            if (!client.DefaultRequestHeaders.Contains("apikey")) client.DefaultRequestHeaders.Add("apikey", _options.ApiKey);
            if (!client.DefaultRequestHeaders.Contains("x-api-key")) client.DefaultRequestHeaders.Add("x-api-key", _options.ApiKey);

            var targetInstance = ResolveInstanceName(instanceName);

            if (string.IsNullOrWhiteSpace(targetInstance))
                return new WhatsAppSendResult(false, "InstanceName da Evolution nao configurado");

            var stateCheck = await EnsureInstanceOpenForSendAsync(client, targetInstance, cancellationToken);
            if (!stateCheck.Success)
            {
                return new WhatsAppSendResult(false, stateCheck.Message ?? "Instancia WhatsApp nao conectada");
            }

            var endpoints = new[]
            {
                "/group/updateParticipant/{instanceName}",
                "/group/updateParticipants/{instanceName}",
                "/group/participantsUpdate/{instanceName}"
            };

            var payloadFactories = new List<Func<Dictionary<string, object?>>>
            {
                () => new()
                {
                    ["groupJid"] = groupId,
                    ["action"] = "add",
                    ["participants"] = sanitizedJids
                },
                () => new()
                {
                    ["groupId"] = groupId,
                    ["action"] = "add",
                    ["participants"] = sanitizedJids
                },
                () => new()
                {
                    ["jid"] = groupId,
                    ["action"] = "add",
                    ["participants"] = sanitizedJids
                },
                () => new()
                {
                    ["groupJid"] = groupId,
                    ["operation"] = "add",
                    ["participants"] = sanitizedJids
                }
            };

            // Opera em micro-lotes para reduzir risco de bloqueio por bursts de adição.
            var chunks = sanitizedJids.Chunk(5).Select(c => c.ToList()).ToList();
            var sentCount = 0;
            for (var chunkIndex = 0; chunkIndex < chunks.Count; chunkIndex++)
            {
                cancellationToken.ThrowIfCancellationRequested();

                var chunk = chunks[chunkIndex];
                string? chunkFailure = null;
                var attemptTrace = new List<string>();
                var chunkSent = false;

                foreach (var endpoint in endpoints)
                {
                    var path = ResolveEndpoint(endpoint, targetInstance);
                    for (var i = 0; i < payloadFactories.Count; i++)
                    {
                        var payload = payloadFactories[i]();
                        payload["participants"] = chunk;
                        var jsonPayload = JsonSerializer.Serialize(payload);
                        _logger.LogInformation(
                            "Adicionando lote {ChunkIndex}/{TotalChunks} com {Count} participante(s) ao grupo {GroupId}. Endpoint={Endpoint} Payload={PayloadIndex}",
                            chunkIndex + 1,
                            chunks.Count,
                            chunk.Count,
                            groupId,
                            path,
                            i + 1);

                        using var content = new StringContent(jsonPayload, Encoding.UTF8, "application/json");
                        var res = await client.PostAsync(path, content, cancellationToken);
                        var body = await res.Content.ReadAsStringAsync(cancellationToken);

                        if (res.IsSuccessStatusCode)
                        {
                            _logger.LogInformation(
                                "Lote {ChunkIndex}/{TotalChunks} adicionado com sucesso. Endpoint={Endpoint} Payload={PayloadIndex}",
                                chunkIndex + 1,
                                chunks.Count,
                                path,
                                i + 1);
                            chunkSent = true;
                            sentCount += chunk.Count;
                            break;
                        }

                        var compactBody = string.IsNullOrWhiteSpace(body) ? "<vazio>" : body;
                        attemptTrace.Add($"{path} [payload {i + 1}] => {(int)res.StatusCode}");
                        chunkFailure = $"Status: {res.StatusCode} - {compactBody}";
                        _logger.LogWarning(
                            "Falha ao adicionar lote {ChunkIndex}/{TotalChunks} no endpoint {Endpoint} payload #{PayloadIndex}: {Status} {Body}",
                            chunkIndex + 1,
                            chunks.Count,
                            path,
                            i + 1,
                            res.StatusCode,
                            compactBody);
                    }

                    if (chunkSent)
                    {
                        break;
                    }
                }

                if (!chunkSent)
                {
                    var attempts = attemptTrace.Count == 0 ? "nenhuma tentativa executada" : string.Join(" | ", attemptTrace);
                    return new WhatsAppSendResult(false, $"Falha no lote {chunkIndex + 1}/{chunks.Count}: {chunkFailure ?? "falha desconhecida"}. Tentativas: {attempts}");
                }

                if (chunkIndex < chunks.Count - 1)
                {
                    var pauseMs = Random.Shared.Next(3500, 7001);
                    await Task.Delay(pauseMs, cancellationToken);
                }
            }

            return new WhatsAppSendResult(true, $"Participantes adicionados com sucesso em lotes. Total={sentCount}");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao adicionar participantes Evolution");
            return new WhatsAppSendResult(false, $"Erro: {ex.Message}");
        }
    }

    private static IReadOnlyList<string> ExtractParticipants(string body, string groupId)
    {
        try
        {
            using var doc = JsonDocument.Parse(body);

            var direct = ExtractParticipantIds(doc.RootElement);
            if (direct.Count > 0)
            {
                return direct;
            }

            var nested = new List<string>();
            ExtractParticipantsFromElement(doc.RootElement, groupId, nested);
            return nested
                .Where(x => !string.IsNullOrWhiteSpace(x))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray();
        }
        catch
        {
            return Array.Empty<string>();
        }
    }

    private static void ExtractParticipantsFromElement(JsonElement element, string groupId, List<string> participants)
    {
        if (element.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in element.EnumerateArray())
            {
                ExtractParticipantsFromElement(item, groupId, participants);
            }

            return;
        }

        if (element.ValueKind != JsonValueKind.Object)
        {
            return;
        }

        var currentGroupId = GetString(element, "id", "jid", "groupId", "remoteJid", "chatId");
        if (string.Equals(currentGroupId, groupId, StringComparison.OrdinalIgnoreCase))
        {
            participants.AddRange(ExtractParticipantIds(element));
            if (participants.Count > 0)
            {
                return;
            }
        }

        foreach (var prop in element.EnumerateObject())
        {
            if (prop.Value.ValueKind == JsonValueKind.Object || prop.Value.ValueKind == JsonValueKind.Array)
            {
                ExtractParticipantsFromElement(prop.Value, groupId, participants);
                if (participants.Count > 0)
                {
                    return;
                }
            }
        }
    }

    private static List<string> ExtractParticipantIds(JsonElement element)
    {
        var participants = new List<string>();

        if (element.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in element.EnumerateArray())
            {
                AppendParticipantId(item, participants);
            }
        }
        else if (element.ValueKind == JsonValueKind.Object)
        {
            foreach (var name in new[] { "participants", "member", "members", "data" })
            {
                if (element.TryGetProperty(name, out var node) && node.ValueKind == JsonValueKind.Array)
                {
                    foreach (var item in node.EnumerateArray())
                    {
                        AppendParticipantId(item, participants);
                    }

                    if (participants.Count > 0)
                    {
                        break;
                    }
                }
            }
        }

        return participants
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private static void AppendParticipantId(JsonElement item, List<string> participants)
    {
        var id = item.ValueKind == JsonValueKind.String
            ? item.GetString()
            : item.ValueKind == JsonValueKind.Object
                ? GetString(item, "phoneNumber", "id", "jid", "participant", "user")
                : null;

        if (string.IsNullOrWhiteSpace(id))
        {
            return;
        }

        var normalized = id.Trim();
        if (!normalized.Contains('@'))
        {
            normalized += "@s.whatsapp.net";
        }

        if (normalized.EndsWith("@s.whatsapp.net", StringComparison.OrdinalIgnoreCase))
        {
            participants.Add(normalized);
        }
    }

    private static bool IsRateOverlimit(string? body)
        => !string.IsNullOrWhiteSpace(body) &&
           body.Contains("rate-overlimit", StringComparison.OrdinalIgnoreCase);

    private sealed record CachedGroupsEntry(IReadOnlyList<WhatsAppGroupInfo> Groups, DateTimeOffset ExpiresAt);

    private sealed record CachedParticipantsEntry(IReadOnlyList<string> Participants, DateTimeOffset ExpiresAt);

    private Uri? SafeCreateUri(string? url)
    {
        if (string.IsNullOrWhiteSpace(url)) return null;
        if (Uri.TryCreate(url.Trim(), UriKind.Absolute, out var uri)) return uri;
        return null;
    }
}
