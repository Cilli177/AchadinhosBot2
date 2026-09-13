using System.Text.Json;
using System.Text.Json.Nodes;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Configuration;
using AchadinhosBot.Next.Domain.Requests;
using AchadinhosBot.Next.Domain.Settings;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;

namespace AchadinhosBot.Next.Endpoints;

public static class SettingsEndpoints
{
    public static void MapSettingsEndpoints(
        this RouteGroupBuilder api,
        Func<AutomationSettings, IEnumerable<string>> validateSettings,
        Func<string?, string?, string, string, string> resolvePublicBaseUrl,
        Action<AutomationSettings> maskProviderKeys)
    {
        api.MapGet("/settings", async (
            ISettingsStore store,
            IOptions<WebhookOptions> webhookOptions,
            IHostEnvironment hostEnvironment,
            HttpContext context,
            CancellationToken ct) =>
        {
            var settings = await store.GetAsync(ct);
            MaskSettingsForResponse(settings);

            var payload = JsonSerializer.SerializeToNode(
                settings,
                new JsonSerializerOptions(JsonSerializerDefaults.Web))?.AsObject() ?? new JsonObject();
            payload["publicBaseUrl"] = resolvePublicBaseUrl(
                settings.BioHub?.PublicBaseUrl,
                webhookOptions.Value.PublicBaseUrl,
                context.Request.Scheme,
                context.Request.Host.ToString());
            payload["runtimeEnvironment"] = hostEnvironment.EnvironmentName;
            payload["isProduction"] = hostEnvironment.IsProduction();

            return Results.Json(payload);
        });

        api.MapGet("/settings/versions", async (
            ISettingsVersionStore settingsVersionStore,
            CancellationToken ct) =>
        {
            var versions = await settingsVersionStore.ListVersionsAsync(ct);
            return Results.Ok(new { success = true, versions });
        });

        api.MapPost("/settings/restore", async (
            [FromBody] RestoreSettingsRequest payload,
            ISettingsVersionStore settingsVersionStore,
            IAuditTrail audit,
            HttpContext context,
            CancellationToken ct) =>
        {
            if (payload is null || string.IsNullOrWhiteSpace(payload.VersionFileName))
            {
                return Results.BadRequest(new { success = false, error = "versionFileName invalido" });
            }

            var restored = await settingsVersionStore.RestoreAsync(payload.VersionFileName, ct);
            if (restored is null)
            {
                return Results.NotFound(new { success = false, error = "snapshot nao encontrado" });
            }

            maskProviderKeys(restored);
            await audit.WriteAsync("settings.restored", context.User.Identity?.Name ?? "unknown", new { version = payload.VersionFileName }, ct);
            return Results.Ok(new
            {
                success = true,
                restored = payload.VersionFileName,
                settings = restored
            });
        }).RequireAuthorization("AdminOnly");

        api.MapPut("/settings", async (
            AutomationSettings payload,
            ISettingsStore store,
            IAuditTrail audit,
            HttpContext context,
            CancellationToken ct) =>
        {
            var errors = validateSettings(payload).ToArray();
            if (errors.Length > 0)
            {
                return Results.BadRequest(new { success = false, errors });
            }

            var current = await store.GetAsync(ct);
            ReconcileSecrets(payload, current);

            await store.SaveAsync(payload, ct);
            await audit.WriteAsync("settings.updated", context.User.Identity?.Name ?? "unknown", new { autoReplies = payload.AutoReplies.Count }, ct);
            return Results.Ok(new { success = true });
        }).RequireAuthorization("AdminOnly");
    }

    private static void MaskSettingsForResponse(AutomationSettings settings)
    {
        AutomationSettingsSanitizer.MaskSecretsInPlace(settings);
        MaskProvider(settings.OpenAI);
        MaskProvider(settings.Gemini);
        MaskProvider(settings.DeepSeek);
        MaskProvider(settings.Nemotron);
        MaskProvider(settings.Qwen);
        MaskProvider(settings.VilaNvidia);

        if (settings.InstagramPublish is not null)
        {
            settings.InstagramPublish.AccessToken = MaskIfPresent(settings.InstagramPublish.AccessToken);
            settings.InstagramPublish.ManyChatApiKey = MaskIfPresent(settings.InstagramPublish.ManyChatApiKey);
        }

        if (settings.MercadoLivreAffiliateScout is not null)
        {
            settings.MercadoLivreAffiliateScout.LoginUser = MaskIfPresent(settings.MercadoLivreAffiliateScout.LoginUser);
            settings.MercadoLivreAffiliateScout.LoginPassword = MaskIfPresent(settings.MercadoLivreAffiliateScout.LoginPassword);
            settings.MercadoLivreAffiliateScout.TwoFactorCode = MaskIfPresent(settings.MercadoLivreAffiliateScout.TwoFactorCode);
            settings.MercadoLivreAffiliateScout.StorageStateJson = MaskIfPresent(settings.MercadoLivreAffiliateScout.StorageStateJson);
        }
    }

    private static void ReconcileSecrets(AutomationSettings payload, AutomationSettings current)
    {
        ReconcileProvider(payload.OpenAI, current.OpenAI, () => payload.OpenAI = current.OpenAI ?? new OpenAISettings());
        ReconcileProvider(payload.Gemini, current.Gemini, () => payload.Gemini = current.Gemini ?? new GeminiSettings());
        ReconcileProvider(payload.DeepSeek, current.DeepSeek, () => payload.DeepSeek = current.DeepSeek ?? new DeepSeekSettings());
        ReconcileProvider(payload.Nemotron, current.Nemotron, () => payload.Nemotron = current.Nemotron ?? new NemotronSettings());
        ReconcileProvider(payload.Qwen, current.Qwen, () => payload.Qwen = current.Qwen ?? new QwenSettings());
        ReconcileProvider(payload.VilaNvidia, current.VilaNvidia, () => payload.VilaNvidia = current.VilaNvidia ?? new VilaNvidiaSettings());

        if (payload.InstagramPublish is null)
        {
            payload.InstagramPublish = current.InstagramPublish ?? new InstagramPublishSettings();
        }
        else
        {
            payload.InstagramPublish.AccessToken = ResolveSecretWithMask(payload.InstagramPublish.AccessToken, current.InstagramPublish?.AccessToken);
            payload.InstagramPublish.ManyChatApiKey = ResolveSecretWithMask(payload.InstagramPublish.ManyChatApiKey, current.InstagramPublish?.ManyChatApiKey);
        }

        if (payload.MercadoLivreAffiliateScout is null)
        {
            payload.MercadoLivreAffiliateScout = current.MercadoLivreAffiliateScout ?? new MercadoLivreAffiliateScoutSettings();
        }
        else
        {
            payload.MercadoLivreAffiliateScout.LoginUser = ResolveSecretWithMask(payload.MercadoLivreAffiliateScout.LoginUser, current.MercadoLivreAffiliateScout?.LoginUser);
            payload.MercadoLivreAffiliateScout.LoginPassword = ResolveSecretWithMask(payload.MercadoLivreAffiliateScout.LoginPassword, current.MercadoLivreAffiliateScout?.LoginPassword);
            payload.MercadoLivreAffiliateScout.TwoFactorCode = ResolveSecretWithMask(payload.MercadoLivreAffiliateScout.TwoFactorCode, current.MercadoLivreAffiliateScout?.TwoFactorCode);
            payload.MercadoLivreAffiliateScout.StorageStateJson = ResolveSecretWithMask(payload.MercadoLivreAffiliateScout.StorageStateJson, current.MercadoLivreAffiliateScout?.StorageStateJson);
        }
    }

    private static void ReconcileProvider<T>(T? incoming, T? current, Action restoreCurrent)
        where T : class
    {
        if (incoming is null)
        {
            restoreCurrent();
            return;
        }

        switch (incoming)
        {
            case OpenAISettings openAi:
                var currentOpenAi = current as OpenAISettings;
                var incomingOpenAiApiKey = openAi.ApiKey;
                openAi.ApiKey = ResolveSecretWithMask(incomingOpenAiApiKey, currentOpenAi?.ApiKey);
                openAi.ApiKeys = MergeSecretListWithMask(currentOpenAi?.ApiKeys, openAi.ApiKeys, incomingOpenAiApiKey, currentOpenAi?.ApiKey);
                break;
            case GeminiSettings gemini:
                var currentGemini = current as GeminiSettings;
                var incomingGeminiApiKey = gemini.ApiKey;
                gemini.ApiKey = ResolveSecretWithMask(incomingGeminiApiKey, currentGemini?.ApiKey);
                gemini.ApiKeys = MergeSecretListWithMask(currentGemini?.ApiKeys, gemini.ApiKeys, incomingGeminiApiKey, currentGemini?.ApiKey);
                break;
            case DeepSeekSettings deepSeek:
                var currentDeepSeek = current as DeepSeekSettings;
                var incomingDeepSeekApiKey = deepSeek.ApiKey;
                deepSeek.ApiKey = ResolveSecretWithMask(incomingDeepSeekApiKey, currentDeepSeek?.ApiKey);
                deepSeek.ApiKeys = MergeSecretListWithMask(currentDeepSeek?.ApiKeys, deepSeek.ApiKeys, incomingDeepSeekApiKey, currentDeepSeek?.ApiKey);
                break;
            case NemotronSettings nemotron:
                var currentNemotron = current as NemotronSettings;
                var incomingNemotronApiKey = nemotron.ApiKey;
                nemotron.ApiKey = ResolveSecretWithMask(incomingNemotronApiKey, currentNemotron?.ApiKey);
                nemotron.ApiKeys = MergeSecretListWithMask(currentNemotron?.ApiKeys, nemotron.ApiKeys, incomingNemotronApiKey, currentNemotron?.ApiKey);
                break;
            case QwenSettings qwen:
                var currentQwen = current as QwenSettings;
                var incomingQwenApiKey = qwen.ApiKey;
                qwen.ApiKey = ResolveSecretWithMask(incomingQwenApiKey, currentQwen?.ApiKey);
                qwen.ApiKeys = MergeSecretListWithMask(currentQwen?.ApiKeys, qwen.ApiKeys, incomingQwenApiKey, currentQwen?.ApiKey);
                break;
            case VilaNvidiaSettings vila:
                var currentVila = current as VilaNvidiaSettings;
                var incomingVilaApiKey = vila.ApiKey;
                vila.ApiKey = ResolveSecretWithMask(incomingVilaApiKey, currentVila?.ApiKey);
                vila.ApiKeys = MergeSecretListWithMask(currentVila?.ApiKeys, vila.ApiKeys, incomingVilaApiKey, currentVila?.ApiKey);
                break;
        }
    }

    private static void MaskProvider(OpenAISettings? settings) => MaskProviderSecrets(settings, x => x.ApiKey, (x, value) => x.ApiKey = value, x => x.ApiKeys, (x, value) => x.ApiKeys = value);
    private static void MaskProvider(GeminiSettings? settings) => MaskProviderSecrets(settings, x => x.ApiKey, (x, value) => x.ApiKey = value, x => x.ApiKeys, (x, value) => x.ApiKeys = value);
    private static void MaskProvider(DeepSeekSettings? settings) => MaskProviderSecrets(settings, x => x.ApiKey, (x, value) => x.ApiKey = value, x => x.ApiKeys, (x, value) => x.ApiKeys = value);
    private static void MaskProvider(NemotronSettings? settings) => MaskProviderSecrets(settings, x => x.ApiKey, (x, value) => x.ApiKey = value, x => x.ApiKeys, (x, value) => x.ApiKeys = value);
    private static void MaskProvider(QwenSettings? settings) => MaskProviderSecrets(settings, x => x.ApiKey, (x, value) => x.ApiKey = value, x => x.ApiKeys, (x, value) => x.ApiKeys = value);
    private static void MaskProvider(VilaNvidiaSettings? settings) => MaskProviderSecrets(settings, x => x.ApiKey, (x, value) => x.ApiKey = value, x => x.ApiKeys, (x, value) => x.ApiKeys = value);

    private static void MaskProviderSecrets<T>(T? settings, Func<T, string?> getKey, Action<T, string?> setKey, Func<T, List<string>?> getKeys, Action<T, List<string>> setKeys)
        where T : class
    {
        if (settings is null) return;
        setKey(settings, MaskIfPresent(getKey(settings)));
        var keys = getKeys(settings);
        if (keys is { Count: > 0 })
        {
            setKeys(settings, keys.Where(key => !string.IsNullOrWhiteSpace(key)).Select(_ => "********").ToList());
        }
    }

    private static string? ResolveSecretWithMask(string? incoming, string? current)
        => string.IsNullOrWhiteSpace(incoming) || incoming.Trim() == "********" ? current : incoming.Trim();

    private static List<string> MergeSecretListWithMask(IEnumerable<string>? currentValues, IEnumerable<string>? incomingValues, string? incomingSingle, string? currentSingle)
    {
        var current = NormalizeSecretList(currentValues);
        var singleCurrent = NormalizeSecret(currentSingle);
        if (!string.IsNullOrWhiteSpace(singleCurrent)) current.Add(singleCurrent);

        var incoming = NormalizeSecretList(incomingValues);
        var hasMaskedValue = incomingValues?.Any(x => string.Equals(x?.Trim(), "********", StringComparison.Ordinal)) ?? false;
        var singleIncoming = NormalizeSecret(incomingSingle);
        if (incoming.Count == 0 && string.IsNullOrWhiteSpace(singleIncoming)) return current;

        var merged = hasMaskedValue ? new List<string>(current) : new List<string>();
        merged.AddRange(incoming);
        if (!string.IsNullOrWhiteSpace(singleIncoming)) merged.Add(singleIncoming);
        return merged.Where(x => !string.IsNullOrWhiteSpace(x)).Distinct(StringComparer.Ordinal).ToList();
    }

    private static List<string> NormalizeSecretList(IEnumerable<string>? values)
        => (values ?? Array.Empty<string>()).Select(NormalizeSecret).Where(x => !string.IsNullOrWhiteSpace(x)).Cast<string>().Distinct(StringComparer.Ordinal).ToList();

    private static string? NormalizeSecret(string? value)
        => string.IsNullOrWhiteSpace(value) || value.Trim() == "********" ? null : value.Trim();

    private static string? MaskIfPresent(string? value) => string.IsNullOrWhiteSpace(value) ? value : "********";
}
