using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Domain.PriceWatch;

namespace AchadinhosBot.Next.Application.Services;

public sealed partial class PriceWatchConversationService
{
    private const string AllowedInstanceName = WhatsAppInstanceRoutingPolicy.ParticipantOpsInstance;

    private readonly PriceWatchService _priceWatchService;
    private readonly IWhatsAppGateway _whatsAppGateway;
    private readonly ILogger<PriceWatchConversationService> _logger;

    public PriceWatchConversationService(
        PriceWatchService priceWatchService,
        IWhatsAppGateway whatsAppGateway,
        ILogger<PriceWatchConversationService> logger)
    {
        _priceWatchService = priceWatchService;
        _whatsAppGateway = whatsAppGateway;
        _logger = logger;
    }

    public async Task<bool> TryHandleAsync(string? instanceName, string chatId, string? senderId, string? text, CancellationToken ct)
    {
        if (!string.Equals(instanceName?.Trim(), AllowedInstanceName, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (string.IsNullOrWhiteSpace(chatId) ||
            chatId.EndsWith("@g.us", StringComparison.OrdinalIgnoreCase) ||
            string.IsNullOrWhiteSpace(text))
        {
            return false;
        }

        var normalized = text.Trim();
        var intent = Interpret(normalized);

        if (intent.StopAlerts)
        {
            var paused = await _priceWatchService.PauseByContactAsync(chatId, ct);
            var reply = paused > 0
                ? $"Pronto, pausei {paused} alerta(s) do seu Radar de Preco."
                : "Nao encontrei alertas ativos para pausar por aqui.";
            await _whatsAppGateway.SendTextAsync(instanceName, chatId, reply, ct);
            return true;
        }

        if (intent.AcceptSimilarProducts.HasValue)
        {
            var updated = await _priceWatchService.SetAcceptSimilarByContactAsync(chatId, intent.AcceptSimilarProducts.Value, ct);
            if (updated is null)
            {
                await _whatsAppGateway.SendTextAsync(
                    instanceName,
                    chatId,
                    "Combinado. Quando voce ativar um radar, eu confirmo essa preferencia junto com o produto.",
                    ct);
                return true;
            }

            var reply = intent.AcceptSimilarProducts.Value
                ? $"Fechado, tambem posso te avisar sobre produto similar ao {updated.ProductName ?? "produto monitorado"}, mas so quando eu tiver alta confianca de que faz sentido."
                : $"Perfeito, vou manter apenas o produto exato do radar {updated.ProductName ?? "monitorado"}.";
            await _whatsAppGateway.SendTextAsync(instanceName, chatId, reply, ct);
            return true;
        }

        if (!intent.WantsPriceWatch)
        {
            return false;
        }

        if (string.IsNullOrWhiteSpace(intent.Url))
        {
            var productLine = string.IsNullOrWhiteSpace(intent.ProductHint)
                ? "Qual produto voce quer acompanhar?"
                : $"Entendi: voce quer acompanhar {intent.ProductHint}.";
            await _whatsAppGateway.SendTextAsync(
                instanceName,
                chatId,
                $"{productLine}\nMe envie o link do produto para eu confirmar o item certo e evitar alerta de modelo parecido. Se quiser, ja mande tambem o valor alvo. Ex: monitora esse link ate R$ 300.\n\nVoce aceita receber produto similar se aparecer uma oportunidade melhor? Pode responder: similar sim ou similar nao.",
                ct);
            return true;
        }

        try
        {
            var watch = await _priceWatchService.CreateAsync(new PriceWatchCreateRequest(
                    ContactJid: chatId,
                    ProductUrl: intent.Url,
                    DesiredPrice: intent.DesiredPrice,
                    IntervalHours: 12,
                    InstanceName: instanceName,
                    AcceptSimilarProducts: intent.AcceptSimilarProducts ?? false),
                "whatsapp",
                ct);

            var targetText = intent.DesiredPrice is null
                ? "Vou te avisar quando encontrar uma queda real em relacao ao ultimo preco enviado."
                : $"Vou te avisar se chegar em ate {intent.DesiredPrice.Value.ToString("C", CultureInfo.GetCultureInfo("pt-BR"))} ou ficar bem perto disso.";

            var priceReadText = watch.LastFoundPrice is null
                ? "\nAinda nao consegui ler o preco inicial desse link, mas vou continuar tentando validar com seguranca."
                : $"\nPreco atual monitorado: {watch.LastFoundPrice.Value.ToString("C", CultureInfo.GetCultureInfo("pt-BR"))}.";

            await _whatsAppGateway.SendTextAsync(
                instanceName,
                chatId,
                $"Radar de Preco ativado.\n{watch.ProductName ?? "Produto monitorado"}{priceReadText}\n{targetText}\n{BuildSimilarText(watch.AcceptSimilarProducts)}\n\nPara cancelar, responda PARAR.",
                ct);
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Falha ao criar PriceWatch via conversa WhatsApp. Chat={ChatId}", chatId);
            await _whatsAppGateway.SendTextAsync(instanceName, chatId, "Nao consegui ativar esse radar agora. Pode tentar de novo com o link do produto?", ct);
            return true;
        }
    }

    private static PriceWatchConversationIntent Interpret(string text)
    {
        var normalized = NormalizeForIntent(text);
        var url = UrlRegex().Match(text).Value;
        var desiredPrice = ExtractDesiredPrice(text);
        var similarPreference = ExtractSimilarPreference(normalized);
        var productHint = ExtractProductHint(text);
        var looksLikeProductUrl = LooksLikeProductUrl(url);

        var stopAlerts = IsStopRequest(normalized);
        var wantsWatch =
            looksLikeProductUrl ||
            HasPriceWatchIntent(normalized) ||
            (desiredPrice.HasValue && !string.IsNullOrWhiteSpace(productHint) && productHint.Length >= 4);

        return new PriceWatchConversationIntent(
            wantsWatch,
            stopAlerts,
            url,
            desiredPrice,
            productHint,
            similarPreference);
    }

    private static bool HasPriceWatchIntent(string normalized)
    {
        if (string.IsNullOrWhiteSpace(normalized))
        {
            return false;
        }

        var hasNotifyIntent =
            normalized.Contains("me avisa", StringComparison.Ordinal) ||
            normalized.Contains("me avise", StringComparison.Ordinal) ||
            normalized.Contains("me chama", StringComparison.Ordinal) ||
            normalized.Contains("me manda", StringComparison.Ordinal) ||
            normalized.Contains("quero saber", StringComparison.Ordinal) ||
            normalized.Contains("me fala", StringComparison.Ordinal) ||
            normalized.Contains("manda pra mim", StringComparison.Ordinal);

        var hasMonitoringIntent =
            normalized.Contains("monitora", StringComparison.Ordinal) ||
            normalized.Contains("monitorar", StringComparison.Ordinal) ||
            normalized.Contains("acompanha", StringComparison.Ordinal) ||
            normalized.Contains("acompanhar", StringComparison.Ordinal) ||
            normalized.Contains("fica de olho", StringComparison.Ordinal) ||
            normalized.Contains("de olho", StringComparison.Ordinal) ||
            normalized.Contains("radar", StringComparison.Ordinal);

        var hasPriceDropIntent =
            normalized.Contains("quando baixar", StringComparison.Ordinal) ||
            normalized.Contains("se baixar", StringComparison.Ordinal) ||
            normalized.Contains("baixar de preco", StringComparison.Ordinal) ||
            normalized.Contains("preco baixar", StringComparison.Ordinal) ||
            normalized.Contains("preco cair", StringComparison.Ordinal) ||
            normalized.Contains("cair o preco", StringComparison.Ordinal) ||
            normalized.Contains("ficar mais barato", StringComparison.Ordinal) ||
            normalized.Contains("aparecer promocao", StringComparison.Ordinal) ||
            normalized.Contains("entrar em promocao", StringComparison.Ordinal) ||
            normalized.Contains("melhor preco", StringComparison.Ordinal) ||
            normalized.Contains("preco melhor", StringComparison.Ordinal) ||
            normalized.Contains("valor menor", StringComparison.Ordinal) ||
            normalized.Contains("oferta melhor", StringComparison.Ordinal);

        var hasPurchaseTimingIntent =
            normalized.Contains("quero comprar quando", StringComparison.Ordinal) ||
            normalized.Contains("compro se", StringComparison.Ordinal) ||
            normalized.Contains("compraria se", StringComparison.Ordinal) ||
            normalized.Contains("vale a pena quando", StringComparison.Ordinal) ||
            normalized.Contains("ate quanto", StringComparison.Ordinal);

        return hasNotifyIntent || hasMonitoringIntent || hasPriceDropIntent || hasPurchaseTimingIntent;
    }

    private static bool IsStopRequest(string normalized)
        => normalized is "parar" or "cancelar" or "pausar" or "stop" ||
           normalized.Contains("parar alerta", StringComparison.Ordinal) ||
           normalized.Contains("pausar alerta", StringComparison.Ordinal) ||
           normalized.Contains("cancelar alerta", StringComparison.Ordinal) ||
           normalized.Contains("cancelar radar", StringComparison.Ordinal) ||
           normalized.Contains("pausar radar", StringComparison.Ordinal) ||
           normalized.Contains("nao quero mais receber", StringComparison.Ordinal);

    private static decimal? ExtractDesiredPrice(string text)
    {
        var match = DesiredPriceRegex().Match(text);
        if (!match.Success)
        {
            return null;
        }

        return PriceWatchService.TryParsePrice(match.Groups["price"].Value);
    }

    private static string? ExtractProductHint(string text)
    {
        var cleaned = UrlRegex().Replace(text, " ");
        cleaned = IntentCleanupRegex().Replace(cleaned, " ");
        cleaned = DesiredPriceRegex().Replace(cleaned, " ");
        cleaned = Regex.Replace(cleaned, @"\s+", " ", RegexOptions.CultureInvariant).Trim(" .,:;-".ToCharArray());
        return cleaned.Length >= 3 ? cleaned : null;
    }

    private static bool LooksLikeProductUrl(string? url)
    {
        if (string.IsNullOrWhiteSpace(url) || !Uri.TryCreate(url, UriKind.Absolute, out var uri))
        {
            return false;
        }

        var host = uri.Host.ToLowerInvariant();
        return host.Contains("mercadolivre", StringComparison.Ordinal) ||
               host.Contains("mercadolibre", StringComparison.Ordinal) ||
               host.Equals("meli.la", StringComparison.Ordinal) ||
               host.Contains("amazon.", StringComparison.Ordinal) ||
               host.Contains("shopee", StringComparison.Ordinal) ||
               host.Contains("shein", StringComparison.Ordinal);
    }

    private static bool? ExtractSimilarPreference(string text)
    {
        var normalized = NormalizeForIntent(text);
        if (SimilarNoRegex().IsMatch(normalized))
        {
            return false;
        }

        if (SimilarYesRegex().IsMatch(normalized))
        {
            return true;
        }

        if (normalized.Contains("pode ser parecido", StringComparison.Ordinal) ||
            normalized.Contains("pode ser equivalente", StringComparison.Ordinal) ||
            normalized.Contains("aceito parecido", StringComparison.Ordinal) ||
            normalized.Contains("aceito equivalente", StringComparison.Ordinal))
        {
            return true;
        }

        return null;
    }

    private static string BuildSimilarText(bool acceptSimilar)
        => acceptSimilar
            ? "Tambem posso te avisar sobre produto similar quando aparecer oportunidade melhor e a semelhanca for bem confiavel."
            : "Quer que eu tambem te avise sobre produto similar se aparecer oportunidade melhor? Responda similar sim ou similar nao.";

    private static string NormalizeForIntent(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return string.Empty;
        }

        var normalized = value.Normalize(NormalizationForm.FormD);
        var sb = new StringBuilder(normalized.Length);
        foreach (var ch in normalized)
        {
            var category = CharUnicodeInfo.GetUnicodeCategory(ch);
            if (category != UnicodeCategory.NonSpacingMark)
            {
                sb.Append(char.ToLowerInvariant(ch));
            }
        }

        return Regex.Replace(sb.ToString().Normalize(NormalizationForm.FormC), @"\s+", " ", RegexOptions.CultureInvariant).Trim();
    }

    [GeneratedRegex(@"https?://[^\s]+", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex UrlRegex();

    [GeneratedRegex(@"(?:ate|até|abaixo de|menos de|menor que|por ate|por até|quero ate|quero até|chegar em|ficar em|no maximo|no máximo|maximo|máximo|teto de|valor alvo de?)\s*(?<price>R?\$?\s*(?:\d{1,3}(?:\.\d{3})+|\d+)(?:,\d{2})?|\d+(?:[,.]\d{2})?)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex DesiredPriceRegex();

    [GeneratedRegex(@"\b(me avisa|me avise|avisa|avise|me chama|me manda|me fala|quero saber|monitora|monitorar|quando baixar|se baixar|baixar|radar|quero|procura|procurar|acompanha|acompanhar|fica de olho|de olho|preco|preço|valor|produto|oferta|promocao|promoção|comprar|compra)\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex IntentCleanupRegex();

    [GeneratedRegex(@"\b(similar(es)?|parecido(s)?|equivalente(s)?|outro modelo)\b.*\b(sim|pode|aceito|manda|enviar|receber|ok|beleza)\b|\b(sim|pode|aceito|ok|beleza)\b.*\b(similar(es)?|parecido(s)?|equivalente(s)?|outro modelo)\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex SimilarYesRegex();

    [GeneratedRegex(@"\b(similar(es)?|parecido(s)?|equivalente(s)?|outro modelo)\b.*\b(nao|não|nunca|somente|apenas)\b|\b(nao|não)\b.*\b(similar(es)?|parecido(s)?|equivalente(s)?|outro modelo)\b|\b(so|só|somente|apenas)\b.*\b(exato|esse|mesmo)\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex SimilarNoRegex();

    private sealed record PriceWatchConversationIntent(
        bool WantsPriceWatch,
        bool StopAlerts,
        string? Url,
        decimal? DesiredPrice,
        string? ProductHint,
        bool? AcceptSimilarProducts);
}
