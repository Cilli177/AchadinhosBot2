using System.Text;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Configuration;
using AchadinhosBot.Next.Domain.Instagram;
using AchadinhosBot.Next.Domain.Logs;
using AchadinhosBot.Next.Domain.Models;
using AchadinhosBot.Next.Domain.Settings;
using AchadinhosBot.Next.Infrastructure.Instagram;
using Microsoft.Extensions.Options;

namespace AchadinhosBot.Next.Infrastructure.MercadoLivre;

public sealed class MercadoLivreReelDraftService
{
    private readonly IInstagramPublishStore _publishStore;
    private readonly IInstagramPublishLogStore _publishLogStore;
    private readonly IWhatsAppGateway _whatsAppGateway;
    private readonly InstagramLinkMetaService _linkMetaService;
    private readonly EvolutionOptions _evolutionOptions;

    public MercadoLivreReelDraftService(
        IInstagramPublishStore publishStore,
        IInstagramPublishLogStore publishLogStore,
        IWhatsAppGateway whatsAppGateway,
        InstagramLinkMetaService linkMetaService,
        IOptions<EvolutionOptions> evolutionOptions)
    {
        _publishStore = publishStore;
        _publishLogStore = publishLogStore;
        _whatsAppGateway = whatsAppGateway;
        _linkMetaService = linkMetaService;
        _evolutionOptions = evolutionOptions.Value;
    }

    public async Task<int> CreateDraftsForApprovalAsync(
        IReadOnlyList<MercadoLivreAffiliateScoutOffer> offers,
        MercadoLivreAffiliateScoutSettings settings,
        CancellationToken ct)
    {
        if (!settings.CreateReelDraftsFromScout)
        {
            return 0;
        }

        var enrichedOffers = await EnrichMissingVideoUrlsAsync(offers, ct);
        var existing = await _publishStore.ListAsync(ct);
        var usedVideos = existing
            .Where(x => !string.IsNullOrWhiteSpace(x.VideoUrl))
            .Select(x => x.VideoUrl!)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        var candidate = enrichedOffers
            .Where(x => !string.IsNullOrWhiteSpace(x.VideoUrl))
            .FirstOrDefault(x => !usedVideos.Contains(x.VideoUrl!));
        if (candidate is null)
        {
            return 0;
        }

        var offerUrl = FirstNotEmpty(candidate.SharedUrl, candidate.ProductUrl);
        if (string.IsNullOrWhiteSpace(offerUrl))
        {
            return 0;
        }

        var draft = new InstagramPublishDraft
        {
            PostType = "reel",
            ProductName = FirstNotEmpty(candidate.Title, "Oferta Mercado Livre"),
            Caption = BuildCaption(candidate),
            OfferUrl = offerUrl,
            OriginalOfferUrl = offerUrl,
            VideoUrl = candidate.VideoUrl,
            VideoCoverUrl = candidate.ImageUrl,
            ImageUrls = string.IsNullOrWhiteSpace(candidate.ImageUrl) ? new List<string>() : new List<string> { candidate.ImageUrl! },
            SuggestedImageUrls = string.IsNullOrWhiteSpace(candidate.ImageUrl) ? new List<string>() : new List<string> { candidate.ImageUrl! },
            SuggestedVideoUrls = new List<string> { candidate.VideoUrl! },
            Store = "Mercado Livre",
            CurrentPrice = candidate.PriceText,
            SourceDataOrigin = "mercadolivre_scout_reel",
            AutoReplyEnabled = true,
            AutoReplyKeyword = "LINK",
            AutoReplyLink = offerUrl,
            AutoReplyMessage = BuildWhatsAppMessage(candidate, offerUrl),
            SendToCatalog = true,
            CatalogTarget = CatalogTargets.Prod,
            CatalogIntentLocked = true,
            ProcessName = "mercadolivre_scout_reel",
            Status = "draft"
        };
        await _publishStore.SaveAsync(draft, ct);
        await _publishLogStore.AppendAsync(new InstagramPublishLogEntry
        {
            Action = "mercadolivre_reel_draft_created",
            Success = true,
            DraftId = draft.Id,
            Details = $"VideoUrl={candidate.VideoUrl};OfferUrl={offerUrl}",
            ProcessName = draft.ProcessName
        }, ct);

        if (settings.ReelSendForApproval)
        {
            var groupId = settings.ReelApprovalWhatsAppGroupId?.Trim();
            if (!string.IsNullOrWhiteSpace(groupId))
            {
                var instanceName = FirstNotEmpty(settings.ReelApprovalWhatsAppInstanceName, _evolutionOptions.InstanceName, "ZapOfertas");
                var send = await _whatsAppGateway.SendImageUrlAsync(instanceName, groupId, candidate.VideoUrl!, BuildApprovalMessage(draft), "video/mp4", "reel-ml.mp4", ct);
                await _publishLogStore.AppendAsync(new InstagramPublishLogEntry
                {
                    Action = "mercadolivre_reel_approval_sent",
                    Success = send.Success,
                    DraftId = draft.Id,
                    Details = $"Target={groupId};Message={send.Message}",
                    ProcessName = draft.ProcessName
                }, ct);
            }
        }

        return 1;
    }

    private async Task<IReadOnlyList<MercadoLivreAffiliateScoutOffer>> EnrichMissingVideoUrlsAsync(
        IReadOnlyList<MercadoLivreAffiliateScoutOffer> offers,
        CancellationToken ct)
    {
        var enriched = new List<MercadoLivreAffiliateScoutOffer>(offers.Count);
        foreach (var offer in offers)
        {
            if (!string.IsNullOrWhiteSpace(offer.VideoUrl))
            {
                enriched.Add(offer);
                continue;
            }

            var offerUrl = FirstNotEmpty(offer.SharedUrl, offer.ProductUrl);
            if (string.IsNullOrWhiteSpace(offerUrl))
            {
                enriched.Add(offer);
                continue;
            }

            try
            {
                var meta = await _linkMetaService.GetMetaAsync(offerUrl, ct);
                var videoUrl = meta.Videos?.FirstOrDefault(x => !string.IsNullOrWhiteSpace(x));
                enriched.Add(string.IsNullOrWhiteSpace(videoUrl) ? offer : offer with { VideoUrl = videoUrl });
            }
            catch
            {
                enriched.Add(offer);
            }
        }

        return enriched;
    }

    private static string BuildCaption(MercadoLivreAffiliateScoutOffer offer)
        => $"Achado do Mercado Livre: {FirstNotEmpty(offer.Title, "Oferta selecionada")}\nPreco: {FirstNotEmpty(offer.PriceText, "confira no link")}\n\nAcesse a bio e entre no catalogo para ver este produto.";

    private static string BuildWhatsAppMessage(MercadoLivreAffiliateScoutOffer offer, string offerUrl)
        => $"🔥 *Oferta em destaque*\n\n*{FirstNotEmpty(offer.Title, "Oferta Mercado Livre")}*\n💰 Preço: *{FirstNotEmpty(offer.PriceText, "confira no link")}*\n\n🛒 Pegar oferta: {offerUrl}";

    private static string BuildApprovalMessage(InstagramPublishDraft draft)
    {
        var sb = new StringBuilder();
        sb.AppendLine("🎬 *REEL ML - APROVACAO*");
        sb.AppendLine();
        sb.AppendLine($"Draft: `{draft.Id[..Math.Min(8, draft.Id.Length)]}`");
        sb.AppendLine($"Produto: *{draft.ProductName}*");
        sb.AppendLine("Origem: scout Mercado Livre");
        sb.AppendLine();
        sb.AppendLine("Este reel aguarda aprovacao manual para avaliarmos a qualidade do video.");
        return sb.ToString().Trim();
    }

    private static string FirstNotEmpty(params string?[] values)
        => values.FirstOrDefault(x => !string.IsNullOrWhiteSpace(x))?.Trim() ?? string.Empty;
}
