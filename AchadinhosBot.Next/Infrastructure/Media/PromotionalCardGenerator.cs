using SixLabors.Fonts;
using SixLabors.ImageSharp;
using SixLabors.ImageSharp.Drawing.Processing;
using SixLabors.ImageSharp.PixelFormats;
using SixLabors.ImageSharp.Processing;
using AchadinhosBot.Next.Application.Abstractions;
using Microsoft.Extensions.Logging;

namespace AchadinhosBot.Next.Infrastructure.Media;

public sealed class PromotionalCardGenerator : IPromotionalCardGenerator
{
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ILogger<PromotionalCardGenerator> _logger;

    public PromotionalCardGenerator(IHttpClientFactory httpClientFactory, ILogger<PromotionalCardGenerator> logger)
    {
        _httpClientFactory = httpClientFactory;
        _logger = logger;
    }

    public async Task<byte[]?> GenerateCardAsync(
        string productName,
        string currentPrice,
        string? previousPrice,
        string? discountPercent,
        string imageUrl,
        CancellationToken cancellationToken)
    {
        try
        {
            // Try downloading product image with browser User-Agent (Amazon/Shopee CDNs require it)
            Image<Rgba32>? productImg = null;
            try
            {
                using var client = _httpClientFactory.CreateClient("default");
                client.DefaultRequestHeaders.TryAddWithoutValidation(
                    "User-Agent",
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36");
                client.DefaultRequestHeaders.TryAddWithoutValidation("Accept", "image/webp,image/apng,image/*,*/*;q=0.8");

                var imageBytes = await client.GetByteArrayAsync(imageUrl, cancellationToken);
                productImg = await Image.LoadAsync<Rgba32>(new MemoryStream(imageBytes), cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Nao foi possivel baixar imagem do produto ({Url}). Gerando card sem imagem.", imageUrl);
                // Create a placeholder so the card is still generated
                productImg = new Image<Rgba32>(800, 800, Color.ParseHex("#1e293b"));
            }

            using (productImg)
            {
                // Canvas size for Instagram Story (1080x1920)
                using var canvas = new Image<Rgba32>(1080, 1920);

                // Fill background with Deep Navy
                canvas.Mutate(x => x.Fill(Color.ParseHex("#0f172a")));

                // Draw a subtle accent block at the top
                var topRect = new RectangleF(0, 0, 1080, 200);
                canvas.Mutate(x => x.Fill(Color.ParseHex("#1e293b"), topRect));

                // Resize product image to fit nicely
                productImg.Mutate(x => x.Resize(new ResizeOptions
                {
                    Size = new Size(800, 800),
                    Mode = ResizeMode.Pad,
                    PadColor = Color.Transparent
                }));

                // Draw product image in the center (X: 140, Y: 250)
                canvas.Mutate(x => x.DrawImage(productImg, new Point(140, 250), 1f));

                // Load the bundled Montserrat font (works inside Docker/Linux with no system fonts)
                var fonts = new FontCollection();
                var fontPaths = new[]
                {
                    Path.Combine(AppContext.BaseDirectory, "wwwroot", "fonts", "Montserrat.ttf"),
                    Path.Combine(AppContext.BaseDirectory, "wwwroot", "fonts", "Montserrat-Bold.ttf"),
                };
                FontFamily family = default;
                foreach (var fp in fontPaths)
                {
                    if (File.Exists(fp))
                    {
                        family = fonts.Add(fp);
                        break;
                    }
                }

                if (string.IsNullOrEmpty(family.Name))
                {
                    // Last-resort: try system fonts
                    family = SystemFonts.Families.FirstOrDefault();
                }

                if (string.IsNullOrEmpty(family.Name))
                {
                    _logger.LogWarning("Nenhuma fonte encontrada no sistema ou bundled. Impossivel gerar texto no cartao.");
                    return null;
                }

                var titleFont = family.CreateFont(42, FontStyle.Bold);
                var superTitleFont = family.CreateFont(64, FontStyle.Bold);
                var priceFont = family.CreateFont(120, FontStyle.Bold);
                var regularFont = family.CreateFont(36, FontStyle.Regular);

                // Draw Header Text ("VIP")
                var vipOptions = new RichTextOptions(titleFont)
                {
                    Origin = new PointF(100, 100),
                    HorizontalAlignment = HorizontalAlignment.Left,
                    VerticalAlignment = VerticalAlignment.Center
                };
                canvas.Mutate(x => x.DrawText(vipOptions, "VIP", Color.ParseHex("#c4a468")));

                // Draw Header Text ("OFERTA VIP EXCLUSIVA")
                var headerTextOptions = new RichTextOptions(titleFont)
                {
                    Origin = new PointF(220, 100),
                    HorizontalAlignment = HorizontalAlignment.Left,
                    VerticalAlignment = VerticalAlignment.Center
                };
                canvas.Mutate(x => x.DrawText(headerTextOptions, "OFERTA VIP EXCLUSIVA", Color.ParseHex("#c4a468")));

                // "Desconto Imperdivel" badge area
                var badgeRect = new RectangleF(100, 1150, 420, 60);
                canvas.Mutate(x => x.Fill(Color.ParseHex("#c4a46820"), badgeRect));
                var badgeTextOptions = new RichTextOptions(regularFont)
                {
                    Origin = new PointF(310, 1180),
                    HorizontalAlignment = HorizontalAlignment.Center,
                    VerticalAlignment = VerticalAlignment.Center
                };
                canvas.Mutate(x => x.DrawText(badgeTextOptions, "DESCONTO IMPERDÍVEL", Color.ParseHex("#c4a468")));

                // Draw Product Title
                var titleTextOptions = new RichTextOptions(superTitleFont)
                {
                    Origin = new PointF(100, 1260),
                    HorizontalAlignment = HorizontalAlignment.Left,
                    VerticalAlignment = VerticalAlignment.Top,
                    WrappingLength = 880
                };
                var shortTitle = productName.Length > 55 ? productName[..52] + "..." : productName;
                canvas.Mutate(x => x.DrawText(titleTextOptions, shortTitle, Color.White));

                // Draw Price
                var priceTextOptions = new RichTextOptions(priceFont)
                {
                    Origin = new PointF(100, 1550),
                    HorizontalAlignment = HorizontalAlignment.Left,
                    VerticalAlignment = VerticalAlignment.Center
                };
                canvas.Mutate(x => x.DrawText(priceTextOptions, currentPrice, Color.ParseHex("#c4a468")));

                // Draw Previous Price / Discount if any
                if (!string.IsNullOrWhiteSpace(previousPrice))
                {
                    var prevPriceTextOptions = new RichTextOptions(regularFont)
                    {
                        Origin = new PointF(100, 1660),
                        HorizontalAlignment = HorizontalAlignment.Left,
                        VerticalAlignment = VerticalAlignment.Center
                    };
                    var discountStr = !string.IsNullOrWhiteSpace(discountPercent) ? $" (-{discountPercent}%)" : "";
                    var prevText = $"De: {previousPrice}{discountStr}";
                    canvas.Mutate(x => x.DrawText(prevPriceTextOptions, prevText, Color.ParseHex("#94a3b8")));
                }

                // Draw CTA button
                var ctaRect = new RectangleF(100, 1720, 880, 140);
                canvas.Mutate(x => x.Fill(Color.ParseHex("#c4a468"), ctaRect));

                var ctaTextOptions = new RichTextOptions(superTitleFont)
                {
                    Origin = new PointF(540, 1790),
                    HorizontalAlignment = HorizontalAlignment.Center,
                    VerticalAlignment = VerticalAlignment.Center
                };
                canvas.Mutate(x => x.DrawText(ctaTextOptions, "Comprar Agora", Color.ParseHex("#0f172a")));

                using var ms = new MemoryStream();
                await canvas.SaveAsJpegAsync(ms, cancellationToken);
                return ms.ToArray();
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao gerar cartao promocional para imagem: {Url}", imageUrl);
            return null;
        }
    }
}
