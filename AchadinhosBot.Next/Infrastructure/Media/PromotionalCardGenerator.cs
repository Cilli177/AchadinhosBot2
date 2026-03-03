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
            using var client = _httpClientFactory.CreateClient("default");
            var imageBytes = await client.GetByteArrayAsync(imageUrl, cancellationToken);
            using var productImg = await Image.LoadAsync<Rgba32>(new MemoryStream(imageBytes), cancellationToken);

            // Canvas size for Instagram Story (1080x1920)
            using var canvas = new Image<Rgba32>(1080, 1920);

            // Fill background with a modern dark color
            canvas.Mutate(x => x.Fill(Color.ParseHex("#121214")));

            // Draw a subtle accent block at the top
            var topRect = new RectangleF(0, 0, 1080, 300);
            canvas.Mutate(x => x.Fill(Color.ParseHex("#8b5cf6"), topRect));

            // Resize product image to fit nicely
            productImg.Mutate(x => x.Resize(new ResizeOptions
            {
                Size = new Size(800, 800),
                Mode = ResizeMode.Pad,
                PadColor = Color.White
            }));

            // Draw product image in the center (X: 140, Y: 400)
            canvas.Mutate(x => x.DrawImage(productImg, new Point(140, 400), 1f));

            // Load fonts
            var family = SystemFonts.Families.FirstOrDefault();
            if (family == null)
            {
                _logger.LogWarning("Nenhuma fonte encontrada no sistema. Impossivel gerar texto no cartao.");
                return null; // ou salvar fonte "ttf" empacotada no projeto
            }

            var titleFont = family.CreateFont(56, FontStyle.Bold);
            var priceFont = family.CreateFont(96, FontStyle.Bold);
            var regularFont = family.CreateFont(42, FontStyle.Regular);

            var drawOptions = new DrawingOptions();

            // Draw Header Text
            var headerTextOptions = new RichTextOptions(titleFont)
            {
                Origin = new PointF(540, 150),
                HorizontalAlignment = HorizontalAlignment.Center,
                VerticalAlignment = VerticalAlignment.Center
            };
            canvas.Mutate(x => x.DrawText(headerTextOptions, "OFERTA EM DESTAQUE", Color.White));

            // Draw Product Title
            var titleTextOptions = new RichTextOptions(regularFont)
            {
                Origin = new PointF(540, 1300),
                HorizontalAlignment = HorizontalAlignment.Center,
                VerticalAlignment = VerticalAlignment.Center,
                WrappingLength = 900
            };
            var shortTitle = productName.Length > 80 ? productName[..77] + "..." : productName;
            canvas.Mutate(x => x.DrawText(titleTextOptions, shortTitle, Color.ParseHex("#e1e1e6")));

            // Draw Price
            var priceTextOptions = new RichTextOptions(priceFont)
            {
                Origin = new PointF(540, 1450),
                HorizontalAlignment = HorizontalAlignment.Center,
                VerticalAlignment = VerticalAlignment.Center
            };
            canvas.Mutate(x => x.DrawText(priceTextOptions, currentPrice, Color.ParseHex("#04d361")));

            // Draw Previous Price / Discount if any
            if (!string.IsNullOrWhiteSpace(previousPrice))
            {
                var prevPriceTextOptions = new RichTextOptions(regularFont)
                {
                    Origin = new PointF(540, 1550),
                    HorizontalAlignment = HorizontalAlignment.Center,
                    VerticalAlignment = VerticalAlignment.Center
                };
                var discountStr = !string.IsNullOrWhiteSpace(discountPercent) ? $" (-{discountPercent}%)" : "";
                var prevText = $"De: {previousPrice}{discountStr}";
                canvas.Mutate(x => x.DrawText(prevPriceTextOptions, prevText, Color.ParseHex("#a8a8b3")));
                
                // Strike through line
                var measure = TextMeasurer.MeasureSize(prevText, new TextOptions(regularFont));
                var lineY = 1550;
                // canvas.Mutate(x => x.DrawLines(new Pen(Color.Red, 4), new PointF(540 - (measure.Width / 2), lineY), new PointF(540 + (measure.Width / 2), lineY)));
            }

            // Draw CTA
            var ctaRect = new RectangleF(140, 1700, 800, 120);
            canvas.Mutate(x => x.Fill(Color.ParseHex("#8b5cf6"), ctaRect));
            
            var ctaTextOptions = new RichTextOptions(titleFont)
            {
                Origin = new PointF(540, 1760),
                HorizontalAlignment = HorizontalAlignment.Center,
                VerticalAlignment = VerticalAlignment.Center
            };
            canvas.Mutate(x => x.DrawText(ctaTextOptions, "COMENTE 'EU QUERO'", Color.White));

            using var ms = new MemoryStream();
            await canvas.SaveAsJpegAsync(ms, cancellationToken);
            return ms.ToArray();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao gerar cartao promocional para imagem: {Url}", imageUrl);
            return null;
        }
    }
}
