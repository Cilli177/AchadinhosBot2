using SixLabors.Fonts;
using SixLabors.ImageSharp;
using SixLabors.ImageSharp.Drawing.Processing;
using SixLabors.ImageSharp.Formats.Jpeg;
using SixLabors.ImageSharp.PixelFormats;
using SixLabors.ImageSharp.Processing;

namespace AchadinhosBot.Next.Infrastructure.MercadoLivre;

internal static class MercadoLivreStoryImageComposer
{
    private static readonly Size StorySize = new(1080, 1920);

    public static byte[]? Compose(byte[] input)
    {
        try
        {
            using var image = Image.Load<Rgba32>(input);
            image.Mutate(ctx =>
            {
                ctx.Resize(new ResizeOptions
                {
                    Size = StorySize,
                    Mode = ResizeMode.Crop,
                    Sampler = KnownResamplers.Lanczos3
                });

                var badge = new RectangleF(120, 1450, 840, 250);
                ctx.Fill(Color.FromRgba(0, 0, 0, 210), badge);
                ctx.Fill(Color.FromRgb(255, 214, 10), new RectangleF(120, 1450, 18, 250));

                var titleFont = ResolveFont(72, FontStyle.Bold);
                var subtitleFont = ResolveFont(46, FontStyle.Bold);
                var textColor = Color.White;
                var accentColor = Color.FromRgb(255, 214, 10);

                ctx.DrawText("LINK NA BIO", titleFont, accentColor, new PointF(178, 1502));
                ctx.DrawText("ACESSE O CATALOGO", subtitleFont, textColor, new PointF(178, 1600));
            });

            using var output = new MemoryStream();
            image.SaveAsJpeg(output, new JpegEncoder { Quality = 92 });
            return output.ToArray();
        }
        catch
        {
            return null;
        }
    }

    private static Font ResolveFont(float size, FontStyle style)
    {
        foreach (var name in new[] { "Arial", "Segoe UI", "DejaVu Sans" })
        {
            if (SystemFonts.TryGet(name, out var family))
            {
                return family.CreateFont(size, style);
            }
        }

        return SystemFonts.Families.First().CreateFont(size, style);
    }
}
