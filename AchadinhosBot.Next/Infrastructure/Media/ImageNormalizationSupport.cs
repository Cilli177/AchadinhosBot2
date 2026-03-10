using SixLabors.ImageSharp;
using SixLabors.ImageSharp.Formats.Jpeg;
using SixLabors.ImageSharp.Processing;

namespace AchadinhosBot.Next.Infrastructure.Media;

internal static class ImageNormalizationSupport
{
    public static byte[]? NormalizeForInstagramPublication(byte[] input, string postType)
    {
        try
        {
            using var image = Image.Load(input);
            if (image.Width == 0 || image.Height == 0)
            {
                return null;
            }

            var normalizedType = string.Equals(postType, "story", StringComparison.OrdinalIgnoreCase) ||
                                 string.Equals(postType, "reel", StringComparison.OrdinalIgnoreCase)
                ? "story"
                : "feed";

            var targetSize = normalizedType == "story"
                ? new Size(1080, 1920)
                : new Size(1080, 1080);

            image.Mutate(ctx => ctx.Resize(new ResizeOptions
            {
                Size = targetSize,
                Mode = ResizeMode.Crop,
                Sampler = KnownResamplers.Lanczos3
            }));

            using var output = new MemoryStream();
            image.SaveAsJpeg(output, new JpegEncoder { Quality = 90 });
            return output.ToArray();
        }
        catch
        {
            return null;
        }
    }

    public static byte[]? TranscodeToJpeg(byte[] input, int? maxWidth = null, int? maxHeight = null, int quality = 90)
    {
        try
        {
            using var image = Image.Load(input);
            if (image.Width == 0 || image.Height == 0)
            {
                return null;
            }

            if (maxWidth.HasValue || maxHeight.HasValue)
            {
                image.Mutate(ctx => ctx.Resize(new ResizeOptions
                {
                    Size = new Size(maxWidth ?? image.Width, maxHeight ?? image.Height),
                    Mode = ResizeMode.Max,
                    Sampler = KnownResamplers.Lanczos3
                }));
            }

            using var output = new MemoryStream();
            image.SaveAsJpeg(output, new JpegEncoder { Quality = Math.Clamp(quality, 1, 100) });
            return output.ToArray();
        }
        catch
        {
            return null;
        }
    }

    public static byte[]? TranscodeToPng(byte[] input)
    {
        try
        {
            using var image = Image.Load(input);
            if (image.Width == 0 || image.Height == 0)
            {
                return null;
            }

            using var output = new MemoryStream();
            image.SaveAsPng(output);
            return output.ToArray();
        }
        catch
        {
            return null;
        }
    }
}
