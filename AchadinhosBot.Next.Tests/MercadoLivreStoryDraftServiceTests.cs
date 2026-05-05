using AchadinhosBot.Next.Domain.Instagram;
using AchadinhosBot.Next.Domain.Settings;
using AchadinhosBot.Next.Infrastructure.MercadoLivre;
using SixLabors.ImageSharp;
using SixLabors.ImageSharp.Formats.Jpeg;
using SixLabors.ImageSharp.PixelFormats;

namespace AchadinhosBot.Next.Tests;

public sealed class MercadoLivreStoryDraftServiceTests
{
    [Fact]
    public void GetNextAvailableStorySlots_UsesBrazilScheduleAndSkipsOccupiedSlots()
    {
        var settings = new MercadoLivreAffiliateScoutSettings
        {
            StoryDraftsPerDay = 8,
            StoryScheduleTimes = new List<string> { "09:00", "11:00", "13:00" }
        };
        var existing = new[]
        {
            new InstagramPublishDraft
            {
                PostType = "story",
                SourceDataOrigin = "mercadolivre_scout_story",
                ScheduledFor = new DateTimeOffset(2026, 4, 30, 14, 0, 0, TimeSpan.Zero)
            }
        };

        var slots = MercadoLivreStoryDraftService.GetNextAvailableStorySlots(
            settings,
            existing,
            new DateTimeOffset(2026, 4, 30, 12, 30, 0, TimeSpan.Zero));

        Assert.Equal(new DateTimeOffset(2026, 4, 30, 16, 0, 0, TimeSpan.Zero), slots[0]);
    }

    [Fact]
    public void Compose_AddsStoryBadgeAndReturnsJpeg()
    {
        using var image = new Image<Rgba32>(320, 320, Color.White);
        using var input = new MemoryStream();
        image.SaveAsJpeg(input, new JpegEncoder());

        var bytes = MercadoLivreStoryImageComposer.Compose(input.ToArray());

        Assert.NotNull(bytes);
        using var output = Image.Load(bytes!);
        Assert.Equal(1080, output.Width);
        Assert.Equal(1920, output.Height);
    }
}
