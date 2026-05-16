using AchadinhosBot.Next.Application.Services;
using AchadinhosBot.Next.Domain.Settings;

namespace AchadinhosBot.Next.Tests;

public sealed class WhatsAppParticipantAddSafetyTests
{
    [Fact]
    public void RegisterSuccessfulAdd_TracksCountersPerInstance()
    {
        var automation = new WhatsAppAdminAutomationSettings
        {
            MaxParticipantsAddedPerDay = 100,
            MinMinutesBetweenParticipantAdds = 15
        };
        var now = new DateTimeOffset(2026, 4, 1, 12, 0, 0, TimeSpan.Zero);

        WhatsAppParticipantAddSafety.Normalize(automation, now);
        WhatsAppParticipantAddSafety.RegisterSuccessfulAdd(automation, "ZapOfertas", 7, now);
        WhatsAppParticipantAddSafety.RegisterSuccessfulAdd(automation, "ZapOfertas2", 3, now.AddMinutes(2));

        var zapOfertas = WhatsAppParticipantAddSafety.GetSnapshot(automation, "ZapOfertas");
        var zapOfertas2 = WhatsAppParticipantAddSafety.GetSnapshot(automation, "ZapOfertas2");

        Assert.Equal(7, zapOfertas.ParticipantsAddedToday);
        Assert.Equal(3, zapOfertas2.ParticipantsAddedToday);
        Assert.NotEqual(zapOfertas.LastParticipantAddAt, zapOfertas2.LastParticipantAddAt);
    }

    [Fact]
    public void GetSnapshot_FallsBackToDefaultWhenInstanceHasNoCustomProfile()
    {
        var automation = new WhatsAppAdminAutomationSettings
        {
            MaxParticipantsAddedPerDay = 80,
            MinMinutesBetweenParticipantAdds = 12,
            ParticipantsAddedToday = 5,
            ParticipantAddQuotaDateUtc = new DateTimeOffset(2026, 4, 1, 0, 0, 0, TimeSpan.Zero)
        };

        var snapshot = WhatsAppParticipantAddSafety.GetSnapshot(automation, "ZapOfertas");

        Assert.True(snapshot.UsesDefaultSettings);
        Assert.Equal(80, snapshot.MaxParticipantsAddedPerDay);
        Assert.Equal(12, snapshot.MinMinutesBetweenParticipantAdds);
        Assert.Equal(5, snapshot.ParticipantsAddedToday);
    }

    [Fact]
    public void UpdateConfiguredLimits_CreatesCustomProfileForInstance()
    {
        var automation = new WhatsAppAdminAutomationSettings
        {
            MaxParticipantsAddedPerDay = 120,
            MinMinutesBetweenParticipantAdds = 10
        };
        var now = new DateTimeOffset(2026, 4, 1, 12, 0, 0, TimeSpan.Zero);

        WhatsAppParticipantAddSafety.UpdateConfiguredLimits(automation, "ZapOfertas", 25, 90, now);

        var snapshot = WhatsAppParticipantAddSafety.GetSnapshot(automation, "ZapOfertas");

        Assert.False(snapshot.UsesDefaultSettings);
        Assert.Equal(25, snapshot.MaxParticipantsAddedPerDay);
        Assert.Equal(90, snapshot.MinMinutesBetweenParticipantAdds);
    }
}
