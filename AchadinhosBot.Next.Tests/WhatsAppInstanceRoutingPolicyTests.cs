using AchadinhosBot.Next.Application.Services;

namespace AchadinhosBot.Next.Tests;

public sealed class WhatsAppInstanceRoutingPolicyTests
{
    [Theory]
    [InlineData("ZapOfertas", "ZapOfertas")]
    [InlineData("ZapOfertas2", "ZapOfertas2")]
    [InlineData(" MinhaInstancia ", "MinhaInstancia")]
    public void ResolveParticipantOpsInstance_PreservesExplicitInstanceSelection(string instanceName, string expected)
    {
        var resolved = WhatsAppInstanceRoutingPolicy.ResolveParticipantOpsInstance(instanceName);

        Assert.Equal(expected, resolved);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void ResolveParticipantOpsInstance_FallsBackToParticipantOpsDefaultWhenMissing(string? instanceName)
    {
        var resolved = WhatsAppInstanceRoutingPolicy.ResolveParticipantOpsInstance(instanceName);

        Assert.Equal(WhatsAppInstanceRoutingPolicy.ParticipantOpsInstance, resolved);
    }
}
