using AchadinhosBot.Next.Configuration;
using AchadinhosBot.Next.Infrastructure.Safety;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace AchadinhosBot.Next.Tests;

public sealed class DeliverySafetyPolicyTests
{
    [Fact]
    public void IsWhatsAppDestinationAllowed_AllowsOfficialGroupWhenKillSwitchIsOff()
    {
        var policy = CreatePolicy(
            environmentName: Environments.Development,
            new DeliverySafetyOptions
            {
                BlockOfficialDestinationsOutsideProduction = true,
                BlockOfficialWhatsAppAlways = false,
                OfficialWhatsAppGroupIds = new List<string> { "120363405661434395@g.us" }
            });

        var allowed = policy.IsWhatsAppDestinationAllowed("120363405661434395@g.us", out var reason);

        Assert.True(allowed);
        Assert.Null(reason);
    }

    [Fact]
    public void IsWhatsAppDestinationAllowed_BlocksOfficialGroupWhenKillSwitchIsOn()
    {
        var policy = CreatePolicy(
            environmentName: Environments.Production,
            new DeliverySafetyOptions
            {
                BlockOfficialDestinationsOutsideProduction = false,
                BlockOfficialWhatsAppAlways = true,
                OfficialWhatsAppGroupIds = new List<string> { "120363405661434395@g.us" }
            });

        var allowed = policy.IsWhatsAppDestinationAllowed("120363405661434395@g.us", out var reason);

        Assert.False(allowed);
        Assert.Contains("destino oficial WhatsApp", reason);
    }

    [Fact]
    public void IsTelegramDestinationAllowed_BlocksOfficialChatOutsideProduction()
    {
        var policy = CreatePolicy(
            environmentName: Environments.Development,
            new DeliverySafetyOptions
            {
                BlockOfficialDestinationsOutsideProduction = true,
                OfficialTelegramChatIds = new List<long> { -1003632436217 }
            });

        var allowed = policy.IsTelegramDestinationAllowed(-1003632436217, out var reason);

        Assert.False(allowed);
        Assert.Contains("destino oficial Telegram", reason);
    }

    private static DeliverySafetyPolicy CreatePolicy(string environmentName, DeliverySafetyOptions options)
    {
        var hostEnvironment = new TestHostEnvironment(environmentName);
        return new DeliverySafetyPolicy(hostEnvironment, Options.Create(options));
    }

    private sealed class TestHostEnvironment : IHostEnvironment
    {
        public TestHostEnvironment(string environmentName)
        {
            EnvironmentName = environmentName;
            ApplicationName = "AchadinhosBot.Next.Tests";
            ContentRootPath = Directory.GetCurrentDirectory();
            ContentRootFileProvider = new NullFileProvider();
        }

        public string EnvironmentName { get; set; }
        public string ApplicationName { get; set; }
        public string ContentRootPath { get; set; }
        public IFileProvider ContentRootFileProvider { get; set; }
    }
}
