using AchadinhosBot.Next.Application.Services;
using AchadinhosBot.Next.Domain.Models;
using Microsoft.AspNetCore.Http;

namespace AchadinhosBot.Next.Tests;

public sealed class CatalogTargetResolverTests
{
    [Theory]
    [InlineData("achadinhos-dev.local", CatalogTargets.Dev)]
    [InlineData("api-dev.example.test", CatalogTargets.Dev)]
    [InlineData("reidasofertas.ia.br", CatalogTargets.Prod)]
    public void Resolve_UsesIsolatedCatalogForDevelopmentHosts(string host, string expectedTarget)
    {
        var context = new DefaultHttpContext();
        context.Request.Host = new HostString(host);
        Assert.Equal(expectedTarget, CatalogTargetResolver.Resolve(context.Request));
    }
}
