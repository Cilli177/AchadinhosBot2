using System.Net;
using AchadinhosBot.Next.Domain.Settings;
using AchadinhosBot.Next.Infrastructure.Instagram;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;
using Xunit.Abstractions;

namespace AchadinhosBot.Next.Tests;

public sealed class InstagramManualValidation
{
    private readonly ITestOutputHelper _output;

    public InstagramManualValidation(ITestOutputHelper output)
    {
        _output = output;
    }

    [Fact(Skip = "Manual integration test that depends on real Instagram credentials and network access.")]
    public async Task ValidateMediaStatus_RealCall()
    {
        // NOTE: This test uses real credentials and makes a real API call.
        // It is intended for manual validation of the Instagram Status API fix.
        
        var settings = new InstagramPublishSettings
        {
            Enabled = true,
            AccessToken = "EAAYME7Cl5x4BQvYw01zh7q79q1QJHM4iEAe6MxWwyFZAZA9rZBuKi7uD7oxRQfaijOXbWvRtJz6dZAJo4qPZCG85ZCDZCHTIuBPZBh9JuoUIN7Ja3trjFnoxPqNuwaYQxPGlmCbts3P72mpb2XhTTHMHobBCCPWyM6mI8dS3ZAXZBZCbXn4BZBiTUiTmmKaSwctBO1nK",
            InstagramUserId = "17841479982697707",
            GraphBaseUrl = "https://graph.facebook.com/v24.0"
        };

        var httpClient = new HttpClient();
        var clientFactory = new SimpleHttpClientFactory(httpClient);
        var metaClient = new MetaGraphClient(clientFactory);

        var mediaId = "17914112322328927";
        _output.WriteLine($"Checking status for Media ID: {mediaId}");

        var result = await metaClient.GetMediaStatusAsync(settings, mediaId, CancellationToken.None);

        _output.WriteLine($"Success: {result.Success}");
        if (!result.Success)
        {
            _output.WriteLine($"Error: {result.Error}");
        }
        _output.WriteLine($"Raw Response: {result.RawResponse}");

        Assert.True(result.Success, $"Failed to get status: {result.Error}");
        Assert.Contains("shortcode", result.RawResponse);
        Assert.Contains("timestamp", result.RawResponse);
        Assert.DoesNotContain("\"status\"", result.RawResponse); // Should not have the invalid status field
    }

    private sealed class SimpleHttpClientFactory : IHttpClientFactory
    {
        private readonly HttpClient _client;
        public SimpleHttpClientFactory(HttpClient client) => _client = client;
        public HttpClient CreateClient(string name) => _client;
    }
}
