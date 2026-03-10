using System.Diagnostics;
using System.Text.Json;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Domain.Instagram;

namespace AchadinhosBot.Next.Infrastructure.Media;

public sealed class FfmpegVideoProcessingService : IVideoProcessingService
{
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ILogger<FfmpegVideoProcessingService> _logger;
    private readonly string _publicMediaDirectory;

    public FfmpegVideoProcessingService(
        IHttpClientFactory httpClientFactory,
        ILogger<FfmpegVideoProcessingService> logger)
    {
        _httpClientFactory = httpClientFactory;
        _logger = logger;
        _publicMediaDirectory = Path.Combine(AppContext.BaseDirectory, "wwwroot", "media", "admin");
        Directory.CreateDirectory(_publicMediaDirectory);
    }

    public async Task<VideoProcessingResult> PrepareForInstagramPublicationAsync(
        InstagramPublishDraft draft,
        string? publicBaseUrl,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(draft.VideoUrl))
        {
            return new VideoProcessingResult(false, null, Error: "Rascunho sem video para processar.");
        }

        var resolvedVideoUrl = ResolvePublicMediaUrl(draft.VideoUrl, publicBaseUrl);
        if (string.IsNullOrWhiteSpace(resolvedVideoUrl))
        {
            return new VideoProcessingResult(false, null, Error: "Nao foi possivel resolver a URL publica do video.");
        }

        var needsRender = RequiresRender(draft);
        if (!needsRender)
        {
            return new VideoProcessingResult(true, resolvedVideoUrl, ResolvePublicMediaUrl(draft.VideoCoverUrl, publicBaseUrl), false);
        }

        if (!await BinaryExistsAsync("ffmpeg", cancellationToken) || !await BinaryExistsAsync("ffprobe", cancellationToken))
        {
            return new VideoProcessingResult(false, null, Error: "ffmpeg/ffprobe nao encontrados no ambiente.");
        }

        var tempRoot = Path.Combine(Path.GetTempPath(), "achadinhos-video", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempRoot);

        try
        {
            var inputVideoPath = await MaterializeInputAsync(draft.VideoUrl!, publicBaseUrl, tempRoot, "input-video", ".mp4", cancellationToken);
            if (inputVideoPath is null)
            {
                return new VideoProcessingResult(false, null, Error: "Nao foi possivel obter o video original.");
            }

            var probe = await ProbeVideoAsync(inputVideoPath, cancellationToken);
            if (probe is null)
            {
                return new VideoProcessingResult(false, null, Error: "Nao foi possivel inspecionar o video com ffprobe.");
            }

            var trimStart = Clamp(draft.VideoTrimStartSeconds ?? 0d, 0d, probe.DurationSeconds);
            var trimEndCandidate = draft.VideoTrimEndSeconds ?? probe.DurationSeconds;
            var trimEnd = Clamp(trimEndCandidate, trimStart, probe.DurationSeconds);
            var outputDuration = Math.Max(0.1d, trimEnd - trimStart);

            string? inputMusicPath = null;
            double? musicWindow = null;
            if (!string.IsNullOrWhiteSpace(draft.MusicTrackUrl))
            {
                inputMusicPath = await MaterializeInputAsync(draft.MusicTrackUrl!, publicBaseUrl, tempRoot, "input-music", ".mp3", cancellationToken);
                if (inputMusicPath is null)
                {
                    return new VideoProcessingResult(false, null, Error: "Nao foi possivel obter a trilha de audio.");
                }

                var musicStart = Math.Max(0d, draft.MusicStartSeconds ?? 0d);
                var musicEnd = draft.MusicEndSeconds.HasValue && draft.MusicEndSeconds.Value > musicStart
                    ? draft.MusicEndSeconds.Value
                    : musicStart + outputDuration;
                musicWindow = Math.Max(0.1d, Math.Min(outputDuration, musicEnd - musicStart));
            }

            var outputFileName = $"ig-render-{Guid.NewGuid():N}.mp4";
            var outputPath = Path.Combine(_publicMediaDirectory, outputFileName);
            var renderArgs = BuildRenderArguments(
                inputVideoPath,
                inputMusicPath,
                outputPath,
                trimStart,
                outputDuration,
                draft,
                probe.HasAudio,
                musicWindow);

            var renderResult = await RunProcessAsync("ffmpeg", renderArgs, cancellationToken);
            if (renderResult.ExitCode != 0 || !File.Exists(outputPath))
            {
                _logger.LogWarning("Falha ao renderizar video Instagram. ExitCode={ExitCode} Error={Error}", renderResult.ExitCode, renderResult.StdErr);
                return new VideoProcessingResult(false, null, Error: "Falha ao renderizar o video com ffmpeg.");
            }

            string? coverUrl = ResolvePublicMediaUrl(draft.VideoCoverUrl, publicBaseUrl);
            var coverSeek = Clamp((draft.VideoCoverAtSeconds ?? trimStart) - trimStart, 0d, Math.Max(0.1d, outputDuration - 0.05d));
            var coverFileName = $"ig-cover-{Guid.NewGuid():N}.jpg";
            var coverPath = Path.Combine(_publicMediaDirectory, coverFileName);
            var coverArgs = $"-y -ss {FormatSeconds(coverSeek)} -i {Quote(outputPath)} -frames:v 1 -q:v 2 {Quote(coverPath)}";
            var coverResult = await RunProcessAsync("ffmpeg", coverArgs, cancellationToken);
            if (coverResult.ExitCode == 0 && File.Exists(coverPath))
            {
                coverUrl = BuildPublicAdminMediaUrl(coverFileName, publicBaseUrl);
            }

            return new VideoProcessingResult(
                true,
                BuildPublicAdminMediaUrl(outputFileName, publicBaseUrl),
                coverUrl,
                true);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Falha inesperada ao preparar video {DraftId} para publicacao.", draft.Id);
            return new VideoProcessingResult(false, null, Error: ex.Message);
        }
        finally
        {
            try
            {
                if (Directory.Exists(tempRoot))
                {
                    Directory.Delete(tempRoot, true);
                }
            }
            catch
            {
            }
        }
    }

    private static bool RequiresRender(InstagramPublishDraft draft)
    {
        return (draft.VideoTrimStartSeconds ?? 0d) > 0d
               || (draft.VideoTrimEndSeconds ?? 0d) > 0d
               || !string.IsNullOrWhiteSpace(draft.MusicTrackUrl)
               || (draft.MusicStartSeconds ?? 0d) > 0d
               || (draft.MusicEndSeconds ?? 0d) > 0d
               || Math.Abs((draft.MusicVolume ?? 1d) - 1d) > 0.001d
               || Math.Abs((draft.OriginalAudioVolume ?? 1d) - 1d) > 0.001d;
    }

    private async Task<string?> MaterializeInputAsync(
        string source,
        string? publicBaseUrl,
        string tempRoot,
        string prefix,
        string fallbackExtension,
        CancellationToken cancellationToken)
    {
        var localPath = TryResolveLocalAdminMediaPath(source);
        if (localPath is not null)
        {
            var extension = Path.GetExtension(localPath);
            var destination = Path.Combine(tempRoot, prefix + (string.IsNullOrWhiteSpace(extension) ? fallbackExtension : extension));
            File.Copy(localPath, destination, overwrite: true);
            return destination;
        }

        var absoluteUrl = ResolvePublicMediaUrl(source, publicBaseUrl);
        if (string.IsNullOrWhiteSpace(absoluteUrl))
        {
            return null;
        }

        var client = _httpClientFactory.CreateClient("default");
        using var response = await client.GetAsync(absoluteUrl, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
        if (!response.IsSuccessStatusCode)
        {
            return null;
        }

        var extensionFromUrl = TryInferExtension(absoluteUrl, fallbackExtension);
        var filePath = Path.Combine(tempRoot, prefix + extensionFromUrl);
        await using var output = new FileStream(filePath, FileMode.Create, FileAccess.Write, FileShare.None);
        await using var input = await response.Content.ReadAsStreamAsync(cancellationToken);
        await input.CopyToAsync(output, cancellationToken);
        return filePath;
    }

    private static string? TryResolveLocalAdminMediaPath(string source)
    {
        if (string.IsNullOrWhiteSpace(source))
        {
            return null;
        }

        if (source.StartsWith("/media/admin/", StringComparison.OrdinalIgnoreCase))
        {
            return Path.Combine(AppContext.BaseDirectory, "wwwroot", source.TrimStart('/').Replace('/', Path.DirectorySeparatorChar));
        }

        if (Uri.TryCreate(source, UriKind.Absolute, out var uri) &&
            uri.AbsolutePath.StartsWith("/media/admin/", StringComparison.OrdinalIgnoreCase))
        {
            return Path.Combine(AppContext.BaseDirectory, "wwwroot", uri.AbsolutePath.TrimStart('/').Replace('/', Path.DirectorySeparatorChar));
        }

        return null;
    }

    private static string? ResolvePublicMediaUrl(string? source, string? publicBaseUrl)
    {
        if (string.IsNullOrWhiteSpace(source))
        {
            return null;
        }

        if (Uri.TryCreate(source, UriKind.Absolute, out var absolute))
        {
            return absolute.ToString();
        }

        if (string.IsNullOrWhiteSpace(publicBaseUrl))
        {
            return null;
        }

        return publicBaseUrl.TrimEnd('/') + "/" + source.TrimStart('/');
    }

    private string BuildPublicAdminMediaUrl(string fileName, string? publicBaseUrl)
    {
        if (string.IsNullOrWhiteSpace(publicBaseUrl))
        {
            return "/media/admin/" + fileName;
        }

        return publicBaseUrl.TrimEnd('/') + "/media/admin/" + fileName;
    }

    private static string BuildRenderArguments(
        string inputVideoPath,
        string? inputMusicPath,
        string outputPath,
        double trimStart,
        double outputDuration,
        InstagramPublishDraft draft,
        bool hasOriginalAudio,
        double? musicWindow)
    {
        var trimArgs = $"-y -ss {FormatSeconds(trimStart)} -i {Quote(inputVideoPath)}";
        if (string.IsNullOrWhiteSpace(inputMusicPath))
        {
            return $"{trimArgs} -t {FormatSeconds(outputDuration)} -map 0:v:0 -map 0:a? -c:v libx264 -preset veryfast -c:a aac -movflags +faststart {Quote(outputPath)}";
        }

        var musicStart = Math.Max(0d, draft.MusicStartSeconds ?? 0d);
        var musicVolume = Clamp(draft.MusicVolume ?? 1d, 0d, 2d);
        var originalVolume = Clamp(draft.OriginalAudioVolume ?? 1d, 0d, 2d);
        var durationArgs = musicWindow.HasValue ? $" -t {FormatSeconds(musicWindow.Value)}" : string.Empty;
        var secondInputArgs = $"-ss {FormatSeconds(musicStart)}{durationArgs} -i {Quote(inputMusicPath)}";

        if (hasOriginalAudio)
        {
            var filter = $"[0:a]volume={FormatNumber(originalVolume)}[base];[1:a]volume={FormatNumber(musicVolume)}[music];[base][music]amix=inputs=2:duration=first:dropout_transition=2[aout]";
            return $"{trimArgs} {secondInputArgs} -t {FormatSeconds(outputDuration)} -filter_complex {Quote(filter)} -map 0:v:0 -map [aout] -c:v libx264 -preset veryfast -c:a aac -shortest -movflags +faststart {Quote(outputPath)}";
        }

        var musicOnlyFilter = $"[1:a]volume={FormatNumber(musicVolume)}[aout]";
        return $"{trimArgs} {secondInputArgs} -t {FormatSeconds(outputDuration)} -filter_complex {Quote(musicOnlyFilter)} -map 0:v:0 -map [aout] -c:v libx264 -preset veryfast -c:a aac -shortest -movflags +faststart {Quote(outputPath)}";
    }

    private async Task<VideoProbeInfo?> ProbeVideoAsync(string inputPath, CancellationToken cancellationToken)
    {
        var result = await RunProcessAsync(
            "ffprobe",
            $"-v error -print_format json -show_format -show_streams {Quote(inputPath)}",
            cancellationToken);

        if (result.ExitCode != 0 || string.IsNullOrWhiteSpace(result.StdOut))
        {
            _logger.LogWarning("ffprobe falhou. ExitCode={ExitCode} Error={Error}", result.ExitCode, result.StdErr);
            return null;
        }

        try
        {
            using var doc = JsonDocument.Parse(result.StdOut);
            var streams = doc.RootElement.TryGetProperty("streams", out var streamsNode) && streamsNode.ValueKind == JsonValueKind.Array
                ? streamsNode.EnumerateArray().ToList()
                : new List<JsonElement>();
            var hasAudio = streams.Any(x => string.Equals(TryGetString(x, "codec_type"), "audio", StringComparison.OrdinalIgnoreCase));
            var durationRaw = doc.RootElement.TryGetProperty("format", out var formatNode)
                ? TryGetString(formatNode, "duration")
                : null;

            if (!double.TryParse(durationRaw, System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out var durationSeconds))
            {
                return null;
            }

            return new VideoProbeInfo(durationSeconds, hasAudio);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Nao foi possivel interpretar a saida do ffprobe.");
            return null;
        }
    }

    private static string? TryGetString(JsonElement node, string propertyName)
        => node.TryGetProperty(propertyName, out var value) ? value.ToString() : null;

    private static async Task<bool> BinaryExistsAsync(string fileName, CancellationToken cancellationToken)
    {
        var result = await RunStaticProcessAsync(fileName, "-version", cancellationToken);
        return result.ExitCode == 0;
    }

    private Task<ProcessResult> RunProcessAsync(string fileName, string arguments, CancellationToken cancellationToken)
        => RunStaticProcessAsync(fileName, arguments, cancellationToken);

    private static async Task<ProcessResult> RunStaticProcessAsync(string fileName, string arguments, CancellationToken cancellationToken)
    {
        using var process = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = fileName,
                Arguments = arguments,
                RedirectStandardError = true,
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            }
        };

        process.Start();
        var stdOutTask = process.StandardOutput.ReadToEndAsync(cancellationToken);
        var stdErrTask = process.StandardError.ReadToEndAsync(cancellationToken);
        await process.WaitForExitAsync(cancellationToken);
        return new ProcessResult(process.ExitCode, await stdOutTask, await stdErrTask);
    }

    private static string TryInferExtension(string url, string fallbackExtension)
    {
        if (Uri.TryCreate(url, UriKind.Absolute, out var uri))
        {
            var extension = Path.GetExtension(uri.AbsolutePath);
            if (!string.IsNullOrWhiteSpace(extension))
            {
                return extension;
            }
        }

        return fallbackExtension;
    }

    private static double Clamp(double value, double min, double max)
        => Math.Min(Math.Max(value, min), max);

    private static string FormatSeconds(double value)
        => value.ToString("0.###", System.Globalization.CultureInfo.InvariantCulture);

    private static string FormatNumber(double value)
        => value.ToString("0.###", System.Globalization.CultureInfo.InvariantCulture);

    private static string Quote(string value)
        => "\"" + value.Replace("\"", "\\\"", StringComparison.Ordinal) + "\"";

    private sealed record VideoProbeInfo(double DurationSeconds, bool HasAudio);
    private sealed record ProcessResult(int ExitCode, string StdOut, string StdErr);
}
