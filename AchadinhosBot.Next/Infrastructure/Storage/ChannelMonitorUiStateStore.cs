using System.Text.Json;
using AchadinhosBot.Next.Application.Abstractions;
using AchadinhosBot.Next.Domain.Agents;

namespace AchadinhosBot.Next.Infrastructure.Storage;

public sealed class ChannelMonitorUiStateStore : IChannelMonitorUiStateStore
{
    private readonly string _path;
    private readonly SemaphoreSlim _mutex = new(1, 1);

    public ChannelMonitorUiStateStore()
    {
        _path = Path.Combine(AppContext.BaseDirectory, "data", "channel-monitor-ui-state.json");
    }

    public async Task<ChannelMonitorUiState> GetAsync(CancellationToken cancellationToken)
    {
        await _mutex.WaitAsync(cancellationToken);
        try
        {
            if (!File.Exists(_path))
            {
                return new ChannelMonitorUiState();
            }

            var json = await File.ReadAllTextAsync(_path, cancellationToken);
            return JsonSerializer.Deserialize<ChannelMonitorUiState>(json) ?? new ChannelMonitorUiState();
        }
        catch
        {
            return new ChannelMonitorUiState();
        }
        finally
        {
            _mutex.Release();
        }
    }

    public async Task<ChannelMonitorUiState> SaveAsync(ChannelMonitorUiState state, CancellationToken cancellationToken)
    {
        var payload = state ?? new ChannelMonitorUiState();

        await _mutex.WaitAsync(cancellationToken);
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
            var json = JsonSerializer.Serialize(payload);
            await File.WriteAllTextAsync(_path, json, cancellationToken);
            return payload;
        }
        finally
        {
            _mutex.Release();
        }
    }
}
